import os
import sys
import glob
import json
import threading
import subprocess
import sqlite3
import shlex
import cProfile
import pstats
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from multiprocessing import Pool, Manager
from collections import Counter
from typing import List, Dict

import boto3
import pandas as pd
import redis
import sqlalchemy as sa
from sqlalchemy import and_, or_
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import OperationalError, IntegrityError
import yaml
from decouple import config

import db
from ssh_utils import (
    get_instance_name,
    get_instances_with_name_prefix,
    get_ssh_key_and_user,
    ssh_connect,
    download_logs,
    check_sn_status,
    check_sn_masternode_status,
    get_sn_network_data,
)
from log_parser import (
    parse_and_append_logs,
    calculate_hash_id,
    earliest_date_cutoff as parser_earliest_date_cutoff,
)

redis_client = redis.StrictRedis(host='localhost', port=6379, db=0)
engine = None
instance_ids = []
ssh_key_path = None
aws_access_key_id = None
aws_secret_access_key = None
aws_region = None
ansible_inventory_file = None
backup_base_path = None
sqlite_file_path = None
use_sequential_data_collection = 0


def remove_dupes_from_list_but_preserve_order_func(list_of_items):
    return list(dict.fromkeys(list_of_items).keys())


def insert_log_entries(parsed_log_entries: List[Dict], session: Session, chunk_size: int = 250000, max_retries: int = 3):
    def commit_with_retry(sess: Session):
        for retry_count in range(max_retries):
            try:
                sess.commit()
                break
            except OperationalError as e:
                if 'database is locked' in str(e).lower() and retry_count < max_retries - 1:
                    sleep_time = 2 ** retry_count
                    time.sleep(sleep_time)
                else:
                    raise
            except IntegrityError as e:
                sess.rollback()
                print(f"IntegrityError occurred: {e}. Skipping this insert.")
    for idx in range(0, len(parsed_log_entries), chunk_size):
        chunk = parsed_log_entries[idx:idx + chunk_size]
        hash_ids = [calculate_hash_id(log_entry) for log_entry in chunk]
        hash_id_existence = redis_client.mget(hash_ids)
        hash_id_exists_map = {hid: exists for hid, exists in zip(hash_ids, hash_id_existence)}
        new_log_entries = []
        for log_entry, log_entry_hash_id in zip(chunk, hash_ids):
            if not hash_id_exists_map.get(log_entry_hash_id):
                redis_client.set(log_entry_hash_id, 1)
                new_log_entries.append(db.LogEntry(hash_id=log_entry_hash_id, **log_entry))
        new_log_entries = remove_dupes_from_list_but_preserve_order_func(new_log_entries)
        session.add_all(new_log_entries)
        commit_with_retry(session)


def get_status_info_for_instance(instance_id):
    global aws_region, aws_access_key_id, aws_secret_access_key, ssh_key_path, ansible_inventory_file
    print(f"Checking {instance_id}...")
    with open(ansible_inventory_file, 'r') as f:
        ansible_inventory = yaml.safe_load(f)
    public_ip, key_path = None, None
    instance_name = instance_id
    ssh_user = ansible_inventory['all']['vars']['ansible_user']
    hosts = ansible_inventory.get('all', {}).get('hosts', {})
    if instance_id in hosts:
        host_info = hosts[instance_id]
        public_ip = host_info.get('ansible_host')
        key_path = host_info.get('ansible_ssh_private_key_file')
    if not public_ip or not key_path:
        print(f"Instance {instance_id} is not in the Ansible inventory file, using AWS API to get public IP address and instance name.")
        ec2 = boto3.client('ec2', region_name=aws_region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
        instance = ec2.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]
        public_ip = instance['PublicIpAddress']
        instance_name = get_instance_name(instance['Tags'])
    print(f"Now checking for SSH connectivity on instance named {instance_name} with instance ID of {instance_id} and public IP address of {public_ip}...")
    ssh_status, ssh_error = ssh_connect(public_ip, ssh_user, key_path if key_path else ssh_key_path)
    if ssh_status:
        print(f"{instance_id} ({instance_name}) is reachable by SSH")
        print(f"Now checking the status of the Pastel node on {instance_name} using `pastel-cli getinfo`...")
        output_dict = check_sn_status(public_ip, ssh_user, key_path if key_path else ssh_key_path, instance_name)
        print(f"Result of `getinfo` command on {instance_name}: {output_dict}")
        print(f"Now checking the masternode status of {instance_name} using `pastel-cli masternode list full` and `list extra`...")
        combined_masternode_status_dict = check_sn_masternode_status(public_ip, ssh_user, key_path if key_path else ssh_key_path, instance_name)
        print(f"Result of `masternode list full` and `list extra` command on {instance_name}: {combined_masternode_status_dict}")
        print(f"Now getting network data for {instance_name} using various network commands...")
        get_sn_network_data(public_ip, ssh_user, key_path if key_path else ssh_key_path, instance_name)
        print('Done getting network data!')
    else:
        if ssh_error == "Authentication failed.":
            print(f"{instance_id} ({instance_name}) has an authentication issue!")
        else:
            print(f"{instance_id} ({instance_name}) is not reachable by SSH!")


def insert_log_entries_worker(db_write_queue):
    Session = sessionmaker(bind=engine)
    none_count = 0
    while none_count < len(instance_ids):
        logs_to_insert = db_write_queue.get()
        if logs_to_insert is None:
            none_count += 1
        else:
            session = Session()
            try:
                session.bulk_insert_mappings(db.LogEntry, logs_to_insert)
                session.commit()
            except Exception as e:
                print(f"Error inserting log entries: {e}")
            finally:
                session.close()
        db_write_queue.task_done()


def process_instance(instance_id, db_write_queue):
    global aws_region, aws_access_key_id, aws_secret_access_key, ansible_inventory_file
    num_cores = os.cpu_count()
    if num_cores is not None:
        num_cores = max(1, num_cores - 2)
    with open(ansible_inventory_file, 'r') as f:
        ansible_inventory = yaml.safe_load(f)
    print(f"Checking {instance_id}...")
    public_ip, key_path = None, None
    instance_name = instance_id
    ssh_user = ansible_inventory['all']['vars']['ansible_user']
    hosts = ansible_inventory.get('all', {}).get('hosts', {})
    if instance_id in hosts:
        host_info = hosts[instance_id]
        public_ip = host_info.get('ansible_host')
        key_path = host_info.get('ansible_ssh_private_key_file')
    if not public_ip or not key_path:
        print('Instance is not in the Ansible inventory file, using AWS API to get public IP address and instance name.')
        ec2 = boto3.client('ec2', region_name=aws_region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
        instance = ec2.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]
        public_ip = instance['PublicIpAddress']
        instance_name = get_instance_name(instance['Tags'])
    Session = sessionmaker(bind=engine)
    session = Session()
    user = ssh_user
    key_path = key_path if key_path else ssh_key_path
    print(f"Now checking for SSH connectivity on instance named {instance_name} with instance ID of {instance_id} and public IP address of {public_ip}...")
    ssh_status, ssh_error = ssh_connect(public_ip, user, key_path)
    if ssh_status:
        print(f"{instance_id} ({instance_name}) is reachable by SSH")
        log_files = [
            "/home/ubuntu/.pastel/debug.log",
            "/home/ubuntu/.pastel/supernode.log",
            "/home/ubuntu/.pastel/hermes.log",
            "/home/ubuntu/pastel_dupe_detection_service/logs/dd-service-log.txt",
            "/home/ubuntu/pastel_dupe_detection_service/logs/entry/entry.log",
            "/home/ubuntu/python_inference_layer_server/pastel_supernode_inference_layer.log",
        ]
        list_of_local_log_file_names = download_logs(public_ip, user, key_path, instance_name, log_files)
        print('Now parsing log files...')
        all_parsed_log_entries = []
        with ThreadPoolExecutor(max_workers=num_cores) as executor:
            futures = [executor.submit(parse_and_append_logs, local_file_name, instance_id, instance_name, public_ip,
                        os.path.basename(local_file_name).split('.')[0].split('__')[-1].replace('debug', 'cnode').replace('entry', 'dd_entry'))
                        for local_file_name in list_of_local_log_file_names]
        for future in futures:
            all_parsed_log_entries.extend(future.result())
        print(f'Done parsing log files on {instance_name}! Total number of log entries: {len(all_parsed_log_entries):,}')
        db_write_queue.put(all_parsed_log_entries)
        session.close()
        print(f'Done inserting log entries into database on {instance_name}! Number of log entries inserted: {len(all_parsed_log_entries):,}')
    else:
        if ssh_error == "Authentication failed.":
            print(f"{instance_id} ({instance_name}) has an authentication issue!")
        else:
            print(f"{instance_id} ({instance_name}) is not reachable by SSH!")
    db_write_queue.put(None)


def main_workflow():
    num_cores = os.cpu_count()
    if num_cores is not None:
        num_cores = max(1, num_cores - 2)
    manager = Manager()
    db_write_queue = manager.JoinableQueue()
    db_writer_thread = threading.Thread(target=insert_log_entries_worker, args=(db_write_queue,))
    db_writer_thread.start()
    with ProcessPoolExecutor(max_workers=num_cores) as executor:
        futures = []
        for instance_id in instance_ids:
            future = executor.submit(process_instance, instance_id, db_write_queue)
            futures.append(future)
        for future in futures:
            try:
                future.result()
            except Exception as e:
                print(f"Error processing instance: {e}")
    db_write_queue.put(None)
    db_writer_thread.join()


def initialize():
    global engine, instance_ids, ssh_key_path, aws_access_key_id, aws_secret_access_key, aws_region
    global ansible_inventory_file, backup_base_path, sqlite_file_path, earliest_date_cutoff, use_sequential_data_collection

    aws_access_key_id = config("AWS_ACCESS_KEY_ID", cast=str)
    aws_secret_access_key = config("AWS_SECRET_ACCESS_KEY", cast=str)
    aws_region = config("AWS_REGION", cast=str)
    ansible_inventory_file = config("ANSIBLE_INVENTORY_FILE", cast=str)
    ssh_key_path = config("SSH_KEY_PATH", cast=str)
    earliest_date_cutoff = datetime.now() - timedelta(days=7)
    parser_earliest_date_cutoff = earliest_date_cutoff  # set in log_parser
    globals()['earliest_date_cutoff'] = earliest_date_cutoff
    db.earliest_date_cutoff = earliest_date_cutoff
    sqlite_file_path = config("SQLITE_FILE_PATH", cast=str)
    node_status_data_backup_path = config("NODE_STATUS_DATA_BACKUP_PATH", cast=str)
    backup_base_path = db.BASE_PATH + node_status_data_backup_path

    db.sqlite_file_path = sqlite_file_path
    db.backup_base_path = backup_base_path
    db.engine = sa.create_engine(f'sqlite:///{sqlite_file_path}', connect_args={'timeout': 20}, pool_size=10, max_overflow=20)
    engine = db.engine
    db.Base.metadata.create_all(engine)

    inventory_ids = get_instance_ids_from_inventory(ansible_inventory_file)
    instance_name_prefix = config("INSTANCE_NAME_PREFIX", cast=str)
    try:
        instances = get_instances_with_name_prefix(instance_name_prefix, aws_access_key_id, aws_secret_access_key, aws_region)
        aws_instance_ids = [instance.id for instance in instances]
    except Exception as e:
        print("Error getting instances from AWS API: ", e)
        aws_instance_ids = []
        instances = None
    instance_ids = aws_instance_ids + inventory_ids


def get_instance_ids_from_inventory(inventory_file):
    with open(inventory_file, 'r') as file:
        inventory = yaml.safe_load(file)
    hosts = inventory.get('all', {}).get('hosts', {})
    return list(hosts.keys())


if __name__ == "__main__":
    os.system('clear')
    print('Clearing existing Redis contents...')
    redis_client.flushall()
    print('Done clearing Redis contents!')
    initialize()
    main_workflow()
