import os
import subprocess
import json
import datetime as dt
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

import boto3
import paramiko
import yaml
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from decouple import config

from db import (
    SNStatus,
    SNMasternodeStatus,
    SNNetworkActivityNetstat,
    SNNetworkActivityLSOF,
    SNNetworkActivitySS,
    engine,
)

SSH_TIMEOUT_SECONDS = config("SSH_TIMEOUT_SECONDS", cast=int)


def get_instance_name(tags):
    for tag in tags:
        if tag['Key'] == 'Name':
            return tag['Value']
    return None


def get_instances_with_name_prefix(name_prefix, aws_access_key_id, aws_secret_access_key, aws_region):
    ec2 = boto3.resource('ec2', region_name=aws_region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    instances = ec2.instances.filter(
        Filters=[
            {'Name': 'tag:Name', 'Values': [f'{name_prefix}*']},
            {'Name': 'instance-state-name', 'Values': ['running']},
        ]
    )
    instances = sorted(instances, key=lambda instance: get_instance_name(instance.tags))
    return instances


def get_inventory():
    with open(config("ANSIBLE_INVENTORY_FILE", cast=str), 'r') as f:
        return yaml.safe_load(f)


def get_ssh_key_and_user(instance_name):
    inventory = get_inventory()
    hosts = inventory.get('all', {}).get('hosts', {})
    if instance_name in hosts:
        host_data = hosts[instance_name]
        return host_data.get('ansible_ssh_private_key_file'), inventory['all']['vars'].get('ansible_user', 'ubuntu')
    return None, None


def ssh_connect(ip, user, key_path):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, username=user, key_filename=key_path, timeout=5)
        ssh.close()
        return True, None
    except paramiko.AuthenticationException:
        return False, "Authentication failed."
    except Exception as e:
        return False, str(e)


def execute_network_commands_func(command: str) -> str:
    result = subprocess.run(command, shell=True, text=True, capture_output=True)
    return result.stdout


def parse_netstat_output(output: str):
    lines = output.split('\n')[2:]
    records = []
    for line in lines:
        if line:
            fields = line.split()
            record = {
                'netstat__proto': fields[0],
                'netstat__recv_q': int(fields[1]),
                'netstat__send_q': int(fields[2]),
                'netstat__local_address': fields[3],
                'netstat__foreign_address': fields[4],
                'netstat__state': fields[5] if len(fields) > 5 else None,
                'netstat__pid_program_name': fields[6] if len(fields) > 6 else None,
            }
            records.append(record)
    return records


def parse_lsof_output(output: str):
    lines = output.split('\n')[1:]
    records = []
    for line in lines:
        if line:
            fields = line.split()
            record = {
                'lsof__command': fields[0],
                'lsof__pid': int(fields[1]),
                'lsof__user': fields[2],
                'lsof__fd': fields[3],
                'lsof__type': fields[4],
                'lsof__device': fields[5],
                'lsof__size_off': fields[6],
                'lsof__node': fields[7],
                'lsof__name': fields[8],
            }
            records.append(record)
    return records


def parse_ss_output(output: str):
    lines = output.split('\n')[1:]
    records = []
    for line in lines:
        if line:
            fields = line.split()
            record = {
                'ss__state': fields[0],
                'ss__recv_q': int(fields[1]),
                'ss__send_q': int(fields[2]),
                'ss__local_address_port': fields[3],
                'ss__peer_address_port': fields[4],
                'ss__process': ' '.join(fields[5:]),
            }
            records.append(record)
    return records


def get_sn_network_data(remote_ip, user, key_path, instance_name):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        ssh.connect(remote_ip, username=user, key_filename=key_path, timeout=SSH_TIMEOUT_SECONDS)
        commands_and_parsers = [
            ('sudo netstat -tulnp', parse_netstat_output, SNNetworkActivityNetstat),
            ('sudo lsof -i', parse_lsof_output, SNNetworkActivityLSOF),
            ('sudo ss -tnp', parse_ss_output, SNNetworkActivitySS),
        ]
        for command, parser, model in commands_and_parsers:
            stdin, stdout, stderr = ssh.exec_command(command)
            output = stdout.read().decode('utf-8')
            parsed_records = parser(output)
            for record in parsed_records:
                record.update({
                    'public_ip': remote_ip,
                    'instance_name': instance_name,
                    'datetime_of_data': datetime.now().isoformat(),
                })
                sn_network_activity = model(**record)
                session.add(sn_network_activity)
        session.commit()
    except Exception as e:
        print(f"Error while getting network data: {str(e)}")
    finally:
        ssh.close()
        session.close()


def download_logs(remote_ip, user, key_path, instance_name, log_files):
    log_files_directory = "downloaded_log_files"
    os.makedirs(log_files_directory, exist_ok=True)
    current_time = dt.datetime.now()
    list_of_local_log_file_names = []

    def is_recently_downloaded(file_name):
        if os.path.exists(file_name):
            file_modification_time = dt.datetime.fromtimestamp(os.path.getmtime(file_name))
            time_difference = current_time - file_modification_time
            return time_difference < dt.timedelta(minutes=5)
        return False

    def download_log_file(log_file, local_file_name, sudo_prefix="sudo ", skip_first_line=False):
        try:
            cat_command = f"{sudo_prefix}cat {log_file}"
            if skip_first_line:
                cat_command = f"{sudo_prefix}tail -n +2 {log_file}"
            subprocess.run(['bash', '-c', f'ssh -i {key_path} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {user}@{remote_ip} "{cat_command}" > {local_file_name}'], check=True)
            print(f"Downloaded log file {log_file} from {instance_name} ({remote_ip}) to {local_file_name}")
        except subprocess.CalledProcessError as e:
            print(f"Error downloading log file {log_file} from {instance_name} ({remote_ip}): {e}")

    with ThreadPoolExecutor() as executor:
        futures = []
        for log_file in log_files:
            local_file_name = os.path.join(log_files_directory, f"{instance_name.replace(' ', '_')}__{remote_ip.replace('.','_')}__{os.path.basename(log_file)}")
            list_of_local_log_file_names.append(local_file_name)
            if is_recently_downloaded(local_file_name):
                print(f"Log file {local_file_name} was downloaded within the past 5 minutes, skipping download.")
                continue
            futures.append(executor.submit(download_log_file, log_file, local_file_name))
        remote_journalctl_output = f"/home/{user}/journalctl_output.txt"
        try:
            subprocess.run(["ssh", "-i", key_path, "-o", "StrictHostKeyChecking=no", f"{user}@{remote_ip}", f"sudo journalctl --since '-1 weeks' > {remote_journalctl_output}"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error running journalctl command on {instance_name} ({remote_ip}): {e}")
        local_journalctl_file_name = os.path.join(log_files_directory, f"{instance_name.replace(' ', '_')}__{remote_ip.replace('.','_')}__systemd_log.txt")
        list_of_local_log_file_names.append(local_journalctl_file_name)
        if not is_recently_downloaded(local_journalctl_file_name):
            futures.append(executor.submit(download_log_file, remote_journalctl_output, local_journalctl_file_name, skip_first_line=True))
        for future in futures:
            future.result()
    print(f"Finished downloading all log files from {instance_name} ({remote_ip})")
    return list_of_local_log_file_names


def check_sn_status(remote_ip, user, key_path, instance_name):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    Session = sessionmaker(bind=engine)
    session = Session()
    output_dict = {'Error': f'Could not connect to instance {instance_name}.'}
    try:
        ssh.connect(remote_ip, username=user, key_filename=key_path, timeout=SSH_TIMEOUT_SECONDS)
        stdin, stdout, stderr = ssh.exec_command('/home/ubuntu/pastel/pastel-cli masternode status')
        mn_status_output = stdout.read().decode('utf-8')
        mn_status_output_dict = json.loads(mn_status_output) if mn_status_output else {}
        stdin, stdout, stderr = ssh.exec_command('/home/ubuntu/pastel/pastel-cli getinfo')
        output = stdout.read().decode('utf-8')
        if output:
            output_dict = json.loads(output)
            output_dict['public_ip'] = remote_ip
            output_dict['instance_name'] = instance_name
            output_dict['datetime_of_data'] = datetime.now().isoformat()
            if mn_status_output_dict:
                output_dict['masternode_collateral_txid_and_outpoint'] = mn_status_output_dict['outpoint']
                output_dict['masternode_collateral_address'] = mn_status_output_dict['payee']
                output_dict['sn_pastelid_pubkey'] = mn_status_output_dict['extKey']
                output_dict['sn_alias'] = mn_status_output_dict['alias']
                output_dict['sn_status'] = mn_status_output_dict['status']
            sn_status = SNStatus(**output_dict)
            session.add(sn_status)
            session.commit()
        else:
            print(f"No output from getinfo command for {instance_name} ({remote_ip})")
    except Exception as e:
        print(f"Error while checking sn status for {instance_name} ({remote_ip}): {str(e)}")
    finally:
        ssh.close()
        session.close()
    return output_dict


def check_sn_masternode_status(remote_ip, user, key_path, instance_name):
    cmd1 = '/home/ubuntu/pastel/pastel-cli masternode list full'
    result1 = subprocess.run(['ssh', '-i', key_path, '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-o', f'ConnectTimeout={SSH_TIMEOUT_SECONDS}', f'{user}@{remote_ip}', cmd1], capture_output=True, text=True)
    if result1.stdout:
        data1 = json.loads(result1.stdout)
        cmd2 = '/home/ubuntu/pastel/pastel-cli masternode top'
        result2 = subprocess.run(['ssh', '-i', key_path, '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null','-o', f'ConnectTimeout={SSH_TIMEOUT_SECONDS}', f'{user}@{remote_ip}', cmd2], capture_output=True, text=True)
        data2 = json.loads(result2.stdout)
        rank_as_of_block_height = int(list(data2.keys())[0])
        data2_values = [x for x in list(data2.values())[0]]
        masternode_top_dict = {}
        for current_value in data2_values:
            txid = current_value['outpoint']
            masternode_top_dict[txid] = {
                'masternode_rank': int(current_value['rank']),
                'sn_pastelid_pubkey': current_value['extKey'],
                'rank_as_of_block_height': rank_as_of_block_height,
            }
        cmd3 = '/home/ubuntu/pastel/pastel-cli masternode list extra'
        result3 = subprocess.run(['ssh', '-i', key_path, '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null','-o', f'ConnectTimeout={SSH_TIMEOUT_SECONDS}', f'{user}@{remote_ip}', cmd3], capture_output=True, text=True)
        data3 = json.loads(result3.stdout)
        Session = sessionmaker(bind=engine)
        session = Session()
        combined = {}
        for key, value in data1.items():
            extra = masternode_top_dict.get(key, {})
            if extra:
                sn_pastelid_pubkey = extra.get('sn_pastelid_pubkey')
                masternode_rank = extra.get('masternode_rank')
                rank_as_of_block_height = extra.get('rank_as_of_block_height')
            else:
                extra = data3.get(key, {})
                sn_pastelid_pubkey = extra.get('extKey')
                masternode_rank = -1
                rank_as_of_block_height = -1
            values = value.split()
            status = SNMasternodeStatus(
                masternode_collateral_txid_and_outpoint=key,
                masternode_status_message=values[0],
                protocol_version=values[1],
                masternode_collateral_address=values[2],
                datetime_last_seen=values[3],
                active_seconds=values[4],
                datetime_last_paid=values[5],
                last_paid_blockheight=values[6],
                ip_address_and_port=values[7],
                sn_pastelid_pubkey=sn_pastelid_pubkey,
                masternode_rank=masternode_rank,
                rank_as_of_block_height=rank_as_of_block_height,
                public_ip=remote_ip,
                instance_name=instance_name,
                datetime_of_data=datetime.now().isoformat(),
            )
            combined[key] = status.to_dict()
            session.add(status)
            session.commit()
        session.close()
    else:
        combined = {'Error': f'Could not connect to instance {instance_name}.'}
    return combined
