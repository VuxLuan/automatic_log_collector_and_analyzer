import mmap
import os
import re
import hashlib
from functools import lru_cache
from datetime import datetime
from typing import List, Dict
from tqdm import tqdm

from decouple import config

# Globals set by main
earliest_date_cutoff = None


def calculate_hash_id(log_entry):
    hash_content = f"{log_entry['instance_id']}{log_entry['machine_name']}{log_entry['public_ip']}{log_entry['log_file_source']}{log_entry['message']}"
    return hashlib.sha256(hash_content.encode()).hexdigest()


@lru_cache(maxsize=None)
def get_current_year():
    return datetime.now().year

cnode_pattern = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")

gonode_pattern = re.compile(r"\[.*\]")
dd_service_pattern = re.compile(r"(\d{1,7}) - (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})? \[.*\]")
dd_entry_pattern = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) -(.*)$')
systemd_pattern = re.compile(r"(\S+)\s(\d+)\s(\d+):(\d+):(\d+)\s(\S+)\s(.*)")
inference_layer_pattern = re.compile(r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),%f - pastel_supernode_inference_layer - (?P<level>\w+) - (?P<message>.+)")

def parse_cnode_log(log_line):
    match = cnode_pattern.search(log_line)
    if match:
        try:
            timestamp = datetime.strptime(match.group(), "%Y-%m-%d %H:%M:%S")
            message = log_line[match.end():].strip()
            return {'timestamp': timestamp, 'message': message}
        except ValueError:
            return None
    return None

def parse_systemd_log(log_line):
    match = systemd_pattern.match(log_line)
    if match:
        log_parts = match.groups()
        timestamp_str = f"{log_parts[0]} {log_parts[1]} {log_parts[2]}:{log_parts[3]}:{log_parts[4]}"
        timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
        current_year = get_current_year()
        timestamp = timestamp.replace(year=current_year)
        message = log_parts[6]
        return {'timestamp': timestamp, 'message': message}
    return None

def parse_gonode_log(log_line):
    match = gonode_pattern.search(log_line)
    if match:
        datetime_str = match.group().strip("[]")
        timestamp = datetime.strptime(datetime_str, "%b %d %H:%M:%S.%f")
        current_year = get_current_year()
        timestamp = timestamp.replace(year=current_year)
        message = log_line[match.end():].strip()
        return {'timestamp': timestamp, 'message': message}
    return None

def parse_dd_service_log(log_line, last_timestamp=None):
    match = dd_service_pattern.search(log_line)
    if match:
        if match.group(2) is not None:
            datetime_str = match.group(2).strip("[]")
            timestamp = datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S.%f")
        elif last_timestamp is not None:
            timestamp = last_timestamp
        else:
            return None
        message = log_line[match.end():].strip()
        return {'timestamp': timestamp, 'message': message}
    return None

def parse_dd_entry_log(entry_line, last_timestamp=None):
    match = dd_entry_pattern.search(entry_line)
    if match:
        datetime_str = match.group(1)
        message = match.group(2).strip()
        try:
            timestamp = datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            timestamp = last_timestamp
        return {'timestamp': timestamp, 'message': message}
    return None

def parse_inference_layer_log(line):
    match = inference_layer_pattern.match(line)
    if match:
        try:
            timestamp_str = match.group("timestamp")
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            message = match.group("message").strip()
            return {"timestamp": timestamp, "message": message}
        except ValueError:
            return None
    return None

def parse_logs(local_file_name: str, instance_id: str, machine_name: str, public_ip: str, log_file_source: str) -> List[Dict]:
    list_of_ignored_strings = ['sshd[']
    log_entries = []
    if "debug.log" in local_file_name:
        parse_function = parse_cnode_log
    elif ("supernode.log" in local_file_name) or ("hermes.log" in local_file_name):
        parse_function = parse_gonode_log
    elif "dd-service-log.txt" in local_file_name:
        parse_function = parse_dd_service_log
    elif "entry.log" in local_file_name:
        parse_function = parse_dd_entry_log
    elif "systemd_log.txt" in local_file_name:
        parse_function = parse_systemd_log
    elif "pastel_supernode_inference_layer.log" in local_file_name:
        parse_function = parse_inference_layer_log
    else:
        raise ValueError("Unsupported log file format")
    if os.path.getsize(local_file_name) == 0:
        print(f"File '{local_file_name}' is empty. Skipping parsing.")
        return log_entries
    with open(local_file_name, 'r') as f:
        mmapped_file = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        for line in tqdm(iter(mmapped_file.readline, b'')):
            line = line.decode('utf-8')
            try:
                parsed_log = parse_function(line)
                if parsed_log:
                    if len(parsed_log['message']) > 0 and not any(ignored_string in parsed_log['message'] for ignored_string in list_of_ignored_strings):
                        if parsed_log['timestamp'] < earliest_date_cutoff:
                            continue
                        log_entries.append({
                            'instance_id': instance_id,
                            'machine_name': machine_name,
                            'public_ip': public_ip,
                            'log_file_source': log_file_source,
                            'timestamp': parsed_log['timestamp'],
                            'message': parsed_log['message'],
                        })
            except Exception:
                pass
        mmapped_file.close()
    return log_entries

def parse_and_append_logs(local_file_name, instance_id, instance_name, public_ip, log_file_source):
    return parse_logs(local_file_name, instance_id, instance_name, public_ip, log_file_source)
