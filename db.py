import os
import sqlite3
import shutil
from datetime import datetime

import pandas as pd
import sqlalchemy as sa
from sqlalchemy import Column, Integer, JSON, ForeignKey
from sqlalchemy.orm import relationship
from decouple import config

# Globals to be set by the main script
engine = None
sqlite_file_path = None
backup_base_path = None
earliest_date_cutoff = None
BASE_PATH = config("BASE_PATH", cast=str)

Base = sa.orm.declarative_base()

class LogEntry(Base):
    __tablename__ = 'log_entries'
    id = sa.Column(sa.Integer, primary_key=True)
    hash_id = sa.Column(sa.String, index=True)
    instance_id = sa.Column(sa.String)
    machine_name = sa.Column(sa.String, index=True)
    public_ip = sa.Column(sa.String, index=True)
    log_file_source = sa.Column(sa.String, index=True)
    timestamp = sa.Column(sa.DateTime)
    message = sa.Column(sa.String)

class SNStatus(Base):
    __tablename__ = 'sn_status'
    id = sa.Column(sa.Integer, primary_key=True)
    public_ip = sa.Column(sa.String)
    instance_name = sa.Column(sa.String)
    datetime_of_data = sa.Column(sa.String)
    version = sa.Column(sa.Integer)
    protocolversion = sa.Column(sa.Integer)
    walletversion = sa.Column(sa.Integer)
    chain = sa.Column(sa.String)
    balance = sa.Column(sa.Float)
    blocks = sa.Column(sa.Integer)
    timeoffset = sa.Column(sa.Integer)
    connections = sa.Column(sa.Integer)
    proxy = sa.Column(sa.String)
    difficulty = sa.Column(sa.Float)
    testnet = sa.Column(sa.Boolean)
    keypoololdest = sa.Column(sa.Integer)
    keypoolsize = sa.Column(sa.Integer)
    paytxfee = sa.Column(sa.Float)
    relayfee = sa.Column(sa.Float)
    errors = sa.Column(sa.String)
    masternode_collateral_txid_and_outpoint = sa.Column(sa.String)
    masternode_collateral_address = sa.Column(sa.String)
    sn_pastelid_pubkey = sa.Column(sa.String)
    sn_alias = sa.Column(sa.String)
    sn_status = sa.Column(sa.String)

    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class SNMasternodeStatus(Base):
    __tablename__ = 'sn_masternode_status'
    public_ip = sa.Column(sa.String)
    instance_name = sa.Column(sa.String)
    datetime_of_data = sa.Column(sa.String)
    id = sa.Column(sa.Integer, primary_key=True)
    masternode_collateral_txid_and_outpoint = sa.Column(sa.String)
    masternode_status_message = sa.Column(sa.String)
    protocol_version = sa.Column(sa.String)
    masternode_collateral_address = sa.Column(sa.String)
    datetime_last_seen = sa.Column(sa.String)
    active_seconds = sa.Column(sa.String)
    datetime_last_paid = sa.Column(sa.String)
    last_paid_blockheight = sa.Column(sa.String)
    ip_address_and_port = sa.Column(sa.String)
    rank_as_of_block_height = Column(sa.Integer)
    masternode_rank = Column(sa.Integer)
    sn_pastelid_pubkey = Column(sa.String)

    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class SNNetworkActivityNetstat(Base):
    __tablename__ = 'sn_network_activity_netstat'
    id = sa.Column(sa.Integer, primary_key=True)
    public_ip = sa.Column(sa.String)
    instance_name = sa.Column(sa.String)
    datetime_of_data = sa.Column(sa.String)
    netstat__proto = sa.Column(sa.String)
    netstat__recv_q = sa.Column(sa.Integer)
    netstat__send_q = sa.Column(sa.Integer)
    netstat__local_address = sa.Column(sa.String)
    netstat__foreign_address = sa.Column(sa.String)
    netstat__state = sa.Column(sa.String)
    netstat__pid_program_name = sa.Column(sa.String)

    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class SNNetworkActivityLSOF(Base):
    __tablename__ = 'sn_network_activity_lsof'
    id = sa.Column(sa.Integer, primary_key=True)
    public_ip = sa.Column(sa.String)
    instance_name = sa.Column(sa.String)
    datetime_of_data = sa.Column(sa.String)
    lsof__command = sa.Column(sa.String)
    lsof__pid = sa.Column(sa.Integer)
    lsof__user = sa.Column(sa.String)
    lsof__fd = sa.Column(sa.String)
    lsof__type = sa.Column(sa.String)
    lsof__device = sa.Column(sa.String)
    lsof__size_off = sa.Column(sa.String)
    lsof__node = sa.Column(sa.String)
    lsof__name = sa.Column(sa.String)

    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class SNNetworkActivitySS(Base):
    __tablename__ = 'sn_network_activity_ss'
    id = sa.Column(sa.Integer, primary_key=True)
    public_ip = sa.Column(sa.String)
    instance_name = sa.Column(sa.String)
    datetime_of_data = sa.Column(sa.String)
    ss__state = sa.Column(sa.String)
    ss__recv_q = sa.Column(sa.Integer)
    ss__send_q = sa.Column(sa.Integer)
    ss__local_address_port = sa.Column(sa.String)
    ss__peer_address_port = sa.Column(sa.String)
    ss__process = sa.Column(sa.String)

    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class NodeHealthChecks(Base):
    __tablename__ = 'node_health_checks'
    id = Column(Integer, primary_key=True)
    missing_status_responses = Column(JSON)
    out_of_sync_nodes = Column(JSON)
    nodes_with_zero_connections = Column(JSON)

class NodeMasternodeHealthChecks(Base):
    __tablename__ = 'node_masternode_health_checks'
    id = Column(Integer, primary_key=True)
    masternode_rank_outlier_report_explanations = Column(JSON, nullable=True)
    all_new_start_required = Column(JSON, nullable=True)
    supernodes_reported_to_be_in_new_start_required_mode = Column(JSON, nullable=True)

class EntriesBeforeAndAfterPanics(Base):
    __tablename__ = 'entries_before_and_after_panics'
    id = Column(Integer, primary_key=True)
    log_entry_id = Column(Integer, ForeignKey('log_entries.id'))
    log_entry = relationship("LogEntry")

class MiscErrorEntries(Base):
    __tablename__ = 'misc_error_entries'
    id = Column(Integer, primary_key=True)
    log_entry_id = Column(Integer, ForeignKey('log_entries.id'))
    log_entry = relationship("LogEntry")


def backup_table(table_name):
    with sqlite3.connect(sqlite_file_path) as conn:
        df = pd.read_sql(f'SELECT * FROM {table_name}', conn)
        backup_file_name = f'{backup_base_path}_{table_name}.csv'
        df.to_csv(backup_file_name, index=False)
        timestamp = datetime.now().strftime('__%Y_%m_%d__%H_%M_%S')
        backup_dir = BASE_PATH + config("BACKUP_DATABASE_TABLE_CSV_FILES_DIR_NAME", cast=str)
        os.makedirs(backup_dir, exist_ok=True)
        backup_file_name_timestamped = f'{table_name}{timestamp}.csv'
        backup_file_path_timestamped = os.path.join(backup_dir, backup_file_name_timestamped)
        shutil.copy2(backup_file_name, backup_file_path_timestamped)
        print(f"Backed up {table_name} to {backup_file_name} and {backup_file_path_timestamped}")


def load_table(table_name):
    backup_path = f'{backup_base_path}_{table_name}.csv'
    if os.path.exists(backup_path):
        df = pd.read_csv(backup_path)
        initial_len = len(df)
        print(f"Loaded {table_name} from {backup_path}")
        df = df[pd.to_datetime(df['datetime_of_data']) > earliest_date_cutoff]
        print(
            f"Filtered {table_name} to only include entries after {earliest_date_cutoff} "
            f"({len(df)} entries retained, {initial_len - len(df)} removed)"
        )
        with sqlite3.connect(sqlite_file_path) as conn:
            df.to_sql(table_name, conn, if_exists='append', index=False)


def create_view_of_connection_counts():
    create_view_sql = """
    CREATE VIEW connection_count_per_service_view AS
    SELECT public_ip, instance_name, lsof__command, datetime_of_data_truncated, COUNT(*) as count
    FROM (
        SELECT sn.*, SUBSTR(sn.datetime_of_data, 1, 15) as datetime_of_data_truncated
        FROM sn_network_activity_lsof sn
        WHERE sn.lsof__type = 'IPv4' OR sn.lsof__type = 'IPv6'
    )
    WHERE SUBSTR(datetime_of_data_truncated, 1, 15) >= (
        SELECT SUBSTR(MAX(datetime_of_data), 1, 15)
        FROM sn_network_activity_lsof
    )
    GROUP BY public_ip, instance_name, lsof__command, datetime_of_data_truncated;
    """
    with engine.connect() as connection:
        try:
            connection.execute(sa.DDL(create_view_sql))
        except OperationalError as e:  # noqa: F841
            if "table connection_count_per_service_view already exists" in str(e):
                pass
            else:
                raise e
    print('View created!')


def add_summary_statistic_views(engine):
    views = [
        {
            "name": "log_entry_count_by_node_and_source",
            "query": """
                SELECT
                    machine_name,
                    log_file_source,
                    COUNT(*) as entry_count
                FROM log_entries
                GROUP BY machine_name, log_file_source
            """,
        },
        {
            "name": "error_count_by_node_and_source",
            "query": """
                SELECT
                    machine_name,
                    log_file_source,
                    COUNT(*) as error_count
                FROM log_entries
                WHERE LOWER(message) LIKE '%error%' OR LOWER(message) LIKE '%failed%' OR LOWER(message) LIKE '%exception%'
                GROUP BY machine_name, log_file_source
            """,
        },
    ]
    with engine.connect() as connection:
        for view in views:
            try:
                connection.execute(sa.text(f"DROP VIEW IF EXISTS {view['name']}"))
                print(f"Dropped existing view: {view['name']}")
                create_view_sql = f"CREATE VIEW {view['name']} AS {view['query']}"
                connection.execute(sa.text(create_view_sql))
                print(f"Created view: {view['name']}")
            except Exception as e:
                print(f"Error creating view {view['name']}: {str(e)}")
    print("Finished creating all summary statistic views.")
