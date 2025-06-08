import sqlite3
import time
import os
from typing import List

PROCESS_DB = os.path.join(os.path.dirname(__file__), 'processes.db')
SIGNATURE_DB = os.path.join(os.path.dirname(__file__), 'signatures.db')
BOOT_DB = os.path.join(os.path.dirname(__file__), 'boot_files.db')


def init_process_db(db_path: str = PROCESS_DB) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute(
        "CREATE TABLE IF NOT EXISTS process_checksums (path TEXT PRIMARY KEY, checksum TEXT, last_seen INTEGER)"
    )
    conn.commit()
    return conn


def init_signature_db(db_path: str = SIGNATURE_DB) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute(
        "CREATE TABLE IF NOT EXISTS signatures (signature TEXT PRIMARY KEY)"
    )
    conn.commit()
    return conn


def store_process(path: str, checksum: str, db_path: str = PROCESS_DB):
    with init_process_db(db_path) as conn:
        c = conn.cursor()
        c.execute(
            "INSERT OR REPLACE INTO process_checksums (path, checksum, last_seen) VALUES (?, ?, ?)",
            (path, checksum, int(time.time())),
        )
        conn.commit()


def find_paths_by_checksum(checksum: str, db_path: str = PROCESS_DB) -> List[str]:
    with init_process_db(db_path) as conn:
        c = conn.cursor()
        rows = c.execute(
            "SELECT path FROM process_checksums WHERE checksum=?", (checksum,)
        ).fetchall()
        return [r[0] for r in rows]


def load_signatures(db_path: str = SIGNATURE_DB) -> List[str]:
    with init_signature_db(db_path) as conn:
        c = conn.cursor()
        rows = c.execute("SELECT signature FROM signatures").fetchall()
        return [r[0] for r in rows]
