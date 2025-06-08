#!/usr/bin/env python3
"""Boot partition integrity checker.

On first run this script backs up files from /boot into a sqlite database
as base64 encoded blobs. On subsequent runs it verifies the checksums of
those files and restores any that changed using ``dd``.
"""
import os
import sqlite3
import base64
import hashlib
import subprocess
from pathlib import Path

BOOT_DB = os.path.join(os.path.dirname(__file__), 'boot_files.db')
BOOT_DIR = '/boot'


def init_boot_db(db_path: str = BOOT_DB) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute(
        """CREATE TABLE IF NOT EXISTS boot_files (
            path TEXT PRIMARY KEY,
            checksum TEXT,
            data TEXT
        )"""
    )
    conn.commit()
    return conn


def sha256_data(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def sha256_file(path: str) -> str:
    try:
        with open(path, 'rb') as f:
            return sha256_data(f.read())
    except Exception:
        return ''


def backup_boot_files(root: str = BOOT_DIR, db_path: str = BOOT_DB) -> None:
    with init_boot_db(db_path) as conn:
        cur = conn.cursor()
        for dirpath, _, files in os.walk(root):
            for name in files:
                fpath = os.path.join(dirpath, name)
                try:
                    with open(fpath, 'rb') as f:
                        data = f.read()
                except Exception:
                    continue
                rel = os.path.relpath(fpath, root)
                checksum = sha256_data(data)
                b64 = base64.b64encode(data).decode()
                cur.execute(
                    'INSERT OR REPLACE INTO boot_files (path, checksum, data) VALUES (?, ?, ?)',
                    (rel, checksum, b64)
                )
        conn.commit()


def restore_file(rel_path: str, data_b64: str, root: str = BOOT_DIR) -> None:
    target = os.path.join(root, rel_path)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    data = base64.b64decode(data_b64)
    # Use dd to write the data for extra paranoia
    subprocess.run(['dd', f'of={target}', 'bs=1M', 'status=none'], input=data, check=True)


def verify_boot_files(root: str = BOOT_DIR, db_path: str = BOOT_DB) -> None:
    with init_boot_db(db_path) as conn:
        cur = conn.cursor()
        rows = cur.execute('SELECT path, checksum, data FROM boot_files').fetchall()
        for rel_path, checksum, data in rows:
            target = os.path.join(root, rel_path)
            cur_sum = sha256_file(target)
            if cur_sum != checksum:
                restore_file(rel_path, data, root)


def main():
    with init_boot_db() as conn:
        cur = conn.cursor()
        count = cur.execute('SELECT COUNT(*) FROM boot_files').fetchone()[0]
    if count == 0:
        backup_boot_files()
    else:
        verify_boot_files()


if __name__ == '__main__':
    main()
