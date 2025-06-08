#!/usr/bin/env python3
"""Boot partition integrity checker.

On first run this script backs up files from ``/boot`` into a SQLite
database as base64 encoded blobs **and** stores a full image of the boot
partition.  On subsequent runs it verifies the checksums of those files
and if any mismatch it restores the entire partition using ``dd``.
"""
import os
import sqlite3
import base64
import hashlib
import subprocess
from pathlib import Path

BOOT_DB = os.path.join(os.path.dirname(__file__), 'boot_files.db')
BOOT_DIR = '/boot'


def get_boot_device() -> str:
    """Return the block device backing the boot partition."""
    try:
        out = subprocess.check_output(
            ['findmnt', '-n', '-o', 'SOURCE', BOOT_DIR],
            text=True,
        )
        dev = out.strip()
        if dev:
            return dev
    except Exception:
        pass
    try:
        with open('/etc/mtab') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == BOOT_DIR:
                    return parts[0]
    except Exception:
        pass
    return ''


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
    c.execute(
        """CREATE TABLE IF NOT EXISTS boot_image (
            id INTEGER PRIMARY KEY,
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
        # Also store a full partition image to allow complete restoration
        dev = get_boot_device()
        if dev:
            try:
                img = subprocess.check_output(
                    ['dd', f'if={dev}', 'bs=1M', 'status=none']
                )
                img_b64 = base64.b64encode(img).decode()
                checksum = sha256_data(img)
                cur.execute(
                    'INSERT OR REPLACE INTO boot_image (id, checksum, data) VALUES (1, ?, ?)',
                    (checksum, img_b64)
                )
            except Exception:
                pass
        conn.commit()


def restore_file(rel_path: str, data_b64: str, root: str = BOOT_DIR) -> None:
    target = os.path.join(root, rel_path)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    data = base64.b64decode(data_b64)
    # Use dd to write the data for extra paranoia
    subprocess.run(['dd', f'of={target}', 'bs=1M', 'status=none'], input=data, check=True)


def restore_boot_partition(conn, root: str = BOOT_DIR) -> None:
    """Restore the entire boot partition from the stored image."""
    dev = get_boot_device()
    if not dev:
        return
    cur = conn.cursor()
    row = cur.execute('SELECT data FROM boot_image WHERE id=1').fetchone()
    if not row:
        return
    data = base64.b64decode(row[0])
    subprocess.run(['dd', f'of={dev}', 'bs=1M', 'status=none'], input=data, check=True)


def verify_boot_files(root: str = BOOT_DIR, db_path: str = BOOT_DB) -> None:
    with init_boot_db(db_path) as conn:
        cur = conn.cursor()
        rows = cur.execute('SELECT path, checksum FROM boot_files').fetchall()
        for rel_path, checksum in rows:
            target = os.path.join(root, rel_path)
            cur_sum = sha256_file(target)
            if cur_sum != checksum:
                restore_boot_partition(conn, root)
                break


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
