import argparse
import sqlite3
from .ml import SignatureClassifier
from .db import SIGNATURE_DB, init_signature_db

DEFAULT_URLS = [
    "https://bazaar.abuse.ch/export/csv/full/",
]


def main():
    parser = argparse.ArgumentParser(description="Update signature database")
    parser.add_argument('--urls', nargs='*', default=DEFAULT_URLS,
                        help='CSV or ZIP URLs with signatures')
    parser.add_argument('--db-path', default=SIGNATURE_DB,
                        help='Path to signature sqlite db')
    args = parser.parse_args()

    clf = SignatureClassifier()
    df = clf.fetch_dataset(args.urls)

    with init_signature_db(args.db_path) as conn:
        cur = conn.cursor()
        for sig in df['signature']:
            cur.execute(
                "INSERT OR IGNORE INTO signatures(signature) VALUES (?)", (sig,)
            )
        conn.commit()
    print(f"Stored {len(df)} signatures to {args.db_path}")


if __name__ == '__main__':
    main()
