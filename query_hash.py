#!/usr/bin/env python3.11
"""
Utility to query the LMDB hash database.
Usage: python3 query_hash.py <hash_to_check> [--db /path/to/db]
"""

import sys
import argparse
import lmdb

def query_hash(db_path, hash_to_check):
    """
    Checks for the existence of a hash in the LMDB database.
    """
    try:
        # Open the database in read-only mode
        env = lmdb.open(db_path, readonly=True)
    except lmdb.Error as e:
        print(f"Error: Could not open database at '{db_path}'.")
        print(f"Please ensure the path is correct and the database exists.")
        print(f"LMDB Error: {e}")
        sys.exit(1)

    with env.begin() as txn:
        # Keys are stored as bytes
        key = hash_to_check.encode('utf-8')
        value = txn.get(key)

    env.close()

    if value is not None:
        print(f"Hash FOUND in the database.")
        return True
    else:
        print(f"Hash NOT FOUND in the database.")
        return False

def main():
    parser = argparse.ArgumentParser(description='Query for a hash in the LMDB database.')
    parser.add_argument('hash', help='The hash to check for.')
    parser.add_argument('--db', default='hashes.lmdb', help='Path to the LMDB database directory')
    args = parser.parse_args()

    if not args.hash or len(args.hash) != 64:
        print("Error: Please provide a valid 64-character Blake3 hash.", file=sys.stderr)
        sys.exit(1)

    query_hash(args.db, args.hash)

if __name__ == "__main__":
    main()