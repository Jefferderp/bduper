#!/usr/bin/env python3.11
"""
Script to recursively calculate Blake3 hashes of all files under a directory.
Usage: python3 hash_files.py <directory>
"""

import os
import sys
import argparse
import threading
import signal
import queue

try:
    import psutil
    def get_physical_core_count():
        return psutil.cpu_count(logical=False) or os.cpu_count() or 4
except ImportError:
    def get_physical_core_count():
        # Fallback if psutil isn't available
        return os.cpu_count() or 4

try:
    import blake3
except ImportError:
    print("Error: The 'blake3' module is required.")
    print("Please install it using: pip install blake3")
    sys.exit(1)

try:
    import lmdb
except ImportError:
    print("Error: The 'lmdb' module is required.")
    print("Please install it using: pip install lmdb")
    sys.exit(1)

def calculate_file_hash(file_path, chunk_size=8192, length=None):
    """
    Calculate the Blake3 hash of a file's contents using chunked reading.
    This avoids loading the entire file into memory, similar to --no-mmap option in b3sum.
    If a length is specified, the hash is truncated.
    """
    hasher = blake3.blake3()
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    
    if length:
        return hasher.hexdigest(length=length)
    return hasher.hexdigest()

class Stats:
    """A thread-safe class to hold pipeline statistics."""
    def __init__(self):
        self.files_found = 0
        self.files_hashed = 0
        self.hashes_written = 0
        self.skipped_duplicates = 0
        self.files_deleted = 0
        self.lock = threading.Lock()

    def increment_found(self):
        with self.lock:
            self.files_found += 1

    def increment_hashed(self):
        with self.lock:
            self.files_hashed += 1

    def increment_written(self):
        with self.lock:
            self.hashes_written += 1
    
    def increment_skipped(self):
        with self.lock:
            self.skipped_duplicates += 1
            
    def increment_deleted(self):
        with self.lock:
            self.files_deleted += 1

    def get(self):
        with self.lock:
            return self.files_found, self.files_hashed, self.hashes_written, self.skipped_duplicates, self.files_deleted

def status_reporter(stats, shutdown_event, dry_run=False, delete_duplicates=False, no_save_hashes=False):
    """Periodically prints the status of the pipeline."""
    while not shutdown_event.is_set():
        found, hashed, written, skipped, deleted = stats.get()
        
        skipped_msg = f"deleted: {deleted:,}" if delete_duplicates else "ignored"
        
        written_str = f"{written:,} new hashes"
        if dry_run or no_save_hashes:
            written_str = "0 (read-only mode)"
        
        # Use carriage return to print on the same line
        print(f"  Hashed: {hashed:,} of {found:,} files | Skipped: {skipped:,} duplicates ({skipped_msg}) | Saved: {written_str} ", end='\r')
        shutdown_event.wait(0.25) # Update 4 times per second

def scanner_worker(dir_q, file_q, stats):
    """
    Worker thread that scans directories from a queue, putting subdirectories
    and files onto their respective queues.
    """
    while True:
        directory = dir_q.get()
        if directory is None:
            break
        
        try:
            for entry in os.scandir(directory):
                if entry.is_dir(follow_symlinks=False):
                    dir_q.put(entry.path)
                elif entry.is_file(follow_symlinks=False):
                    file_q.put(entry.path)
                    stats.increment_found()
        except OSError as e:
            print(f"Error scanning directory {directory}: {e}", file=sys.stderr)
        finally:
            dir_q.task_done()

def hasher_worker(file_q, hash_q, stats):
    """
    Worker thread that consumes file paths from a queue, hashes them,
    and puts the result onto the hash queue.
    """
    while True:
        file_path = file_q.get()
        if file_path is None:
            hash_q.put(None)
            break
        
        try:
            file_hash = calculate_file_hash(file_path, length=24)
            hash_q.put((file_path, file_hash))
            stats.increment_hashed()
        except Exception as e:
            print(f"Error processing file {file_path}: {e}", file=sys.stderr)
        finally:
            file_q.task_done()

def database_writer(db_path, hash_q, delete_q, num_hashers, stats, dry_run=False, delete_duplicates=False, no_save_hashes=False):
    """
    A dedicated writer thread that consumes hashes from a queue and
    writes them to an LMDB database. Skips writing if dry_run is True.
    If a duplicate is found and delete_duplicates is True, the file path
    is put on the delete_q for the deleter_worker threads to handle.
    """
    # In dry-run mode, just consume items from the queue without writing
    if dry_run:
        hashers_finished = 0
        while hashers_finished < num_hashers:
            item = hash_q.get()
            if item is None:
                hashers_finished += 1
        return

    map_size = 100 * 1024 * 1024 * 1024
    env = lmdb.open(db_path, map_size=map_size, writemap=True, readonly=no_save_hashes)
    
    hashes_in_txn = 0
    hashers_finished = 0
    
    txn = env.begin(write=not no_save_hashes)

    while hashers_finished < num_hashers:
        try:
            item = hash_q.get(timeout=0.1)
            if item is None:
                hashers_finished += 1
                continue
            
            file_path, file_hash = item

            # If we are not saving hashes, we only check for existence
            if no_save_hashes:
                if txn.get(file_hash.encode('utf-8')) is not None:
                    stats.increment_skipped()
                    if delete_duplicates:
                        delete_q.put(file_path)
                else:
                    # If not saving, we are not finding "new" hashes, so we don't increment written
                    pass
            else:
                # Original behavior
                if txn.put(file_hash.encode('utf-8'), b'', overwrite=False):
                    hashes_in_txn += 1
                    stats.increment_written()
                else:
                    stats.increment_skipped()
                    if delete_duplicates:
                        delete_q.put(file_path)

            if not no_save_hashes and hashes_in_txn >= 1000:
                txn.commit()
                hashes_in_txn = 0
                txn = env.begin(write=True)

        except queue.Empty:
            continue
            
    if not no_save_hashes and hashes_in_txn > 0:
        txn.commit()
    else:
        txn.abort()

    env.close()

def deleter_worker(delete_q, stats):
    """
    Worker thread that consumes file paths from a queue and deletes them.
    """
    while True:
        file_path = delete_q.get()
        if file_path is None:
            break
        
        try:
            os.remove(file_path)
            stats.increment_deleted()
        except OSError as e:
            print(f"Error deleting file {file_path}: {e}", file=sys.stderr)
        finally:
            delete_q.task_done()

def main():
    num_physical_cores = get_physical_core_count()
    
    parser = argparse.ArgumentParser(
        description='Calculate Blake3 hash for all files recursively.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('directory', help='Directory to scan recursively')
    parser.add_argument('-db', '--database', default='hashes.lmdb', help='Path to the LMDB database directory')
    parser.add_argument(
        '-D', '--delete', action='store_true',
        help='Delete files that are found to be duplicates'
    )
    parser.add_argument(
        '-st', '--scanner-threads', type=int,
        default=2,
        help='Number of scanner threads (default: 2)'
    )
    parser.add_argument(
        '-ht', '--hasher-threads', type=int,
        default=num_physical_cores * 2,
        help=f'Number of hasher threads (default: {num_physical_cores * 2})'
    )
    parser.add_argument(
        '-d', '--dry-run', action='store_true',
        help='Scan and hash files, but do not write to the database'
    )
    parser.add_argument(
        '-dt', '--deleter-threads', type=int,
        default=num_physical_cores,
        help=f'Number of deleter threads (default: {num_physical_cores})'
    )
    parser.add_argument(
        '-n', '--no-save-hashes', action='store_true',
        help='Do not save newly-found hashes to the database.'
    )
    parser.add_argument(
        '--debug', action='store_true',
        help='Print debug information and exit'
    )
    args = parser.parse_args()

    if args.debug:
        print("--- DEBUG MODE ---")

        # Create a set of all arguments passed on the command line for quick lookup
        cli_args = set(sys.argv[1:])
        
        # Keep track of which destinations we've already printed
        printed_dests = set()

        # 1. The passed values of any command-line arguments
        print("\n[Arguments]")
        for action in parser._actions:
            # Check if any of the action's option strings (e.g., '-ht', '--hasher-threads') are in cli_args
            if any(opt in cli_args for opt in action.option_strings):
                dest = action.dest
                if dest not in printed_dests:
                    print(f"  - {dest}: {getattr(args, dest)}")
                    printed_dests.add(dest)
        
        # Handle the positional 'directory' argument
        if args.directory:
            if 'directory' not in printed_dests:
                print(f"  - directory: {args.directory}")
                printed_dests.add('directory')

        # 2. The default values used, only if overriding arguments weren't passed
        print("\n[Defaults]")
        for action in parser._actions:
            dest = action.dest
            if dest not in printed_dests and dest not in ('help', 'debug') and action.default is not None:
                print(f"  - {dest}: {action.default}")

        # 3. The database file location, and if it was found
        db_path = args.database
        db_exists = os.path.exists(db_path)
        print(f"\n[Database]")
        print(f"  - Location: {os.path.abspath(db_path)}")
        print(f"  - Exists: {db_exists}")

        # 4. The number of rows (hashes) in the database
        if db_exists:
            try:
                env = lmdb.open(db_path, readonly=True)
                with env.begin() as txn:
                    num_hashes = txn.stat()['entries']
                    print(f"  - Row count: {num_hashes:,}")
                env.close()
            except lmdb.Error as e:
                print(f"  - Error reading database: {e}")
        else:
            print("  - Row count: 0")
        
        sys.exit(0)
    
    if not os.path.isdir(args.directory):
        print(f"Error: '{args.directory}' is not a valid directory")
        sys.exit(1)

    # Use the new --database argument
    db_path = args.database
        
    if not args.dry_run and not os.path.exists(db_path):
        os.makedirs(db_path)
    
    # --- Pipeline Setup ---
    stats = Stats()
    dir_queue = queue.Queue()
    file_queue = queue.Queue()
    hash_queue = queue.Queue()
    delete_queue = queue.Queue()
    
    # --- Threading Configuration ---
    num_scanner_threads = args.scanner_threads
    num_hasher_threads = args.hasher_threads
    num_deleter_threads = args.deleter_threads
    
    print(f"Using {num_scanner_threads} scanner threads, {num_hasher_threads} hasher threads, {num_deleter_threads} deleter threads.")
    if args.dry_run:
        print("--- DRY RUN MODE (no changes will be made) ---")
    
    # --- Start Pipeline Threads ---
    status_shutdown_event = threading.Event()
    status_thread = threading.Thread(target=status_reporter, args=(stats, status_shutdown_event, args.dry_run, args.delete, args.no_save_hashes))
    status_thread.start()
    
    writer_thread = threading.Thread(
        target=database_writer,
        args=(db_path, hash_queue, delete_queue, num_hasher_threads, stats, args.dry_run, args.delete, args.no_save_hashes)
    )
    writer_thread.start()
    
    deleter_threads = []
    if args.delete:
        for _ in range(num_deleter_threads):
            thread = threading.Thread(target=deleter_worker, args=(delete_queue, stats))
            thread.start()
            deleter_threads.append(thread)
    
    hasher_threads = []
    for _ in range(num_hasher_threads):
        thread = threading.Thread(target=hasher_worker, args=(file_queue, hash_queue, stats))
        thread.start()
        hasher_threads.append(thread)
        
    scanner_threads = []
    for _ in range(num_scanner_threads):
        thread = threading.Thread(target=scanner_worker, args=(dir_queue, file_queue, stats))
        thread.start()
        scanner_threads.append(thread)
        
    # --- Main Thread: Orchestrate Shutdown ---
    dir_queue.put(args.directory)
    dir_queue.join()
    
    for _ in range(num_scanner_threads):
        dir_queue.put(None)
        
    file_queue.join()

    for _ in range(num_hasher_threads):
        file_queue.put(None)
        
    # --- Final Cleanup ---
    for thread in scanner_threads:
        thread.join()
    for thread in hasher_threads:
        thread.join()
    writer_thread.join()
    
    if args.delete:
        delete_queue.join()
        for _ in range(num_deleter_threads):
            delete_queue.put(None)
        for thread in deleter_threads:
            thread.join()
    
    # Stop the status reporter
    status_shutdown_event.set()
    status_thread.join()
    
    # Print final stats
    found, hashed, written, skipped, deleted = stats.get()
    
    skipped_msg = f"deleted: {deleted:,}" if args.delete else "ignored"
    written_str = f"{written:,} unique"
    if args.dry_run or args.no_save_hashes:
        written_str = "0 (read only mode)"

    final_message = (
        f"\Found: {found:,} | Hashed: {hashed:,} | "
        f"Skipped: {skipped:,} duplicates ({skipped_msg}) | "
        f"Saved: {written_str}"
    )
    print(f"\n{final_message}\n")
    
    if not args.dry_run:
        print(f"Database: {db_path}")

def signal_handler(sig, frame):
    """Handle Ctrl+C and exit immediately."""
    print("\nProcess interrupted by user. Shutting down immediately...")
    os._exit(130)

if __name__ == "__main__":
    # Register the signal handler for Ctrl+C (SIGINT)
    signal.signal(signal.SIGINT, signal_handler)
    main()