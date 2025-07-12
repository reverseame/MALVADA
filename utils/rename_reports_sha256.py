import os
import json
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

def process_file(entry, directory):
    if not entry.name.endswith('.json'):
        return

    full_path = entry.path
    try:
        with open(full_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        sha256 = data.get('target', {}).get('file', {}).get('sha256')
        if sha256:
            new_filename = f"{sha256}.json"
            new_full_path = os.path.join(directory, new_filename)

            if not os.path.exists(new_full_path):
                os.rename(full_path, new_full_path)
                return f"Renamed: {entry.name} -> {new_filename}"
            else:
                return f"Skipped (exists): {new_filename}"
        else:
            return f"SHA256 not found in {entry.name}"
    except (json.JSONDecodeError, FileNotFoundError, OSError) as e:
        return f"Failed to process {entry.name}: {e}"

def rename_files(directory, max_workers=8):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.is_file():
                    futures.append(executor.submit(process_file, entry, directory))

        for future in as_completed(futures):
            result = future.result()
            if result:
                print(result)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Rename JSON files based on SHA256 hash.')
    parser.add_argument('directory', help='Path to the directory containing JSON files')
    parser.add_argument('--workers', type=int, default=8, help='Number of threads to use (default: 8)')
    args = parser.parse_args()

    if os.path.isdir(args.directory):
        rename_files(args.directory, args.workers)
    else:
        print(f"Invalid directory: {args.directory}")
