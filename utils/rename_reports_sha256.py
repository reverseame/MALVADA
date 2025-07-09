import os
import json
import argparse

def rename_files(directory):
    for filename in os.listdir(directory):
        if filename.endswith('.json'):
            full_path = os.path.join(directory, filename)
            try:
                with open(full_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                sha256 = data.get('target', {}).get('file', {}).get('sha256')
                if sha256:
                    new_filename = f"{sha256}.json"
                    new_full_path = os.path.join(directory, new_filename)

                    if not os.path.exists(new_full_path):
                        os.rename(full_path, new_full_path)
                        print(f"Renamed: {filename} -> {new_filename}")
                    else:
                        print(f"Skipped (exists): {new_filename}")
                else:
                    print(f"SHA256 not found in {filename}")
            except Exception as e:
                print(f"Failed to process {filename}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Rename JSON files based on SHA256 hash.')
    parser.add_argument('directory', help='Path to the directory containing JSON files')
    args = parser.parse_args()

    if os.path.isdir(args.directory):
        rename_files(args.directory)
    else:
        print(f"Invalid directory: {args.directory}")
