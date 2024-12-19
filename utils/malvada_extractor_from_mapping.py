import os
import json
import glob
import shutil
import argparse
import logging
from random import shuffle

def parse_args():
    parser = argparse.ArgumentParser(
        description='MALVADA extractor. Utility script to facilitate the extraction of reports from'
        ' MALVADA-generated datasets based on AVCLASS / CAPEv2 labels.'
        ' Read the options for further important features of this script.')
    parser.add_argument('dataset_path', type=str, help='The path to the dataset')
    parser.add_argument('-o', '--output_path', type=str, default='./extracted_reports',
                        help='The path to the output dir (default: ./extracted_reports).')
    parser.add_argument('-c', '--criteria', type=str, default='r',
                        help='The criteria to choose the reports, either (r)andom (dataset will'
                        'be shuffled each time) or (f)irst found (default: r)')
    parser.add_argument('-l', '--label_mapping', type=str,
                        help='The path to the label mapping to use, either AVClass or CAPE. The label mapping files can be downloaded from the official WinMET URL: https://doi.org/10.5281/zenodo.12647555')
    parser.add_argument('-f', '--family', type=str,
                        help='The family or families to extract. Specify multiple families with commas. Example: -f "Agenttesla, Virlock, Guloader"')
    # parser.add_argument('-i', '--include', type=str, default=None,
    #                     help='The families to include in the extraction in format <class-1>,'
    #                     '<class-2>, ... (spaces are optional, for example \'Reline, Disabler,'
    #                     ' Agenttesla\') If not specified all families are included (default: None).')
    # parser.add_argument('-e', '--exclude', type=str, default=None,
    #                     help='The families to exclude in the extraction (only considered if all'
    #                     'families are included) (default: None).')
    parser.add_argument('-n', '--n-extract', type=int, default=100,
                        help='The number of samples to extract for each of the families included'
                        ' (default: 100). If all families are included, this number will'
                        'be used as the total of reports to extract.')

    return parser.parse_args()


def open_json_file(file_path: str) -> dict:
    '''
    Opens and parses a JSON file.

    Args:
        file_path (str): Path to the JSON file.

    Returns:
        dict: Parsed JSON data.
    '''
    try:
        with open(file_path, 'r') as json_file:
            return json.load(json_file)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON file. {e}", file=sys.stderr)
        sys.exit(1)

def get_label_reports(mapping: dict, family: str) -> dict | None:
    return mapping.get(family, None)

def extract_reports_to_dir(reports: list, input_dir: str, output_dir: str, number: int) -> None:
    for report in reports[:number]:
        shutil.copy2(f"{input_dir}/{report['report']}", output_dir)

def main():
    args = parse_args()

    # Check if the dataset_path exists and is a directory
    if not (os.path.exists(args.dataset_path) and os.path.isdir(args.dataset_path)):
        print(
            f"[!] Error: {args.dataset_path} does not exist or is not a directory.")
        exit()

    # Create output dir if it doesn't exist
    if not os.path.exists(args.output_path):
        os.mkdir(args.output_path)
    else:
        print(f'[!] Warning:The output directory {args.output_path} already exists')

    # Open and parse the JSON file
    report_label_mapping = open_json_file(args.label_mapping)

    # Retrieve all the requested families for extraction
    for label in args.family.split(','):
        label = label.strip()
        reports = get_label_reports(report_label_mapping, label)
        if reports == None:
            print(f'Family {label} not present in mapping file {args.label_mapping}, skipping.')
            continue
        number_of_reports_in_mapping = reports['n_reports']
        actual_report_list = reports['reports']
        number_of_reports_to_exctract = args.n_extract
        if number_of_reports_in_mapping < args.n_extract:
            print(f'There are only {number_of_reports_in_mapping} {label} reports (you specified {args.n_extract}). Exctracting them.')
            number_of_reports_to_exctract = number_of_reports_in_mapping

        if args.criteria == 'r':
            shuffle(actual_report_list)
            print(f'Extracting {number_of_reports_to_exctract} {label} reports after shuffle.')  
            extract_reports_to_dir(actual_report_list, args.dataset_path, args.output_path, number_of_reports_to_exctract)
        else:
            print(f'Extracting first {number_of_reports_to_exctract} {label} reports.') 
            extract_reports_to_dir(actual_report_list, args.dataset_path, args.output_path, number_of_reports_to_exctract)       

if __name__ == '__main__':
    main()
