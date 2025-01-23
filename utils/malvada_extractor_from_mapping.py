import os
import json
import sys
import shutil
import argparse
import pathlib
from random import shuffle
from rich.progress import (
    BarColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
    SpinnerColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
)


def parse_args():
    parser = argparse.ArgumentParser(
        description='MALVADA extractor. Utility script to facilitate the extraction of reports from'
        ' MALVADA-generated datasets based on AVCLASS / CAPEv2 labels.'
        ' Read the options for further important features of this script.')
    parser.add_argument('dataset_path', type=str, help='The path to the dataset')
    parser.add_argument('-o', '--output_path', type=str, default='./extracted_reports',
                        help='The path to the output dir (default: ./extracted_reports).')
    parser.add_argument('-c', '--criteria', type=str, default='r',
                        help='The criteria to choose the reports, either (r)andom (dataset will '
                        'be shuffled each time) or (f)irst found (default: r)')
    parser.add_argument('-l', '--label-path', type=str,
                        help='The path to the label mapping to use, either AVClass or CAPE. The '
                        'label mapping files can be downloaded from the official WinMET URL:'
                        'https://doi.org/10.5281/zenodo.12647555 or generated with the script'
                        'utils/get_malware_family_report_mappings.py')
    parser.add_argument('-f', '--family', type=str,
                        help='The family or families to extract. Specify multiple families with '
                        'commas. Example: -f "Agenttesla, Virlock, Guloader"')
    parser.add_argument('-n', '--n-extract', type=int, default=100,
                        help='The number of samples to extract for each of the families included'
                        ' (default: 100).')
    parser.add_argument('-s', '--silent', help='Silent mode, only minimal ASCII output.',
                        action='store_true', default=False)

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
        shutil.copy2(pathlib.Path(input_dir) / report['report'], output_dir)


def main():
    args = parse_args()

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        "•",
        TimeElapsedColumn(),
        "•",
        TimeRemainingColumn(),
    )

    # Check if the dataset_path exists and is a directory
    if not (os.path.exists(args.dataset_path) and os.path.isdir(args.dataset_path)):
        progress.console.log(
            f"[red][!] Error:[/red] {args.dataset_path} does not exist or is not a directory.")
        sys.exit(1)

    # Create output dir if it doesn't exist
    if not os.path.exists(args.output_path):
        os.mkdir(args.output_path)
    else:
        progress.console.log('[bold orange3][!] Warning:[/bold orange3] The output directory '
                             f'{args.output_path} already exists')

    # Open and parse the JSON file
    report_label_mapping = open_json_file(args.label_path)
    # total_reports = report_label_mapping['n_reports']

    if not args.silent:
        progress.console.rule(
            "[bold green]MALVADA EXTRACTOR", style="green")

    if not args.silent:
        progress.console.log(f'[+] Families to extract: [green]{args.family}')
        progress.console.log(f'[+] Number of reports to extract of each: [green]{args.n_extract}')
        progress.console.rule('[bold green]Starting extraction[/bold green]', style='green')
        task = progress.add_task('Extract reports', total=None)
        progress.start_task(task)
        progress.start()

    else:
        progress.console.log('Extracting reports...')

    # Retrieve all the requested families for extraction
    for label in args.family.split(','):
        label = label.strip()
        reports = get_label_reports(report_label_mapping, label)
        if reports is None:
            progress.console.log(f'[bold orange3][!] Warning:[/bold orange3] Family {label} not '
                                 f'present in mapping file {args.label_mapping}, skipping.')
            continue

        n_reports_in_map = reports['n_reports']
        actual_report_list = reports['reports']
        n_reports_to_extract = args.n_extract

        if n_reports_in_map < args.n_extract:
            progress.console.log(f'[bold orange3][!] Warning:[/bold orange3] There are only '
                                 f'{n_reports_in_map} {label} reports.')
            n_reports_to_extract = n_reports_in_map

        if args.criteria == 'r':
            shuffle(actual_report_list)
            progress.console.log(
                f'[+] Extracting {n_reports_to_extract} {label} reports after shuffle.')
            extract_reports_to_dir(actual_report_list, args.dataset_path,
                                   args.output_path, n_reports_to_extract)
        else:  # args.criteria == 'f'
            progress.console.log(f'[+] Extracting first {n_reports_to_extract} {label} reports.')
            extract_reports_to_dir(actual_report_list, args.dataset_path,
                                   args.output_path, n_reports_to_extract)

        progress.update(task, advance=1)

    if not args.silent:
        progress.console.log(f'[+] Extracted the reports to [green]{args.output_path}[/green]')
        progress.stop_task(task)
        progress.stop()
        progress.console.rule(
            "[bold green]MALVADA EXTRACTOR", style="green")


if __name__ == '__main__':
    main()
