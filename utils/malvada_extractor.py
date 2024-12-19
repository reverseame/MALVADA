import os
import json
import glob
import shutil
import argparse
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
        ' Read the options for further important features of this script.'
        ' This script expects AVClass and CAPE label mappings to be in the specified dataset_path.')
    parser.add_argument('dataset_path', type=str, help='The path to the dataset')
    parser.add_argument('-o', '--output_path', type=str, default='./extracted_reports',
                        help='The path to the output dir (default: ./extracted_reports).')
    parser.add_argument('-c', '--criteria', type=str, default='r',
                        help='The criteria to choose the reports, either (r)andom (dataset will'
                        'be shuffled each time) or (f)irst found (default: r)')
    parser.add_argument('-l', '--label', type=str, default='A',
                        help='The labels to use, either (A)VCLASS or (C)APEv2 (default: A).')
    parser.add_argument('-i', '--include', type=str, default=None,
                        help='The families to include in the extraction in format <class-1>,'
                        '<class-2>, ... (spaces are optional, for example \'Reline, Disabler,'
                        ' Agenttesla\') If not specified all families are included (default: None).')
    parser.add_argument('-e', '--exclude', type=str, default=None,
                        help='The families to exclude in the extraction (only considered if all'
                        'families are included) (default: None).')
    parser.add_argument('-n', '--n-extract', type=int, default=100,
                        help='The number of samples to extract for each of the families included'
                        ' (default: 100). If all families are included, this number will'
                        'be used as the total of reports to extract.')
    parser.add_argument(
        '-s', '--silent', help='Silent mode, only minimal ASCII output.',
        action='store_true', default=False)

    return parser.parse_args()


def extract_reports(
        reports: list[str],
        included: list[str],
        excluded: list[str],
        label: str,
        progress: Progress,
        task: int,
        n_extract: int,
        silent: bool) -> dict:
    '''
    Takes the query, i.e. included, excluded families, label, n_extract and the total reports in
    the dataset and returns a dictionary with the labels as keys and lists of the corresponding
    reports as values.

    Args:
        reports: List contaning all the report names to process.
        included: List containing the families to include (can be empty).
        excluded: List containing the families *not* to include (can be empty).
        label: Label to use, either `C` for CAPEv2 or `A` for AVCLASS.
        progress: rich.progress.Progress object to update the progress bar.
        task: The task associated to the progress bar.
        n_extract: The number of reports to extract per family or in total whether
            included != [] or not
        silent: If True, the progress bar won't be updated (neither shown in the first place).

    Returns:
        Dictionary containing family labels as keys and lists of corresponding report names with
        those labels as values.
    '''

    reports_to_move = {key: [] for key in included}

    # Get the actual report names
    for report_name in reports:
        with open(report_name, 'r') as f:
            report = json.load(f)

        if label == 'C':  # CAPEv2
            label = report['detections']
        else:  # args.label == 'A'  AVCLASS
            label = report['avclass_detection']

        # 2 possible cases:
        #   - included != [] (excluded doesn't matter), add if the label matches and there's room
        #   - included == [] (excluded doesn't matter), add if the label is not in excluded
        #       (which won't be if excluded == []) and there's room
        if (((label in included) and (len(reports_to_move[label]) < n_extract)) or
                ((len(included) == 0) and (label not in excluded) and
                 (sum(len(lst) for lst in reports_to_move.values()) < n_extract))):
            reports_to_move.setdefault(label, []).append(report_name)
            progress.update(task, advance=1) if not silent else None

        # To exit we have the same 2 cases:
        #   - included != [], check that all families have n_extract reports
        #   - included == [], check that the total number of reports is n_extract
        if ((included != [] and all(len(lst) == n_extract for lst in reports_to_move.values())) or
                (included == [] and sum(len(lst) for lst in reports_to_move.values()) == n_extract)):
            break

    return reports_to_move


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
        exit()

    # Set up the reports for the pipeline
    reports = glob.glob(args.dataset_path + "/*.json")

    # Randomize if specified
    if args.criteria == 'r':
        shuffle(reports)

    total_reports = len(reports)

    if not args.silent:
        progress.console.rule(
            "[bold green]MALVADA EXTRACTOR", style="green")

    # Check if there are no reports within the directory
    if not total_reports:
        progress.console.log("Error: No reports found.")
        exit()

    # Parse families included & excluded
    included = []
    if args.include is not None:
        included = [c.strip() for c in args.include.split(sep=',')]

    excluded = []
    if args.exclude is not None:
        excluded = [c.strip() for c in args.exclude.split(sep=',')]

    if not args.silent:
        progress.console.log(f'[+] Families included: [green]{args.include}')
        progress.console.log(f'[+] Number of reports to extract: [green]{args.n_extract}')
        progress.console.log(f'[+] Families excluded: [green]{args.exclude}')
        progress.console.rule('[bold green]Starting extraction[/bold green]', style='green')
        progress.start()
        total = args.n_extract * len(included) if args.exclude is None else args.n_extract
        task = progress.add_task('Extract reports', total=total)
        progress.start_task(task)
    else:
        progress.console.log('Extracting reports...')

    reports_to_move = extract_reports(reports, included, excluded, args.label,
                                      progress, task, args.n_extract, args.silent)

    # Create output dir if it doesn't exist
    if not os.path.exists(args.output_path):
        os.mkdir(args.output_path)
    else:
        progress.console.log('[bold orange3][!] Warning:[/bold orange3] The output directory'
                             f'[bold orange3]{args.output_path}[/bold orange3] already exists')

    # Move to output dir (first flatten the list of lists)
    for report in [r for rs in reports_to_move.values() for r in rs]:
        # shutil.copy2 already handles the naming and other metadata
        shutil.copy2(report, args.output_path)

    if not args.silent:
        progress.console.log(f'[+] Extracted the reports to [green]{args.output_path}[/green]')
        progress.stop_task(task)
        progress.stop()
        progress.console.rule(
            "[bold green]MALVADA EXTRACTOR", style="green")


if __name__ == '__main__':
    main()
