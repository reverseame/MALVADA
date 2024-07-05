import argparse
import json
import glob
import os
from pathlib import Path
from rich.progress import (
    BarColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
    SpinnerColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
)

DUPLICATES_DIR = "./duplicate_reports/"


def parse_arguments():
    """
    Arguments parsing.
    """
    parser = argparse.ArgumentParser(
        description="Parses CAPE JSON reports and sanitizes it (deletes unnecessary entnries).")
    parser.add_argument("json_dir", help="The directory containing one or more json reports.")
    parser.add_argument(
        "-d", "--duplicates", help="The strategy for duplicates, e.g. which one will be kept: 'first', 'biggest'.", default="biggest")
    parser.add_argument("-s", "--silent", action="store_true", help="Silent mode.")
    arguments = parser.parse_args()
    return arguments


def search_duplicates(json_files: list, progress: Progress, task: int, silent: bool) -> dict:
    """
    Search for duplicate reports in the given list of json files. Duplication is detected using the
    SHA512 hash of the binary file as the identifier.

    Args:
        json_files: List of JSON files to search for duplicates.
        progress: rich.progress.Progress object to show the processing status.
        task: rich.progress.Task object to update progress.
        silent: If True, no output will be printed.

    Returns:
        A dictionary with the duplicate reports, where the key is the SHA512 hash of the binary file,
        and the value is a list of dictionaries, where each dictionary has the path to the report
        and the size of the file.
    """
    seen_values = {}
    duplicate_reports = {}

    for json_file in json_files:
        with open(json_file) as file:
            cape_report = json.load(file)
        progress.update(task, advance=1) if not silent else None
        report_id = cape_report['target']['file']['sha512']

        if report_id in seen_values:
            size = os.path.getsize(json_file)
            if report_id not in duplicate_reports:
                duplicate_reports[report_id] = [{json_file: size}]
                duplicate_reports[report_id].append(
                    {seen_values[report_id]: os.path.getsize(seen_values[report_id])})
            else:
                duplicate_reports[report_id].append({json_file: size})
        else:
            seen_values[report_id] = json_file

    return duplicate_reports


def move_duplicate_reports(duplicate_reports: dict, duplicates_strat: str = 'biggest') -> list:
    """
    Discards duplicate reports according to the strategy specified.

    Args:
        duplicate_reports: A dictionary with the duplicate reports, where the key is the SHA512 hash
            of the binary file, and the value is a list of dictionaries, where each dictionary has
            the path to the report and the size of the file. WARNING: it will be modified.
        duplicates_strat: The strategy to follow when discarding duplicates, either 'first' (the
            first to encounter prevails) or 'biggest' (the biggest file on disk prevails). (Default: 'biggest')

    Returns:
        A list with the paths to the reports that were moved (and should be discarded from the dataset).
    """
    files_to_discard = []

    if duplicates_strat == 'first':
        for report in duplicate_reports:
            for i in range(1, len(duplicate_reports[report])):
                Path(next(iter(duplicate_reports[report][i]))).rename(
                    DUPLICATES_DIR + "duplicate_reports/" + Path(next(iter(duplicate_reports[report][i]))).name)
                files_to_discard.append(next(iter(duplicate_reports[report][i])))
    elif duplicates_strat == 'biggest':
        for report in duplicate_reports:
            size = next(iter(duplicate_reports[report][0].values()))
            index = 0
            for i in range(1, len(duplicate_reports[report])):
                # if the i-th report is bigger than the current biggest, move the current biggest to
                # the duplicates folder and update the biggest size and index
                if next(iter(duplicate_reports[report][i].values())) > size:
                    size = next(iter(duplicate_reports[report][i].values()))
                    Path(next(iter(duplicate_reports[report][index]))).rename(
                        DUPLICATES_DIR + "duplicate_reports/" + Path(next(iter(duplicate_reports[report][index]))).name)
                    files_to_discard.append(next(iter(duplicate_reports[report][index])))
                    index = i
                else:  # if the i-th report is smaller than the current biggest, move it to the duplicates folder
                    Path(next(iter(duplicate_reports[report][i]))).rename(
                        DUPLICATES_DIR + "duplicate_reports/" + Path(next(iter(duplicate_reports[report][i]))).name)
                    files_to_discard.append(next(iter(duplicate_reports[report][i])))

    return files_to_discard


def main(json_files: list, duplicates_strat: str, silent: bool, progress: Progress) -> list:
    """
    Performs the analysis for reports of duplicate binary files, taking the version specified by
    the strategy argument.

    Args:
        json_files: List of the reports to process.
        duplicates_strat: The strategy to follow when discarding duplicates, either 'first' (the
            first to encounter prevails) or 'biggest' (the biggest file on disk prevails) (Default: 'biggest').
        silent: If True, no output will be printed.
        progress: rich.progress.Progress object to show the processing status.

    Returns:
        A list containing the names (paths) of found duplicate reports.

    """

    total_reports_in_folder = len(json_files)
    task = None

    if not silent:
        progress.console.rule(
            "[bold orange3]Phase 2: Detect duplicate reports[/bold orange3]", style="orange3")
        progress.console.log(f"[+] Total reports: [orange3]{total_reports_in_folder}")
        progress.console.log(f"[+] Strategy for duplicates: [orange3]{duplicates_strat}")
        task = progress.add_task("[orange3]Detect duplicate reports", total=total_reports_in_folder)

    # Creating duplicates directory, if it does not exist
    Path(DUPLICATES_DIR).mkdir(parents=True, exist_ok=True)

    # Search for duplicate reports
    duplicate_reports = search_duplicates(json_files, progress, task, silent)

    ### Writing duplicate reports ###
    with open(DUPLICATES_DIR + "duplicate_reports.json", "w") as file:
        if not silent:
            progress.console.log(
                f"[+] Writing reports with duplicates to [orange3]{DUPLICATES_DIR}duplicate_reports.json")
        json.dump(duplicate_reports, file, indent=4)

    ### Moving duplicate reports to DUPLICATES_DIR/duplicate_reports/ ###
    if not silent:
        progress.console.log(
            f"[+] Moving duplicate reports to [orange3]{DUPLICATES_DIR}duplicate_reports/")
    Path(DUPLICATES_DIR + "duplicate_reports/").mkdir(parents=True, exist_ok=True)

    # Take only one report for each duplicate according to the strategy provided
    reports_to_discard = move_duplicate_reports(duplicate_reports, duplicates_strat)

    if not silent:
        progress.stop_task(task)
        progress.console.rule("[bold orange3]End of Phase 2[/bold orange3]", style="orange3")

    return reports_to_discard


if __name__ == "__main__":
    """
    If this script is executed directly (and not as part of the pipeline), it will parse the
    arguments and execute the `main()` function.
    """

    args = parse_arguments()
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

    if not args.silent:
        progress.start()
        progress.console.rule("[bold green]MALVADA", style="green")
    if args.duplicates not in ["first", "biggest"]:
        progress.console.log(f"[!] Error:{args.duplicates} is not a valid strategy for"
                             "duplicates, should be 'first' or 'biggest'.")
        exit()

    main(glob.glob(args.json_dir + "/*.json"), args.duplicates, args.silent, progress)
    if not args.silent:
        progress.console.rule("[bold green]MALVADA", style="green")
        progress.stop()
