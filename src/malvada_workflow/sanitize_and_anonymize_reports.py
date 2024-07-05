import argparse
import json
import glob
import subprocess
import concurrent.futures
from rich.progress import (
    BarColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
    SpinnerColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
)

SECTIONS_TO_DELETE = [
    "statistics",
    "info",
    "local_conf",
    "debug",
    "detections2pid",
    "malfamily",
    "malfamily_tag",
    "malscore",
    "network",
    "procmemory",
    "shots",
    "suricata",
    "ttps",
    "url_analysis"
]


def parse_arguments():
    """
    Arguments parsing.
    """
    parser = argparse.ArgumentParser(
        description="Parses CAPE JSON reports and sanitizes it (deletes unnecessary entries).")
    parser.add_argument("json_dir", help="The directory containing one or more json reports.")
    parser.add_argument("-s", "--silent", action="store_true", help="Silent mode.")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Number of workers to use.")
    parser.add_argument("-a", "--anonymize-terms",
                        help='Anonymize the terms in the file provided with [REDACTED].'
                             'By default the terms will be taken from the terms_to_anonymize.txt file,'
                             'one by line.',
                        default="terms_to_anonymize.txt")
    arguments = parser.parse_args()
    return arguments


def delete_environ_recursive(data) -> None:
    """
    This function recursively traverses a JSON object and deletes the "environ" entry from all child elements within the "children" list (if it exists).

    Args:
        data (dict or list): The JSON data structure to process.
    """
    if isinstance(data, dict):
        # If it's a dictionary, check for "children" and process them
        if "children" in data:
            for child in data["children"]:
                delete_environ_recursive(child)

        # Replace "environ" value from the current dictionary (if it exists)
        if "environ" in data:
            data["environ"] = "[REDACTED]"

    elif isinstance(data, list):
        # If it's a list, iterate through elements and process them recursively
        for item in data:
            delete_environ_recursive(item)


def anonymize_report(json_file: str, terms_file: str) -> None:
    """
    Anonymize the report by redacting the terms from the terms_file file.

    Args:
        json_file: The file to process.
        terms_file: The file containing the terms to anonymize in the report.
    """
    with open(terms_file) as file:
        terms = file.read().splitlines()

    sed_command = ["sed", "-i"]
    sed_command.append('')
    for term in terms:
        sed_command[2] += f's/{term}/[REDACTED]/g; '

    sed_command[2] = sed_command[2][:-2]

    sed_command.append(json_file)
    subprocess.run(sed_command)


def process_file(json_file: str, terms_file: str) -> None:
    """
    Sanitized and anonymized a JSON file.

    Args:
        json_file: The file to process.
        terms_file: The file containing the terms to anonymize in the report.
    """

    with open(json_file) as file:
        cape_report = json.load(file)

    # Delete entire sections
    for entry in SECTIONS_TO_DELETE:
        if entry in cape_report:
            del cape_report[entry]

    # Delete environmental information
    for entry in cape_report["behavior"]["processes"]:
        if "environ" in entry:
            entry["environ"] = "[REDACTED]"

    # Delete environmental information from processtree
    delete_environ_recursive(cape_report['behavior']['processtree'])

    # Add detections field if it does not exist for consistency with the avclass detections field
    if 'detections' not in cape_report:
        cape_report['detections'] = '(n/a)'

    with open(json_file, "w") as file:
        json.dump(cape_report, file, indent=2)

    # Anonimize the report
    anonymize_report(json_file, terms_file)


def main(json_files: list, silent: bool, terms_file: str, progress: Progress, workers: int = 10) -> None:
    """
    Main function, runs the sanitize and anonymize process concurrently, using the number of workers provided.

    Args:
        json_files: List with the file names of the reports to process.
        silent: If True, no output will be printed.
        terms_file: Name of the file containing the terms to anonymize in the report.
        progress: rich.progress.Progress object to show the processing status.
        workers: Number of workers to use for the concurrent processing.
    """

    total_reports_in_folder = len(json_files)
    task = None

    if not silent:
        progress.console.rule(
            "[bold yellow2]Phase 3: Sanitize and anonymize reports[/bold yellow2]", style="yellow2")
        progress.console.log(f"[+] Total reports: [yellow2]{total_reports_in_folder}")
        task = progress.add_task("[yellow2]Sanitize & anonymize reports",
                                 total=total_reports_in_folder)

    with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
        results = []
        for json_file in json_files:
            results.append(executor.submit(process_file, json_file, terms_file))

        for f in concurrent.futures.as_completed(results):
            progress.update(task, advance=1) if not silent else None

    if not silent:
        progress.stop_task(task)
        progress.console.rule("[bold yellow2]End of Phase 3[/bold yellow2]", style="yellow2")


if __name__ == "__main__":
    """
    If this script is executed directly (and not as part of the pipeline), it will parse
    the arguments and execute the `main()` function.
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
    main(glob.glob(args.json_dir + "/*.json"), args.silent,
         args.anonymize_terms, progress, args.workers)
    if not args.silent:
        progress.console.rule("[bold green]MALVADA", style="green")
        progress.stop()
