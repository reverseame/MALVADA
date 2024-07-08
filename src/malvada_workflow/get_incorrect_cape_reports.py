import argparse
# import json
# Allegedly WAY faster https://artem.krylysov.com/blog/2015/09/29/benchmark-python-json-libraries/
import ujson as json
import glob
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

ERRORS_DIR = "./reports_with_errors/"


def parse_arguments():
    """
    Arguments parsing.
    """
    parser = argparse.ArgumentParser(
        description="Parses CAPE JSON reports and generates statistics.")
    parser.add_argument("json_dir", help="The directory containing one or more json reports.")
    parser.add_argument("-s", "--silent", action="store_true", help="Silent mode.")
    return parser.parse_args()


class ReportStats:
    """
    Encapsulates all the important information to handle which and what kind of reports have errors.

    Args:
        silent: If True, the script will not print anything to the console.
        progress: rich.progress.Progress object to show the processing status.
    """

    def __init__(self, silent: bool, progress: Progress) -> None:
        self.report_fatal = []
        self.reports_no_processes = []
        self.reports_no_hooked_functions = []
        self.reports_vt_error = []
        self.reports_no_vt = []
        self.silent = silent
        self.progress = progress

    def process_report(self, cape_report: dict, json_file: str) -> None:
        """
        Takes a CAPE report and processes it, classifying the report based on fatal errors,
        no processes spawned, or no hooked functions in the main process.

        Args:
            cape_report: The data of the report to process.
            json_file: Name of the report to process (its path, as specified when invoking the framework).
        """

        # Fatal errors, CAPE could not even generate the report or the analysis
        if 'target' not in cape_report:
            self.report_fatal.append(json_file)
            return

        # If no processes spawned, skip
        if not len(cape_report['behavior']['processes']):
            self.reports_no_processes.append(json_file)
            return

        # If no hooked functions in main process, skip
        if not len(cape_report['behavior']['processes'][0]['calls']):
            self.reports_no_hooked_functions.append(json_file)
            return

        # VirusTotal positives information
        if 'virustotal' not in cape_report['target']['file']:
            self.reports_no_vt.append(json_file)
        elif 'error' in cape_report['target']['file']['virustotal']:
            self.reports_vt_error.append(json_file)

    def write_results(self) -> None:
        """
        Writes the analysis results of all CAPE reports to the corresponding files.
        """

        ### Writing report/execution errors ###
        errors = {
            'Fatal reports': {
                'Reports': self.report_fatal,
                'n': len(self.report_fatal)
            },
            'Reports with no processes': {
                'Reports': self.reports_no_processes,
                'n': len(self.reports_no_processes)
            },
            'Reports with no hooked functions': {
                'Reports': self.reports_no_hooked_functions,
                'n': len(self.reports_no_hooked_functions)
            }
        }

        with open(ERRORS_DIR + "reports_with_errors.json", "w") as file:
            if not self.silent:
                self.progress.log(
                    f"[+] Writing reports with errors to [magenta]{ERRORS_DIR}reports_with_errors.json")
            json.dump(errors, file, indent=4, escape_forward_slashes=False)

        ### Moving reports with errors to ERRORS_DIR/reports_with_errors/ ###
        if not self.silent:
            self.progress.log(
                f"[+] Moving reports with errors to [magenta]{ERRORS_DIR}reports_with_errors/")
        Path(ERRORS_DIR + "reports_with_errors/").mkdir(parents=True, exist_ok=True)
        for report in self.report_fatal + self.reports_no_processes + self.reports_no_hooked_functions:
            Path(report).rename(ERRORS_DIR + "reports_with_errors/" + Path(report).name)

        ### Writing VT errors ###
        vt_errors = {
            "Reports with no VT entry": {
                'Reports': self.reports_no_vt,
                'n': len(self.reports_no_vt)
            },
            "Reports with VT error": {
                'Reports': self.reports_vt_error,
                'n': len(self.reports_vt_error)
            }
        }

        with open(ERRORS_DIR + "reports_with_vt_errors.json", "w") as file:
            if not self.silent:
                self.progress.log(
                    f"[+] Writing reports with VT errors to [magenta]{ERRORS_DIR}reports_with_vt_errors.json")
            json.dump(vt_errors, file, indent=4, escape_forward_slashes=False)

        ### Moving reports with VT errors to ERRORS_DIR/reports_with_errors/ ###
        if not self.silent:
            self.progress.log(
                f"[+] Moving reports with VT errors to [magenta]{ERRORS_DIR}reports_with_vt_errors/")
        Path(ERRORS_DIR + "reports_with_vt_errors/").mkdir(parents=True, exist_ok=True)
        for report in self.reports_no_vt + self.reports_vt_error:
            Path(report).rename(ERRORS_DIR + "reports_with_vt_errors/" + Path(report).name)


def main(json_files: list, silent: bool, progress: Progress) -> tuple:
    """
    Main function, runs the analysis so as to detect reports with errors.

    Args:
        json_files: list of reports to process.
        silent: If True, no output will be printed.
        progress: rich.progress.Progress object to show the processing status.

    Returns:
        A Tuple containing the total reports with erorrs and total reports with VT errors, (errors, vt_errors).

    """

    if not silent:
        progress.console.rule(
            "[bold magenta]Phase 1: Detect incorrect reports[/bold magenta]", style="magenta")
        progress.console.log(f"[+] Total reports: [magenta]{len(json_files)}")

    stats = ReportStats(silent, progress)

    # Creating errors directory, if it does not exist
    Path(ERRORS_DIR).mkdir(parents=True, exist_ok=True)
    stats.total_reports_in_folder = len(json_files)

    task = None
    if not silent:
        task = progress.add_task("[magenta]Detect incorrect reports",
                                 total=stats.total_reports_in_folder)
        progress.start_task(task)

    for json_file in json_files:
        with open(json_file) as file:
            cape_report = json.load(file)
        stats.process_report(cape_report, json_file)
        progress.update(task, advance=1) if not silent else None

    progress.stop_task(task) if not silent else None
    stats.write_results()

    if not silent:
        progress.console.rule("[bold magenta]End of Phase 1[/bold magenta]", style="magenta")

    return (stats.report_fatal + stats.reports_no_processes + stats.reports_no_hooked_functions, stats.reports_no_vt + stats.reports_vt_error)


if __name__ == "__main__":
    """
    If this script is executed directly (and not as part of the pipeline), it will parse
    the arguments and execute the `main()` function.
    """

    args = parse_arguments()
    reports = glob.glob(args.json_dir + "/*.json")
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

    # Check if there are no reports within the directory
    if not len(reports):
        progress.console.log("Error: No reports found.")
        progress.stop()
        exit()

    main(reports, args.silent, progress)
    if not args.silent:
        progress.console.rule("[bold green]MALVADA", style="green")
        progress.stop() if not args.silent else None
