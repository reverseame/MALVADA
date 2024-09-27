import argparse
import ujson as json
import glob
from pathlib import Path
from collections import Counter
from rich.progress import (
    BarColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
    SpinnerColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
)

RESULTS_DIR = "./results/"


def parse_arguments():
    """
    Argument parsing.
    """
    parser = argparse.ArgumentParser(
        description="Parses CAPE JSON reports and generates statistics.")
    parser.add_argument("json_dir", help="The directory containing one or more json reports.")
    parser.add_argument("-s", "--silent", action="store_true", help="Silent mode.")
    parser.add_argument("-vt", "--vt-positives-threshold", type=int, default=10,
                        help="Threshold for VirusTotal positives (default: 10).")
    return parser.parse_args()


class ReportStats:
    """
    Encapsulates all the statistics

    Args:
        silent: If True, no output will be printed
        vt_positives_threshold: Detection threshold (based on VT results) to consider a report
        undetected (below the threshold) or malicious (above the threshold). (Default: 10)
    """

    def __init__(self, silent: bool, vt_positives_threshold: int) -> None:
        self.total_reports_in_folder = 0
        self.total_hooked_functions = 0
        self.min_hooked_functions = []
        self.max_hooked_functions = [0, 0]

        # Spawned processes
        self.total_spawned_processes = 0
        self.min_spawned_processes = []
        self.max_spawned_processes = [0, 0]

        # Detections
        self.total_vt_positives = 0
        self.min_vt_positives = []
        self.max_vt_positives = [0, 0]
        self.no_vt_positives = []
        self.cape_detection_labels = []
        self.avclass_detection_labels = []
        self.reports_no_cape_consensus = []
        self.reports_no_avclass_consensus = []

        # Others
        self.silent = silent
        self.vt_positives_threshold = vt_positives_threshold

    def process_report(self, cape_report: str, json_file: str) -> None:
        """
        Takes a CAPE report and processes it, computing the necessary statistics and saving them
        in the corresponding attributes.

        Args:
            cape_report: The report to process.
            json_file: Name of the report to process (its path, as specified when invoking the framework).
        """
        # Add spawned processes information
        actual_report_spawned_processes = len(cape_report['behavior']['processes'])
        if not len(self.min_spawned_processes):
            self.min_spawned_processes.append(actual_report_spawned_processes)
            self.min_spawned_processes.append(json_file)
        elif actual_report_spawned_processes < self.min_spawned_processes[0]:
            self.min_spawned_processes[0] = actual_report_spawned_processes
            self.min_spawned_processes[1] = json_file

        if self.max_spawned_processes[0] < actual_report_spawned_processes:
            self.max_spawned_processes[0] = actual_report_spawned_processes
            self.max_spawned_processes[1] = json_file

        self.total_spawned_processes += actual_report_spawned_processes

        # Add hooked functions information
        for process in cape_report['behavior']['processes']:
            self.total_hooked_functions += len(process['calls'])

            if not len(self.min_hooked_functions):
                self.min_hooked_functions.append(len(process['calls']))
                self.min_hooked_functions.append(json_file)
            elif len(process['calls']) < self.min_hooked_functions[0]:
                self.min_hooked_functions[0] = len(process['calls'])
                self.min_hooked_functions[1] = json_file

            if len(process['calls']) > self.max_hooked_functions[0]:
                self.max_hooked_functions[0] = len(process['calls'])
                self.max_hooked_functions[1] = json_file

        # VirusTotal positives information
        try:
            actual_report_vt_positives = cape_report['target']['file']['virustotal']['positives']

            if not len(self.min_vt_positives):
                self.min_vt_positives.append(actual_report_vt_positives)
                self.min_vt_positives.append(json_file)
            elif actual_report_vt_positives < self.min_vt_positives[0]:
                self.min_vt_positives[0] = actual_report_vt_positives
                self.min_vt_positives[1] = json_file

            if self.max_vt_positives[0] < actual_report_vt_positives:
                self.max_vt_positives[0] = actual_report_vt_positives
                self.max_vt_positives[1] = json_file

            if actual_report_vt_positives <= self.vt_positives_threshold:
                self.no_vt_positives.append(json_file)
        except Exception as e:
            if not self.silent:
                print(f"[!!] ERROR parsing report {json_file}. Problems related to VirusTotal entry:"
                      f"{e} - {e.stderr}\n[!!] Skipping report")
            return

        # CAPE Detections (label consensus)
        # There was no CAPE label consensus => detections field contains '(n/a)' AND VT detections
        if cape_report['detections'] == '(n/a)' and actual_report_vt_positives:
            self.reports_no_cape_consensus.append(json_file)
            self.cape_detection_labels.append("(n/a)")
        elif actual_report_vt_positives:
            for detection in cape_report['detections']:
                # We use .capitalize() to unify labels like Virlock and VirLock
                self.cape_detection_labels.append(detection['family'].capitalize())

        # AVClass Detections (label consensus)
        if 'avclass_detection' not in cape_report:
            if not self.silent:
                print(f"[!!] ERROR parsing report {json_file}. No AVClass detection field found.")
            return None

        avclass_label = cape_report['avclass_detection'].capitalize()
        if avclass_label != "(n/a)":
            self.avclass_detection_labels.append(cape_report['avclass_detection'])
        else:
            self.avclass_detection_labels.append("(n/a)")
            self.reports_no_avclass_consensus.append(json_file)

    def write_results(self, progress: Progress) -> None:
        """
        Writes the analysis results of all CAPE reports to their correspondingg files, including
        the general statistics, the fatal reports, the reports with no processes, no hooked functions, etc.

        Args:
            progress: rich.progress.Progress object to show the processing status.
        """
        ### Writing stats ###
        stats = {
            'Total reports': self.total_reports_in_folder,
            # 'Total processed reports': self.reports_with_no_errors,
            # 'Total reports terminating with NtTerminateProcess(-1)': self.NtTerminateProcess_minus1,
            'Process stats': {
                'Average spawned processes': self.total_spawned_processes / self.total_reports_in_folder,
                'Min spawned processes': {
                    'n_processes': self.min_spawned_processes[0],
                    'Example report': self.min_spawned_processes[1]
                },
                'Max spawned processes': {
                    'n_processes': self.max_spawned_processes[0],
                    'Example report': self.max_spawned_processes[1]
                },
            },
            'Hooked functions stats': {
                # 'Reports with no hooked functions': len(self.reports_no_hooked_functions),
                'Average Hooked functions per process': self.total_hooked_functions / self.total_spawned_processes,
                'Min Hooked functions': {
                    'n_hooked_functions': self.min_hooked_functions[0],
                    'Example report': self.min_hooked_functions[1]
                },
                'Max Hooked functions': {
                    'n_hooked_functions': self.max_hooked_functions[0],
                    'Example report': self.max_hooked_functions[1],
                },
            },
            'Detection stats': {
                'Average VT detections': self.total_vt_positives / self.total_reports_in_folder,
                'Min VT detections': {
                    'n_detections': self.min_vt_positives[0],
                    'Example report': self.min_vt_positives[1]},
                'Max VT detections': {
                    'n_detections': self.max_vt_positives[0],
                    'Example report': self.max_vt_positives[1]},
                # https://stackoverflow.com/a/20950686/3267980
                'CAPE Detections': Counter(self.cape_detection_labels).most_common(),
                'AVClass Detections': Counter(self.avclass_detection_labels).most_common()
            },
        }
        try:
            with open(RESULTS_DIR + "reports_statistics.json", "w") as file:
                if not self.silent:
                    progress.console.log(
                        f"[+] Writing report statistics to [medium_violet_red]{RESULTS_DIR}reports_statistics.json")
                json.dump(stats, file, indent=4, escape_forward_slashes=False)
        except Exception as e:
            if not self.silent:
                progress.console.log(
                    f"[!!] Error writing results to file reports_statistics.json. {e} - {e.stderr}")

        ### Writing undetected reports ###
        undetected = {
            f"Undetected or benign ({self.vt_positives_threshold}/N or less VT detections)": self.no_vt_positives
        }
        try:
            with open(RESULTS_DIR + "undetected_or_benign_reports.json", "w") as file:
                if not self.silent:
                    progress.console.log(f"[+] Writing benign or undetected ({self.vt_positives_threshold}/N or less VT detections) reports to [medium_violet_red]"
                                         f"{RESULTS_DIR}undetected_or_benign_reports.json")
                json.dump(undetected, file, indent=4, escape_forward_slashes=False)
        except Exception as e:
            if not self.silent:
                progress.console.log(
                    f"[!!] Error writing results to file undetected_or_benign_reports.json. {e} - {e.stderr}")

        ### Writing unlabeled (no consensus) stats ###
        no_consensus = {
            'Reports with no CAPE detection consensus (n/a)': self.reports_no_cape_consensus,
            'Reports with no AVClass detection consensus (n/a)': self.reports_no_avclass_consensus,
        }
        try:
            with open(RESULTS_DIR + "unlabeled_reports.json", "w") as file:
                if not self.silent:
                    progress.console.log(
                        f"[+] Writing unlabeled reports to [medium_violet_red]{RESULTS_DIR}unlabeled_reports.json")
                json.dump(no_consensus, file, indent=4, escape_forward_slashes=False)
        except Exception as e:
            if not self.silent:
                progress.console.log(
                    f"[!!] Error writing results to file unlabeled_reports.json. {e}")


def main(json_files: list, silent: bool, vt_positives_threshold: int, progress: Progress) -> tuple:
    """
    Main function, collects all the statistics and writes them to the corresponding files.

    Args:
        json_files: List of file names (paths) of the reports to process.
        silent: If True, no output will be printed to the console.
        vt_positives_threshold: Detection threshold (based on VT results) to consider a report
            undetected (below the threshold) or malicious (above the threshold). (Default: 10)
        progress: rich.progress.Progress object to show the processing status

    Returns:
        Tuple cointaining the reports with 0 VT detections, the reports with no CAPE consensus and the reports with no AVClass consensus.
    """

    if not silent:
        progress.console.rule(
            "[bold medium_violet_red]Phase 5: Report Stats Generation[/bold medium_violet_red]", style="medium_violet_red")
        task = progress.add_task(
            "[medium_violet_red]Report Stats Generation", total=len(json_files))

    # Creating results directory, if it does not exist
    Path(RESULTS_DIR).mkdir(parents=True, exist_ok=True)

    stats = ReportStats(silent, vt_positives_threshold)
    stats.total_reports_in_folder = len(json_files)

    if not silent:
        progress.console.log(
            f"[+] Total reports: [medium_violet_red]{stats.total_reports_in_folder}")

    for json_file in json_files:
        try:
            with open(json_file) as file:
                cape_report = json.load(file)
            stats.process_report(cape_report, json_file)
            progress.update(task, advance=1) if not silent else None
        except Exception as e:
            if not silent:
                progress.console.log(f"[!!] Error reading report {json_file}: {e}")

    stats.write_results(progress)
    if not silent:
        progress.stop_task(task)
        progress.console.rule(
            "[bold medium_violet_red]End of Phase 5[/bold medium_violet_red]", style="medium_violet_red")

    return (stats.no_vt_positives, stats.reports_no_cape_consensus, stats.reports_no_avclass_consensus)


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

    reports = glob.glob(args.json_dir + "/*.json")

    # Check if there are no reports within the directory
    if not len(reports):
        progress.console.log("Error: No reports found.")
        progress.stop()
        exit()

    main(reports, args.silent, args.vt_positives_threshold, progress)
    if not args.silent:
        progress.console.rule("[bold green]MALVADA", style="green")
        progress.stop()
