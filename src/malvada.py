import argparse
import glob
import os
import shutil
import malvada_workflow
from rich.progress import (
    BarColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
    SpinnerColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
)


def parse_arguments():
    """
    Arguments parsing.
    """
    parser = argparse.ArgumentParser(description='Generates a dataset from CAPE reports. '
                                                 'WARNING: This script will modify the reports in '
                                                 'the directory provided.')
    parser.add_argument(
        'json_dir', help='The directory containing one or more json reports.')
    parser.add_argument('-w', '--workers', type=int, default=10,
                        help='Number of workers to use (default: 10).')
    parser.add_argument('-s', '--silent', action='store_true',
                        help='Silent mode (default: False).')
    parser.add_argument('-vt', '--vt-positives-threshold', type=int,
                        default=10, help='Threshold for VirusTotal positives (default: 10).')
    parser.add_argument('-a', '--anonimize-terms',
                        help='Replace the terms in the file provided with [REDACTED], one by line '
                             '(default: \'terms_to_anonymize.txt\').',
                        default='terms_to_anonymize.txt')
    return parser.parse_args()


def main() -> None:
    """
    Main script for the generation of the dataset.
    """

    # Parse arguments
    args = parse_arguments()
    duplicates_strat = 'biggest'  # Default strategy for duplicates
    interpret = 'python3'

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

    # Check if the json_dir exists and is a directory
    if not (os.path.exists(args.json_dir) and os.path.isdir(args.json_dir)):
        progress.console.log(
            f"Error: {args.json_dir} does not exist or is not a directory.")
        exit()

    # Check if the interpret is valid
    if not shutil.which(interpret):
        progress.console.log(f"Error: {interpret} is not a valid interpreter.")
        exit()

    # Set up the reports for the pipeline
    reports = glob.glob(args.json_dir + "/*.json")
    total_reports = len(reports)

    if not args.silent:
        progress.console.rule(
            "[bold green]MALVADA", style="green")
        progress.console.log(f"[+] Total workers: [green]{args.workers}")
        progress.console.log(f"[+] Total reports: [green]{total_reports}")
        progress.console.log(
            f"[+] File with terms to anonymize: [green]{args.anonimize_terms}")
        progress.console.log(
            f"[+] VirusTotal positives threshold: [green]{args.vt_positives_threshold}")
        progress.console.rule(
            "[bold green]Starting pipeline[/bold green]", style="green")

    progress.start() if not args.silent else None

    # Phase 1
    reports_with_errors, reports_with_vt_errors = malvada_workflow.get_incorrect_cape_reports(
        reports, args.silent, progress)
    # set for faster lookup
    reports_to_remove = set(reports_with_errors + reports_with_vt_errors)
    # Remove reports with errors
    reports = [report for report in reports if report not in reports_to_remove]

    # Phase 2
    dup_reports = malvada_workflow.get_duplicate_reports(
        reports, duplicates_strat, args.silent, progress)

    # Remove duplicate reports
    reports = [report for report in reports if report not in dup_reports]

    # Phase 3
    malvada_workflow.sanitize_and_anonymize_reports(
        reports, args.silent, args.anonimize_terms, progress, args.workers)

    # Phase 4
    malvada_workflow.get_avclass_labels(reports, args.silent, progress, args.workers)

    # Phase 5
    undetected_reports, no_consensus_reports, no_vt_consensus_reports = malvada_workflow.get_cape_reports_stats(
        reports, args.silent, args.vt_positives_threshold, progress)

    # Final info
    if not args.silent:
        progress.console.rule("[bold green]Pipeline finished[/bold green]", style="green")
        progress.console.log("[+] Execution time: [green]"
                             f"{round(sum([task.elapsed for task in progress.tasks]), 2)}[/green] seconds.")
        progress.console.log(f"[+] Reports passing all phases: [green]{len(reports)}[/green]")
        progress.console.log(f"[+] Reports with errors: [green]{len(reports_with_errors)}[/green]")
        progress.console.log(
            f"[+] Reports with VirusTotal errors: [green]{len(reports_with_vt_errors)}[/green]")
        progress.console.log(f"[+] Duplicate reports: [green]{len(dup_reports)}[/green]")
        progress.console.log(f"[+] Undetected reports: [green]{len(undetected_reports)}[/green]")
        progress.console.log(
            f"[+] Reports with no CAPE consensus: [green]{len(no_consensus_reports)}[/green]")
        progress.console.log(
            f"[+] Reports with no AVClass consensus: [green]{len(no_vt_consensus_reports)}[/green]")
        progress.console.rule("[bold green]MALVADA", style="green")
        progress.stop()


if __name__ == '__main__':
    main()
