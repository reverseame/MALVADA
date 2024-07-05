# Test Reports
Set of 200 RAW reports to test MALVADA.

## Usage
Extract the `.7z` file that contains the RAW reports. Space on disk after extraction: ~1.03 GiB.

```
$ md5sum test_reports.7z 
6daf269f52c9192a878f0840ac89df5e  test_reports.7z

$ 7z x test_reports.7z
...
Everything is Ok     

Files: 200
Size:       1383927271
Compressed: 34915263
```

From this folder invoke MALVADA with:

```
$ python3 ../src/malvada.py .
```

After the execution, the directory should have the following structure:

```
$ tree
.
├── 11482.json
├── [...]
├── 9736.json
├── duplicate_reports
│   ├── duplicate_reports
│   └── duplicate_reports.json
├── README.md
├── reports_with_errors
│   ├── reports_with_errors
│   │   ├── 24801.json
│   │   ├── [...]
│   │   └── 32596.json
│   ├── reports_with_errors.json
│   ├── reports_with_vt_errors
│   │   └── 32510.json
│   └── reports_with_vt_errors.json
├── results
│   ├── report_statistics.json
│   ├── undetected_or_benign_reports.json
│   └── unlabeled_reports.json
└── test_reports.7z
```

The results of the execution are:
- 115 reports passed all processing stages
- 84 reports with errors, moved to `reports_with_errors/reports_with_errors` and listed in `reports_with_errors/reports_with_errors.json`
- 1 report with VT errors, moved to `reports_with_errors/reports_with_vt_errors` and listed in `reports_with_errors/reports_with_vt_errors.json`
- 0 duplicate_reports
- 3 undetected reports, listed in `results/undetected_or_benign_reports.json`
- 68 reports with no CAPE consensus, listed in `unlabeled_reports.json`
- 15 reports with no AVClass consensus, listed in `unlabeled_reports.json`

```
────────────────────────────────────────────── Pipeline finished ──────────────────────────────────────────────
           [+] Execution time: 53.67 seconds.                                                    malvada.py:118
           [+] Reports passing all phases: 115                                                   malvada.py:120
           [+] Reports with errors: 84                                                           malvada.py:121
           [+] Reports with VirusTotal errors: 1                                                 malvada.py:122
           [+] Duplicate reports: 0                                                              malvada.py:124
           [+] Undetected reports: 3                                                             malvada.py:125
           [+] Reports with no CAPE consensus: 68                                                malvada.py:126
           [+] Reports with no AVClass consensus: 15                                             malvada.py:128
─────────────────────────────────────────────────── MALVADA ───────────────────────────────────────────────────
```
