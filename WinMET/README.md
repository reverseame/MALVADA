# WinMET (Windows Malware Execution Traces) Dataset

Available at: [![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.12737794.svg)](https://doi.org/10.5281/zenodo.12737794)

WinMET dataset contains the reports generated with CAPE sandbox after analyzing several malware samples. The reports are valid JSON files that contain the spawned processes, the sequence of WinAPI and system calls invoked by each process, their parameters, their return values, and OS accesed resources, amongst many others.

This dataset was generated using the MALVADA framework, which you can read more about in our publication: TBA. The article also provides insights about the contents of this dataset.

## How to use the dataset
The 7z file is password protected. The password is: `infected`.

Compressed size on disk: ~2.5GiB.
Decompressed size on disk: ~105GiB.
Total decompressed `.json` files: 9889.

The name of each `.json` file is irrelevant. It corresponds to its analysis ID.

`cape_report_to_label_mapping.json `and `avclass_report_to_label_mapping.json` contain the mappings of each report with its corresponding consensus label, sorted in descendent order (given the number of reports belonging to each label/family).

### Integrity checks:
- MD5: 75b3354fb186ae5a47c320e253bd96ee
- SHA256: 00faac011f4938a29ba9afbd9f0b50d89ede342d1d0d6877cb90b46eabd92c72
- SHA512: 038ca9303623cadaa72eab680221e81e1d335449d08f6395b39eb99baad4092e02c00955089fba31ce1a9dd04260ae80b622491f754774331bced18e8e3be1c4

## Citation
If you use this dataset, cite it as follows:

TBA.

## Statistics
The following statistic (and many more) can be obtained by analyzing the **WinMET** dataset with the [MALVADA](TBA) framework.

- Total reports: 9889.
- Average VT (VirusTotal) detections: ~53.
- There 268 benign or undetected reports. That is, 10 or less VT detections (default threshold).
- There are 2584 reports with no CAPE consensus label.
- There are 695 reports with no AVClass consensus label.
- Top 20 [CAPE](https://github.com/kevoreilly/CAPEv2/blob/de34cf5aa6054104d149fb5319317f10fb30e1c4/lib/cuckoo/common/integrations/virustotal.py#L155) consensus labels (there are many more):
	- "(n/a)": 2584
	- "Redline": 1227
	- "Agenttesla": 1010
	- "Crifi": 622
	- "Amadey": 606
	- "Smokeloader": 538
	- "Virlock": 471
	- "Msilheracles": 408
	- "Tedy": 364
	- "Disabler": 343
	- "Xorstringsnet": 321
	- "Snake": 252
	- "Autorun": 252
	- "Metastealer": 246
	- "Formbook": 244
	- "Lokibot": 202
	- "Strab": 188
	- "Loki": 185
    - "Mint": 179
    - "Taskun": 178
- Top 20 [AVClass](https://github.com/malicialab/avclass) consensus labels (there are many more)
	- "Reline": 2187
	- "Disabler": 732
	- "(n/a)": 695
	- "Amadey": 575
	- "Agenttesla": 478
	- "Taskun": 382
	- "Virlock": 293
	- "Equationdrug": 270
	- "Stop": 268
	- "Strab": 260
	- "Noon": 259
	- "Gamarue": 181
	- "Dofoil": 135
	- "Makoob": 113
	- "Mokes": 110
	- "Snakelogger": 110
	- "Bladabindi": 98
	- "Zard": 84
	- "Gcleaner": 83
	- "Deyma": 80