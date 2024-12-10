# MALVADA utils
Utility scripts that help extracting information from MALVADA-parsed reports.

* `get_labels_per_each_report.py`. Extracts consensus labels from each .json file . 
* `get_malware_family_report_mappings.py`. Generates cape_ and avclass_ report mappings from each .json file. That is, which reports belong to which consensus family (or label). 
* `malvada_extractor.py`. Facilitates the extraction of reports from MALVADA-generated datasets based on AVCLASS / CAPEv2 labels.