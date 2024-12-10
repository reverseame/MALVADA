# MALVADA utils
Utility scripts that help extracting information from MALVADA-parsed reports.

* get_labels_per_each_report.py: parses the reports directory and extracts consensus labels from each .json file. 
* get_malware_family_report_mappings.py: parses the reports directory and generates cape_ and avclass_ report mappings. That is, which reports belong to which consensus family. 
* malvada_extractor.py: Utility script to facilitate the extraction of reports from MALVADA-generated datasets based on AVCLASS / CAPEv2 labels.