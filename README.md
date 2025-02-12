# MALVADA - A Windows Malware Execution Traces Dataset generation framework

MALVADA is a software framework that parses one or more [CAPE](https://github.com/kevoreilly/CAPEv2) `.json` reports coming from Windows programs and processes them in [different phases](https://github.com/reverseame/MALVADA/blob/main/src/malvada.py#L89) to provide various statistics about their contents. 

The main objective of MALVADA is to help generate datasets. Specifically, reporting datasets generated with [CAPE](https://github.com/kevoreilly/CAPEv2) *(although it can be extended to other sandboxing engines format)*.

## Installation

Install the requirements specified in `requirements.txt`.
```
$ pip3 install -r requirements.txt
```

The last requirement specified in the `requirements.txt` file is [AVClass](https://github.com/malicialab/avclass) (from `malicialab`). In case you face any problem during installation, you can try to install it independently with:

```
$ pip3 install avclass-malicialab
```

## Usage

To use this framework you just need to run the main script `malvada.py` ([/src/malvada.py](/src/malvada.py)) and pass it the path to a `directory` that contains the set of `.json` reports you want to process:
```
$ python3 malvada.py directory
```
**NOTE:** The phases MALVADA comprises can be invoked individually, calling [their respective scripts](./src/malvada_workflow).

The tool will process all the reports in the `directory` and move them in their corresponding folders, if appropriate. You can test the tool using the report samples provided in [test_reports](./test_reports).

The *help* message is printed with the `-h` flag:
```
$ python3 malvada.py -h
usage: malvada.py [-h] [-w WORKERS] [-s] [-vt VT_POSITIVES_THRESHOLD] [-a ANONIMIZE_TERMS] json_dir

Generates the MALset dataset from CAPE reports. WARNING: This script will modify the reports in the directory provided.

positional arguments:
  json_dir              The directory containing one or more json reports.

options:
  -h, --help            show this help message and exit
  -w WORKERS, --workers WORKERS
                        Number of workers to use (default: 10).
  -s, --silent          Silent mode (default: False).
  -vt VT_POSITIVES_THRESHOLD, --vt-positives-threshold VT_POSITIVES_THRESHOLD
                        Threshold for VirusTotal positives (default: 10).
  -a ANONIMIZE_TERMS, --anonimize-terms ANONIMIZE_TERMS
                        Replace the terms in the file provided with [REDACTED], one by line (default: 'terms_to_anonymize.txt').
```
### Contextual overview of MALVADA
<p align="center">
    <img src="https://github.com/user-attachments/assets/669a09e5-19ac-470f-9da9-9b15239d3806" alt="MALVADA_Contextual_Overview" width="70%">
</p>

### Phases of MALVADA
MALVADA processes the reports in the following phases:
1. Detect *incorrect* reports. That is, those that are poorly formatted for some reason (samples do not run, they crash, etc...).
2. Remove duplicate reports (based on the SHA512 of the submitted sample).
3. Sanitize and anonymize reports. That is, remove sensitive information and the terms specified (by default) in `terms_to_anonymize.txt`.
4. Add [AVClass](https://github.com/malicialab/avclass) result to the report. That is, parse the results from all VT vendors, transform them into valid input for [AVClass](https://github.com/malicialab/avclass) and invoke [AVClass](https://github.com/malicialab/avclass) itself. The AVClass consesus result is added in the key `avclass_detection`.
5. Generate statistics.

### Internal architecture of MALVADA
<p align="center">
    <img src="https://github.com/user-attachments/assets/576ac899-5748-443b-921a-3ccb5877b7ca" alt="MALVADA_Internal_Architecture" width="70%">
</p>

### Example
Output after executing MALVADA with the [test_reports](./test_reports):

`$ python3 src/malvada.py test_reports -w 100` (100 workers, default is 10)

![MALVADA execution example](./doc/images/execution_example.png?raw=true "MALVADA Execution Example")

## How to cite

If you are using this software, please cite it as follows:
```
Raducu, R., Villagrasa-Labrador, A., Rodríguez, R. J., & Álvarez, P. (2025). MALVADA: A framework for generating datasets of malware execution traces. SoftwareX, 30.
```
```latex
@article{RADUCU2025_MALVADA,
title = {MALVADA: A framework for generating datasets of malware execution traces},
journal = {SoftwareX},
volume = {30},
year = {2025},
issn = {2352-7110},
doi = {https://doi.org/10.1016/j.softx.2025.102082},
url = {https://www.sciencedirect.com/science/article/pii/S2352711025000494},
author = {Razvan Raducu and Alain Villagrasa-Labrador and Ricardo J. Rodríguez and Pedro Álvarez},
keywords = {Dataset generation, Malware behavior, Execution traces, Malware classification},
abstract = {Malware attacks have been growing steadily in recent years, making more sophisticated detection methods necessary. These approaches typically rely on analyzing the behavior of malicious applications, for example by examining execution traces that capture their runtime behavior. However, many existing execution trace datasets are simplified, often resulting in the omission of relevant contextual information, which is essential to capture the full scope of a malware sample’s behavior. This paper introduces MALVADA, a flexible framework designed to generate extensive datasets of execution traces from Windows malware. These traces provide detailed insights into program behaviors and help malware analysts to classify a malware sample. MALVADA facilitates the creation of large datasets with minimal user effort, as demonstrated by the WinMET dataset, which includes execution traces from approximately 10,000 Windows malware samples.}
}
```

More info in the "Cite this repository" GitHub contextual menu.

## Authors
Razvan Raducu  
Alain Villagrasa Labrador  
Ricardo J. Rodríguez  
Pedro Álvarez  

## Funding support

Part of this research was supported by the Spanish National Cybersecurity Institute (INCIBE) under *Proyectos Estratégicos de Ciberseguridad -- CIBERSEGURIDAD EINA UNIZAR* and by the Recovery, Transformation and Resilience Plan funds, financed by the European Union (Next Generation).

![INCIBE_logos](https://github.com/user-attachments/assets/a83425c3-9546-4123-9bef-39a7ea52af09)

