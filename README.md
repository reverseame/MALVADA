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
### Phases of MALVADA
MALVADA processes the reports in the following phases:
1. Detect *incorrect* reports. That is, those that are poorly formatted for some reason (samples do not run, they crash, etc...).
2. Remove duplicate reports (based on the SHA512 of the submitted sample).
3. Sanitize and anonymize reports. That is, remove sensitive information and the default terms specified in `terms_to_anonymize.txt` .
4. Add `avclass_labels` to the report. That is, parse the results from all VT vendors, transform them into valid input for [AVClass](https://github.com/malicialab/avclass) and invoke [AVClass](https://github.com/malicialab/avclass) itself. The AVClass consesus result is added in the key `avclass_detection`.
5. Generate statistics.

### Example
Output after executing MALVADA with the [test_reports](./test_reports):

First, extract the reports

`$ 7z x test_reports.7z`

Then, invoke MALVADA:

`$ python3 malvada.py test_reports`

![MALVADA execution example](./doc/images/execution_example.png?raw=true "MALVADA Execution Example")

## How to cite

If you are using this software, please cite it as follows:
```
TBD
```

More info in the "Cite this repository" GitHub contextual menu.

## Authors
Razvan Raducu  
Alain Villagrasa Labrador  
Ricardo J. Rodríguez  
Pedro Álvarez  
