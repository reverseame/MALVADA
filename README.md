# MALVADA

This framework parses one or more CAPE JSON reports and provides several useful stats about their contents.

## Installation

Install the requirements specified in `requirements.txt`.
```
$ pip3 install -r requirements.txt
```

The last requirement specified in the `requirements.txt` file is [AVClass](https://github.com/malicialab/avclass) (from malicialab). In case you face any problem during installation, you can try to install it independently with:
```
$ pip3 install avclass-malicialab
```

## Usage
To use this framework you only need to place in the same directory the set of `.json` reports you want to process. Then simply invoke the tool:
```
$ python3 malvada.py directory
```
The tool will process al the reports in `directory` and move them in their corresponding folders, if that is the case. You can test the tool using the report samples provided in [test_reports](./test_reports).

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
### Example
Output after executing MALVADA with the [test_reports](./test_reports):
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
