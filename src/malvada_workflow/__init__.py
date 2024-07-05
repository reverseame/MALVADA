"""
MALVADA Framework: Malware Execution Traces Dataset generation.

This framework parses one or more CAPE JSON reports and provides several useful stats about their contents.

MALVADA performs 5 steps before generating the final dataset. For more information on the pipeline process,
 refer to the source code or the documentation present in the official repostiroy. Additionally, you may find the associated paper [DOI:TBA] useful.

Authors:
    - Razvan "RazviOverflow" Raducu
    - Alain "Str1ien" Villagrasa Labrador
    - Pedro Álvarez
    - Ricardo J. Rodríguez

Official repository: https://github.com/reverseame/MALVADA

"""

from .get_incorrect_cape_reports import main as get_incorrect_cape_reports
from .get_duplicate_reports import main as get_duplicate_reports
from .sanitize_and_anonymize_reports import main as sanitize_and_anonymize_reports
from .get_avclass_labels import main as get_avclass_labels
from .get_cape_reports_stats import main as get_cape_reports_stats
