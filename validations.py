"""
Module to validate required fields from SSL grader
version: 1.0
"""

import re
import json

# with open("error-messages.json", "r") as errors_file:
#     error_messages = json.load(errors_file)
# error_list = []
# error_list.append(error_messages["errors"])

def is_valid_hostname(hostname):
    if hostname[-1] == ".":
        # strip exactly one dot from the right, if present
        hostname = hostname[:-1]
    if len(hostname) > 253:
       # error_list.append(error_messages["errors"][1000])
        return False

    labels = hostname.split(".")

    # the TLD must be not all-numeric
    if re.match(r"[0-9]+$", labels[-1]):
        return False

    allowed = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(label) for label in labels)

def is_valid_port(port):
    try:
        port = int(port)
        if port <= 0 or port > 65535:
            return False
        return True
    except ValueError:
        return False

if __name__ == '__main__':
    print(is_valid_hostname("dbs.com"))
        
        