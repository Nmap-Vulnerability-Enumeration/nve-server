import json
import jsonschema
import os
import pprint
import re
import requests

from cpe import CPE
from src.vulnerability import Vulnerability

NIST_CVE_BASE_URL = "https://services.nvd.nist.gov/rest/json/cve/1.0"
NIST_DB_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"
NIST_MAX_PAGE_SIZE = 5000
# NIST_JSON_SCHEMA = None
# NIS_CVE_SCHEMA = None

# with open(os.path.realpath("res/nist_modified_schema.json"), "r") as f:
#     NIST_JSON_SCHEMA = json.load(f)

# with open(os.path.realpath("res/cve.json"), "r") as f:
#     NIS_CVE_SCHEMA = json.load(f)


def get_my_external_ip():
    req = requests.get('https://api.ipify.org')
    if req.status_code == requests.codes.ok:
        return req.text
    req.raise_for_status()


def get_cve_details(cve: str):
    req = requests.get("%s/%s" % (NIST_CVE_BASE_URL, cve))
    if req.status_code == requests.codes.ok:
        return req.json()
    req.raise_for_status()

# def matches_schema(obj, schema):
#     if schema not in NIST_JSON_SCHEMA["definitions"]:
#         raise ValueError("Error: Unknown schema")

#     try:
#         jsonschema.validate(obj, NIST_JSON_SCHEMA)
#         return True
#     except jsonschema.ValidationError as e:
#         print(e)
#         return False


def parse_nist_response(response: dict):
    container = dict()

    if response["totalResults"] == 0:
        return dict()

    for cve_item in response["result"]["CVE_Items"]:
        cve_id = cve_item["cve"]["CVE_data_meta"]["ID"]
        container[cve_id] = Vulnerability.from_nist(cve_item)

    return container


def query_nist_cve(params: dict):
    req = requests.get(NIST_DB_BASE_URL, params=params)
    if req.status_code == requests.codes.ok:
        response = req.json()
        if len(response) == 0:
            return {}

        if response["resultsPerPage"] < response["totalResults"] and "resultsPerPage" not in params:
            params["resultsPerPage"] = min(
                response["totalResults"], NIST_MAX_PAGE_SIZE)
            return query_nist_cve(params)
        else:
            return parse_nist_response(response)

    else:
        req.raise_for_status()


def convert_to_cpe23(cpe):
    cpe_elements = cpe.split(":")
    version = cpe_elements.pop(4) if len(cpe_elements) > 4 else ""
    cpe_elements[1] = cpe_elements[1][1:]
    cpe_elements.insert(1, version)
    return ":".join(cpe_elements)

def cpe_match_str(match_str, cpe):
    match_reg = CPE(match_str).as_fs()
    cpe23 = CPE(cpe).as_fs()

    regex = re.compile(match_reg)
    return regex.match(cpe23) != None

def cpe_match(cpe_l, cpe_r):
    cpe23l = CPE(cpe_l)
    cpe23r = CPE(cpe_r)

    if cpe23l.as_fs().count("*") > cpe23r.as_fs().count("*"):
        reg = cpe23l.as_fs()
        s = cpe23r.as_fs()
    else:
        reg = cpe23r.as_fs()
        s = cpe23l.as_fs()
    
    regex = re.compile(reg)
    return regex.match(s) != None


def get_version(cpe):
    details = cpe.split(":")
    if len(details) < 5:
        return None
    else:
        return cpe.split(":")[4] if "/" in cpe else cpe.split(":")[1]


def version_compare(version_l, version_r):
    '''
    The function comapres to semantic version strings.

    Returns 0 if version_l and version_r represent the same version

    Returns 1 if version_l is higher than version_r

    Returns -1 if version_l is lower than version_r
    '''

    ver_l = [int(x) for x in version_l.split(".")]
    ver_r = [int(x) for x in version_r.split(".")]

    for i in range(3):
        if ver_l[i] > ver_r[i]:
            return 1
        elif ver_l[i] < ver_r[i]:
            return -1

    return 0


def cpe_in_list(cpe, cpe_list):
    for item in cpe_list:
        if cpe_match(cpe, item):
            return True
    return False

def match_str_in_list(match_str, cpe_list):
    for item in cpe_list:
        if cpe_match_str(match_str, item):
            return True
    return False

