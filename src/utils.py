import json
import jsonschema
import os
import pprint
import requests

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


def cpe_match(cpe_l, cpe_r):
    cpe_l_23 = convert_to_cpe23(cpe_l) if "/" in cpe_l else cpe_l
    cpe_r_23 = convert_to_cpe23(cpe_r) if "/" in cpe_r else cpe_r

    if len(cpe_l_23) < len(cpe_r_23):
        return cpe_r_23.startswith(cpe_l_23)
    else:
        return cpe_l_23.startswith(cpe_r_23)


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


def is_vulnerable(cpe_list, config_node):
    and_node = config_node["operator"] == "AND"
    negate = config_node["negate"] if "negate" in config_node else False
    return_val = None

    if "cpe_match" in config_node:
        for match in config_node:
            cpe_found = cpe_in_list(match["cpe23Uri"], cpe_list)
            if cpe_found and not and_node:  # if cpe found and its an or node
                return_val = True
                break
            elif (not cpe_found) and and_node:  # if cpe not found and its an and node
                return_val = False
                break
        if return_val == None:
            return_val = and_node  # if its an and node, return true; otherwise return false

    elif "children" in config_node:
        for child in config_node["children"]:
            is_vuln = is_vulnerable(cpe_in_list, child)
            if is_vuln and not and_node:
                return_val = True
                break
            elif (not is_vuln) and and_node:
                return_val = False
                break
        if return_val == None:
            return_val = and_node

    else:
        raise ValueError("Node needs children or cpe_match")

    return return_val if negate == False else (not return_val)
