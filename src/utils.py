import json
import jsonschema
import os
import pprint
import requests

from vulnerability import Vulnerability

NIST_CVE_BASE_URL = "https://services.nvd.nist.gov/rest/json/cve/1.0/"
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
    req = requests.get(NIST_CVE_BASE_URL + cve)
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
    req = requests.get(NIST_DB_BASE_URL, params = params)
    if req.status_code == requests.codes.ok:
        response = req.json()
        if len(response) == 0:
            return {}
        
        if response["resultsPerPage"] < response["totalResults"] and "resultsPerPage" not in response:
            params["resultsPerPage"] = max(response["totalResults"], NIST_MAX_PAGE_SIZE)
            return query_nist_cve(params)
        else:
            return response # parse_nist_response(response)
    
    elif req.status_code == 404:
        print("err")
        return None
    
    else:
        req.raise_for_status()

def cpe_match(cpe_l, cpe_r):
    def convert_to_cpe23(cpe):
        cpe_elements = cpe.split(":")
        version = cpe_elements.pop(4) if len(cpe_elements) > 4 else ""
        cpe_elements[1] = cpe_elements[1][1:]
        cpe_elements.insert(1, version)
        return ":".join(cpe_elements)

    cpe_l_23 = convert_to_cpe23(cpe_l) if "/" in cpe_l else cpe_l
    cpe_r_23 = convert_to_cpe23(cpe_r) if "/" in cpe_r else cpe_r

    if len(cpe_l_23) < len(cpe_r_23):
        return cpe_r_23.startswith(cpe_l_23)
    else:
        return cpe_l_23.startswith(cpe_r_23)
