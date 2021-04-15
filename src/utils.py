import json
import pprint
import requests

NIST_DB_BASE_URL = "https://services.nvd.nist.gov/rest/json/cve/1.0"
NIST_MAX_PAGE_SIZE = 5000

def get_my_external_ip():
    req = requests.get('https://api.ipify.org')
    if req.status_code == requests.codes.ok:
       return req.text
    req.raise_for_status()

def get_cve_details(cve: str):
    pass

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
            return response
    
    elif req.status_code == 404:
        return None
    
    else:
        req.raise_for_status()