import nmap

from datetime import datetime
from device import Device
from vulnerability import Vulnerability
import utils

class NmapScanner:
    _switchs = {
        "os_search" : "-O"
    }

    def __init__(self, default_ip = None, default_snet_mask = None):
        self._scanner = nmap.PortScanner()
        self._search_params = self._default_params()

        self._search_params["os_search"]["active"] = True

        self._cache = {
            "devices": dict(),
            "vulns": dict(),
            "updated": None
        }
        self.devices = dict()
        self.vulns = dict()
        self.last_update = None

        self._default_ip = _default_ip if _default_ip != None else utils.get_my_external_ip()
        self._default_snet_mask = default_snet_mask if default_snet_mask != None else 20


    def run_scan(self, ip : str = None, snet_mask: int = None, arguments: str = None, sudo: bool = True, cache: bool = True):
        my_ip = ip if ip != None else self._default_ip
        mask = str(snet_mask) if snet_mask != None else str(self._default_snet_mask)
        args = arguments if arguments != None else self._construct_args()

        devices = self._parse_devices(self._scanner.scan(hosts = "%s/%s" % (my_ip, mask), arguments = args, sudo = sudo))
        vulns = self._fetch_vulns(devices)

        if cache:
            self._cache["devices"] = devices
            self._cache["vulns"] = vulns
            self._cache["updated"] = datetime.now()
        
        return devices, vulns

    def refresh(self):
        self.run_scan()

    def export(self, path, cached : bool = True):
        pass

    def _construct_args(self):
        args = ""

        for key in self._search_params:
            param = self._search_params[key]
            if param["active"]:
                if param["value"] != None:
                    args += "%s=%s " % (NmapScanner._switchs[key], param["value"])
                else:
                    args += "%s " % NmapScanner._switchs[key]
        
        return args
    
    def _default_params(self):
        _args = {}
        for key in NmapScanner._switchs:
            _args[key] = {
                "active": False,
                "value": None
            }
        
        return _args

    def update_args(self, args: dict):
        for key in args:
            if key not in self._search_params:
                raise ValueError("arg is not a valid argument type")
            
            self._search_params[key]["active"] = args[key]["active"]
            self._search_params[key]["value"] = args[key]["value"]
