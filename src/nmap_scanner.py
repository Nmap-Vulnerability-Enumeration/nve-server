import json
import nmap
import utils

from datetime import datetime
from device import Device, DeviceEncoder
from vulnerability import Vulnerability

class NmapScanner:
    _switchs = {
        "os_search" : "-O",
        "version_search": "-sV"
    }

    def __init__(self, default_ip = None, default_snet_mask = None):
        self._scanner = nmap.PortScanner()
        self._search_params = self._default_params()

        self._set_default()

        self._devices = dict()
        self._devices_updated = None

        self.devices = dict()
        self.vulns = dict()
        self.last_update = None

        self._default_ip = default_ip if default_ip != None else utils.get_my_external_ip()
        self._default_snet_mask = default_snet_mask if default_snet_mask != None else 20

    def _set_defualt(self):
        self._search_params["os_search"]["active"] = True
        self._search_params["version_search"]["active"] = True

    def run_scan(self, ip : str = None, snet_mask: int = None, arguments: str = None, sudo: bool = True, cache: bool = True):
        my_ip = ip if ip != None else self._default_ip
        mask = str(snet_mask) if snet_mask != None else str(self._default_snet_mask)
        args = arguments if arguments != None else self._construct_args()

        nmap_scan = self._scanner.scan(hosts = "%s/%s" % (my_ip, mask), arguments = args, sudo = sudo)["scan"]
        devices = self._extract_devices(nmap_scan)

        if cache:
            self._devices = devices
            self._devices_updated = datetime.now()
        
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
    
    def _extract_devices(self, nmap_output):
        container = dict()
        for key in nmap_output:
            container[key] = Device.from_nmap(nmap_output[key], key)

        return container

    # def _collect_services(self, devices):
    #     services = dict() # service cpe:[discovery ip]
    #     for device in devices:
    #         pass
    #     pass

    def get_all_devices(self, refresh = False):
        if self._devices_updated == None:
            print("Warning: network hasn't been scanned yet. Using defualt ip and subnet mask to run a scan")
            self.refresh()
        elif refresh:
            self.refresh()

        return self._devices
    
    def get_device(self, discovery_ip: str, refresh = False):
        if self._devices_updated == None:
            print("Warning: network hasn't been scanned yet. Using defualt ip and subnet mask to run a scan")
            self.refresh()
        elif refresh:
            self.refresh()

        if discovery_ip not in self._devices:
            raise ValueError("Device \"%s\" not found. Please provide a valid ipv4 string and/or set refresh to True" % discovery_ip)
    
        return self._devices[discovery_ip]

    def get_device_vuln(self, discovery_ip: str, refresh = False):
        device = self.get_device(discovery_ip, refresh)
        return device.get_vulns()


n = NmapScanner("10.1.64.0", 28)
devices, _ = n.run_scan()
with open("jargon/file.json", "w") as fp:
    json.dump(devices, fp, cls = DeviceEncoder)