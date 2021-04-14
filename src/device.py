import json

class Device:
    '''
    Device class represents the devices discovered by the scanner.
    '''
    def __init__(self,
                 ip: dict,
                 mac: str = None,
                 name: str = None,
                 OS: dict = None,
                 status: dict = None,
                 ports: list = None,
                 uptime: dict = None,
                 vendor: str = None,
                 vulnerabilities: list = None
                 ):
        self.hostname = name
        self.ip = ip
        self.mac = mac
        self.os = OS
        self.status = status
        self.ports = ports
        self.uptime = uptime
        self.vendor = vendor
        self.vulnerabilities = vulnerabilities

    @staticmethod
    def from_nmap(_dict, discovery_ip):
        return Device(
                    Device._get_ips(_dict["addresses"], discovery_ip),
                    Device._get_mac(_dict["addresses"]),
                    Device._get_name(_dict["hostnames"]),
                    Device._get_os(_dict["osmatch"]),
                    _dict["status"],
                    _dict["portused"],
                    _dict["uptime"]["seconds"],
                    Device._get_vendor(_dict["vendor"]) if "vendor" in _dict else None
                )
    
    @staticmethod
    def _get_ips(addresses, discovery_ip):
        if addresses == None or len(addresses) == 0:
            return None

        _ip = dict()

        _ip["discovery"] = discovery_ip
        _ip["ipv4"] = addresses["ipv4"] if "ipv4" in addresses else None
        _ip["ipv6"] = addresses["ipv6"] if "ipv6" in addresses else None

        return _ip

    @staticmethod
    def _get_mac(addresses):
        if addresses == None or len(addresses) == 0:
            return None
        
        return addresses["mac"] if "mac" in addresses else None

    @staticmethod
    def _get_name(hostnames):
        if len(hostnames) == 0:
            return None
        
        return hostnames[0]["name"]

    @staticmethod
    def _get_os(osmatch):
        if len(osmatch) == 0:
            return None

        estimate = osmatch[0]
        
        for os in osmatch:
            if estimate["accuracy"] < os["accuracy"]:
                estimate = os
        
        ret = dict()
        ret["name"] = estimate["name"]
        ret["accuracy"] = estimate["accuracy"]
        ret["osclass"] = Device._get_os_details(estimate["osclass"])

        return ret
    
    @staticmethod
    def _get_os_details(osclass):
        max_accuracy = -1
        classes = dict()
        for _class in osclass:
            if _class["accuracy"] not in classes:
                classes[_class["accuracy"]] = [_class]
            else:
                classes[_class["accuracy"]].append(_class)
            
            if max_accuracy < _class["accuracy"]:
                max_accuracy = _class["accuracy"]
        
        return classes[max_accuracy]

    @staticmethod
    def _get_vendor(vendor):
        if vendor == None or len(vendor) == 0:
            return None
        else:
            return vendor

class DeviceEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Device):
            return {
                "_type": "Device",
                "value": {
                    "hostname": o.hostname,
                    "ip": o.ip,
                    "mac": o.mac,
                    "os": o.os,
                    "status": o.status,
                    "ports": o.ports,
                    "uptime": o.uptime,
                    "vendor": o.vendor,
                    "vuln": o.vulnerabilities
                }
            }

        else:
            return super().default(o)
