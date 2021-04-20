import json
import utils


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
                 tcp_ports: dict = None,
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
        self.tcp_ports = tcp_ports
        self.uptime = uptime
        self.vendor = vendor
        self.vulns = vulnerabilities

    @staticmethod
    def from_nmap(_dict, discovery_ip):
        ip = Device._get_ips(_dict["addresses"], discovery_ip)
        mac = Device._get_mac(_dict["addresses"])
        name = Device._get_name(_dict["hostnames"])
        os = Device._get_os(_dict["osmatch"])
        tcp_ports = {int(key): val for (key, val)
                     in _dict["tcp"].items()} if "tcp" in _dict else dict()
        vendor = Device._get_vendor(
            _dict["vendor"]) if "vendor" in _dict else None

        return Device(ip, mac, name, os, _dict["status"],
                      _dict["portused"], tcp_ports,
                      _dict["uptime"]["seconds"] if "uptime" in _dict else None,
                      vendor)

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
            if int(estimate["accuracy"]) < int(os["accuracy"]):
                estimate = os

        ret = dict()
        ret["name"] = estimate["name"]
        ret["accuracy"] = int(estimate["accuracy"])
        ret["osclass"] = Device._get_os_details(estimate["osclass"])

        return ret

    @staticmethod
    def _get_os_details(osclass):
        max_accuracy = -1
        classes = dict()
        for _class in osclass:
            accuracy = int(_class["accuracy"])
            if accuracy not in classes:
                classes[accuracy] = [_class]
            else:
                classes[accuracy].append(_class)

            if max_accuracy < accuracy:
                max_accuracy = accuracy

        return classes[max_accuracy]

    @staticmethod
    def _get_vendor(vendor):
        if vendor == None or len(vendor) == 0:
            return None
        else:
            return vendor

    def get_all_cpes(self):
        container = dict()

        # get cpe from tcp ports
        for port in self.tcp_ports:
            item = self.tcp_ports[port]
            cpe = item["cpe"]
            # add version if missing in CPE
            if utils.get_version(cpe) == None and "version" in item and len(item["version"]) > 0:
                ver_list = item["version"].split(" ")
                # only take the first str
                if ver_list[0].find(".X") != -1:
                    version = ver_list[0][:ver_list[0].find(".X")]
                else:
                    version = ver_list[0]
                cpe += ":" + version
            else:
                container[cpe] = int(port)

        # get os cpe
        if self.os != None:
            for os_class in self.os["osclass"]:
                if "cpe" in os_class and len(os_class["cpe"]) > 0:
                    for cpe in os_class["cpe"]:
                        container["cpe"] = -1  # -1 port indicates an OS cpe

        return container

    def get_vulns(self, update=True):
        cpes = self.get_all_cpes()

        vulns = self._get_os_vulns(cpes)
        vulns.update(self._get_service_vulns(cpes))

        if update:
            self.vulns = vulns
        return vulns

    def _get_os_vulns(self, cpes):
        if self.os == None:
            return dict()
        os_cpe = [cpe for (cpe, port) in cpes.items() if port == -1]
        params = {
            "cpeMatchString": os_cpe
        }

        cves = utils.query_nist_cve(params)
        if cves == None:
            return dict()

        return {cve_num: vuln for (cve_num, vuln) in cves if vuln.is_vulnerable(self)}

    def _get_service_vulns(self, cpes):
        if len(self.tcp_ports) == 0:
            return dict()

        name_param = ["%s %s" % (service["product"], service["version"])
                      for service in self.tcp_ports.values()]
        params = {
            "keyword": name_param
        }

        cves = utils.query_nist_cve(params)
        if cves == None:
            return dict()

        return {cve_num: vuln for (cve_num, vuln) in cves if vuln.is_vulnerable(self)}


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
                    "tcp": o.tcp_ports,
                    "uptime": o.uptime,
                    "vendor": o.vendor,
                    "vuln": o.vulns
                }
            }

        else:
            return super().default(o)
