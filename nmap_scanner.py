import nmap

class Vulnerability:
    def __init__(self):
        pass

class NmapScanner:
    def __init__(self):
        self._scanner = nmap.PortScanner()
        
        self.devices = []
        self.vulnrabilities = []
        self.last_update = None

    def run_scan(self):
        pass

    def refresh(self):
        pass

    def export(self):
        pass
