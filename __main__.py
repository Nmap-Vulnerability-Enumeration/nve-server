from src.server import NVEServer
from src.nmap_scanner import NmapScanner

DEFAULT_SCANNER = True
server  = None
if DEFAULT_SCANNER:
    scanner = NmapScanner("10.1.64.0", 28)
    server = NVEServer(scanner)
else:
    server = NVEServer()
server.start()