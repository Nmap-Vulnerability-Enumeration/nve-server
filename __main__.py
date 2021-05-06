from src.server import NVEServer
from src.nmap_scanner import NmapScanner

scanner = NmapScanner("10.1.64.0", 28)
server = NVEServer(scanner)
server.start()