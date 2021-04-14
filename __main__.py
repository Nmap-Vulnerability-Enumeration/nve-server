from src.server import NVEServer
from src.nmap_scanner import NmapScanner

scanner = NmapScanner()
server = NVEServer(scanner)
server.start()