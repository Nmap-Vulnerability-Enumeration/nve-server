import utils
from server import NVEServer
from nmap_scanner import NmapScanner

scanner = NmapScanner()
NVEServer.start(scanner)