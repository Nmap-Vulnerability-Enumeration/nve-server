from src.server import NVEServer
from src.nmap_scanner import NmapScanner

scanner = NmapScanner()
#server = NVEServer(scanner) call post to get scanner
server = NVEServer()
server.start()