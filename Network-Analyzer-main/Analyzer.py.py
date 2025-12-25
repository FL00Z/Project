import sys
import threading
import socket
import scapy.all as scapy
from collections import defaultdict
import datetime
import random
import subprocess
import requests
import time
import csv
import os
import ipaddress
import networkx as nx
import netifaces

# PyQt6 Imports
from PyQt6.QtWidgets import (QApplication, QMainWindow, QTextEdit,  
                             QVBoxLayout, QHBoxLayout, QWidget, 
                             QInputDialog, QPushButton, QLabel, QGridLayout)
from PyQt6.QtGui import QAction, QTextCursor, QFont
from PyQt6.QtCore import QObject, pyqtSignal, Qt

# --- [1] MOCK REPORT GENERATOR ---
class Report_Generator:
    def CSV_GenerateReport(self, Data):
        print("<i style='color:#888'>[Log] CSV Report saved (Mock).</i>")
    def TXT_GenerateReport(self, Data):
        print("<i style='color:#888'>[Log] TXT Report saved (Mock).</i>")

# --- [2] OUTPUT REDIRECTION (Now handles HTML) ---
class Stream(QObject):
    new_text = pyqtSignal(str)

    def write(self, text):
        self.new_text.emit(str(text))

    def flush(self):
        pass

# --- [3] LOGIC CLASSES (Refined for HTML Output) ---

class Discover:
    def __init__(self, NetworkIP_CiderIPv4: str = None, NetworkIP: str = None, 
                SubnetCiderNotation: int = None, subnet_mask: str = None, 
                NetworkInterface: str = None, WaitingTimeDelay: int = 3,
                Orginal_MAC: str = None, MOCK_MAC: list = None,
                MACsite: str = None):
        
        self.Reporter = Report_Generator()
        self.NetworkIP_CiderIPv4 = NetworkIP_CiderIPv4
        self.NetworkIP = NetworkIP
        self.SubnetCiderNotation = SubnetCiderNotation
        self.subnet_mask = subnet_mask
        self.WaitingTime = WaitingTimeDelay
        self.Orginal_MAC = Orginal_MAC
        self.MOCK_MAC = MOCK_MAC
        self.NetworkInterface = NetworkInterface
        self.MACsite = MACsite or "https://macvendorlookup.com/api/v2/"
        self.private_IPv4 = None
        
        if not os.path.exists("MAC.CSV"):
            with open("MAC.CSV", "w") as f: f.write("Assignment,Organization Name\n")
            
        self.mac_vendor_data = self.read_mac_vendor_csv("MAC.CSV")
        self.network_graph = nx.Graph()
        self.DiscoveredData = []
        self.HostData = {}
    
    def read_mac_vendor_csv(self, csv_file):
        try:
            mac_vendor_data = {}
            with open(csv_file, 'r') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    if 'Assignment' in row and 'Organization Name' in row:
                        mac_prefix = row.get('Assignment')[:4].upper() 
                        vendor = row.get('Organization Name')
                        if mac_prefix and vendor:
                            mac_vendor_data[mac_prefix] = vendor
            return mac_vendor_data
        except Exception as e:
            return {}

    def get_vendor_info(self, macaddress):
        try:
            mac_prefix = macaddress[:8].replace(':', '').upper()[:4]
            vendor = self.mac_vendor_data.get(mac_prefix)
            if vendor is not None:
                return f"{vendor}"
            else:
                if self.MACsite != None:
                    try:
                        macsend = self.MACsite + macaddress
                        response = requests.get(macsend, timeout=2) 
                        if response.status_code == 200:
                            data = response.json()
                            if data:
                                return f"{data[0].get('company', 'Unknown')} (API)"
                    except:
                        pass
                return "Unknown Vendor"
        except:
            return "Error"

    def GetNetworkData(self, PrintDetails=False, save_to_file=False):
        try:
            interfaces = netifaces.interfaces()
            found = False
            for iface in interfaces:
                if iface == 'lo': continue
                addresses = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addresses:
                    ipv4_info = addresses[netifaces.AF_INET][0]
                    ip_address = ipv4_info['addr']
                    if ipaddress.IPv4Address(ip_address).is_private:
                        self.private_IPv4 = ip_address
                        self.NetworkInterface = iface
                        subnet_mask_str = ipv4_info.get('netmask', '255.255.255.0')
                        network = ipaddress.IPv4Network(f"{ip_address}/{subnet_mask_str}", strict=False)
                        self.NetworkIP_CiderIPv4 = network
                        self.NetworkIP = network.network_address
                        self.SubnetCiderNotation = network.prefixlen
                        found = True
                        
                        if PrintDetails:
                            print(f"""
                            <h3 style='color:#00AAFF; margin-bottom:5px;'>NETWORK CONFIGURATION</h3>
                            <table border='1' cellpadding='5' cellspacing='0' width='100%' style='border-color:#444;'>
                                <tr><td width='30%'><b>Interface</b></td><td>{iface}</td></tr>
                                <tr><td><b>IPv4 Address</b></td><td><span style='color:#00FF41'>{ip_address}</span></td></tr>
                                <tr><td><b>Network Range</b></td><td>{network}</td></tr>
                                <tr><td><b>Subnet Mask</b></td><td>{subnet_mask_str}</td></tr>
                            </table><br>
                            """)
                        return True
            
            if not found:
                 print("<span style='color:red'>[!] Could not detect active private interface.</span>")
            return False

        except Exception as e:
            print(f"<span style='color:red'>[!] Error getting network data: {e}</span>")
            return None

    def ARP_DiscoverHosts(self, maxHostgroup=5, verbose=False, mapping=False, save_to_file=False):
        try:
            self.GetNetworkData(PrintDetails=False)
            print(f"<span style='color:#00AAFF'><b>[>] Starting ARP Scan on {self.NetworkIP_CiderIPv4}...</b></span><br>")
            
            arp_request = scapy.ARP(pdst=str(self.NetworkIP_CiderIPv4))
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            request_broadcast = broadcast / arp_request
            answered_packets = scapy.srp(request_broadcast, timeout=2, verbose=False)[0]

            self.DiscoveredData = []
            
            # Start Table
            table_html = """
            <table border='1' cellpadding='5' cellspacing='0' width='100%' style='border-color:#333; font-size:12px;'>
            <tr style='background-color:#222; color:white;'>
                <th align='left'>IP Address</th>
                <th align='left'>MAC Address</th>
                <th align='left'>Vendor</th>
            </tr>
            """

            for sent, received in answered_packets:
                vendor = self.get_vendor_info(received.hwsrc)
                self.DiscoveredData.append({
                    "IP": received.psrc,
                    "MAC": received.hwsrc,
                    "Vendor": vendor
                })
                # Add Row
                table_html += f"""
                <tr>
                    <td><span style='color:#00FF41'><b>{received.psrc}</b></span></td>
                    <td>{received.hwsrc}</td>
                    <td>{vendor}</td>
                </tr>
                """
            
            table_html += "</table><br>"
            print(table_html)
            print(f"<b>[$] Scan Complete. Found {len(answered_packets)} active devices.</b>")

            if save_to_file:
                self.Reporter.CSV_GenerateReport(Data=self.DiscoveredData)

        except Exception as e:
            print(f"<span style='color:red'>[!] Error during ARP scan: {e}</span>")

class Analyzer:
    def __init__(self):
        self.PrivateScanner = Discover()

    def identify_devices_by_traffic(self, duration=60, verbose=False):
        print(f"<span style='color:#00AAFF'><b>[*] Profiling Traffic Patterns ({duration}s)...</b></span>")
        try:
            traffic_patterns = defaultdict(set)
            def packet_callback(packet):
                if packet.haslayer(scapy.IP):
                    src = packet[scapy.IP].src
                    dst = packet[scapy.IP].dst
                    traffic_patterns[src].add(dst)
            
            scapy.sniff(timeout=duration, prn=packet_callback, store=0)
            
            print("<h3 style='color:#00AAFF'>TRAFFIC PROFILE RESULTS</h3>")
            print("<ul>")
            for ip, destinations in traffic_patterns.items():
                count = len(destinations)
                color = "white"
                if count > 50: color = "orange" # Suspicious
                if count > 200: color = "red"   # Very Suspicious
                
                print(f"<li>Device <b>{ip}</b> connected to <span style='color:{color}'><b>{count}</b> unique destinations</span>.</li>")
            print("</ul>")
                
        except Exception as e:
            print(f"[!] Error: {e}")

    def detect_rogue_access_points(self, verbose=False):
        print("<span style='color:#00AAFF'><b>[*] Scanning for Rogue Access Points...</b></span>")
        try:
            discovered_aps = set()
            def packet_callback(packet):
                if packet.haslayer(scapy.Dot11):
                    try:
                        ssid = packet[scapy.Dot11].info.decode(errors='ignore')
                        bssid = packet[scapy.Dot11].addr2
                        if bssid and (ssid, bssid) not in discovered_aps:
                            discovered_aps.add((ssid, bssid))
                            if ssid:
                                print(f"&nbsp;&nbsp;&nbsp;[+] SSID: <b>{ssid}</b> | MAC: {bssid}")
                    except: pass

            scapy.sniff(prn=packet_callback, store=0, timeout=60)
            print("<b>[$] AP Scan Complete.</b>")
        except Exception as e:
            print(f"[!] Error: {e}")

    def detect_rogue_devices(self, known_devices_macs, verbose=False):
        print("<span style='color:#00AAFF'><b>[*] Scanning for Rogue Devices (ARP Verification)...</b></span>")
        try:
            self.PrivateScanner.ARP_DiscoverHosts(verbose=False)
            rogue_found = False
            
            print("<br><b>[Analysis Results]</b>")
            for host in self.PrivateScanner.DiscoveredData:
                if host["MAC"] not in known_devices_macs:
                    print(f"<span style='color:#FF3333'>[!!!] ROGUE DETECTED: <b>{host['IP']}</b> ({host['MAC']})</span>")
                    rogue_found = True
                elif verbose:
                    print(f"<span style='color:#00FF41'>[+] Verified: {host['IP']}</span>")
            
            if not rogue_found:
                print("<span style='color:#00FF41'><b>[$] Network is CLEAN. No unauthorized MACs found.</b></span>")
        except Exception as e:
            print(f"[!] Error: {e}")

    def query_dns(self, domain, dns_server, timeout=2):
        try:
            pkt = scapy.IP(dst=dns_server) / scapy.UDP(dport=53) / scapy.DNS(rd=1, qd=scapy.DNSQR(qname=domain))
            response = scapy.sr1(pkt, timeout=timeout, verbose=0)
            if response and response.haslayer(scapy.DNS):
                for i in range(response[scapy.DNS].ancount):
                    return response[scapy.DNS].an[i].rdata
        except:
            return None

    def detect_dns_spoofing(self, target_domains, verbose=False):
        print("<h3 style='color:#00AAFF'>DNS INTEGRITY CHECK</h3>")
        dns_servers = ["8.8.8.8", "1.1.1.1"]
        
        for domain, legit_ips in target_domains.items():
            print(f"<b>[-] Verifying: {domain}</b>")
            for server in dns_servers:
                resolved = self.query_dns(domain, server)
                if resolved:
                    if resolved not in legit_ips:
                        print(f"&nbsp;&nbsp;&nbsp;<span style='color:orange'>[?] {server} returned {resolved} (Ref IP: {legit_ips[0]})</span>")
                    else:
                        print(f"&nbsp;&nbsp;&nbsp;<span style='color:#00FF41'>[+] {server} Verified: {resolved}</span>")
                else:
                    print(f"&nbsp;&nbsp;&nbsp;<span style='color:#888'>[.] {server} No response</span>")

    def check_dns_poisoning(self, domain, known_ip):
        print(f"<b>[*] Checking Local DNS for {domain}...</b>")
        try:
            resolved_ip = socket.gethostbyname(domain)
            if resolved_ip != known_ip:
                print(f"<span style='color:red'><b>[!!!] POISONING ALERT</b></span><br>Local DNS resolves {domain} to <b>{resolved_ip}</b><br>Expected: {known_ip}")
            else:
                print(f"<span style='color:#00FF41'><b>[+] Local DNS is Correct:</b></span> {resolved_ip}")
        except Exception as e:
            print(f"[!] Resolution Failed: {e}")

    def detect_syn_flood(self, duration=60, threshold=100, verbose=False):
        print(f"<span style='color:#00AAFF'><b>[*] Monitoring for SYN Flood ({duration}s)...</b></span>")
        syn_count = 0
        def packet_callback(packet):
            nonlocal syn_count
            if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 'S':
                syn_count += 1
        scapy.sniff(timeout=duration, prn=packet_callback, store=0)
        
        if syn_count > threshold:
            print(f"<h2 style='color:red'>[!!!] ALERT: SYN FLOOD DETECTED</h2>")
            print(f"<b>Packet Count:</b> {syn_count} SYN packets / {duration}s")
        else:
            print(f"<span style='color:#00FF41'><b>[+] Traffic Normal.</b></span> SYN packets detected: {syn_count}")

    def monitor_network_for_suspicious_activity(self, duration=60, verbose=False):
        print(f"<span style='color:#00AAFF'><b>[*] Monitoring for Suspicious Flags (DF/Frag) ({duration}s)...</b></span>")
        try:
            self.PrivateScanner.GetNetworkData()
            my_ip = self.PrivateScanner.private_IPv4
            suspicious_count = defaultdict(int)

            def packet_callback(packet):
                if packet.haslayer(scapy.IP) and packet[scapy.IP].dst == my_ip:
                    # Detection Logic: Pings or packets with DF flag from unexpected sources
                    if packet[scapy.IP].flags == "DF":
                        suspicious_count[packet[scapy.IP].src] += 1

            scapy.sniff(timeout=duration, prn=packet_callback, store=0)
            
            print("<b>[$] Monitoring Complete. Results:</b>")
            found = False
            for src, count in suspicious_count.items():
                if count > 5:
                    print(f"<span style='color:orange'>[!] Suspicious Source: <b>{src}</b> ({count} events)</span>")
                    found = True
            if not found:
                print("<span style='color:#888'>No significant anomalies detected.</span>")
                
        except Exception as e:
            print(f"[!] Error: {e}")

class EngineAnalyzer(Analyzer):
    def __init__(self):
        super().__init__()

# --- [4] GUI CLASS ---

class AnalyzerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.engine = EngineAnalyzer()
        
        self.output_log = QTextEdit()
        self.output_log.setReadOnly(True)
        # Using Rich Text (HTML) capable styling
        self.output_log.setStyleSheet("""
            background-color: #0c0c0c; 
            color: #E0E0E0; 
            font-family: 'Segoe UI', Consolas, sans-serif; 
            font-size: 14px;
            border: 1px solid #333;
            padding: 15px;
        """)
        
        sys.stdout = Stream(new_text=self.on_print)
        sys.stderr = Stream(new_text=self.on_print)

        self.initUI()

    def on_print(self, text):
        # This function now intelligently handles HTML vs Plain text
        if not text.strip(): return # Skip empty newlines
        
        # Inject the HTML directly into the text box
        self.output_log.insertHtml(text)
        self.output_log.insertHtml("<br>") # Ensure newline after block
        
        # Auto scroll to bottom
        cursor = self.output_log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.output_log.setTextCursor(cursor)

    def initUI(self):
        self.setWindowTitle('Network Analyzer & Forensic Suite Pro')
        self.setGeometry(100, 100, 1000, 700)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        
        self.logo_label = QLabel("NETWORK FORENSIC ANALYZER")
        self.logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.logo_label.setStyleSheet("font-size: 20px; font-weight: bold; color: #00AAFF; margin: 10px; letter-spacing: 2px;")
        self.main_layout.addWidget(self.logo_label)

        self.main_layout.addWidget(self.output_log)

        self.btn_grid = QGridLayout()
        self.btn_grid.setSpacing(10)

        # Helper to create buttons
        def mkbtn(txt, fn):
            b = QPushButton(txt)
            b.setStyleSheet("""
                QPushButton { background-color: #222; color: white; padding: 15px; font-weight: bold; border: 1px solid #444; border-radius: 5px; }
                QPushButton:hover { background-color: #0088ff; border-color: #0088ff; }
                QPushButton:pressed { background-color: #0055aa; }
            """)
            b.clicked.connect(fn)
            return b
        
        self.btn_grid.addWidget(mkbtn("Show Network Info", self.run_net_info), 0, 0)
        self.btn_grid.addWidget(mkbtn("Run ARP Scan", self.run_arp_scan), 0, 1)
        self.btn_grid.addWidget(mkbtn("Profile Device Traffic", self.run_traffic), 0, 2)
        
        self.btn_grid.addWidget(mkbtn("Detect SYN Flood", self.run_syn), 1, 0)
        self.btn_grid.addWidget(mkbtn("Check DNS Spoofing", self.run_dns), 1, 1)
        self.btn_grid.addWidget(mkbtn("Check DNS Poisoning", self.run_poison), 1, 2)

        self.btn_grid.addWidget(mkbtn("Scan Rogue Devices", self.run_rogue_device), 2, 0)
        self.btn_grid.addWidget(mkbtn("Scan Rogue APs", self.run_rogue_ap), 2, 1)
        self.btn_grid.addWidget(mkbtn("Monitor Suspicious Activity", self.run_suspicious), 2, 2)

        self.main_layout.addLayout(self.btn_grid)
        self.create_menus()
        
        print("<i style='color:#888'>[*] System Ready. Select a tool to begin analysis.</i>")

    def create_menus(self):
        menubar = self.menuBar()
        menubar.setNativeMenuBar(False)
        file_menu = menubar.addMenu('&File')
        
        clear_act = QAction('Clear Log', self)
        clear_act.triggered.connect(self.clear_screen)
        file_menu.addAction(clear_act)
        
        exit_act = QAction('Exit', self)
        exit_act.triggered.connect(self.close)
        file_menu.addAction(exit_act)

    def clear_screen(self):
        self.output_log.clear()

    # --- ACTION HANDLERS ---

    def run_net_info(self):
        self.clear_screen()
        self.engine.PrivateScanner.GetNetworkData(PrintDetails=True)

    def run_arp_scan(self):
        self.clear_screen()
        threading.Thread(target=lambda: self.engine.PrivateScanner.ARP_DiscoverHosts(verbose=True), daemon=True).start()

    def run_traffic(self):
        d, ok = QInputDialog.getInt(self, "Traffic Profile", "Duration (seconds):", 60, 10, 600)
        if ok: 
            self.clear_screen()
            threading.Thread(target=lambda: self.engine.identify_devices_by_traffic(duration=d, verbose=True), daemon=True).start()

    def run_syn(self):
        d, ok = QInputDialog.getInt(self, "SYN Flood", "Duration (seconds):", 30, 10, 600)
        if ok: 
            self.clear_screen()
            threading.Thread(target=lambda: self.engine.detect_syn_flood(duration=d, verbose=True), daemon=True).start()

    def run_dns(self):
        self.clear_screen()
        targets = {"google.com": ["142.250.190.46"], "facebook.com": ["157.240.22.35"]}
        threading.Thread(target=lambda: self.engine.detect_dns_spoofing(targets, verbose=True), daemon=True).start()

    def run_poison(self):
        domain, ok = QInputDialog.getText(self, "DNS Poison Check", "Domain to check:", text="google.com")
        if ok:
            self.clear_screen()
            threading.Thread(target=lambda: self.engine.check_dns_poisoning(domain, "8.8.8.8"), daemon=True).start()

    def run_rogue_device(self):
        self.clear_screen()
        # Demo whitelist
        known = ["00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF"] 
        threading.Thread(target=lambda: self.engine.detect_rogue_devices(known_devices_macs=known, verbose=True), daemon=True).start()

    def run_rogue_ap(self):
        self.clear_screen()
        threading.Thread(target=lambda: self.engine.detect_rogue_access_points(verbose=True), daemon=True).start()

    def run_suspicious(self):
        d, ok = QInputDialog.getInt(self, "Suspicious Activity", "Duration (seconds):", 60, 10, 600)
        if ok: 
            self.clear_screen()
            threading.Thread(target=lambda: self.engine.monitor_network_for_suspicious_activity(duration=d, verbose=True), daemon=True).start()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AnalyzerGUI()
    window.show()
    sys.exit(app.exec())