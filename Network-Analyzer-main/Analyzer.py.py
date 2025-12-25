import sys
import threading
import socket
import csv
import os
import ipaddress
from collections import defaultdict

# Third-party Imports
import scapy.all as scapy
import requests
import networkx as nx
import netifaces

# PyQt6 Imports
from PyQt6.QtWidgets import (QApplication, QMainWindow, QTextEdit,  
                             QVBoxLayout, QWidget, QInputDialog, 
                             QPushButton, QLabel, QGridLayout)
from PyQt6.QtGui import QAction, QTextCursor
from PyQt6.QtCore import QObject, pyqtSignal, Qt

# ==========================================
# CONFIGURATION & CONSTANTS
# ==========================================
MAC_VENDOR_API = "https://macvendorlookup.com/api/v2/"
MAC_DB_FILE = "MAC.CSV"
DEFAULT_TIMEOUT = 2
DNS_SERVERS = ["8.8.8.8", "1.1.1.1"]

# ==========================================
# UTILITIES & HELPERS
# ==========================================

class ReportGenerator:
    """Handles saving data to files (Mock implementation)."""
    def save_csv(self, data):
        print("<i style='color:#888'>[Log] CSV Report saved (Mock).</i>")

class LogStream(QObject):
    """
    Redirects Python's print() statements to the PyQt GUI.
    This allows us to write HTML directly to the text box.
    """
    new_text = pyqtSignal(str)

    def write(self, text):
        self.new_text.emit(str(text))

    def flush(self):
        pass

# ==========================================
# CORE LOGIC: NETWORK SCANNER
# ==========================================

class NetworkScanner:
    """
    Handles active network scanning tasks:
    - Identifying local IP/Subnet
    - ARP Scanning
    - MAC Vendor lookup
    """
    def __init__(self):
        self.reporter = ReportGenerator()
        self.mac_db = self._load_mac_vendor_db()
        
        # Network State
        self.network_cidr = None    # e.g., IPv4Network('192.168.1.0/24')
        self.my_ip = None           # e.g., '192.168.1.15'
        self.interface = None       # e.g., 'eth0' or 'wlan0'
        self.discovered_hosts = []

    def _load_mac_vendor_db(self):
        """Loads MAC address prefixes from a local CSV file."""
        if not os.path.exists(MAC_DB_FILE):
            with open(MAC_DB_FILE, "w") as f: 
                f.write("Assignment,Organization Name\n")
            return {}

        try:
            data = {}
            with open(MAC_DB_FILE, 'r') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    if 'Assignment' in row and 'Organization Name' in row:
                        prefix = row.get('Assignment')[:4].upper()
                        data[prefix] = row.get('Organization Name')
            return data
        except Exception:
            return {}

    def get_vendor(self, mac_address):
        """Resolves MAC address to Manufacturer via Local DB or API."""
        try:
            # Check Local DB first
            clean_mac = mac_address[:8].replace(':', '').upper()[:4]
            if clean_mac in self.mac_db:
                return self.mac_db[clean_mac]
            
            # Fallback to API
            try:
                response = requests.get(f"{MAC_VENDOR_API}{mac_address}", timeout=DEFAULT_TIMEOUT)
                if response.status_code == 200:
                    data = response.json()
                    if data:
                        return f"{data[0].get('company', 'Unknown')} (API)"
            except:
                pass
            return "Unknown Vendor"
        except:
            return "Error"

    def get_network_details(self, print_output=False):
        """Detects the active private network interface and IP configuration."""
        try:
            for iface in netifaces.interfaces():
                if iface == 'lo': continue # Skip localhost
                
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ipv4_data = addrs[netifaces.AF_INET][0]
                    ip = ipv4_data['addr']
                    
                    # We only care about Private IPs (LANs)
                    if ipaddress.IPv4Address(ip).is_private:
                        self.my_ip = ip
                        self.interface = iface
                        netmask = ipv4_data.get('netmask', '255.255.255.0')
                        
                        # Calculate CIDR
                        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        self.network_cidr = network
                        
                        if print_output:
                            self._print_network_html(iface, ip, str(network), netmask)
                        return True
            
            print("<span style='color:red'>[!] Could not detect active private interface.</span>")
            return False
        except Exception as e:
            print(f"<span style='color:red'>[!] Error getting network data: {e}</span>")
            return None

    def _print_network_html(self, iface, ip, cidr, mask):
        print(f"""
        <h3 style='color:#00AAFF; margin-bottom:5px;'>NETWORK CONFIGURATION</h3>
        <table border='1' cellpadding='5' cellspacing='0' width='100%' style='border-color:#444;'>
            <tr><td width='30%'><b>Interface</b></td><td>{iface}</td></tr>
            <tr><td><b>IPv4 Address</b></td><td><span style='color:#00FF41'>{ip}</span></td></tr>
            <tr><td><b>Network Range</b></td><td>{cidr}</td></tr>
            <tr><td><b>Subnet Mask</b></td><td>{mask}</td></tr>
        </table><br>
        """)

    def scan_arp(self, verbose=False, save=False):
        """Performs an ARP scan to discover devices on the LAN."""
        try:
            self.get_network_details(print_output=False)
            print(f"<span style='color:#00AAFF'><b>[>] Starting ARP Scan on {self.network_cidr}...</b></span><br>")
            
            # Scapy ARP Broadcast
            arp_req = scapy.ARP(pdst=str(self.network_cidr))
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_req
            answered = scapy.srp(packet, timeout=2, verbose=False)[0]

            self.discovered_hosts = []
            
            # Build HTML Table Header
            html = """
            <table border='1' cellpadding='5' cellspacing='0' width='100%' style='border-color:#333; font-size:12px;'>
            <tr style='background-color:#222; color:white;'>
                <th align='left'>IP Address</th>
                <th align='left'>MAC Address</th>
                <th align='left'>Vendor</th>
            </tr>
            """

            for sent, received in answered:
                vendor = self.get_vendor(received.hwsrc)
                self.discovered_hosts.append({
                    "IP": received.psrc,
                    "MAC": received.hwsrc,
                    "Vendor": vendor
                })
                html += f"""
                <tr>
                    <td><span style='color:#00FF41'><b>{received.psrc}</b></span></td>
                    <td>{received.hwsrc}</td>
                    <td>{vendor}</td>
                </tr>
                """
            
            html += "</table><br>"
            print(html)
            print(f"<b>[$] Scan Complete. Found {len(answered)} active devices.</b>")

            if save: self.reporter.save_csv(self.discovered_hosts)

        except Exception as e:
            print(f"<span style='color:red'>[!] Error during ARP scan: {e}</span>")

# ==========================================
# CORE LOGIC: THREAT DETECTOR
# ==========================================

class ThreatDetector:
    """
    Handles passive monitoring and anomaly detection:
    - Traffic Profiling
    - Rogue AP/Device Detection
    - DNS Integrity
    - SYN Flood Detection
    """
    def __init__(self):
        self.scanner = NetworkScanner()

    def profile_traffic(self, duration=60):
        print(f"<span style='color:#00AAFF'><b>[*] Profiling Traffic Patterns ({duration}s)...</b></span>")
        try:
            traffic_map = defaultdict(set)
            
            def process_packet(packet):
                if packet.haslayer(scapy.IP):
                    src = packet[scapy.IP].src
                    dst = packet[scapy.IP].dst
                    traffic_map[src].add(dst)
            
            scapy.sniff(timeout=duration, prn=process_packet, store=0)
            
            print("<h3 style='color:#00AAFF'>TRAFFIC PROFILE RESULTS</h3><ul>")
            for ip, destinations in traffic_map.items():
                count = len(destinations)
                # Heuristic: High connection count might indicate scanning or P2P
                color = "white"
                if count > 50: color = "orange" 
                if count > 200: color = "red"   
                
                print(f"<li>Device <b>{ip}</b> connected to <span style='color:{color}'><b>{count}</b> unique destinations</span>.</li>")
            print("</ul>")
                
        except Exception as e:
            print(f"[!] Error: {e}")

    def detect_rogue_aps(self):
        print("<span style='color:#00AAFF'><b>[*] Scanning for Rogue Access Points...</b></span>")
        try:
            discovered = set()
            def process_packet(packet):
                if packet.haslayer(scapy.Dot11): # WiFi Layer
                    try:
                        ssid = packet[scapy.Dot11].info.decode(errors='ignore')
                        bssid = packet[scapy.Dot11].addr2
                        if bssid and (ssid, bssid) not in discovered:
                            discovered.add((ssid, bssid))
                            if ssid:
                                print(f"&nbsp;&nbsp;&nbsp;[+] SSID: <b>{ssid}</b> | MAC: {bssid}")
                    except: pass

            scapy.sniff(prn=process_packet, store=0, timeout=60)
            print("<b>[$] AP Scan Complete.</b>")
        except Exception as e:
            print(f"[!] Error: {e}")

    def detect_rogue_devices(self, whitelist_macs):
        print("<span style='color:#00AAFF'><b>[*] Scanning for Rogue Devices (ARP Verification)...</b></span>")
        try:
            # Refresh the ARP table first
            self.scanner.scan_arp(verbose=False)
            rogue_found = False
            
            print("<br><b>[Analysis Results]</b>")
            for host in self.scanner.discovered_hosts:
                if host["MAC"] not in whitelist_macs:
                    print(f"<span style='color:#FF3333'>[!!!] ROGUE DETECTED: <b>{host['IP']}</b> ({host['MAC']})</span>")
                    rogue_found = True
                else:
                    print(f"<span style='color:#00FF41'>[+] Verified: {host['IP']}</span>")
            
            if not rogue_found:
                print("<span style='color:#00FF41'><b>[$] Network is CLEAN. No unauthorized MACs found.</b></span>")
        except Exception as e:
            print(f"[!] Error: {e}")

    def check_dns_spoofing(self, targets):
        """Queries multiple public DNS servers to check if a domain resolves consistently."""
        print("<h3 style='color:#00AAFF'>DNS INTEGRITY CHECK</h3>")
        
        for domain, legit_ips in targets.items():
            print(f"<b>[-] Verifying: {domain}</b>")
            for server in DNS_SERVERS:
                try:
                    # Construct DNS Query
                    pkt = scapy.IP(dst=server) / scapy.UDP(dport=53) / scapy.DNS(rd=1, qd=scapy.DNSQR(qname=domain))
                    resp = scapy.sr1(pkt, timeout=DEFAULT_TIMEOUT, verbose=0)
                    
                    if resp and resp.haslayer(scapy.DNS):
                        # Extract the IP from the answer
                        resolved_ip = resp[scapy.DNS].an.rdata if resp[scapy.DNS].ancount > 0 else "No Record"
                        
                        if resolved_ip not in legit_ips:
                            print(f"&nbsp;&nbsp;&nbsp;<span style='color:orange'>[?] {server} returned {resolved_ip} (Ref IP: {legit_ips[0]})</span>")
                        else:
                            print(f"&nbsp;&nbsp;&nbsp;<span style='color:#00FF41'>[+] {server} Verified: {resolved_ip}</span>")
                except Exception:
                    print(f"&nbsp;&nbsp;&nbsp;<span style='color:#888'>[.] {server} No response</span>")

    def check_local_poisoning(self, domain, expected_ip):
        """Checks if the system's local DNS resolver (hosts file/cache) is poisoned."""
        print(f"<b>[*] Checking Local DNS for {domain}...</b>")
        try:
            resolved_ip = socket.gethostbyname(domain)
            if resolved_ip != expected_ip:
                print(f"<span style='color:red'><b>[!!!] POISONING ALERT</b></span><br>Local DNS resolves {domain} to <b>{resolved_ip}</b><br>Expected: {expected_ip}")
            else:
                print(f"<span style='color:#00FF41'><b>[+] Local DNS is Correct:</b></span> {resolved_ip}")
        except Exception as e:
            print(f"[!] Resolution Failed: {e}")

    def detect_syn_flood(self, duration=60, threshold=100):
        """Counts TCP SYN packets to detect DoS attempts."""
        print(f"<span style='color:#00AAFF'><b>[*] Monitoring for SYN Flood ({duration}s)...</b></span>")
        syn_count = 0
        
        def count_syn(packet):
            nonlocal syn_count
            # check for TCP layer and if the Flag is 'S' (SYN)
            if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 'S':
                syn_count += 1
                
        scapy.sniff(timeout=duration, prn=count_syn, store=0)
        
        if syn_count > threshold:
            print(f"<h2 style='color:red'>[!!!] ALERT: SYN FLOOD DETECTED</h2>")
            print(f"<b>Packet Count:</b> {syn_count} SYN packets / {duration}s")
        else:
            print(f"<span style='color:#00FF41'><b>[+] Traffic Normal.</b></span> SYN packets detected: {syn_count}")

# ==========================================
# GRAPHICAL USER INTERFACE (GUI)
# ==========================================

class AppWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.logic_engine = ThreatDetector()
        
        # UI Components
        self.output_log = QTextEdit()
        self.output_log.setReadOnly(True)
        self.output_log.setStyleSheet("""
            background-color: #0c0c0c; 
            color: #E0E0E0; 
            font-family: 'Segoe UI', Consolas, sans-serif; 
            font-size: 14px;
            border: 1px solid #333;
            padding: 15px;
        """)
        
        # Redirect stdout/stderr to GUI
        sys.stdout = LogStream(new_text=self.update_log)
        sys.stderr = LogStream(new_text=self.update_log)

        self.init_ui()

    def update_log(self, text):
        """Appends text (HTML allowed) to the main log window."""
        if not text.strip(): return 
        self.output_log.insertHtml(text)
        self.output_log.insertHtml("<br>") 
        
        # Auto-scroll
        cursor = self.output_log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.output_log.setTextCursor(cursor)

    def init_ui(self):
        self.setWindowTitle('Blue Team Network Analyzer')
        self.setGeometry(100, 100, 1000, 700)

        # Layouts
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Header
        header = QLabel("NETWORK FORENSIC ANALYZER")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("font-size: 20px; font-weight: bold; color: #00AAFF; margin: 10px; letter-spacing: 2px;")
        main_layout.addWidget(header)

        # Log Window
        main_layout.addWidget(self.output_log)

        # Button Grid
        btn_grid = QGridLayout()
        btn_grid.setSpacing(10)

        # Add buttons
        self.add_btn(btn_grid, "Show Network Info", self.action_net_info, 0, 0)
        self.add_btn(btn_grid, "Run ARP Scan", self.action_arp_scan, 0, 1)
        self.add_btn(btn_grid, "Profile Traffic", self.action_traffic, 0, 2)
        
        self.add_btn(btn_grid, "Detect SYN Flood", self.action_syn_flood, 1, 0)
        self.add_btn(btn_grid, "Check DNS Spoofing", self.action_dns_spoof, 1, 1)
        self.add_btn(btn_grid, "Check Local Poisoning", self.action_local_poison, 1, 2)

        self.add_btn(btn_grid, "Scan Rogue Devices", self.action_rogue_dev, 2, 0)
        self.add_btn(btn_grid, "Scan Rogue APs", self.action_rogue_ap, 2, 1)
        
        main_layout.addLayout(btn_grid)
        self.create_menu()
        
        print("<i style='color:#888'>[*] System Ready. Select a tool to begin analysis.</i>")

    def add_btn(self, layout, text, func, row, col):
        btn = QPushButton(text)
        btn.setStyleSheet("""
            QPushButton { background-color: #222; color: white; padding: 15px; font-weight: bold; border: 1px solid #444; border-radius: 5px; }
            QPushButton:hover { background-color: #0088ff; border-color: #0088ff; }
            QPushButton:pressed { background-color: #0055aa; }
        """)
        btn.clicked.connect(func)
        layout.addWidget(btn, row, col)

    def create_menu(self):
        menubar = self.menuBar()
        menubar.setNativeMenuBar(False)
        file_menu = menubar.addMenu('&File')
        
        clear = QAction('Clear Log', self)
        clear.triggered.connect(self.output_log.clear)
        file_menu.addAction(clear)
        
        exit_act = QAction('Exit', self)
        exit_act.triggered.connect(self.close)
        file_menu.addAction(exit_act)

    # --- ACTIONS (Threading Wrappers) ---
    # We use threads to prevent the GUI from freezing during scans

    def action_net_info(self):
        self.output_log.clear()
        self.logic_engine.scanner.get_network_details(print_output=True)

    def action_arp_scan(self):
        self.output_log.clear()
        threading.Thread(target=lambda: self.logic_engine.scanner.scan_arp(verbose=True), daemon=True).start()

    def action_traffic(self):
        d, ok = QInputDialog.getInt(self, "Traffic Profile", "Duration (seconds):", 60, 10, 600)
        if ok: 
            self.output_log.clear()
            threading.Thread(target=lambda: self.logic_engine.profile_traffic(duration=d), daemon=True).start()

    def action_syn_flood(self):
        d, ok = QInputDialog.getInt(self, "SYN Flood", "Duration (seconds):", 30, 10, 600)
        if ok: 
            self.output_log.clear()
            threading.Thread(target=lambda: self.logic_engine.detect_syn_flood(duration=d), daemon=True).start()

    def action_dns_spoof(self):
        self.output_log.clear()
        # In a real app, these would be user-configurable or loaded from a file
        targets = {"google.com": ["142.250.190.46"], "facebook.com": ["157.240.22.35"]}
        threading.Thread(target=lambda: self.logic_engine.check_dns_spoofing(targets), daemon=True).start()

    def action_local_poison(self):
        domain, ok = QInputDialog.getText(self, "DNS Poison Check", "Domain to check:", text="google.com")
        if ok:
            self.output_log.clear()
            threading.Thread(target=lambda: self.logic_engine.check_local_poisoning(domain, "8.8.8.8"), daemon=True).start()

    def action_rogue_dev(self):
        self.output_log.clear()
        # Mock whitelist
        known_macs = ["00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF"] 
        threading.Thread(target=lambda: self.logic_engine.detect_rogue_devices(whitelist_macs=known_macs), daemon=True).start()

    def action_rogue_ap(self):
        self.output_log.clear()
        threading.Thread(target=lambda: self.logic_engine.detect_rogue_aps(), daemon=True).start()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AppWindow()
    window.show()
    sys.exit(app.exec())