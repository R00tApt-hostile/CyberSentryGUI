import tkinter as tk
from tkinter import messagebox, filedialog
import subprocess
import scapy.all as scapy
import nmap
import requests
import whois
import socket
import speedtest
from bs4 import BeautifulSoup

# Function for Port Scanner
def port_scanner():
    target = port_entry.get()
    if not target:
        messagebox.showerror("Error", "Please enter a target IP.")
        return
    try:
        result = f"Scanning ports on {target}...\n"
        for port in range(1, 1025):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result_code = sock.connect_ex((target, port))
            if result_code == 0:
                result += f"Port {port} is open\n"
            sock.close()
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to scan ports: {e}")

# Function for Ping Sweep
def ping_sweep():
    network = ping_entry.get()
    if not network:
        messagebox.showerror("Error", "Please enter a network range.")
        return
    try:
        result = f"Pinging {network}...\n"
        for ip in range(1, 255):
            ip_address = f"{network}.{ip}"
            response = subprocess.call(["ping", "-c", "1", "-W", "1", ip_address], stdout=subprocess.DEVNULL)
            if response == 0:
                result += f"{ip_address} is up\n"
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to perform ping sweep: {e}")

# Function for Packet Sniffer
def packet_sniffer():
    try:
        packets = scapy.sniff(count=10, timeout=5)
        result = "Captured packets:\n"
        for packet in packets:
            result += f"{packet.summary()}\n"
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to capture packets: {e}")

# Function for ARP Spoofing Detector
def arp_spoof_detector():
    try:
        arp_table = scapy.arping("192.168.1.0/24", timeout=2)
        result = "ARP Table:\n"
        for sent, received in arp_table:
            result += f"IP: {received.psrc} - MAC: {received.hwsrc}\n"
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to detect ARP spoofing: {e}")

# Function for DNS Spoofing Detector
def dns_spoof_detector():
    try:
        dns_packets = scapy.sniff(filter="udp and port 53", count=5)
        result = "DNS packets:\n"
        for packet in dns_packets:
            result += f"{packet.summary()}\n"
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to detect DNS spoofing: {e}")

# Function for Nmap Integration
def nmap_scan():
    target = nmap_entry.get()
    if not target:
        messagebox.showerror("Error", "Please enter a target.")
        return
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments="-sV")
        result = f"Nmap scan results for {target}:\n"
        for host in nm.all_hosts():
            result += f"Host: {host}\n"
            for proto in nm[host].all_protocols():
                result += f"Protocol: {proto}\n"
                ports = nm[host][proto].keys()
                for port in ports:
                    result += f"Port: {port} - State: {nm[host][proto][port]['state']}\n"
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to perform Nmap scan: {e}")

# Function for MAC Address Changer
def mac_changer():
    interface = mac_entry.get()
    new_mac = mac_new_entry.get()
    if not interface or not new_mac:
        messagebox.showerror("Error", "Please enter interface and new MAC.")
        return
    try:
        subprocess.call(["sudo", "ifconfig", interface, "down"])
        subprocess.call(["sudo", "ifconfig", interface, "hw", "ether", new_mac])
        subprocess.call(["sudo", "ifconfig", interface, "up"])
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"MAC address changed to {new_mac} on {interface}.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to change MAC address: {e}")

# Function for IP Geolocation
def ip_geolocation():
    ip = ip_geo_entry.get()
    if not ip:
        messagebox.showerror("Error", "Please enter an IP address.")
        return
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        result = f"IP: {data['query']}\nCountry: {data['country']}\nISP: {data['isp']}\nCity: {data['city']}"
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to fetch geolocation: {e}")

# Function for Whois Lookup
def whois_lookup():
    domain = whois_entry.get()
    if not domain:
        messagebox.showerror("Error", "Please enter a domain.")
        return
    try:
        domain_info = whois.whois(domain)
        result = f"Domain: {domain_info.domain_name}\nRegistrar: {domain_info.registrar}\nCreation Date: {domain_info.creation_date}"
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to fetch Whois details: {e}")

# Function for Subdomain Finder
def subdomain_finder():
    domain = subdomain_entry.get()
    if not domain:
        messagebox.showerror("Error", "Please enter a domain.")
        return
    try:
        with open("subdomains.txt", "r") as file:
            subdomains = file.read().splitlines()
        result = f"Subdomains for {domain}:\n"
        for subdomain in subdomains:
            url = f"http://{subdomain}.{domain}"
            try:
                requests.get(url)
                result += f"{url} is live\n"
            except:
                pass
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to find subdomains: {e}")

# Function for SSL/TLS Checker
def ssl_checker():
    domain = ssl_entry.get()
    if not domain:
        messagebox.showerror("Error", "Please enter a domain.")
        return
    try:
        import ssl
        cert = ssl.get_server_certificate((domain, 443))
        result = f"SSL/TLS Certificate for {domain}:\n{cert}"
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to check SSL/TLS: {e}")

# Function for HTTP Header Analyzer
def http_header_analyzer():
    url = http_entry.get()
    if not url:
        messagebox.showerror("Error", "Please enter a URL.")
        return
    try:
        response = requests.get(url)
        result = f"HTTP Headers for {url}:\n"
        for key, value in response.headers.items():
            result += f"{key}: {value}\n"
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to analyze HTTP headers: {e}")

# Function for Network Traffic Monitor
def network_traffic_monitor():
    try:
        packets = scapy.sniff(count=10, timeout=5)
        result = "Network traffic:\n"
        for packet in packets:
            result += f"{packet.summary()}\n"
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to monitor network traffic: {e}")

# Function for Firewall Rule Checker
def firewall_checker():
    port = firewall_entry.get()
    if not port:
        messagebox.showerror("Error", "Please enter a port.")
        return
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result_code = sock.connect_ex(("127.0.0.1", int(port)))
        if result_code == 0:
            result = f"Port {port} is open (firewall rule may be allowing it)."
        else:
            result = f"Port {port} is closed or blocked."
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to check firewall rules: {e}")

# Function for Vulnerability Scanner
def vulnerability_scanner():
    target = vuln_entry.get()
    if not target:
        messagebox.showerror("Error", "Please enter a target.")
        return
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments="-sV --script vuln")
        result = f"Vulnerability scan results for {target}:\n"
        for host in nm.all_hosts():
            result += f"Host: {host}\n"
            for proto in nm[host].all_protocols():
                result += f"Protocol: {proto}\n"
                ports = nm[host][proto].keys()
                for port in ports:
                    result += f"Port: {port} - State: {nm[host][proto][port]['state']}\n"
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to perform vulnerability scan: {e}")

# Function for Password Strength Tester
def password_strength_tester():
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password.")
        return
    try:
        strength = 0
        if len(password) >= 8:
            strength += 1
        if any(char.isdigit() for char in password):
            strength += 1
        if any(char.isupper() for char in password):
            strength += 1
        if any(char.islower() for char in password):
            strength += 1
        if any(char in "!@#$%^&*()" for char in password):
            strength += 1
        result = f"Password strength: {strength}/5"
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to test password strength: {e}")

# Function for Wi-Fi Scanner
def wifi_scanner():
    try:
        result = subprocess.check_output(["nmcli", "dev", "wifi"])
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result.decode())
    except Exception as e:
        messagebox.showerror("Error", f"Failed to scan Wi-Fi networks: {e}")

# Function for Packet Crafting
def packet_crafting():
    try:
        packet = scapy.IP(dst="8.8.8.8") / scapy.ICMP()
        result = f"Crafted packet:\n{packet.summary()}"
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to craft packet: {e}")

# Function for Log Analyzer
def log_analyzer():
    try:
        file_path = filedialog.askopenfilename()
        with open(file_path, "r") as file:
            logs = file.read()
        result = f"Logs from {file_path}:\n{logs}"
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to analyze logs: {e}")

# Function for Network Speed Tester
def network_speed_tester():
    try:
        st = speedtest.Speedtest()
        download_speed = st.download() / 1_000_000
        upload_speed = st.upload() / 1_000_000
        result = f"Download Speed: {download_speed:.2f} Mbps\nUpload Speed: {upload_speed:.2f} Mbps"
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to test network speed: {e}")

# GUI Setup
root = tk.Tk()
root.title("Network Security Toolkit - ROOtApt-hostile")
root.geometry("800x600")

# Create Tabs for Different Tools
tab_control = tk.ttk.Notebook(root)

# Port Scanner Tab
port_tab = tk.Frame(tab_control)
tk.Label(port_tab, text="Port Scanner").pack()
port_entry = tk.Entry(port_tab, width=50)
port_entry.pack()
tk.Button(port_tab, text="Scan Ports", command=port_scanner).pack()
tab_control.add(port_tab, text="Port Scanner")

# Ping Sweep Tab
ping_tab = tk.Frame(tab_control)
tk.Label(ping_tab, text="Ping Sweep").pack()
ping_entry = tk.Entry(ping_tab, width=50)
ping_entry.pack()
tk.Button(ping_tab, text="Ping Sweep", command=ping_sweep).pack()
tab_control.add(ping_tab, text="Ping Sweep")

# Packet Sniffer Tab
sniffer_tab = tk.Frame(tab_control)
tk.Label(sniffer_tab, text="Packet Sniffer").pack()
tk.Button(sniffer_tab, text="Start Sniffing", command=packet_sniffer).pack()
tab_control.add(sniffer_tab, text="Packet Sniffer")

# ARP Spoofing Detector Tab
arp_tab = tk.Frame(tab_control)
tk.Label(arp_tab, text="ARP Spoofing Detector").pack()
tk.Button(arp_tab, text="Detect ARP Spoofing", command=arp_spoof_detector).pack()
tab_control.add(arp_tab, text="ARP Spoofing Detector")

# DNS Spoofing Detector Tab
dns_tab = tk.Frame(tab_control)
tk.Label(dns_tab, text="DNS Spoofing Detector").pack()
tk.Button(dns_tab, text="Detect DNS Spoofing", command=dns_spoof_detector).pack()
tab_control.add(dns_tab, text="DNS Spoofing Detector")

# Nmap Integration Tab
nmap_tab = tk.Frame(tab_control)
tk.Label(nmap_tab, text="Nmap Integration").pack()
nmap_entry = tk.Entry(nmap_tab, width=50)
nmap_entry.pack()
tk.Button(nmap_tab, text="Scan with Nmap", command=nmap_scan).pack()
tab_control.add(nmap_tab, text="Nmap Integration")

# MAC Address Changer Tab
mac_tab = tk.Frame(tab_control)
tk.Label(mac_tab, text="MAC Address Changer").pack()
mac_entry = tk.Entry(mac_tab, width=50)
mac_entry.pack()
tk.Label(mac_tab, text="New MAC Address").pack()
mac_new_entry = tk.Entry(mac_tab, width=50)
mac_new_entry.pack()
tk.Button(mac_tab, text="Change MAC", command=mac_changer).pack()
tab_control.add(mac_tab, text="MAC Address Changer")

# IP Geolocation Tab
ip_geo_tab = tk.Frame(tab_control)
tk.Label(ip_geo_tab, text="IP Geolocation").pack()
ip_geo_entry = tk.Entry(ip_geo_tab, width=50)
ip_geo_entry.pack()
tk.Button(ip_geo_tab, text="Get Geolocation", command=ip_geolocation).pack()
tab_control.add(ip_geo_tab, text="IP Geolocation")

# Whois Lookup Tab
whois_tab = tk.Frame(tab_control)
tk.Label(whois_tab, text="Whois Lookup").pack()
whois_entry = tk.Entry(whois_tab, width=50)
whois_entry.pack()
tk.Button(whois_tab, text="Lookup Whois", command=whois_lookup).pack()
tab_control.add(whois_tab, text="Whois Lookup")

# Subdomain Finder Tab
subdomain_tab = tk.Frame(tab_control)
tk.Label(subdomain_tab, text="Subdomain Finder").pack()
subdomain_entry = tk.Entry(subdomain_tab, width=50)
subdomain_entry.pack()
tk.Button(subdomain_tab, text="Find Subdomains", command=subdomain_finder).pack()
tab_control.add(subdomain_tab, text="Subdomain Finder")

# SSL/TLS Checker Tab
ssl_tab = tk.Frame(tab_control)
tk.Label(ssl_tab, text="SSL/TLS Checker").pack()
ssl_entry = tk.Entry(ssl_tab, width=50)
ssl_entry.pack()
tk.Button(ssl_tab, text="Check SSL/TLS", command=ssl_checker).pack()
tab_control.add(ssl_tab, text="SSL/TLS Checker")

# HTTP Header Analyzer Tab
http_tab = tk.Frame(tab_control)
tk.Label(http_tab, text="HTTP Header Analyzer").pack()
http_entry = tk.Entry(http_tab, width=50)
http_entry.pack()
tk.Button(http_tab, text="Analyze Headers", command=http_header_analyzer).pack()
tab_control.add(http_tab, text="HTTP Header Analyzer")

# Network Traffic Monitor Tab
traffic_tab = tk.Frame(tab_control)
tk.Label(traffic_tab, text="Network Traffic Monitor").pack()
tk.Button(traffic_tab, text="Monitor Traffic", command=network_traffic_monitor).pack()
tab_control.add(traffic_tab, text="Network Traffic Monitor")

# Firewall Rule Checker Tab
firewall_tab = tk.Frame(tab_control)
tk.Label(firewall_tab, text="Firewall Rule Checker").pack()
firewall_entry = tk.Entry(firewall_tab, width=50)
firewall_entry.pack()
tk.Button(firewall_tab, text="Check Firewall", command=firewall_checker).pack()
tab_control.add(firewall_tab, text="Firewall Rule Checker")

# Vulnerability Scanner Tab
vuln_tab = tk.Frame(tab_control)
tk.Label(vuln_tab, text="Vulnerability Scanner").pack()
vuln_entry = tk.Entry(vuln_tab, width=50)
vuln_entry.pack()
tk.Button(vuln_tab, text="Scan Vulnerabilities", command=vulnerability_scanner).pack()
tab_control.add(vuln_tab, text="Vulnerability Scanner")

# Password Strength Tester Tab
password_tab = tk.Frame(tab_control)
tk.Label(password_tab, text="Password Strength Tester").pack()
password_entry = tk.Entry(password_tab, width=50)
password_entry.pack()
tk.Button(password_tab, text="Test Password", command=password_strength_tester).pack()
tab_control.add(password_tab, text="Password Strength Tester")

# Wi-Fi Scanner Tab
wifi_tab = tk.Frame(tab_control)
tk.Label(wifi_tab, text="Wi-Fi Scanner").pack()
tk.Button(wifi_tab, text="Scan Wi-Fi", command=wifi_scanner).pack()
tab_control.add(wifi_tab, text="Wi-Fi Scanner")

# Packet Crafting Tab
craft_tab = tk.Frame(tab_control)
tk.Label(craft_tab, text="Packet Crafting").pack()
tk.Button(craft_tab, text="Craft Packet", command=packet_crafting).pack()
tab_control.add(craft_tab, text="Packet Crafting")

# Log Analyzer Tab
log_tab = tk.Frame(tab_control)
tk.Label(log_tab, text="Log Analyzer").pack()
tk.Button(log_tab, text="Analyze Logs", command=log_analyzer).pack()
tab_control.add(log_tab, text="Log Analyzer")

# Network Speed Tester Tab
speed_tab = tk.Frame(tab_control)
tk.Label(speed_tab, text="Network Speed Tester").pack()
tk.Button(speed_tab, text="Test Speed", command=network_speed_tester).pack()
tab_control.add(speed_tab, text="Network Speed Tester")

# Result Display
result_text = tk.Text(root, height=10, width=80)
result_text.pack()

# Add Tabs to GUI
tab_control.pack(expand=1, fill="both")

# Run the GUI
root.mainloop()
