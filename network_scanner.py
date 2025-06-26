#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: Your Name
# Description: A simple network scanner for ethical hacking projects.

import scapy.all as scapy
import socket
from ipaddress import IPv4Network
from concurrent.futures import ThreadPoolExecutor

def scan_host(ip):
    """Check if a host is alive using ICMP ping."""
    try:
        scapy.sr1(scapy.IP(dst=ip)/scapy.ICMP(), timeout=1, verbose=False)
        return ip
    except:
        return None

def scan_port(ip, port):
    """Check if a port is open on a host."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect((ip, port))
            return port
    except:
        return None

def network_scanner(network_cidr, ports=[21, 22, 80, 443, 3389]):
    """Scan a network for live hosts and open ports."""
    live_hosts = []
    open_ports = {}

    # Scan for live hosts
    print(f"[*] Scanning for live hosts in {network_cidr}...")
    network = IPv4Network(network_cidr)
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(scan_host, [str(host) for host in network.hosts()])
    
    live_hosts = [ip for ip in results if ip is not None]
    print(f"[+] Found {len(live_hosts)} live hosts: {', '.join(live_hosts)}")

    # Scan for open ports on live hosts
    print("\n[*] Scanning for open ports...")
    for host in live_hosts:
        with ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(lambda port: scan_port(host, port), ports)
        
        open_ports[host] = [port for port in results if port is not None]
        if open_ports[host]:
            print(f"[+] {host}: Open ports -> {', '.join(map(str, open_ports[host]))}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Basic Network Scanner")
    parser.add_argument("network", help="Network CIDR (e.g., 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", nargs="+", type=int, default=[21, 22, 80, 443, 3389],
                        help="Ports to scan (default: 21,22,80,443,3389)")
    args = parser.parse_args()

    network_scanner(args.network, args.ports)
