#!/usr/bin/env python3
"""
SafeOps Firewall Network Simulation Tool
=========================================
Tests all firewall detection capabilities by simulating real network attacks.

Requirements:
    pip install scapy colorama

Run with Administrator privileges:
    python network_simulator.py --all

Based on detection.toml thresholds:
- SYN Flood: 1000 SYN/sec
- UDP Flood: 5000 UDP/sec
- ICMP Flood: 100 ICMP/sec
- Port Scan: 100 ports in 10s
- Brute Force: 5 SSH failures in 120s
"""

import argparse
import random
import socket
import sys
import time
from datetime import datetime
from typing import Optional

try:
    from scapy.all import (  # type: ignore
        IP, TCP, UDP, ICMP,
        send, RandShort, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    from colorama import init, Fore, Style  # type: ignore
    init()
except ImportError:
    class Fore:  # type: ignore
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = RESET = ""
    class Style:  # type: ignore
        BRIGHT = RESET_ALL = ""

# ============================================================================
# CONFIGURATION (from detection.toml) - Extracted as typed constants
# ============================================================================
TARGET_IP = "127.0.0.1"
ATTACKER_IP = "203.0.113.50"  # TEST-NET-3

# DDoS Thresholds (we exceed these to trigger alerts)
SYN_RATE = 1100        # > 1000/sec threshold
UDP_RATE = 5500        # > 5000/sec threshold  
ICMP_RATE = 120        # > 100/sec threshold

# Port Scan
SCAN_PORTS = 150       # > 100 ports threshold
SCAN_SEQUENTIAL = 25   # > 20 sequential ports

# Brute Force
SSH_ATTEMPTS = 7       # > 5 failures threshold
RDP_ATTEMPTS = 5       # > 3 failures threshold
MYSQL_ATTEMPTS = 5     # > 3 failures threshold

# Blocked Ports (from blocked_ports.txt)
VPN_PORTS = [
    1194,   # OpenVPN
    51820,  # WireGuard
    500,    # IKE
    4500,   # NAT-T
    1723,   # PPTP
    9050,   # Tor SOCKS
    9001,   # Tor OR
]

# DoH Servers (from doh_servers.txt)
DOH_SERVERS = [
    "8.8.8.8",
    "8.8.4.4", 
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
]

# Blocked Domains (from domains.txt)
BLOCKED_DOMAINS = [
    "facebook.com",
    "twitter.com",
    "instagram.com",
    "x.com",
]

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================
def log(level: str, msg: str) -> None:
    """Colored logging output"""
    colors = {
        "INFO": Fore.CYAN,
        "ATTACK": Fore.RED,
        "SUCCESS": Fore.GREEN,
        "WARN": Fore.YELLOW,
    }
    color = colors.get(level, Fore.WHITE)
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"{Style.BRIGHT}[{timestamp}] {color}[{level}]{Style.RESET_ALL} {msg}")

def check_admin() -> bool:
    """Check if running with admin privileges"""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore
    except Exception:
        return False

def banner() -> None:
    """Print banner"""
    print(f"""
{Fore.RED}{Style.BRIGHT}
+===============================================================+
|     SafeOps Firewall - Network Attack Simulator v1.0          |
|     [!] FOR TESTING PURPOSES ONLY - USE RESPONSIBLY [!]       |
+===============================================================+
{Style.RESET_ALL}""")

# ============================================================================
# ATTACK SIMULATIONS (Using Scapy)
# ============================================================================

def simulate_syn_flood(target: str, duration: int = 5) -> int:
    """
    SYN Flood Attack Simulation
    Threshold: 1000 SYN packets/sec per IP
    """
    if not SCAPY_AVAILABLE:
        log("WARN", "Scapy not available, using socket simulation")
        return simulate_syn_flood_socket(target, duration)
    
    log("ATTACK", f"[SYN FLOOD] Starting SYN flood to {target} for {duration}s")
    log("INFO", f"Rate: {SYN_RATE} SYN/sec (threshold: 1000)")
    
    conf.verb = 0
    packets_sent = 0
    start = time.time()
    
    while time.time() - start < duration:
        for _ in range(SYN_RATE // 10):  # Batch sending
            pkt = IP(src=ATTACKER_IP, dst=target) / \
                  TCP(sport=RandShort(), dport=random.randint(1, 65535), flags="S")
            try:
                send(pkt, verbose=False)
                packets_sent += 1
            except Exception:
                pass
        time.sleep(0.1)
    
    log("SUCCESS", f"[SYN FLOOD] Complete: {packets_sent} packets sent")
    return packets_sent

def simulate_syn_flood_socket(target: str, duration: int = 5) -> int:
    """Fallback SYN flood using raw sockets"""
    log("ATTACK", f"[SYN FLOOD] Socket-based simulation to {target}")
    packets = 0
    start = time.time()
    
    while time.time() - start < duration:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.01)
            s.connect_ex((target, random.randint(1, 65535)))
            s.close()
            packets += 1
        except Exception:
            pass
    
    log("SUCCESS", f"[SYN FLOOD] Complete: {packets} connection attempts")
    return packets

def simulate_udp_flood(target: str, duration: int = 5) -> int:
    """
    UDP Flood Attack Simulation
    Threshold: 5000 UDP packets/sec per IP
    """
    log("ATTACK", f"[UDP FLOOD] Starting UDP flood to {target} for {duration}s")
    log("INFO", f"Rate: {UDP_RATE} UDP/sec (threshold: 5000)")
    
    packets_sent = 0
    payload = b"X" * 1024  # 1KB payload
    start = time.time()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    while time.time() - start < duration:
        for _ in range(UDP_RATE // 10):
            try:
                port = random.randint(1, 65535)
                sock.sendto(payload, (target, port))
                packets_sent += 1
            except Exception:
                pass
        time.sleep(0.1)
    
    sock.close()
    log("SUCCESS", f"[UDP FLOOD] Complete: {packets_sent} packets sent")
    return packets_sent

def simulate_icmp_flood(target: str, duration: int = 5) -> int:
    """
    ICMP Flood Attack Simulation
    Threshold: 100 ICMP packets/sec per IP
    """
    if not SCAPY_AVAILABLE:
        log("WARN", "Scapy not available, ICMP simulation requires Scapy")
        return 0
    
    log("ATTACK", f"[ICMP FLOOD] Starting ICMP flood to {target} for {duration}s")
    log("INFO", f"Rate: {ICMP_RATE} ICMP/sec (threshold: 100)")
    
    conf.verb = 0
    packets_sent = 0
    start = time.time()
    
    while time.time() - start < duration:
        for _ in range(ICMP_RATE // 10):
            pkt = IP(src=ATTACKER_IP, dst=target) / ICMP()
            try:
                send(pkt, verbose=False)
                packets_sent += 1
            except Exception:
                pass
        time.sleep(0.1)
    
    log("SUCCESS", f"[ICMP FLOOD] Complete: {packets_sent} packets sent")
    return packets_sent

def simulate_port_scan(target: str) -> int:
    """
    Port Scan Detection Test
    Threshold: 100 unique ports in 10 seconds
    """
    log("ATTACK", f"[PORT SCAN] Scanning {SCAN_PORTS} ports on {target}")
    log("INFO", f"Scanning {SCAN_PORTS} ports (threshold: 100)")
    
    open_ports = []
    scanned = 0
    
    # Random port scan
    ports = random.sample(range(1, 65535), SCAN_PORTS)
    
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.02)
            result = s.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
            s.close()
            scanned += 1
        except Exception:
            pass
    
    log("SUCCESS", f"[PORT SCAN] Complete: {scanned} ports scanned, {len(open_ports)} open")
    return scanned

def simulate_sequential_scan(target: str, start_port: int = 1) -> None:
    """
    Sequential Port Scan (more detectable)
    Threshold: 20 sequential ports
    """
    log("ATTACK", f"[SEQ SCAN] Sequential scan ports {start_port}-{start_port + SCAN_SEQUENTIAL}")
    
    for port in range(start_port, start_port + SCAN_SEQUENTIAL + 5):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.02)
            s.connect_ex((target, port))
            s.close()
        except Exception:
            pass
    
    log("SUCCESS", f"[SEQ SCAN] Complete: {SCAN_SEQUENTIAL + 5} sequential ports")

def simulate_brute_force(target: str, service: str, port: int, attempts: int) -> None:
    """
    Brute Force Attack Simulation
    Simulates failed authentication attempts
    """
    log("ATTACK", f"[BRUTE FORCE] {service.upper()} brute force on {target}:{port}")
    log("INFO", f"Attempts: {attempts}")
    
    for _ in range(attempts):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect_ex((target, port))
            # Send garbage auth data
            s.send(b"USER admin\r\nPASS wrong\r\n")
            time.sleep(0.1)
            s.close()
        except Exception:
            pass
    
    log("SUCCESS", f"[BRUTE FORCE] {service.upper()}: {attempts} attempts complete")

def simulate_vpn_traffic(target: str) -> None:
    """
    VPN Port Access Simulation
    Tests blocked VPN/Tor ports
    """
    log("ATTACK", "[VPN PORTS] Testing blocked VPN ports")
    
    for port in VPN_PORTS:
        try:
            # Try TCP
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            s.connect_ex((target, port))
            s.close()
            
            # Try UDP
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.sendto(b"VPN_PROBE", (target, port))
            u.close()
            
            log("INFO", f"  Port {port} probed")
        except Exception:
            pass
    
    log("SUCCESS", f"[VPN PORTS] {len(VPN_PORTS)} VPN ports tested")

def simulate_doh_bypass(target: Optional[str] = None) -> None:
    """
    DoH Bypass Attempt Simulation
    Tests connections to known DoH servers on port 443
    """
    log("ATTACK", "[DOH BYPASS] Attempting DoH server connections")
    
    for server in DOH_SERVERS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((server, 443))
            s.close()
            status = "open" if result == 0 else "blocked"
            log("INFO", f"  {server}:443 - {status}")
        except Exception:
            log("INFO", f"  {server}:443 - error")
    
    log("SUCCESS", f"[DOH BYPASS] {len(DOH_SERVERS)} DoH servers tested")

def simulate_dns_blocked_domains() -> None:
    """
    Blocked Domain DNS Query Simulation
    Tests DNS queries for blocked domains
    """
    log("ATTACK", "[DNS BLOCK] Querying blocked domains")
    
    for domain in BLOCKED_DOMAINS:
        try:
            socket.gethostbyname(domain)
            log("INFO", f"  {domain} - resolved")
        except socket.gaierror:
            log("INFO", f"  {domain} - blocked/failed")
        except Exception:
            pass
    
    log("SUCCESS", f"[DNS BLOCK] {len(BLOCKED_DOMAINS)} domains queried")

def simulate_xmas_scan(target: str) -> None:
    """
    Xmas Scan (Protocol Anomaly)
    Sets FIN+PSH+URG flags (should trigger anomaly detection)
    """
    if not SCAPY_AVAILABLE:
        log("WARN", "Scapy not available, Xmas scan requires Scapy")
        return
    
    log("ATTACK", f"[XMAS SCAN] Sending Xmas packets to {target}")
    
    conf.verb = 0
    ports = [22, 80, 443, 3389, 8080]
    
    for port in ports:
        pkt = IP(src=ATTACKER_IP, dst=target) / \
              TCP(sport=RandShort(), dport=port, flags="FPU")
        try:
            send(pkt, verbose=False)
        except Exception:
            pass
    
    log("SUCCESS", f"[XMAS SCAN] {len(ports)} Xmas packets sent")

def simulate_null_scan(target: str) -> None:
    """
    Null Scan (Protocol Anomaly)
    Sends TCP packet with no flags set
    """
    if not SCAPY_AVAILABLE:
        log("WARN", "Scapy not available, Null scan requires Scapy")
        return
    
    log("ATTACK", f"[NULL SCAN] Sending Null packets to {target}")
    
    conf.verb = 0
    ports = [22, 80, 443, 3389, 8080]
    
    for port in ports:
        pkt = IP(src=ATTACKER_IP, dst=target) / \
              TCP(sport=RandShort(), dport=port, flags="")
        try:
            send(pkt, verbose=False)
        except Exception:
            pass
    
    log("SUCCESS", f"[NULL SCAN] {len(ports)} Null packets sent")

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def run_all_attacks(target: str) -> None:
    """Run all attack simulations"""
    attacks = [
        ("SYN Flood (DDoS)", lambda: simulate_syn_flood(target, 3)),
        ("UDP Flood (DDoS)", lambda: simulate_udp_flood(target, 3)),
        ("ICMP Flood (DDoS)", lambda: simulate_icmp_flood(target, 3)),
        ("Port Scan", lambda: simulate_port_scan(target)),
        ("Sequential Scan", lambda: simulate_sequential_scan(target)),
        ("Brute Force SSH", lambda: simulate_brute_force(target, "ssh", 22, SSH_ATTEMPTS)),
        ("Brute Force RDP", lambda: simulate_brute_force(target, "rdp", 3389, RDP_ATTEMPTS)),
        ("Brute Force MySQL", lambda: simulate_brute_force(target, "mysql", 3306, MYSQL_ATTEMPTS)),
        ("VPN Port Access", lambda: simulate_vpn_traffic(target)),
        ("DoH Bypass Attempt", lambda: simulate_doh_bypass()),
        ("DNS Blocked Domains", lambda: simulate_dns_blocked_domains),
        ("Xmas Scan (Anomaly)", lambda: simulate_xmas_scan(target)),
        ("Null Scan (Anomaly)", lambda: simulate_null_scan(target)),
    ]
    
    log("INFO", f"Starting {len(attacks)} attack simulations against {target}")
    print("-" * 60)
    
    for name, attack_fn in attacks:
        print()
        log("INFO", f"=== {name} ===")
        try:
            attack_fn()
        except Exception as e:
            log("WARN", f"Attack failed: {e}")
        time.sleep(1)  # Brief pause between attacks
    
    print("\n" + "=" * 60)
    log("SUCCESS", "All attack simulations complete!")
    log("INFO", "Check firewall-alerts.jsonl for generated alerts")

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SafeOps Firewall Network Attack Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python network_simulator.py --all                    Run all attacks
  python network_simulator.py --syn-flood              SYN flood only
  python network_simulator.py --port-scan              Port scan only
  python network_simulator.py --target 192.168.1.100   Custom target
        """
    )
    
    parser.add_argument("--all", action="store_true", help="Run all attack simulations")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP (default: 127.0.0.1)")
    parser.add_argument("--duration", type=int, default=5, help="Attack duration in seconds")
    
    # Individual attacks
    parser.add_argument("--syn-flood", action="store_true", help="SYN flood attack")
    parser.add_argument("--udp-flood", action="store_true", help="UDP flood attack")
    parser.add_argument("--icmp-flood", action="store_true", help="ICMP flood attack")
    parser.add_argument("--port-scan", action="store_true", help="Port scan")
    parser.add_argument("--brute-force", action="store_true", help="Brute force attacks")
    parser.add_argument("--vpn-ports", action="store_true", help="VPN port access")
    parser.add_argument("--doh-bypass", action="store_true", help="DoH bypass attempt")
    parser.add_argument("--xmas-scan", action="store_true", help="Xmas scan (anomaly)")
    parser.add_argument("--null-scan", action="store_true", help="Null scan (anomaly)")
    
    args = parser.parse_args()
    
    banner()
    
    # Check requirements
    if not SCAPY_AVAILABLE:
        log("WARN", "Scapy not installed. Some attacks will use fallback methods.")
        log("INFO", "Install with: pip install scapy")
    
    if sys.platform == "win32" and not check_admin():
        log("WARN", "Not running as Administrator. Some attacks may fail.")
        log("INFO", "Run PowerShell as Administrator for full functionality.")
    
    target = args.target
    
    print()
    log("INFO", f"Target: {target}")
    log("INFO", f"Scapy: {'Available' if SCAPY_AVAILABLE else 'Not installed'}")
    print("-" * 60)
    
    if args.all:
        run_all_attacks(target)
    elif args.syn_flood:
        simulate_syn_flood(target, args.duration)
    elif args.udp_flood:
        simulate_udp_flood(target, args.duration)
    elif args.icmp_flood:
        simulate_icmp_flood(target, args.duration)
    elif args.port_scan:
        simulate_port_scan(target)
        simulate_sequential_scan(target)
    elif args.brute_force:
        simulate_brute_force(target, "ssh", 22, SSH_ATTEMPTS)
        simulate_brute_force(target, "rdp", 3389, RDP_ATTEMPTS)
        simulate_brute_force(target, "mysql", 3306, MYSQL_ATTEMPTS)
    elif args.vpn_ports:
        simulate_vpn_traffic(target)
    elif args.doh_bypass:
        simulate_doh_bypass()
    elif args.xmas_scan:
        simulate_xmas_scan(target)
    elif args.null_scan:
        simulate_null_scan(target)
    else:
        parser.print_help()
        print()
        log("INFO", "Use --all to run all attack simulations")

if __name__ == "__main__":
    main()
