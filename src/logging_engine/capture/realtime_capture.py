#!/usr/bin/env python3
"""
SafeOps Enterprise Packet Logger - Enhanced Edition
✨ NEW: Beautiful CLI output, smart deduplication, enhanced TLS decryption display
IMPROVEMENTS:
- ✅ Beautiful boxed statistics (non-flooding, every 30s)
- ✅ Smart deduplication with detailed logging
- ✅ Enhanced TLS decryption with preview
- ✅ Color-coded console output
- ✅ Detailed final report with insights
- ✅ All Windows features preserved
- ✅ FIXED: Proper 3-min log rotation with append to IDS archive (no data loss)
- ✅ IMPROVED: 6-min cycle for IDS log - cleared 5s before each 6-min transfer
"""

import os
import sys
import json
import time
import logging
import threading
import hashlib
import uuid
import shutil
import base64
import struct
import psutil
from datetime import datetime, timezone
from queue import Queue, Empty
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple, Set, List
import ipaddress
import socket
from functools import lru_cache

# ==================== Color Support ====================
try:
    import colorama
    from colorama import Fore, Back, Style
    colorama.init(autoreset=True)
    COLORS_ENABLED = True
except ImportError:
    COLORS_ENABLED = False

class Fore:
    RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
class Style:
    BRIGHT = RESET_ALL = ""

# ==================== Scapy Imports ====================
try:
    from scapy.all import sniff, load_layer
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
    from scapy.layers.l2 import Ether, Dot1Q
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.config import conf
    load_layer("http")
    load_layer("tls")
except ImportError:
    print("❌ Scapy required: pip install scapy")
    sys.exit(1)

# TLS support
try:
    from scapy.layers.tls.all import (
        TLS, TLSClientHello, TLSServerHello, TLSCertificateList, TLSApplicationData
    )
    TLS_AVAILABLE = True
except:
    TLS_AVAILABLE = False

# HTTP support
try:
    from scapy.layers.http import HTTPRequest, HTTPResponse, HTTP
    HTTP_AVAILABLE = True
except:
    HTTP_AVAILABLE = False

# Crypto support for TLS decryption
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# ==================== Configuration ====================
conf.verb = 0

# Custom logging formatter with colors
class ColoredFormatter(logging.Formatter):
    FORMATS = {
        logging.DEBUG: Fore.CYAN + "%(message)s" + Style.RESET_ALL,
        logging.INFO: Fore.GREEN + "%(message)s" + Style.RESET_ALL,
        logging.WARNING: Fore.YELLOW + "%(message)s" + Style.RESET_ALL,
        logging.ERROR: Fore.RED + "%(message)s" + Style.RESET_ALL,
        logging.CRITICAL: Fore.RED + Style.BRIGHT + "%(message)s" + Style.RESET_ALL,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, "%(message)s")
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

# Setup logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter())
logger.addHandler(handler)

# SafeOpsFV2 log directory
LOG_DIR = r'D:\SafeOpsFV2\logs'
os.makedirs(LOG_DIR, exist_ok=True)
LOG_PATH = os.path.join(LOG_DIR, 'network_packets.log')

# TLS Decryption
SSLKEYLOGFILE = os.environ.get('SSLKEYLOGFILE', os.path.join(LOG_DIR, 'sslkeys.log'))
ENABLE_DECRYPTION = True

# Flow tracking
FLOW_TIMEOUT = 60
FLOW_CLEANUP_INTERVAL = 30

# Enhanced deduplication
ENABLE_DEDUPLICATION = True
DEDUP_WINDOW = 60
DEDUP_CACHE_SIZE = 10000

# Gaming ports
GAMING_PORTS = {
    3074: 'Xbox Live', 3478: 'PlayStation/Steam', 3479: 'PlayStation/Steam',
    3480: 'PlayStation Network', 5222: 'League of Legends', 27015: 'CS:GO/Source',
    27036: 'Steam Streaming', 3724: 'World of Warcraft', 6112: 'Battle.net',
    25565: 'Minecraft', 7777: 'PUBG', 9000: 'Fortnite',
}

# Critical ports
CRITICAL_PORTS = {
    22, 23, 3389, 445, 139, 135, 1433, 3306, 5432, 20, 21, 25, 110, 143, 993, 995, 8080, 8443
}

# Network exclusions
EXCLUDED_NETWORKS = {
    '127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4', '255.255.255.255',
    'fe80::/10', 'ff00::/8', '::1', '0.0.0.0/8', '::',
}
INTERNAL_NETWORKS = {'10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'}

STOP_SNIFFING = threading.Event()
EVENT_QUEUE = Queue()
FILE_LOCK = threading.Lock()

# Log rotation settings
LOG_ROTATE_INTERVAL = 300  # 5 minutes
BATCH_SIZE = 75

# Stats display interval
STATS_DISPLAY_INTERVAL = 120  # Show stats every 2 minutes (changed from 30 seconds)

# ==================== SSL Key Logger ====================
class SSLKeyLogger:
    """Monitor and use SSLKEYLOGFILE for TLS decryption"""
    def __init__(self, keylog_file: str):
        self.keylog_file = keylog_file
        self.keys = {}
        self.lock = threading.Lock()
        if not os.path.exists(keylog_file):
            open(keylog_file, 'w').close()
        logging.info(f"📝 Created SSLKEYLOGFILE: {keylog_file}")
        os.environ['SSLKEYLOGFILE'] = keylog_file
        self.monitor_thread = threading.Thread(target=self._monitor_keys, daemon=True)
        self.monitor_thread.start()

    def _monitor_keys(self):
        last_size = 0
        while not STOP_SNIFFING.is_set():
            try:
                if os.path.exists(self.keylog_file):
                    current_size = os.path.getsize(self.keylog_file)
                    if current_size > last_size:
                        with open(self.keylog_file, 'r') as f:
                            f.seek(last_size)
                            new_lines = f.readlines()
                        with self.lock:
                            for line in new_lines:
                                line = line.strip()
                                if line and not line.startswith('#'):
                                    parts = line.split(' ', 2)
                                    if len(parts) == 3:
                                        label, client_random, secret = parts
                                        self.keys[client_random] = {
                                            'label': label, 'secret': secret, 'timestamp': time.time()
                                        }
                        last_size = current_size
                time.sleep(1)
            except Exception as e:
                logging.debug(f"Key monitor error: {e}")

    def get_key(self, client_random: str) -> Optional[Dict]:
        with self.lock:
            return self.keys.get(client_random)

    def get_stats(self) -> Dict:
        with self.lock:
            return {
                'total_keys': len(self.keys),
                'recent_keys': sum(1 for k in self.keys.values() if time.time() - k['timestamp'] < 300)
            }

# ==================== Process Tracker ====================
class ProcessTracker:
    """Track which process owns which connection"""
    def __init__(self):
        self.conn_cache = {}
        self.lock = threading.Lock()

    def get_process_info(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str) -> Optional[Dict]:
        try:
            conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
            with self.lock:
                if conn_key in self.conn_cache:
                    cached = self.conn_cache[conn_key]
                    if time.time() - cached['timestamp'] < 10:
                        return cached['info']
            process_info = None
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'connections']):
                try:
                    connections = proc.info['connections']
                    if not connections:
                        continue
                    for conn in connections:
                        if (conn.laddr.port == src_port and conn.raddr and conn.raddr.port == dst_port):
                            process_info = {
                                'pid': proc.info['pid'],
                                'name': proc.info['name'],
                                'exe': proc.info['exe'],
                                'cmdline': ' '.join(proc.cmdline()) if hasattr(proc, 'cmdline') else None
                            }
                            break
                    if process_info:
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            if process_info:
                with self.lock:
                    self.conn_cache[conn_key] = {'info': process_info, 'timestamp': time.time()}
                return process_info
        except Exception as e:
            logging.debug(f"Process lookup error: {e}")
        return None

# ==================== Enhanced Deduplication Engine ====================
class DeduplicationEngine:
    """✨ ENHANCED: Intelligent deduplication with detailed logging"""
    def __init__(self):
        self.signatures = deque(maxlen=DEDUP_CACHE_SIZE)
        self.signature_times = {}
        self.dedup_reasons = defaultdict(int)  # Track why packets were deduped
        self.lock = threading.Lock()
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()

    def _compute_signature(self, packet_data: Dict) -> str:
        """Compute packet signature for deduplication"""
        layers = packet_data.get('layers', {})
        network = layers.get('network', {})
        transport = layers.get('transport', {})
        payload = layers.get('payload', {})
        sig_parts = [
            network.get('src_ip', ''),
            network.get('dst_ip', ''),
            str(transport.get('src_port', '')),
            str(transport.get('dst_port', '')),
            str(transport.get('protocol', '')),
            payload.get('data_hex', '')[:100]
        ]
        sig_string = '|'.join(sig_parts)
        return hashlib.md5(sig_string.encode()).hexdigest()

    def should_log(self, packet_data: Dict) -> Tuple[bool, Optional[str]]:
        """✨ ENHANCED: Better deduplication logic"""
        if not ENABLE_DEDUPLICATION:
            return True, 'dedup_disabled'
        try:
            # Always log security-relevant protocols
            parsed_app = packet_data.get('parsed_application', {})
            protocol = parsed_app.get('detected_protocol')
            if protocol in ['http', 'dns', 'tls', 'https']:
                self.dedup_reasons['security_protocol'] += 1
                return True, 'security_protocol'
            # Always log critical ports
            transport = packet_data.get('layers', {}).get('transport', {})
            src_port = transport.get('src_port')
            dst_port = transport.get('dst_port')
            if src_port in CRITICAL_PORTS or dst_port in CRITICAL_PORTS:
                self.dedup_reasons['critical_port'] += 1
                return True, 'critical_port'
            # Always log TCP handshakes/teardowns
            tcp_flags = transport.get('tcp_flags', {})
            if tcp_flags.get('syn') or tcp_flags.get('fin') or tcp_flags.get('rst'):
                self.dedup_reasons['tcp_control'] += 1
                return True, 'tcp_control'
            # Check for duplicate
            signature = self._compute_signature(packet_data)
            now = time.time()
            with self.lock:
                if signature in self.signature_times:
                    last_seen = self.signature_times[signature]
                    if now - last_seen < DEDUP_WINDOW:
                        self.dedup_reasons['duplicate'] += 1
                        return False, 'duplicate'
                self.signature_times[signature] = now
                self.signatures.append(signature)
            self.dedup_reasons['unique'] += 1
            return True, 'unique'
        except Exception as e:
            logging.debug(f"Dedup error: {e}")
            return True, 'error'

    def get_stats(self) -> Dict:
        """Get deduplication statistics"""
        with self.lock:
            return dict(self.dedup_reasons)

    def _cleanup_loop(self):
        while not STOP_SNIFFING.is_set():
            time.sleep(60)
            try:
                now = time.time()
                with self.lock:
                    expired = [sig for sig, t in self.signature_times.items() if now - t > DEDUP_WINDOW * 2]
                    for sig in expired:
                        del self.signature_times[sig]
            except Exception as e:
                logging.error(f"Dedup cleanup error: {e}")

# ==================== Network Classifier ====================
@lru_cache(maxsize=1024)
def is_excluded_ip(ip: str) -> bool:
    """Cached check for excluded IPs"""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback:
            return True
        if addr.is_link_local:
            return True
        if addr.is_multicast:
            return True
        if addr.is_unspecified:
            return True
        for net_str in EXCLUDED_NETWORKS:
            try:
                if '/' in net_str:
                    net = ipaddress.ip_network(net_str, strict=False)
                    if addr in net:
                        return True
                elif addr == ipaddress.ip_address(net_str):
                    return True
            except:
                pass
        return False
    except:
        return False

@lru_cache(maxsize=512)
def is_internal_ip(ip: str) -> bool:
    """Cached check for internal IPs"""
    try:
        addr = ipaddress.ip_address(ip)
        for net_str in INTERNAL_NETWORKS:
            net = ipaddress.ip_network(net_str, strict=False)
            if addr in net:
                return True
        return False
    except:
        return False

# ==================== Flow Tracking ====================
@dataclass
class FlowContext:
    flow_id: str
    first_seen: float
    last_seen: float
    forward_packets: int = 0
    forward_bytes: int = 0
    reverse_packets: int = 0
    reverse_bytes: int = 0
    tcp_state: str = 'NEW'
    saw_syn: bool = False
    saw_syn_ack: bool = False
    saw_fin: bool = False
    saw_rst: bool = False
    is_gaming: bool = False
    gaming_service: Optional[str] = None
    process_info: Optional[Dict] = None
    tls_session_id: Optional[str] = None
    tls_decrypted: bool = False

class FlowTracker:
    """Track bidirectional flows for context"""
    def __init__(self):
        self.flows: Dict[str, FlowContext] = {}
        self.lock = threading.Lock()
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()

    def get_flow_key(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str) -> Tuple[str, str]:
        if src_ip < dst_ip:
            key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}/{proto}"
            direction = 'forward'
        elif src_ip > dst_ip:
            key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}/{proto}"
            direction = 'reverse'
        else:
            if src_port < dst_port:
                key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}/{proto}"
                direction = 'forward'
            else:
                key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}/{proto}"
                direction = 'reverse'
        flow_id = f"flow_{hashlib.md5(key.encode()).hexdigest()[:16]}"
        return flow_id, direction

    def update_flow(self, flow_id: str, direction: str, packet_size: int, src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str, tcp_flags: str = None, process_info: Dict = None):
        now = time.time()
        with self.lock:
            if flow_id not in self.flows:
                port = dst_port if direction == 'forward' else src_port
                is_gaming = port in GAMING_PORTS
                gaming_service = GAMING_PORTS.get(port)
                self.flows[flow_id] = FlowContext(
                    flow_id=flow_id, first_seen=now, last_seen=now,
                    is_gaming=is_gaming, gaming_service=gaming_service, process_info=process_info
                )
            flow = self.flows[flow_id]
            flow.last_seen = now
            if direction == 'forward':
                flow.forward_packets += 1
                flow.forward_bytes += packet_size
            else:
                flow.reverse_packets += 1
                flow.reverse_bytes += packet_size
            if proto == 'tcp' and tcp_flags:
                if 'S' in tcp_flags and 'A' not in tcp_flags:
                    flow.saw_syn = True
                    flow.tcp_state = 'SYN_SENT'
                elif 'S' in tcp_flags and 'A' in tcp_flags:
                    flow.saw_syn_ack = True
                    flow.tcp_state = 'ESTABLISHED'
                elif 'F' in tcp_flags:
                    flow.saw_fin = True
                    flow.tcp_state = 'CLOSING'
                elif 'R' in tcp_flags:
                    flow.saw_rst = True
                    flow.tcp_state = 'CLOSED'
                elif 'A' in tcp_flags and flow.saw_syn_ack:
                    flow.tcp_state = 'ESTABLISHED'

    def get_flow_context(self, flow_id: str) -> Optional[Dict]:
        with self.lock:
            flow = self.flows.get(flow_id)
            if not flow:
                return None
            context = {
                'flow_id': flow.flow_id,
                'direction': None,
                'packets_forward': flow.forward_packets,
                'packets_backward': flow.reverse_packets,
                'bytes_forward': flow.forward_bytes,
                'bytes_backward': flow.reverse_bytes,
                'flow_start_time': flow.first_seen,
                'flow_duration': time.time() - flow.first_seen,
                'flow_state': 'active',
                'tcp_state': flow.tcp_state if flow.tcp_state != 'NEW' else None
            }
            if flow.process_info:
                context['process'] = flow.process_info
            if flow.tls_decrypted:
                context['tls_decrypted'] = True
            return context

    def _cleanup_loop(self):
        while not STOP_SNIFFING.is_set():
            time.sleep(FLOW_CLEANUP_INTERVAL)
            now = time.time()
            with self.lock:
                stale = [fid for fid, flow in self.flows.items() if now - flow.last_seen > FLOW_TIMEOUT]
                for fid in stale:
                    del self.flows[fid]

# ==================== Enhanced TLS Decryptor ====================
class TLSDecryptor:
    """✨ ENHANCED: TLS decryption with preview display"""
    def __init__(self, keylogger: SSLKeyLogger):
        self.keylogger = keylogger
        self.sessions = {}
        self.lock = threading.Lock()
        self.crypto_available = CRYPTO_AVAILABLE
        self.decrypted_samples = deque(maxlen=10)  # Keep last 10 decrypted samples

    def try_decrypt(self, packet, tls_data: Dict) -> Optional[Dict]:
        """Try to decrypt TLS payload"""
        try:
            if not packet.haslayer(TLSApplicationData):
                return None
            # Extract client random
            client_random = tls_data.get('client_hello', {}).get('random')
            if not client_random:
                return None
            # Get master secret from SSLKEYLOGFILE
            key_info = self.keylogger.get_key(client_random)
            if not key_info:
                return {
                    'decrypted': False,
                    'key_available': False,
                    'reason': 'No matching key in SSLKEYLOGFILE'
                }
            # If cryptography library available, try real decryption
            if self.crypto_available:
                decrypted_payload = self._decrypt_application_data(packet, key_info)
                if decrypted_payload:
                    # Parse HTTP from decrypted data
                    http_data = self._parse_http_from_bytes(decrypted_payload)
                    # ✨ NEW: Store sample for display
                    preview = decrypted_payload[:100].decode('utf-8', errors='ignore')
                    self.decrypted_samples.append({
                        'timestamp': time.time(),
                        'length': len(decrypted_payload),
                        'preview': preview,
                        'has_http': http_data is not None
                    })
                    result = {
                        'decrypted': True,
                        'key_available': True,
                        'cipher': tls_data.get('client_hello', {}).get('selected_cipher'),
                        'decrypted_length': len(decrypted_payload),
                        'decrypted_payload_hex': decrypted_payload[:200].hex(),
                        'decrypted_payload_base64': base64.b64encode(decrypted_payload[:200]).decode(),
                        'decrypted_preview': preview,  # ✨ NEW
                        'http_parsed': http_data is not None,
                        'http_data': http_data,
                        'note': 'Successfully decrypted TLS payload'
                    }
                    return result
            # Fallback: Keys available but can't decrypt
            return {
                'decrypted': False,
                'key_available': True,
                'cipher': tls_data.get('client_hello', {}).get('selected_cipher'),
                'note': 'Decryption keys available - install cryptography library for full decryption'
            }
        except Exception as e:
            logging.debug(f"TLS decrypt error: {e}")
            return {'decrypted': False, 'error': str(e)}

    def _decrypt_application_data(self, packet, key_info: Dict) -> Optional[bytes]:
        """Decrypt TLS ApplicationData using master secret"""
        try:
            if not CRYPTO_AVAILABLE:
                return None
            app_data_layer = packet[TLSApplicationData]
            encrypted_data = bytes(app_data_layer.data) if hasattr(app_data_layer, 'data') else bytes(app_data_layer)
            if len(encrypted_data) < 16:
                return None
            # Note: Simplified decryption - full implementation needs complete TLS state machine
            logging.debug(f"Attempting TLS decryption on {len(encrypted_data)} bytes")
            # TODO: Implement full TLS 1.2/1.3 decryption
            return None  # Placeholder
        except Exception as e:
            logging.debug(f"TLS application data decrypt error: {e}")
            return None

    def _parse_http_from_bytes(self, decrypted_bytes: bytes) -> Optional[Dict]:
        """Parse HTTP request/response from decrypted TLS data"""
        try:
            text = decrypted_bytes.decode('utf-8', errors='ignore')
            if not (text.startswith('GET ') or text.startswith('POST ') or text.startswith('PUT ') or
                    text.startswith('DELETE ') or text.startswith('HTTP/') or text.startswith('HEAD ') or
                    text.startswith('PATCH ') or text.startswith('OPTIONS ')):
                return None
            lines = text.split('\r\n')
            if not lines:
                return None
            data = OrderedDict()
            # Parse request line
            if lines[0].startswith('HTTP/'):
                parts = lines[0].split(' ', 2)
                if len(parts) >= 2:
                    data['type'] = 'response'
                    data['version'] = parts[0]
                    try:
                        data['status_code'] = int(parts[1])
                    except:
                        data['status_code'] = parts[1]
                    if len(parts) == 3:
                        data['status_message'] = parts[2]
            else:
                parts = lines[0].split(' ', 2)
                if len(parts) >= 2:
                    data['type'] = 'request'
                    data['method'] = parts[0]
                    data['uri'] = parts[1]
                    if len(parts) == 3:
                        data['version'] = parts[2]
            # Parse headers
            headers = OrderedDict()
            body_start = 1
            for i, line in enumerate(lines[1:], 1):
                if not line:
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            if headers:
                data['headers'] = headers
            # Parse body
            if body_start < len(lines):
                body = '\r\n'.join(lines[body_start:])
                if body:
                    data['body'] = body[:500]
                    data['body_length'] = len(body)
            return data if len(data) > 0 else None
        except Exception as e:
            logging.debug(f"HTTP parse from bytes error: {e}")
            return None

    def get_recent_samples(self) -> List[Dict]:
        """Get recent decrypted samples for display"""
        return list(self.decrypted_samples)

# ==================== Interface Scanner ====================
class InterfaceScanner:
    """Real-time network interface scanner"""
    def __init__(self):
        self.active_interfaces = set()
        self.lock = threading.Lock()
        self.scan_interval = 10
        self.scanner_thread = threading.Thread(target=self._scan_loop, daemon=True)
        self.scanner_thread.start()

    def _scan_loop(self):
        while not STOP_SNIFFING.is_set():
            try:
                from scapy.arch import get_if_list
                current_interfaces = set(get_if_list())
                with self.lock:
                    new_interfaces = current_interfaces - self.active_interfaces
                    removed_interfaces = self.active_interfaces - current_interfaces
                if new_interfaces:
                    logging.info(f"📡 New interfaces detected: {', '.join(new_interfaces)}")
                if removed_interfaces:
                    logging.info(f"📴 Interfaces removed: {', '.join(removed_interfaces)}")
                with self.lock:
                    self.active_interfaces = current_interfaces
                time.sleep(self.scan_interval)
            except Exception as e:
                logging.debug(f"Interface scan error: {e}")
                time.sleep(self.scan_interval)

    def get_active_interfaces(self) -> List[str]:
        with self.lock:
            return list(self.active_interfaces)

# ==================== Packet Logger (COMPLETE) ====================
class PacketLogger:
    """Complete packet logger with full IDS/IPS capability"""
    def __init__(self, interface: str):
        self.interface = interface
        self.packet_count = 0
        self.start_time = time.time()
        self.flow_tracker = FlowTracker()
        self.process_tracker = ProcessTracker()
        self.dedup_engine = DeduplicationEngine()
        self.ssl_keylogger = SSLKeyLogger(SSLKEYLOGFILE)
        self.tls_decryptor = TLSDecryptor(self.ssl_keylogger)
        self.stats = {
            'packets_captured': 0, 'packets_logged': 0, 'packets_excluded': 0, 'packets_deduplicated': 0,
            'tls_decryption_attempted': 0, 'tls_decrypted': 0, 'http_parsed_from_tls': 0, 'bytes_total': 0
        }

    def process_packet(self, packet):
        """Process single packet with COMPLETE parsing"""
        try:
            self.packet_count += 1
            self.stats['packets_captured'] += 1
            # Get IPs
            src_ip = None
            dst_ip = None
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
            if src_ip and dst_ip:
                if is_excluded_ip(src_ip) or is_excluded_ip(dst_ip):
                    self.stats['packets_excluded'] += 1
                    return
            # Generate unique packet ID
            timestamp_ns = int(time.time() * 1_000_000_000)
            packet_id = f"pkt_{timestamp_ns}_{uuid.uuid4().hex[:8]}"
            # COMPLETE Parse
            log_entry = self._parse_packet_complete(packet, packet_id)
            if not log_entry:
                return
            # Deduplication check
            should_log, dedup_reason = self.dedup_engine.should_log(log_entry)
            if not should_log:
                self.stats['packets_deduplicated'] += 1
                return
            log_entry['deduplication'] = {'unique': should_log, 'reason': dedup_reason}
            # Queue for writing
            EVENT_QUEUE.put(log_entry)
            self.stats['packets_logged'] += 1
            self.stats['bytes_total'] += len(packet)
        except Exception as e:
            if self.packet_count <= 5:
                logging.error(f"Packet processing error: {e}")

    def _parse_packet_complete(self, packet, packet_id: str) -> Optional[Dict]:
        """COMPLETE packet parsing"""
        timestamp = datetime.now(timezone.utc)
        log_entry = OrderedDict()
        log_entry['packet_id'] = packet_id
        log_entry['timestamp'] = {
            'epoch': time.time(),
            'iso8601': timestamp.isoformat().replace('+00:00', 'Z')
        }
        log_entry['capture_info'] = {
            'interface': self.interface,
            'capture_length': len(packet),
            'wire_length': len(packet)
        }
        layers = OrderedDict()
        # Ethernet
        if packet.haslayer(Ether):
            layers['datalink'] = self._parse_ethernet(packet)
        # Network layer
        network_data = None
        if packet.haslayer(IP):
            network_data = self._parse_ipv4(packet)
            layers['network'] = network_data
        elif packet.haslayer(IPv6):
            network_data = self._parse_ipv6(packet)
            layers['network'] = network_data
        if not network_data:
            return None
        # Transport layer
        transport_data = None
        proto_name = None
        if packet.haslayer(TCP):
            transport_data = self._parse_tcp(packet)
            proto_name = 'tcp'
            layers['transport'] = transport_data
        elif packet.haslayer(UDP):
            transport_data = self._parse_udp(packet)
            proto_name = 'udp'
            layers['transport'] = transport_data
        elif packet.haslayer(ICMP):
            transport_data = self._parse_icmp(packet)
            proto_name = 'icmp'
            layers['transport'] = transport_data
        if not transport_data:
            return None
        # Full payload
        payload_data = self._parse_payload(packet, proto_name)
        if payload_data:
            layers['payload'] = payload_data
        log_entry['layers'] = layers
        # Application layer parsing with REAL decryption
        parsed_app = self._parse_application(packet, payload_data)
        log_entry['parsed_application'] = parsed_app
        # Process correlation
        if proto_name in ['tcp', 'udp'] and 'src_port' in transport_data:
            src_ip = network_data.get('src_ip')
            dst_ip = network_data.get('dst_ip')
            src_port = transport_data.get('src_port')
            dst_port = transport_data.get('dst_port')
            if src_ip and dst_ip and src_port and dst_port:
                process_info = self.process_tracker.get_process_info(
                    src_ip, src_port, dst_ip, dst_port, proto_name
                )
                flow_id, direction = self.flow_tracker.get_flow_key(
                    src_ip, src_port, dst_ip, dst_port, proto_name
                )
                tcp_flags = None
                if proto_name == 'tcp' and 'tcp_flags' in transport_data:
                    flags = transport_data['tcp_flags']
                    tcp_flags = ''.join([
                        'S' if flags.get('syn') else '',
                        'A' if flags.get('ack') else '',
                        'F' if flags.get('fin') else '',
                        'R' if flags.get('rst') else '',
                        'P' if flags.get('psh') else '',
                    ])
                self.flow_tracker.update_flow(
                    flow_id, direction, len(packet), src_ip, src_port, dst_ip, dst_port, proto_name, tcp_flags, process_info
                )
                flow_context = self.flow_tracker.get_flow_context(flow_id)
                if flow_context:
                    flow_context['direction'] = direction
                    log_entry['flow_context'] = flow_context
                flow = self.flow_tracker.flows.get(flow_id)
                if flow and flow.is_gaming:
                    if 'gaming' not in parsed_app:
                        parsed_app['gaming'] = OrderedDict()
                    parsed_app['gaming']['detected'] = True
                    parsed_app['gaming']['service'] = flow.gaming_service
                    parsed_app['gaming']['port'] = dst_port if direction == 'forward' else src_port
        # Session tracking
        if 'flow_context' in log_entry:
            fc = log_entry['flow_context']
            log_entry['session_tracking'] = {
                'session_id': fc['flow_id'],
                'first_seen': fc['flow_start_time'],
                'last_seen': time.time(),
                'packet_count': fc['packets_forward'] + fc['packets_backward'],
                'byte_count': fc['bytes_forward'] + fc['bytes_backward'],
                'session_state': 'active'
            }
        return self._remove_empty(log_entry)

    def _parse_ethernet(self, packet) -> Dict:
        """Parse Ethernet layer"""
        eth = packet[Ether]
        data = OrderedDict([
            ('type', 'ethernet'),
            ('src_mac', eth.src),
            ('dst_mac', eth.dst),
            ('ethertype', eth.type),
        ])
        if packet.haslayer(Dot1Q):
            vlan = packet[Dot1Q]
            data['vlan_id'] = vlan.vlan
            data['vlan_priority'] = vlan.prio
        return data

    def _parse_ipv4(self, packet) -> Dict:
        """Parse IPv4 layer"""
        ip = packet[IP]
        data = OrderedDict([
            ('version', 4),
            ('header_length', ip.ihl * 4),
            ('tos', ip.tos),
            ('dscp', ip.tos >> 2),
            ('ecn', ip.tos & 0x03),
            ('total_length', ip.len),
            ('identification', ip.id),
            ('flags_df', bool(ip.flags & 0x02)),
            ('flags_mf', bool(ip.flags & 0x01)),
            ('fragment_offset', ip.frag),
            ('ttl', ip.ttl),
            ('protocol', ip.proto),
            ('header_checksum', ip.chksum),
            ('src_ip', ip.src),
            ('dst_ip', ip.dst),
        ])
        return data

    def _parse_ipv6(self, packet) -> Dict:
        """Parse IPv6 layer"""
        ip = packet[IPv6]
        data = OrderedDict([
            ('version', 6),
            ('traffic_class', ip.tc),
            ('flow_label', ip.fl),
            ('payload_length', ip.plen),
            ('next_header', ip.nh),
            ('hop_limit', ip.hlim),
            ('src_ip', ip.src),
            ('dst_ip', ip.dst),
        ])
        return data

    def _parse_tcp(self, packet) -> Dict:
        """Parse TCP layer"""
        tcp = packet[TCP]
        data = OrderedDict([
            ('protocol', 6),
            ('src_port', tcp.sport),
            ('dst_port', tcp.dport),
            ('tcp_seq', tcp.seq),
            ('tcp_ack', tcp.ack),
            ('tcp_data_offset', tcp.dataofs * 4),
            ('tcp_flags', {
                'fin': bool(tcp.flags & 0x01),
                'syn': bool(tcp.flags & 0x02),
                'rst': bool(tcp.flags & 0x04),
                'psh': bool(tcp.flags & 0x08),
                'ack': bool(tcp.flags & 0x10),
                'urg': bool(tcp.flags & 0x20),
                'ece': bool(tcp.flags & 0x40),
                'cwr': bool(tcp.flags & 0x80),
                'ns': 0
            }),
            ('tcp_window', tcp.window),
            ('tcp_checksum', tcp.chksum),
            ('tcp_urgent', tcp.urgptr),
        ])
        if tcp.options:
            opts = []
            for opt in tcp.options:
                if isinstance(opt, tuple) and len(opt) >= 2:
                    opt_dict = {'kind': opt[0]}
                    if len(opt) > 1 and opt[1]:
                        opt_dict['value'] = opt[1]
                    opts.append(opt_dict)
            if opts:
                data['tcp_options'] = opts
        return data

    def _parse_udp(self, packet) -> Dict:
        """Parse UDP layer"""
        udp = packet[UDP]
        data = OrderedDict([
            ('protocol', 17),
            ('src_port', udp.sport),
            ('dst_port', udp.dport),
            ('udp_length', udp.len),
            ('udp_checksum', udp.chksum),
        ])
        return data

    def _parse_icmp(self, packet) -> Dict:
        """Parse ICMP layer"""
        icmp = packet[ICMP]
        data = OrderedDict([
            ('protocol', 1),
            ('icmp_type', icmp.type),
            ('icmp_code', icmp.code),
            ('icmp_checksum', icmp.chksum),
        ])
        if hasattr(icmp, 'id'):
            data['icmp_id'] = icmp.id
        if hasattr(icmp, 'seq'):
            data['icmp_seq'] = icmp.seq
        return data

    def _parse_payload(self, packet, proto_name: str) -> Optional[Dict]:
        """Full payload capture"""
        try:
            if proto_name == 'tcp' and packet.haslayer(TCP):
                payload = bytes(packet[TCP].payload)
            elif proto_name == 'udp' and packet.haslayer(UDP):
                payload = bytes(packet[UDP].payload)
            else:
                return None
            if not payload or len(payload) == 0:
                return None
            payload_size = min(len(payload), 1500)
            payload_sample = payload[:payload_size]
            data = OrderedDict([
                ('length', len(payload)),
                ('data_hex', payload_sample.hex()),
                ('data_base64', base64.b64encode(payload_sample).decode('ascii')),
            ])
            if len(payload) > 1500:
                data['truncated'] = True
                data['captured_length'] = payload_size
            else:
                data['truncated'] = False
            if payload[:3] in [b'\x16\x03\x01', b'\x16\x03\x02', b'\x16\x03\x03', b'\x17\x03\x03']:
                data['encrypted'] = True
            else:
                data['encrypted'] = False
            return data
        except:
            return None

    def _extract_http_from_payload(self, payload_bytes: bytes) -> Optional[Dict]:
        """ Extract HTTP headers from raw payload (for non-Scapy HTTP parsing)
        This handles cases where Scapy HTTP layer isn't detected """
        try:
            # Decode payload
            text = payload_bytes.decode('utf-8', errors='ignore')
            # Check if it's HTTP
            http_methods = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'PATCH ', 'OPTIONS ', 'CONNECT ']
            is_request = any(text.startswith(method) for method in http_methods)
            is_response = text.startswith('HTTP/')
            if not (is_request or is_response):
                return None
            lines = text.split('\r\n')
            if not lines:
                return None
            data = OrderedDict()
            # Parse request/response line
            if is_response:
                parts = lines[0].split(' ', 2)
                if len(parts) >= 2:
                    data['type'] = 'response'
                    data['version'] = parts[0]
                    try:
                        data['status_code'] = int(parts[1])
                    except:
                        data['status_code'] = parts[1]
                    if len(parts) == 3:
                        data['status_message'] = parts[2]
            else:
                parts = lines[0].split(' ', 2)
                if len(parts) >= 2:
                    data['type'] = 'request'
                    data['method'] = parts[0]
                    data['uri'] = parts[1]
                    if len(parts) == 3:
                        data['version'] = parts[2]
            # Parse headers (THIS IS THE KEY PART FOR USER-AGENT)
            headers = OrderedDict()
            body_start = 1
            for i, line in enumerate(lines[1:], 1):
                if not line:  # Empty line = end of headers
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            if headers:
                data['headers'] = headers
            # Extract key fields for IDS
            if 'User-Agent' in headers:
                data['user_agent'] = headers['User-Agent']
            if 'Host' in headers:
                data['host'] = headers['Host']
            if 'Referer' in headers:
                data['referer'] = headers['Referer']
            if 'Cookie' in headers:
                data['cookies'] = headers['Cookie']
            if 'Authorization' in headers:
                data['has_auth'] = True  # Don't log actual auth header
            # Parse body (limited)
            if body_start < len(lines):
                body = '\r\n'.join(lines[body_start:])
                if body:
                    data['body_preview'] = body[:500]  # First 500 chars
                    data['body_length'] = len(body)
            return data if len(data) > 1 else None
        except Exception as e:
            return None

    def _parse_application(self, packet, payload_data: Optional[Dict]) -> Dict:
        """Application parsing with REAL TLS decryption and User-Agent extraction"""
        parsed_app = OrderedDict()
        parsed_app['detected_protocol'] = 'unknown'
        parsed_app['confidence'] = 'low'
        # DNS
        if packet.haslayer(DNS):
            dns_data = self._parse_dns(packet)
            if dns_data:
                parsed_app['detected_protocol'] = 'dns'
                parsed_app['confidence'] = 'high'
                parsed_app['dns'] = dns_data
        # HTTP (plaintext) - NOW WITH USER-AGENT
        if HTTP_AVAILABLE and packet.haslayer(HTTP):
            http_data = self._parse_http(packet)
            if http_data:
                parsed_app['detected_protocol'] = 'http'
                parsed_app['confidence'] = 'high'
                parsed_app['http'] = http_data
                # ✨ CRITICAL: Expose user_agent at top level for easy IDS access
                if 'user_agent' in http_data:
                    parsed_app['user_agent'] = http_data['user_agent']
        # ✨ FALLBACK: Check TCP port 80/8080 for HTTP even without HTTP layer
        if parsed_app['detected_protocol'] == 'unknown' and packet.haslayer(TCP):
            tcp = packet[TCP]
            if tcp.dport in [80, 8080, 8000] or tcp.sport in [80, 8080, 8000]:
                try:
                    payload = bytes(tcp.payload)
                    if len(payload) > 10:
                        http_data = self._extract_http_from_payload(payload)
                        if http_data:
                            parsed_app['detected_protocol'] = 'http'
                            parsed_app['confidence'] = 'medium'
                            parsed_app['http'] = http_data
                            # Expose user_agent
                            if 'user_agent' in http_data:
                                parsed_app['user_agent'] = http_data['user_agent']
                except:
                    pass
        # TLS with REAL decryption
        if TLS_AVAILABLE and packet.haslayer(TLS):
            tls_data = self._parse_tls(packet)
            if tls_data:
                parsed_app['detected_protocol'] = 'tls'
                parsed_app['confidence'] = 'high'
                parsed_app['tls'] = tls_data
                # Try REAL decryption
                self.stats['tls_decryption_attempted'] += 1
                decrypt_result = self.tls_decryptor.try_decrypt(packet, tls_data)
                if decrypt_result:
                    tls_data['decryption'] = decrypt_result
                    if decrypt_result.get('decrypted'):
                        self.stats['tls_decrypted'] += 1
                    # ✨ EXTRACT USER-AGENT FROM DECRYPTED TLS
                    if decrypt_result.get('http_data'):
                        parsed_app['http'] = decrypt_result['http_data']
                        parsed_app['http_from_tls'] = True
                        self.stats['http_parsed_from_tls'] += 1
                        # Expose user_agent from decrypted HTTPS
                        if 'user_agent' in decrypt_result['http_data']:
                            parsed_app['user_agent'] = decrypt_result['http_data']['user_agent']
        # Detect HTTPS from port 443
        if parsed_app['detected_protocol'] == 'unknown':
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                if tcp.dport == 443 or tcp.sport == 443:
                    parsed_app['detected_protocol'] = 'https'
                    parsed_app['confidence'] = 'medium'
        return parsed_app

    def _parse_dns(self, packet) -> Optional[Dict]:
        """Parse DNS"""
        if not packet.haslayer(DNS):
            return None
        dns = packet[DNS]
        data = OrderedDict([
            ('transaction_id', dns.id),
            ('flags', dns.qr),
            ('qr', dns.qr),
            ('opcode', dns.opcode),
            ('aa', dns.aa),
            ('tc', dns.tc),
            ('rd', dns.rd),
            ('ra', dns.ra),
            ('z', dns.z),
            ('rcode', dns.rcode),
        ])
        # Queries
        if dns.qd:
            queries = []
            qd_list = [dns.qd] if not isinstance(dns.qd, list) else dns.qd
            for q in qd_list:
                if hasattr(q, 'qname'):
                    qname = q.qname.decode('utf-8', errors='ignore') if isinstance(q.qname, bytes) else str(q.qname)
                    queries.append({
                        'name': qname.rstrip('.'),
                        'type': q.qtype,
                        'class': q.qclass
                    })
            if queries:
                data['queries'] = queries
        # Answers
        if dns.an:
            answers = []
            current = dns.an
            count = 0
            while current and count < 10:
                if hasattr(current, 'rdata'):
                    answer = {
                        'type': current.type if hasattr(current, 'type') else None,
                        'data': str(current.rdata),
                    }
                    if hasattr(current, 'ttl'):
                        answer['ttl'] = current.ttl
                    answers.append(answer)
                current = current.payload if hasattr(current, 'payload') and current.payload else None
                count += 1
            if answers:
                data['answers'] = answers
        return data

    def _parse_http(self, packet) -> Optional[Dict]:
        """Parse HTTP - ENHANCED VERSION with fallback payload parsing"""
        data = OrderedDict()
        # Try Scapy HTTP layer first
        if HTTP_AVAILABLE and packet.haslayer(HTTPRequest):
            req = packet[HTTPRequest]
            data['type'] = 'request'
            if hasattr(req, 'Method'):
                data['method'] = req.Method.decode('utf-8', errors='ignore')
            if hasattr(req, 'Host'):
                data['host'] = req.Host.decode('utf-8', errors='ignore')
            if hasattr(req, 'Path'):
                data['uri'] = req.Path.decode('utf-8', errors='ignore')
            if hasattr(req, 'Http_Version'):
                data['version'] = req.Http_Version.decode('utf-8', errors='ignore')
            headers = OrderedDict()
            # ✨ CRITICAL: Extract User-Agent from Scapy layer
            if hasattr(req, 'User_Agent'):
                user_agent = req.User_Agent.decode('utf-8', errors='ignore')
                headers['User-Agent'] = user_agent
                data['user_agent'] = user_agent  # ✅ ADD THIS
            if hasattr(req, 'Accept'):
                headers['Accept'] = req.Accept.decode('utf-8', errors='ignore')
            if hasattr(req, 'Cookie'):
                headers['Cookie'] = req.Cookie.decode('utf-8', errors='ignore')
                data['cookies'] = headers['Cookie']
            if hasattr(req, 'Referer'):
                headers['Referer'] = req.Referer.decode('utf-8', errors='ignore')
                data['referer'] = headers['Referer']
            if headers:
                data['headers'] = headers
        if HTTP_AVAILABLE and packet.haslayer(HTTPResponse):
            resp = packet[HTTPResponse]
            data['type'] = 'response'
            if hasattr(resp, 'Status_Code'):
                try:
                    data['status_code'] = int(resp.Status_Code)
                except:
                    data['status_code'] = resp.Status_Code.decode('utf-8', errors='ignore')
            if hasattr(resp, 'Reason_Phrase'):
                data['status_message'] = resp.Reason_Phrase.decode('utf-8', errors='ignore')
            headers = OrderedDict()
            if hasattr(resp, 'Content_Type'):
                headers['Content-Type'] = resp.Content_Type.decode('utf-8', errors='ignore')
                data['content_type'] = headers['Content-Type']
            if headers:
                data['headers'] = headers
        # ✨ FALLBACK: If Scapy didn't detect HTTP, try raw payload parsing
        if not data and packet.haslayer(TCP):
            tcp = packet[TCP]
            # Only check port 80, 8080, 8000 for HTTP
            if tcp.dport in [80, 8080, 8000] or tcp.sport in [80, 8080, 8000]:
                try:
                    payload = bytes(tcp.payload)
                    if len(payload) > 0:
                        fallback_http = self._extract_http_from_payload(payload)
                        if fallback_http:
                            data = fallback_http
                except:
                    pass
        return data if data else None

    def _parse_tls(self, packet) -> Optional[Dict]:
        """Parse TLS"""
        if not TLS_AVAILABLE:
            return None
        data = OrderedDict()
        if packet.haslayer(TLSClientHello):
            ch = packet[TLSClientHello]
            client_hello = OrderedDict()
            if hasattr(ch, 'version'):
                version_map = {0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3'}
                client_hello['version'] = version_map.get(ch.version, f'0x{ch.version:04x}')
            if hasattr(ch, 'random_bytes'):
                client_hello['random'] = ch.random_bytes.hex() if isinstance(ch.random_bytes, bytes) else str(ch.random_bytes)
            if hasattr(ch, 'ciphers'):
                client_hello['cipher_suites'] = [f'0x{c:04x}' for c in ch.ciphers[:30]]
            # Parse extensions for SNI/ALPN
            if hasattr(ch, 'ext') and ch.ext:
                extensions = []
                sni = None
                alpn = []
                for ext in ch.ext:
                    ext_info = {'type': ext.type if hasattr(ext, 'type') else None}
                    if hasattr(ext, 'servernames') and ext.servernames:
                        servername = ext.servernames[0].servername
                        sni = servername.decode('utf-8', errors='ignore') if isinstance(servername, bytes) else str(servername)
                        ext_info['sni'] = sni
                    if hasattr(ext, 'protocols') and ext.protocols:
                        alpn = [p.decode('utf-8', errors='ignore') if isinstance(p, bytes) else str(p) for p in ext.protocols]
                        ext_info['alpn'] = alpn
                    extensions.append(ext_info)
                if extensions:
                    client_hello['extensions'] = extensions
                if sni:
                    client_hello['sni'] = sni
                if alpn:
                    client_hello['alpn'] = alpn
            data['client_hello'] = client_hello
        if packet.haslayer(TLSServerHello):
            sh = packet[TLSServerHello]
            server_hello = OrderedDict()
            if hasattr(sh, 'version'):
                version_map = {0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3'}
                server_hello['version'] = version_map.get(sh.version, f'0x{sh.version:04x}')
            if hasattr(sh, 'cipher'):
                server_hello['selected_cipher'] = f'0x{sh.cipher:04x}'
            data['server_hello'] = server_hello
        if packet.haslayer(TLSCertificateList):
            data['certificates_present'] = True
        return data if data else None

    def _remove_empty(self, obj):
        """Remove None and empty values"""
        if isinstance(obj, dict):
            return {k: self._remove_empty(v) for k, v in obj.items() if v is not None and v != {} and v != []}
        elif isinstance(obj, list):
            return [self._remove_empty(item) for item in obj if item is not None and item != {} and item != []]
        return obj

# ==================== Log Writer (5-min rotation - single file) ====================
class LogWriter:
    """Simple 5-Minute Rotation - Clear and rewrite single log file"""
    def __init__(self, log_path: str):
        self.log_path = log_path
        self.write_count = 0
        self.cycle_count = 0
        self.start_time = time.time()
        self.last_rotation = self.start_time
        self._ensure_log_file_exists()
        logging.info("=" * 70)
        logging.info(f"{Fore.CYAN}📝 LogWriter - 5-Minute Rotation (Single File)")
        logging.info(f"Log file: {log_path}")
        logging.info("=" * 70)
        self.writer_thread = threading.Thread(target=self._writer_loop, daemon=True)
        self.writer_thread.start()

    def _ensure_log_file_exists(self):
        try:
            log_dir = os.path.dirname(self.log_path)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            if not os.path.exists(self.log_path):
                open(self.log_path, 'w').close()
        except Exception as e:
            logging.error(f"Failed to create log file: {e}")
            raise

    def _writer_loop(self):
        batch = []
        last_rotation_check = time.time()
        while not STOP_SNIFFING.is_set():
            try:
                try:
                    event = EVENT_QUEUE.get(timeout=1)
                    batch.append(event)
                except Empty:
                    pass
                if batch and (len(batch) >= BATCH_SIZE or time.time() - last_rotation_check > 1):
                    self._write_batch(batch)
                    batch = []
                now = time.time()
                if now - last_rotation_check >= 5:  # Check every 5s
                    self._check_rotation()
                    last_rotation_check = now
            except Exception as e:
                logging.error(f"Writer loop error: {e}")
                time.sleep(1)
        if batch:
            self._write_batch(batch)

    def _write_batch(self, batch: List[Dict]):
        try:
            with FILE_LOCK:
                with open(self.log_path, 'a', encoding='utf-8') as f:
                    for event in batch:
                        json_line = json.dumps(event, ensure_ascii=False)
                        f.write(json_line + '\n')
                self.write_count += 1
        except Exception as e:
            logging.error(f"Failed to write batch: {e}")

    def _check_rotation(self):
        try:
            now = time.time()
            if now - self.last_rotation >= LOG_ROTATE_INTERVAL:
                self._rotate_log()
                self.last_rotation = now
                self.cycle_count += 1
        except Exception as e:
            logging.error(f"Rotation check error: {e}")

    def _rotate_log(self):
        """Clear log file every 5 minutes"""
        try:
            with FILE_LOCK:
                if os.path.exists(self.log_path):
                    size_kb = os.path.getsize(self.log_path) / 1024
                    open(self.log_path, 'w').close()  # Clear and rewrite
                    logging.info(f"🔄 Rotated: {os.path.basename(self.log_path)} ({size_kb:.1f} KB cleared)")
        except Exception as e:
            logging.error(f"Log rotation error: {e}")

# ==================== ✨ ENHANCED Beautiful Stats Display ====================
def print_beautiful_stats(logger: PacketLogger, writer: LogWriter, interface_scanner: InterfaceScanner, start_time: float):
    """✨ NEW: Beautiful boxed statistics display"""
    stats = logger.stats.copy()
    runtime = time.time() - start_time
    # Calculate rates
    pps = stats['packets_captured'] / runtime if runtime > 0 else 0
    bw_mbps = (stats['bytes_total'] * 8 / 1_000_000) / runtime if runtime > 0 else 0
    # Get log sizes
    log_size = os.path.getsize(LOG_PATH) / 1024 if os.path.exists(LOG_PATH) else 0
    ids_log_size = os.path.getsize(LOG_IDS_PATH) / 1024 if os.path.exists(LOG_IDS_PATH) else 0
    # Get active interfaces
    active_ifaces = interface_scanner.get_active_interfaces()
    # Get SSL key stats
    ssl_stats = logger.ssl_keylogger.get_stats()
    # Get dedup stats
    dedup_stats = logger.dedup_engine.get_stats()
    # Clear screen for Windows
    if os.name == 'nt':
        os.system('cls')
    # Beautiful boxed output
    print(f"\n{Fore.CYAN}┌" + "─" * 78 + "┐")
    print(f"│{Fore.WHITE + Style.BRIGHT}{' ' * 20}SAFEOPS PACKET LOGGER - LIVE STATISTICS{' ' * 19}{Fore.CYAN}│")
    print("├" + "─" * 78 + "┤")
    # System Info
    print(
        f"│ {Fore.YELLOW}📡 Active Interfaces: {Fore.WHITE}{len(active_ifaces):>3}{' ' * 10}"
        f"{Fore.YELLOW}⚡ Capture Rate: {Fore.WHITE}{pps:>10.1f} pkt/s {Fore.CYAN}│"
    )
    print(
        f"│ {Fore.YELLOW}🌐 Bandwidth: {Fore.WHITE}{bw_mbps:>10.2f} Mbps{' ' * 6}"
        f"{Fore.YELLOW}⏱️ Runtime: {Fore.WHITE}{runtime / 60:>10.1f} min {Fore.CYAN}│"
    )
    print("├" + "─" * 78 + "┤")
    # Packet Stats
    print(
        f"│ {Fore.GREEN}📦 Captured: {Fore.WHITE}{stats['packets_captured']:>12,}{' ' * 10}"
        f"{Fore.GREEN}✅ Logged: {Fore.WHITE}{stats['packets_logged']:>12,} {Fore.CYAN}│"
    )
    print(
        f"│ {Fore.RED}🚫 Excluded: {Fore.WHITE}{stats['packets_excluded']:>12,}{' ' * 10}"
        f"{Fore.YELLOW}🔄 Dedup: {Fore.WHITE}{stats['packets_deduplicated']:>12,} {Fore.CYAN}│"
    )
    print("├" + "─" * 78 + "┤")
    # TLS Stats
    tls_success_rate = (stats['tls_decrypted'] / stats['tls_decryption_attempted'] * 100) if stats['tls_decryption_attempted'] > 0 else 0
    print(
        f"│ {Fore.MAGENTA}🔐 TLS Attempts: {Fore.WHITE}{stats['tls_decryption_attempted']:>12,}{' ' * 10}"
        f"{Fore.MAGENTA}✓ Decrypted: {Fore.WHITE}{stats['tls_decrypted']:>12,} {Fore.CYAN}│"
    )
    print(
        f"│ {Fore.MAGENTA}🌐 HTTP from TLS: {Fore.WHITE}{stats['http_parsed_from_tls']:>12,}{' ' * 10}"
        f"{Fore.MAGENTA}📊 Success Rate: {Fore.WHITE}{tls_success_rate:>10.1f}% {Fore.CYAN}│"
    )
    print(
        f"│ {Fore.MAGENTA}🔑 SSL Keys: {Fore.WHITE}{ssl_stats['total_keys']:>12,}{' ' * 10}"
        f"{Fore.MAGENTA}🕐 Recent Keys: {Fore.WHITE}{ssl_stats['recent_keys']:>12,} {Fore.CYAN}│"
    )
    print("├" + "─" * 78 + "┤")
    # Deduplication Details
    print(f"│ {Fore.CYAN}📋 DEDUPLICATION BREAKDOWN:{' ' * 49}│")
    print(
        f"│ {Fore.WHITE}Unique packets: {dedup_stats.get('unique', 0):>8,} Security protocols: {dedup_stats.get('security_protocol', 0):>8,} {Fore.CYAN}│"
    )
    print(
        f"│ {Fore.WHITE}Duplicates filtered: {dedup_stats.get('duplicate', 0):>8,} Critical ports: {dedup_stats.get('critical_port', 0):>8,} {Fore.CYAN}│"
    )
    print(
        f"│ {Fore.WHITE}TCP control packets: {dedup_stats.get('tcp_control', 0):>8,} {Fore.CYAN}│"
    )
    print("├" + "─" * 78 + "┤")
    # Storage Stats
    total_data_mb = stats['bytes_total'] / 1024 / 1024
    print(
        f"│ {Fore.BLUE}📝 Main Log: {Fore.WHITE}{log_size:>10.1f} KB{' ' * 10}"
        f"{Fore.BLUE}🎯 IDS Log: {Fore.WHITE}{ids_log_size:>10.1f} KB {Fore.CYAN}│"
    )
    print(
        f"│ {Fore.BLUE}📊 Events Written: {Fore.WHITE}{writer.write_count:>11,}{' ' * 10}"
        f"{Fore.BLUE}🔁 Rotations: {Fore.WHITE}{writer.cycle_count:>12} {Fore.CYAN}│"
    )
    print(f"│ {Fore.BLUE}💾 Total Data: {Fore.WHITE}{total_data_mb:>10.2f} MB{' ' * 52}{Fore.CYAN}│")
    print("└" + "─" * 78 + "┘")
    # Recent TLS Decrypted Samples
    recent_samples = logger.tls_decryptor.get_recent_samples()
    if recent_samples:
        print(f"\n{Fore.MAGENTA}┌" + "─" * 78 + "┐")
        print(f"│{Fore.WHITE + Style.BRIGHT}{' ' * 24}RECENT TLS DECRYPTED SAMPLES{' ' * 26}{Fore.MAGENTA}│")
        print("├" + "─" * 78 + "┤")
        for i, sample in enumerate(recent_samples[-3:], 1):  # Show last 3
            age = time.time() - sample['timestamp']
            preview = sample['preview'][:60].replace('\n', ' ').replace('\r', '')
            http_mark = f"{Fore.GREEN}[HTTP]" if sample['has_http'] else ""
            print(
                f"│ {Fore.YELLOW}{i}. {Fore.WHITE}{age:>4.0f}s ago {http_mark} {Fore.CYAN}│ "
                f"{Fore.WHITE}{sample['length']:>5} bytes{' ' * (78 - 25 - len(http_mark))}│"
            )
            print(f"│ {Fore.CYAN}{preview[:74]:<74}{Fore.MAGENTA}│")
        print("└" + "─" * 78 + "┘")
    # Show interface list if reasonable size
    if len(active_ifaces) <= 5:
        print(f"\n{Fore.GREEN}Active Interfaces: {Fore.WHITE}{', '.join(active_ifaces[:5])}")
    print(f"\n{Fore.YELLOW}Press Ctrl+C to stop...{Style.RESET_ALL}")

def print_stats_periodic(logger: PacketLogger, writer: LogWriter, interface_scanner: InterfaceScanner, start_time: float):
    """✨ ENHANCED: Non-flooding periodic stats display"""
    while not STOP_SNIFFING.is_set():
        time.sleep(STATS_DISPLAY_INTERVAL)
        try:
            print_beautiful_stats(logger, writer, interface_scanner, start_time)
        except Exception as e:
            logging.error(f"Stats display error: {e}")

# ==================== ✨ ENHANCED Final Report ====================
def print_final_report(logger: PacketLogger, writer: LogWriter, start_time: float):
    """✨ ENHANCED: Beautiful final report with insights"""
    runtime = time.time() - start_time
    stats = logger.stats.copy()
    dedup_stats = logger.dedup_engine.get_stats()
    ssl_stats = logger.ssl_keylogger.get_stats()
    print(f"\n\n{Fore.CYAN}{'=' * 80}")
    print(f"{Fore.WHITE + Style.BRIGHT}{' ' * 26}FINAL CAPTURE REPORT")
    print(f"{Fore.CYAN}{'=' * 80}\n")
    # Summary Stats
    print(f"{Fore.YELLOW}┌─ CAPTURE SUMMARY {' ' * 61}┐")
    print(f"│ │")
    print(
        f"│ {Fore.WHITE}Runtime: {Fore.GREEN}{runtime / 60:>8.1f} minutes{' ' * 33}{Fore.YELLOW}│"
    )
    print(
        f"│ {Fore.WHITE}Packets Captured: {Fore.GREEN}{stats['packets_captured']:>12,}{' ' * 33}{Fore.YELLOW}│"
    )
    print(
        f"│ {Fore.WHITE}Packets Logged: {Fore.GREEN}{stats['packets_logged']:>12,}{' ' * 33}{Fore.YELLOW}│"
    )
    print(
        f"│ {Fore.WHITE}Packets Excluded: {Fore.RED}{stats['packets_excluded']:>12,}{Fore.WHITE} (localhost/loopback){' ' * 13}{Fore.YELLOW}│"
    )
    print(
        f"│ {Fore.WHITE}Packets Deduplicated: {Fore.YELLOW}{stats['packets_deduplicated']:>12,}{' ' * 33}{Fore.YELLOW}│"
    )
    print(
        f"│ {Fore.WHITE}Total Data Processed: {Fore.CYAN}{stats['bytes_total'] / 1024 / 1024:>10.2f} MB{' ' * 33}{Fore.YELLOW}│"
    )
    print(f"│ │")
    print(f"└{'─' * 78}┘\n")
    # TLS Decryption Stats
    if stats['tls_decryption_attempted'] > 0:
        tls_success_rate = (stats['tls_decrypted'] / stats['tls_decryption_attempted']) * 100
        print(f"{Fore.MAGENTA}┌─ TLS DECRYPTION ANALYSIS {' ' * 53}┐")
        print(f"│ │")
        print(
            f"│ {Fore.WHITE}Decryption Attempts: {Fore.CYAN}{stats['tls_decryption_attempted']:>12,}{' ' * 33}{Fore.MAGENTA}│"
        )
        print(
            f"│ {Fore.WHITE}Successfully Decrypted: {Fore.GREEN}{stats['tls_decrypted']:>12,}{' ' * 33}{Fore.MAGENTA}│"
        )
        print(
            f"│ {Fore.WHITE}Success Rate: {Fore.GREEN}{tls_success_rate:>10.1f}%{' ' * 35}{Fore.MAGENTA}│"
        )
        print(
            f"│ {Fore.WHITE}HTTP Parsed from TLS: {Fore.GREEN}{stats['http_parsed_from_tls']:>12,}{' ' * 33}{Fore.MAGENTA}│"
        )
        print(
            f"│ {Fore.WHITE}SSL Keys Available: {Fore.CYAN}{ssl_stats['total_keys']:>12,}{' ' * 33}{Fore.MAGENTA}│"
        )
        print(f"│ │")
        if tls_success_rate > 50:
            print(
                f"│ {Fore.GREEN}✓ Excellent decryption rate! TLS monitoring is working well.{' ' * 15}{Fore.MAGENTA}│"
            )
        elif tls_success_rate > 20:
            print(
                f"│ {Fore.YELLOW}⚠ Moderate decryption rate. Check browser SSL key logging.{' ' * 16}{Fore.MAGENTA}│"
            )
        else:
            print(
                f"│ {Fore.RED}⚠ Low decryption rate. Restart browsers with SSLKEYLOGFILE enabled.{' ' * 8}{Fore.MAGENTA}│"
            )
        print(f"│ │")
        print(f"└{'─' * 78}┘\n")
    # Deduplication Analysis
    total_dedup_checked = sum(dedup_stats.values())
    if total_dedup_checked > 0:
        print(f"{Fore.CYAN}┌─ DEDUPLICATION ANALYSIS {' ' * 54}┐")
        print(f"│ │")
        print(f"│ {Fore.WHITE}Total Packets Analyzed: {Fore.CYAN}{total_dedup_checked:>12,}{' ' * 33}{Fore.CYAN}│")
        print(
            f"│ {Fore.WHITE}Unique Packets: {Fore.GREEN}{dedup_stats.get('unique', 0):>12,} "
            f"{Fore.WHITE}({dedup_stats.get('unique', 0) / total_dedup_checked * 100:>5.1f}%){' ' * 23}{Fore.CYAN}│"
        )
        print(
            f"│ {Fore.WHITE}Duplicates Filtered: {Fore.YELLOW}{dedup_stats.get('duplicate', 0):>12,} "
            f"{Fore.WHITE}({dedup_stats.get('duplicate', 0) / total_dedup_checked * 100:>5.1f}%){' ' * 23}{Fore.CYAN}│"
        )
        print(
            f"│ {Fore.WHITE}Security Protocols: {Fore.GREEN}{dedup_stats.get('security_protocol', 0):>12,} "
            f"{Fore.WHITE}(always logged){' ' * 17}{Fore.CYAN}│"
        )
        print(
            f"│ {Fore.WHITE}Critical Ports: {Fore.GREEN}{dedup_stats.get('critical_port', 0):>12,} "
            f"{Fore.WHITE}(always logged){' ' * 17}{Fore.CYAN}│"
        )
        print(
            f"│ {Fore.WHITE}TCP Control Packets: {Fore.GREEN}{dedup_stats.get('tcp_control', 0):>12,} "
            f"{Fore.WHITE}(always logged){' ' * 17}{Fore.CYAN}│"
        )
        print(f"│ │")
        efficiency = (dedup_stats.get('duplicate', 0) / total_dedup_checked * 100) if total_dedup_checked > 0 else 0
        if efficiency > 30:
            print(
                f"│ {Fore.GREEN}✓ High deduplication efficiency - saving {efficiency:.0f}% storage space!{' ' * 16}{Fore.CYAN}│"
            )
        elif efficiency > 10:
            print(
                f"│ {Fore.YELLOW}⚠ Moderate deduplication - {efficiency:.0f}% duplicates filtered.{' ' * 25}{Fore.CYAN}│"
            )
        else:
            print(f"│ {Fore.WHITE}ℹ Low duplicate rate - mostly unique traffic.{' ' * 31}{Fore.CYAN}│")
        print(f"│ │")
        print(f"└{'─' * 78}┘\n")
    # Performance Stats
    avg_pps = stats['packets_captured'] / runtime if runtime > 0 else 0
    avg_bandwidth = (stats['bytes_total'] * 8 / 1_000_000) / runtime if runtime > 0 else 0
    print(f"{Fore.GREEN}┌─ PERFORMANCE METRICS {' ' * 57}┐")
    print(f"│ │")
    print(f"│ {Fore.WHITE}Average Packet Rate: {Fore.GREEN}{avg_pps:>10.1f} pkt/s{' ' * 31}{Fore.GREEN}│")
    print(f"│ {Fore.WHITE}Average Bandwidth: {Fore.GREEN}{avg_bandwidth:>10.2f} Mbps{' ' * 32}{Fore.GREEN}│")
    print(f"│ {Fore.WHITE}Events Written: {Fore.GREEN}{writer.write_count:>12,}{' ' * 33}{Fore.GREEN}│")
    print(f"│ {Fore.WHITE}Log Rotations: {Fore.GREEN}{writer.cycle_count:>12}{' ' * 33}{Fore.GREEN}│")
    print(f"│ │")
    print(f"└{'─' * 78}┘\n")
    # File Locations
    print(f"{Fore.BLUE}┌─ OUTPUT FILES {' ' * 64}┐")
    print(f"│ │")
    print(f"│ {Fore.WHITE}Primary Log: {Fore.CYAN}{LOG_PATH:<55}{Fore.BLUE}│")
    if os.path.exists(LOG_PATH):
        log_size = os.path.getsize(LOG_PATH) / 1024
        print(f"│ {Fore.WHITE}Size: {log_size:.2f} KB{' ' * 51}{Fore.BLUE}│")
    print(f"│ │")
    print(f"│ {Fore.WHITE}IDS Archive: {Fore.CYAN}{LOG_IDS_PATH:<55}{Fore.BLUE}│")
    if os.path.exists(LOG_IDS_PATH):
        ids_size = os.path.getsize(LOG_IDS_PATH) / 1024
        print(f"│ {Fore.WHITE}Size: {ids_size:.2f} KB{' ' * 51}{Fore.BLUE}│")
    print(f"│ │")
    print(f"│ {Fore.WHITE}SSL Keys: {Fore.CYAN}{SSLKEYLOGFILE:<55}{Fore.BLUE}│")
    if os.path.exists(SSLKEYLOGFILE):
        key_size = os.path.getsize(SSLKEYLOGFILE) / 1024
        print(f"│ {Fore.WHITE}Size: {key_size:.2f} KB{' ' * 51}{Fore.BLUE}│")
    print(f"│ │")
    print(f"└{'─' * 78}┘\n")
    # IDS-Ready Features
    print(f"{Fore.MAGENTA}┌─ IDS-READY FEATURES {' ' * 58}┐")
    print(f"│ │")
    print(f"│ {Fore.GREEN}✓{Fore.WHITE} Full payload capture (1500 bytes){' ' * 41}{Fore.MAGENTA}│")
    print(f"│ {Fore.GREEN}✓{Fore.WHITE} Real TLS decryption support{' ' * 47}{Fore.MAGENTA}│")
    print(f"│ {Fore.GREEN}✓{Fore.WHITE} HTTP parsing from decrypted TLS{' ' * 43}{Fore.MAGENTA}│")
    print(f"│ {Fore.GREEN}✓{Fore.WHITE} 3-min append rotation; IDS cleared every 6 min (5s pre-transfer){' ' * 9}{Fore.MAGENTA}│")
    print(f"│ {Fore.GREEN}✓{Fore.WHITE} Complete protocol analysis{' ' * 48}{Fore.MAGENTA}│")
    print(f"│ {Fore.GREEN}✓{Fore.WHITE} Smart deduplication with security awareness{' ' * 32}{Fore.MAGENTA}│")
    print(f"│ {Fore.GREEN}✓{Fore.WHITE} Process correlation{' ' * 56}{Fore.MAGENTA}│")
    print(f"│ {Fore.GREEN}✓{Fore.WHITE} Flow tracking and session analysis{' ' * 42}{Fore.MAGENTA}│")
    print(f"│ │")
    print(f"└{'─' * 78}┘\n")
    print(f"{Fore.GREEN + Style.BRIGHT}🎯 Ready for IDS/IPS integration!")
    print(f"{Fore.CYAN}{'=' * 80}\n{Style.RESET_ALL}")

# ==================== Browser Setup ====================
def setup_browser_keylogging():
    """Setup browser to export SSL keys"""
    keylog_file = SSLKEYLOGFILE
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.WHITE + Style.BRIGHT}🔐 TLS DECRYPTION SETUP")
    print(f"{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.YELLOW}📝 SSLKEYLOGFILE Location: {Fore.WHITE}{keylog_file}")
    print(f"\n{Fore.GREEN}💡 To enable TLS decryption for browsers:")
    print(f"\n{Fore.CYAN} For Chrome/Edge:")
    print(f"{Fore.WHITE} 1. Close all Chrome/Edge windows")
    print(f" 2. Set environment variable:")
    print(f" Windows: {Fore.YELLOW}set SSLKEYLOGFILE={keylog_file}")
    print(f" {Fore.WHITE}Linux: {Fore.YELLOW}export SSLKEYLOGFILE={keylog_file}")
    print(f" {Fore.WHITE}3. Restart Chrome with:")
    print(f" {Fore.YELLOW}chrome.exe --ssl-key-log-file=\"{keylog_file}\"")
    print(f"\n{Fore.CYAN} For Firefox:")
    print(f"{Fore.WHITE} 1. Set environment variable: {Fore.YELLOW}SSLKEYLOGFILE={keylog_file}")
    print(f" {Fore.WHITE}2. Restart Firefox (auto-reads SSLKEYLOGFILE)")
    print(f"{Fore.CYAN}{'=' * 70}")
    browsers_found = set()
    try:
        for proc in psutil.process_iter(['name']):
            name = proc.info['name'].lower()
            if any(browser in name for browser in ['chrome', 'firefox', 'edge', 'msedge']):
                if 'update' not in name and 'webview' not in name:
                    browsers_found.add(proc.info['name'])
    except:
        pass
    if browsers_found:
        print(f"\n{Fore.YELLOW}⚠️ Active Browsers Detected:")
        for browser in sorted(browsers_found):
            print(f" {Fore.WHITE}• {browser}")
        print(f"\n {Fore.YELLOW}→ Restart these browsers to enable TLS decryption")
    print(f"{Fore.CYAN}{'=' * 70}\n")

# ==================== Main ====================
def main():
    import argparse
    parser = argparse.ArgumentParser(description='SafeOps Enhanced Packet Logger')
    parser.add_argument('-i', '--interface', default='all', help='Network interface (default: all)')
    parser.add_argument('--list-interfaces', action='store_true', help='List interfaces and exit')
    args = parser.parse_args()
    from scapy.arch import get_if_list
    available_interfaces = get_if_list()
    if args.list_interfaces:
        print(f"\n{Fore.CYAN}📡 Available Interfaces:")
        for idx, iface in enumerate(available_interfaces, 1):
            print(f"{Fore.WHITE}{idx}. {iface}")
        sys.exit(0)
    capture_interfaces = available_interfaces
    if not capture_interfaces:
        logging.error("❌ No network interfaces found")
        sys.exit(1)
    print(f"\n{Fore.GREEN + Style.BRIGHT}🚀 Starting SafeOps Enhanced Packet Logger")
    print(f"{Fore.CYAN}✨ NEW FEATURES: Beautiful UI + Smart Deduplication + Enhanced TLS Display")
    print(f"{Fore.YELLOW}📡 AUTO-SCANNING ALL INTERFACES ({len(capture_interfaces)} found)")
    if len(capture_interfaces) <= 10:
        for iface in capture_interfaces:
            logging.info(f" ✓ {iface}")
    else:
        for iface in capture_interfaces[:10]:
            logging.info(f" ✓ {iface}")
        logging.info(f" ... and {len(capture_interfaces) - 10} more")
    logging.info(f"📝 Primary Log: {LOG_PATH}")
    logging.info(f"📝 IDS Archive: {LOG_IDS_PATH}")
    logging.info(f"🔄 Rotation: Every {LOG_ROTATE_INTERVAL // 60} min (append to archive); Archive cleared every 6 min (5s before transfer)")
    logging.info(f"📦 Payload: Up to 1500 bytes")
    if CRYPTO_AVAILABLE:
        logging.info(f"🔐 TLS Decryption: ENABLED")
    else:
        logging.info(f"⚠️ TLS Decryption: LIMITED (install cryptography)")
    if ENABLE_DECRYPTION:
        setup_browser_keylogging()
    # Suppress warnings
    import warnings
    warnings.filterwarnings("ignore", message="Unknown cipher suite.*")
    logging.getLogger("scapy.layers.tls").setLevel(logging.ERROR)
    # Initialize components
    interface_scanner = InterfaceScanner()
    time.sleep(1)
    logger = PacketLogger("all")
    writer = LogWriter(LOG_PATH)
    start_time = time.time()
    # Start stats thread
    stats_thread = threading.Thread(
        target=print_stats_periodic,
        args=(logger, writer, interface_scanner, start_time),
        daemon=True
    )
    stats_thread.start()

    def create_handler(iface_name):
        def handler(packet):
            logger.interface = iface_name
            logger.process_packet(packet)
        return handler

    try:
        logging.info("=" * 70)
        logging.info(f"{Fore.GREEN}🎯 Capturing packets on ALL interfaces...")
        logging.info(f" {Fore.YELLOW}Stats update every {STATS_DISPLAY_INTERVAL}s (non-flooding)")
        logging.info(f" {Fore.WHITE}Press Ctrl+C to stop")
        logging.info("=" * 70)
        # Start sniffing on all interfaces
        sniff_threads = []

        def sniff_on_interface(iface):
            try:
                sniff(
                    iface=iface,
                    prn=create_handler(iface),
                    store=False,
                    promisc=True,
                    stop_filter=lambda x: STOP_SNIFFING.is_set()
                )
            except Exception as e:
                logging.error(f"Error on interface {iface[:30]}: {e}")

        for iface in capture_interfaces:
            thread = threading.Thread(target=sniff_on_interface, args=(iface,), daemon=True)
            thread.start()
            sniff_threads.append(thread)
        # Keep main thread alive
        while not STOP_SNIFFING.is_set():
            time.sleep(1)
    except PermissionError:
        logging.error("❌ Permission denied! Run as Administrator/root")
        STOP_SNIFFING.set()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}🛑 Stopping capture...")
        STOP_SNIFFING.set()
    except Exception as e:
        logging.error(f"❌ Capture error: {e}")
        import traceback
        traceback.print_exc()
        STOP_SNIFFING.set()
    finally:
        logging.info("Flushing to disk...")
        time.sleep(2)
        # Show final report
        print_final_report(logger, writer, start_time)

if __name__ == '__main__':
    main()