#!/usr/bin/env python3
"""
ids_writer.py — Enhanced Performance IDS/IPS Alert Logger

NEW FEATURES:
- Support for UPDATED network_packets.log JSON structure
- 3-minute log rotation compatibility
- Improved performance with batch processing
- Enhanced memory management
- Optimized for high-throughput scenarios
- Advanced deduplication with configurable strategies

Processes network packets into IDS/IPS alerts with:
- Essential network info (src, dst, ports, protocol)
- Deep protocol inspection (HTTP, DNS, TLS, SSH, FTP, SMTP)
- Smart filtering (skip TCP handshakes, ACKs, empty packets)
- Advanced deduplication to prevent log flooding
- IPv4 & IPv6 support
- Packet ID retention for correlation
- Timestamp in IST (Indian Standard Time)

Input:  safeops/logs/network_packets.log (auto-rotates every 3 min)
Output: safeops/logs/ids/ids.log
"""

import os
import sys
import json
import time
import uuid
import socket
import signal
import logging
import hashlib
from datetime import datetime, timezone, timedelta
from threading import Event, Lock, Thread
from queue import Queue, Full, Empty
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Dict, Any, Tuple, Set
from pathlib import Path
from collections import defaultdict

# ==================== PATHS ====================
BASE_DIR = Path(__file__).resolve().parents[4]  # safeops/
LOGS_DIR = BASE_DIR / 'logs'
BACKEND_DIR = BASE_DIR / 'backend'
MODULES_DIR = BACKEND_DIR / 'modules'

# Input/Output
INPUT_LOG = LOGS_DIR / 'network_packets.log'
INPUT_IDS_LOG = LOGS_DIR / 'network_packets_ids.log'  # Previous 3-min window
IDS_DIR = LOGS_DIR / 'ids'
IDS_LOG = IDS_DIR / 'ids.log'

IDS_DIR.mkdir(parents=True, exist_ok=True)

# ==================== ENHANCED CONFIGURATION ====================
DEVICE_ID = socket.gethostname()
WORKER_THREADS = 8  # Increased for better throughput
QUEUE_MAXSIZE = 20000
POLL_INTERVAL = 0.05  # Faster polling (50ms)

# Advanced deduplication settings
DUPLICATE_SUPPRESS_SECONDS = 600.0  # 10 minutes
DEDUP_STRATEGY = 'connection'  # 5-tuple based
CONNECTION_TIMEOUT = 1800.0  # 30 minutes

# Performance optimizations
BATCH_WRITE_SIZE = 100  # Write logs in batches
BATCH_WRITE_TIMEOUT = 1.0  # Max wait time for batch
LOG_ROTATION_CHECK_INTERVAL = 30  # Check rotation every 30s
CACHE_CLEANUP_INTERVAL = 60  # Cleanup caches every 60s

# AGGRESSIVE FILTERING
SKIP_TCP_HANDSHAKES = True  # Skip SYN, SYN-ACK
SKIP_TCP_CLOSE = True  # Skip FIN, RST
SKIP_PURE_ACKS = True  # Skip ACK-only packets
LOG_ONLY_APP_LAYER = True  # ENFORCE: Only packets with application data

# IST timezone offset (UTC+5:30)
IST_OFFSET = timedelta(hours=5, minutes=30)

# ==================== LOGGING ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
log = logging.getLogger('ids_writer')


class BatchLogger:
    """High-performance batch logger with buffering"""

    def __init__(self, path: Path, batch_size: int = 100, timeout: float = 1.0):
        self.path = path
        self.batch_size = batch_size
        self.timeout = timeout
        self.buffer = []
        self.lock = Lock()
        self.last_flush = time.time()

    def write(self, message: str):
        """Add message to buffer"""
        with self.lock:
            self.buffer.append(message)

            # Auto-flush on batch size or timeout
            if len(self.buffer) >= self.batch_size or \
                    (time.time() - self.last_flush) >= self.timeout:
                self._flush_unsafe()

    def _flush_unsafe(self):
        """Flush buffer to disk (must be called with lock held)"""
        if not self.buffer:
            return

        try:
            with open(self.path, 'a', encoding='utf-8') as f:
                f.write('\n'.join(self.buffer) + '\n')

            self.buffer.clear()
            self.last_flush = time.time()
        except Exception as e:
            log.error(f"Batch write failed: {e}")

    def flush(self):
        """Force flush buffer"""
        with self.lock:
            self._flush_unsafe()


# Initialize batch logger
ids_logger = BatchLogger(IDS_LOG, BATCH_WRITE_SIZE, BATCH_WRITE_TIMEOUT)


# ==================== ENHANCED DUPLICATE SUPPRESSION ====================
class EnhancedDuplicateFilter:
    """
    Multi-layer deduplication with performance optimizations:
    1. Connection-level (5-tuple) grouping with time windows
    2. Protocol-specific suppression (HTTP flows, DNS queries, TLS handshakes)
    3. Intelligent cache cleanup and rotation
    4. Real-time statistics
    5. LRU-style cache management
    """

    def __init__(self, strategy='connection', max_cache_size=50000):
        self.strategy = strategy
        self.max_cache_size = max_cache_size

        # Connection cache: key -> {first_seen, last_seen, count, app_type, payload_hash}
        self.connection_cache: Dict[str, Dict[str, Any]] = {}

        # Per-connection payload tracking to avoid duplicates
        self.connection_payloads: Dict[str, Set[str]] = defaultdict(set)

        self.lock = Lock()
        self.last_cleanup = time.time()

        self.stats = {
            'total_packets': 0,
            'connection_duplicates': 0,
            'payload_duplicates': 0,
            'flow_duplicates': 0,
            'tcp_handshake_filtered': 0,
            'tcp_close_filtered': 0,
            'ack_filtered': 0,
            'no_app_layer_filtered': 0,
            'unique_logged': 0,
            'expired_connections': 0,
        }

    def _generate_connection_key(self, record: dict) -> str:
        """Generate 5-tuple connection key (src_ip:port -> dst_ip:port:protocol)"""
        src_ip = record.get('src_ip', '')
        dst_ip = record.get('dst_ip', '')
        src_port = record.get('src_port', 0)
        dst_port = record.get('dst_port', 0)
        protocol = record.get('protocol', '')

        key_str = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{protocol}"
        return hashlib.md5(key_str.encode()).hexdigest()[:16]  # Shorter hash

    def _generate_payload_hash(self, record: dict) -> str:
        """
        Generate hash of significant payload for deduplication.
        Protocol-specific: DNS/UDP are stateless, TCP streams need connection tracking.
        """
        payload_parts = []
        protocol = record.get('protocol', '').upper()

        # For UDP (DNS, stateless) - include full query details
        if protocol == 'UDP':
            if 'dns' in record:
                dns_data = record['dns']
                # Include query AND query_type to distinguish A vs AAAA lookups
                payload_parts.append(dns_data.get('query', ''))
                payload_parts.append(str(dns_data.get('query_type', '')))
                payload_parts.append(str(dns_data.get('response_code', '')))

        # HTTP (stateful, connection-based)
        elif 'http' in record:
            http_data = record['http']
            payload_parts.append(http_data.get('method', ''))
            payload_parts.append(http_data.get('host', ''))
            payload_parts.append(http_data.get('uri', ''))
            payload_parts.append(str(http_data.get('status_code', '')))

        # TLS (stateful, per-connection)
        elif 'tls' in record:
            tls_data = record['tls']
            payload_parts.append(tls_data.get('sni', ''))

        # SSH (stateful)
        elif 'ssh' in record:
            payload_parts.append('ssh_session')

        # FTP (stateful)
        elif 'ftp' in record:
            ftp_data = record['ftp']
            payload_parts.append(ftp_data.get('command', ''))
            payload_parts.append(ftp_data.get('filename', ''))

        # SMTP (stateful)
        elif 'smtp' in record:
            smtp_data = record['smtp']
            payload_parts.append(smtp_data.get('from', ''))
            payload_parts.append(smtp_data.get('to', ''))
            payload_parts.append(smtp_data.get('subject', ''))

        payload_str = '|'.join(str(p) for p in payload_parts if p)
        return hashlib.md5(payload_str.encode()).hexdigest()[:16] if payload_str else ''

    def check_duplicate(self, record: dict) -> Tuple[bool, str]:
        """
        Smart deduplication with performance optimizations:
        - UDP (stateless): Deduplicate only exact payload matches
        - TCP (stateful): Deduplicate by connection + payload
        Returns: (is_duplicate, reason)
        """
        now = time.time()
        protocol = record.get('protocol', '').upper()
        conn_key = self._generate_connection_key(record)
        payload_hash = self._generate_payload_hash(record)

        if not conn_key or not payload_hash:
            return False, 'no_key'

        with self.lock:
            self.stats['total_packets'] += 1

            # UDP is stateless - deduplicate by EXACT payload only
            if protocol == 'UDP':
                # For UDP, check if exact payload already seen in this connection
                if payload_hash in self.connection_payloads.get(conn_key, set()):
                    self.stats['payload_duplicates'] += 1
                    return True, 'udp_dup'

                # New UDP payload - add to seen set
                if conn_key not in self.connection_payloads:
                    self.connection_payloads[conn_key] = set()
                self.connection_payloads[conn_key].add(payload_hash)
                self.stats['unique_logged'] += 1

                # Automatic cleanup if cache too large
                if len(self.connection_payloads) > self.max_cache_size:
                    self._cleanup_cache_unsafe(now, DUPLICATE_SUPPRESS_SECONDS)

                return False, 'unique'

            # TCP is stateful - connection tracking
            elif protocol == 'TCP':
                cached_conn = self.connection_cache.get(conn_key)

                if cached_conn:
                    elapsed = now - cached_conn['last_seen']

                    # Connection still active
                    if elapsed < DUPLICATE_SUPPRESS_SECONDS:
                        # Check payload within connection
                        if payload_hash in self.connection_payloads[conn_key]:
                            self.stats['payload_duplicates'] += 1
                            return True, 'tcp_payload_dup'

                        # New payload in same TCP connection - log it
                        self.connection_payloads[conn_key].add(payload_hash)
                        cached_conn['last_seen'] = now
                        cached_conn['count'] += 1
                        self.stats['unique_logged'] += 1
                        return False, 'unique'
                    else:
                        # Connection expired - reset
                        self.stats['expired_connections'] += 1
                        self.connection_cache[conn_key] = {
                            'first_seen': now,
                            'last_seen': now,
                            'count': 1,
                            'app_type': protocol,
                        }
                        self.connection_payloads[conn_key] = {payload_hash}
                        self.stats['unique_logged'] += 1
                        return False, 'unique'
                else:
                    # New TCP connection
                    self.connection_cache[conn_key] = {
                        'first_seen': now,
                        'last_seen': now,
                        'count': 1,
                        'app_type': protocol,
                    }
                    self.connection_payloads[conn_key] = {payload_hash}
                    self.stats['unique_logged'] += 1

                    # Automatic cleanup if cache too large
                    if len(self.connection_cache) > self.max_cache_size:
                        self._cleanup_cache_unsafe(now, DUPLICATE_SUPPRESS_SECONDS)

                    return False, 'unique'

            else:
                # Other protocols - log all
                self.stats['unique_logged'] += 1
                return False, 'unique'

    def _cleanup_cache_unsafe(self, now: float, suppress_seconds: float):
        """Cleanup expired entries (must be called with lock held)"""
        cutoff = now - CONNECTION_TIMEOUT
        old_conn_size = len(self.connection_cache)
        old_payload_size = len(self.connection_payloads)

        # Remove expired connections
        expired_keys = [k for k, v in self.connection_cache.items()
                        if v['last_seen'] < cutoff]

        for k in expired_keys:
            del self.connection_cache[k]
            if k in self.connection_payloads:
                del self.connection_payloads[k]

        # If still too large, remove oldest entries (LRU)
        if len(self.connection_cache) > self.max_cache_size:
            sorted_items = sorted(self.connection_cache.items(),
                                  key=lambda x: x[1]['last_seen'])
            keep_count = int(self.max_cache_size * 0.8)  # Keep 80%

            # Remove oldest
            remove_keys = [k for k, _ in sorted_items[:-keep_count]]
            for k in remove_keys:
                del self.connection_cache[k]
                if k in self.connection_payloads:
                    del self.connection_payloads[k]

        cleaned = (old_conn_size - len(self.connection_cache))
        if cleaned > 0:
            log.debug(f"Cleaned {cleaned} expired connections")

    def periodic_cleanup(self, suppress_seconds: float):
        """Manual cleanup call for background thread"""
        now = time.time()

        # Only cleanup if needed
        if now - self.last_cleanup < CACHE_CLEANUP_INTERVAL:
            return

        with self.lock:
            self._cleanup_cache_unsafe(now, suppress_seconds)
            self.last_cleanup = now

    def increment_filter_stat(self, key: str):
        """Increment filter statistics"""
        with self.lock:
            if key in self.stats:
                self.stats[key] += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics with corrected percentage calculations"""
        with self.lock:
            total_packets_seen = self.stats['total_packets']

            # Total filtered packets (all types)
            total_filtered = (self.stats['tcp_handshake_filtered'] +
                              self.stats['tcp_close_filtered'] +
                              self.stats['ack_filtered'] +
                              self.stats['no_app_layer_filtered'])

            # Total duplicates removed
            total_duplicates = (self.stats['connection_duplicates'] +
                                self.stats['payload_duplicates'] +
                                self.stats['flow_duplicates'])

            # Calculate rates based on total seen
            if total_packets_seen > 0:
                dup_rate = (total_duplicates / total_packets_seen * 100)
                filter_rate = (total_filtered / total_packets_seen * 100)
            else:
                dup_rate = 0.0
                filter_rate = 0.0

            return {
                'total_seen': total_packets_seen,
                'total_filtered': total_filtered,
                'total_duplicates': total_duplicates,
                'connection_dups': self.stats['connection_duplicates'],
                'payload_dups': self.stats['payload_duplicates'],
                'handshakes_filtered': self.stats['tcp_handshake_filtered'],
                'close_filtered': self.stats['tcp_close_filtered'],
                'acks_filtered': self.stats['ack_filtered'],
                'no_app_filtered': self.stats['no_app_layer_filtered'],
                'unique_logged': self.stats['unique_logged'],
                'dedup_rate': f"{dup_rate:.2f}%",
                'filter_rate': f"{filter_rate:.2f}%",
                'active_connections': len(self.connection_cache),
                'expired_cleaned': self.stats['expired_connections'],
            }


dup_filter = EnhancedDuplicateFilter(strategy=DEDUP_STRATEGY)


# ==================== HELPERS ====================
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def to_ist(utc_timestamp: str) -> str:
    """Convert UTC to IST"""
    try:
        if 'Z' in utc_timestamp:
            utc_timestamp = utc_timestamp.replace('Z', '+00:00')
        dt = datetime.fromisoformat(utc_timestamp)
        ist_dt = dt + IST_OFFSET
        return ist_dt.strftime('%Y-%m-%d %H:%M:%S IST')
    except Exception:
        return utc_timestamp


def safe_int(value, default=None):
    try:
        return int(value) if value not in (None, '') else default
    except (ValueError, TypeError):
        return default


def has_meaningful_data(obj: Any) -> bool:
    """Check if object has meaningful data"""
    if obj is None or obj == '' or obj == 0 or obj == []:
        return False
    if isinstance(obj, dict):
        # Dict is meaningful if it has at least one non-empty key-value pair
        for v in obj.values():
            if v not in (None, '', 0, [], {}):
                return True
        return False
    if isinstance(obj, (list, str)):
        return len(obj) > 0
    return True


def extract_timestamp(packet: dict) -> Tuple[str, str]:
    """Extract timestamp - UTC and IST (UPDATED for new schema)"""
    ts = packet.get('timestamp', {})

    if isinstance(ts, dict):
        utc_iso = ts.get('iso8601')
        if not utc_iso:
            epoch = ts.get('epoch')
            if epoch:
                utc_iso = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
            else:
                utc_iso = now_iso()
    elif isinstance(ts, (int, float)):
        utc_iso = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    elif isinstance(ts, str):
        utc_iso = ts
    else:
        utc_iso = now_iso()

    ist_time = to_ist(utc_iso)
    return utc_iso, ist_time


def should_skip_packet(packet: dict, protocol: str, tcp_flags: dict, parsed_app: dict) -> Tuple[bool, str]:
    """
    Aggressive filtering - returns (skip, reason)
    Skip packets that don't have application layer data or are TCP control packets
    """

    # TCP handshake filtering
    if SKIP_TCP_HANDSHAKES and protocol == 'TCP' and tcp_flags:
        # SYN (connection initiation)
        if tcp_flags.get('syn') and not tcp_flags.get('ack'):
            dup_filter.increment_filter_stat('tcp_handshake_filtered')
            return True, 'tcp_syn'

        # SYN-ACK (handshake response)
        if tcp_flags.get('syn') and tcp_flags.get('ack'):
            dup_filter.increment_filter_stat('tcp_handshake_filtered')
            return True, 'tcp_synack'

    # TCP close filtering
    if SKIP_TCP_CLOSE and protocol == 'TCP' and tcp_flags:
        if tcp_flags.get('fin') or tcp_flags.get('rst'):
            dup_filter.increment_filter_stat('tcp_close_filtered')
            return True, 'tcp_close'

    # Pure ACK filtering
    if SKIP_PURE_ACKS and protocol == 'TCP' and tcp_flags:
        if tcp_flags.get('ack') and not tcp_flags.get('psh') and not tcp_flags.get('syn') and not tcp_flags.get(
                'fin') and not tcp_flags.get('rst'):
            dup_filter.increment_filter_stat('ack_filtered')
            return True, 'pure_ack'

    # Application layer enforcement
    if LOG_ONLY_APP_LAYER:
        detected_proto = parsed_app.get('detected_protocol', '').lower()

        has_app_data = False

        # Check each protocol type
        if detected_proto in ('http', 'https'):
            http_data = parsed_app.get('http', {})
            if has_meaningful_data(http_data):
                has_app_data = True

        elif detected_proto == 'dns':
            dns_data = parsed_app.get('dns', {})
            if has_meaningful_data(dns_data):
                has_app_data = True

        elif detected_proto == 'tls':
            tls_data = parsed_app.get('tls', {})
            if has_meaningful_data(tls_data):
                has_app_data = True

        elif detected_proto in ('ssh', 'ftp', 'smtp'):
            proto_data = parsed_app.get(detected_proto, {})
            if has_meaningful_data(proto_data):
                has_app_data = True

        if not has_app_data:
            dup_filter.increment_filter_stat('no_app_layer_filtered')
            return True, 'no_app_data'

    return False, 'pass'


# ==================== OPTIMIZED SCHEMA MAPPER ====================
def map_to_ids_schema(packet: dict) -> Optional[dict]:
    """
    Map raw packet to IDS schema with retention of packet_id for correlation.
    UPDATED: Support new JSON structure from network_packets.log
    Returns None if packet should be skipped.

    Priority order:
    1. timestamp_ist
    2. packet_id (for correlation)
    3. src_ip, dst_ip
    4. src_port, dst_port
    5. protocol
    6. Protocol-specific data (http, dns, tls, etc.)
    """

    layers = packet.get('layers', {})
    network = layers.get('network', {})
    transport = layers.get('transport', {})
    parsed_app = packet.get('parsed_application', {})

    # Protocol identification
    proto_num = network.get('protocol') or transport.get('protocol')
    protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
    protocol = protocol_map.get(proto_num, str(proto_num) if proto_num else 'UNKNOWN')

    # TCP flags
    tcp_flags = transport.get('tcp_flags', {})

    # AGGRESSIVE FILTERING
    should_skip, skip_reason = should_skip_packet(packet, protocol, tcp_flags, parsed_app)
    if should_skip:
        return None

    # Timestamps (UPDATED for new schema)
    utc_timestamp, ist_timestamp = extract_timestamp(packet)

    # Network basics (IPv4 & IPv6)
    src_ip = network.get('src_ip', '')
    dst_ip = network.get('dst_ip', '')
    src_port = safe_int(transport.get('src_port'))
    dst_port = safe_int(transport.get('dst_port'))

    # Build record - ANALYST FRIENDLY ORDER
    record = {
        'timestamp_ist': ist_timestamp,
        'packet_id': packet.get('packet_id', f"pkt_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"),
        'src_ip': src_ip,
        'dst_ip': dst_ip,
    }

    if src_port is not None:
        record['src_port'] = src_port
    if dst_port is not None:
        record['dst_port'] = dst_port

    record['protocol'] = protocol

    # Protocol-specific data (UPDATED for new schema)
    detected_proto = parsed_app.get('detected_protocol', '').lower()

    # HTTP/HTTPS
    http_data = parsed_app.get('http', {})
    if detected_proto in ('http', 'https') and has_meaningful_data(http_data):
        http_obj = {}
        if http_data.get('method'):
            http_obj['method'] = http_data['method']
        if http_data.get('host'):
            http_obj['host'] = http_data['host']
        if http_data.get('uri'):
            http_obj['uri'] = http_data['uri']
        if http_data.get('status_code'):
            http_obj['status_code'] = http_data['status_code']

        headers = http_data.get('headers', {})
        if headers.get('User-Agent'):
            http_obj['user_agent'] = headers['User-Agent']
        if headers.get('Content-Type'):
            http_obj['content_type'] = headers['Content-Type']

        # Construct full URL
        if http_data.get('host') and http_data.get('uri'):
            scheme = 'https' if detected_proto == 'https' or dst_port == 443 else 'http'
            http_obj['url'] = f"{scheme}://{http_data['host']}{http_data['uri']}"

        if http_obj:
            record['http'] = http_obj

    # DNS - Fixed to handle new schema
    dns_data = parsed_app.get('dns', {})
    if detected_proto == 'dns' and has_meaningful_data(dns_data):
        dns_obj = {}

        # Queries
        queries = dns_data.get('queries', [])
        if queries:
            q = queries[0]
            dns_obj['query'] = q.get('name', '')
            dns_obj['query_type'] = str(q.get('type', ''))

        # Answers
        answers = dns_data.get('answers', [])
        if answers:
            # Clean up answers
            cleaned_answers = []
            for answer in answers[:10]:  # Limit to 10 answers
                answer_data = answer.get('data', '')
                # Remove b'...' wrapper if present
                if isinstance(answer_data, str):
                    if answer_data.startswith("b'") and answer_data.endswith("'"):
                        answer_data = answer_data[2:-1]
                    if answer_data.startswith('b"') and answer_data.endswith('"'):
                        answer_data = answer_data[2:-1]
                cleaned_answers.append(answer_data)

            if cleaned_answers:
                dns_obj['answers'] = cleaned_answers

            # TTL from first answer
            if answers[0].get('ttl'):
                dns_obj['ttl'] = answers[0]['ttl']

        # Response code
        if dns_data.get('rcode') is not None:
            dns_obj['response_code'] = str(dns_data['rcode'])

        if dns_obj:
            record['dns'] = dns_obj

    # TLS (UPDATED for new schema)
    tls_data = parsed_app.get('tls', {})
    if detected_proto == 'tls' and has_meaningful_data(tls_data):
        tls_obj = {}

        # Client Hello
        client_hello = tls_data.get('client_hello', {})
        if client_hello.get('sni'):
            tls_obj['sni'] = client_hello['sni']
        if client_hello.get('version'):
            tls_obj['version'] = client_hello['version']

        # ALPN
        alpn = client_hello.get('alpn')
        if alpn:
            tls_obj['alpn'] = ','.join(alpn) if isinstance(alpn, list) else str(alpn)

        # Cipher suite
        if client_hello.get('cipher_suites'):
            tls_obj['cipher_suites'] = client_hello['cipher_suites'][:5]  # First 5

        # Server Hello
        server_hello = tls_data.get('server_hello', {})
        if server_hello.get('selected_cipher'):
            tls_obj['selected_cipher'] = server_hello['selected_cipher']

        # Decryption status
        decryption = tls_data.get('decryption', {})
        if decryption.get('decrypted'):
            tls_obj['decrypted'] = True

        if tls_obj:
            record['tls'] = tls_obj

    # SSH
    ssh_data = parsed_app.get('ssh', {})
    if detected_proto == 'ssh' and has_meaningful_data(ssh_data):
        ssh_obj = {}
        if ssh_data.get('version'):
            ssh_obj['version'] = ssh_data['version']
        if ssh_data.get('banner'):
            ssh_obj['banner'] = ssh_data['banner']
        if ssh_obj:
            record['ssh'] = ssh_obj

    # FTP
    ftp_data = parsed_app.get('ftp', {})
    if detected_proto == 'ftp' and has_meaningful_data(ftp_data):
        ftp_obj = {}
        if ftp_data.get('command'):
            ftp_obj['command'] = ftp_data['command']
        if ftp_data.get('filename'):
            ftp_obj['filename'] = ftp_data['filename']
        if ftp_obj:
            record['ftp'] = ftp_obj

    # SMTP
    smtp_data = parsed_app.get('smtp', {})
    if detected_proto == 'smtp' and has_meaningful_data(smtp_data):
        smtp_obj = {}
        if smtp_data.get('from'):
            smtp_obj['from'] = smtp_data['from']
        if smtp_data.get('to'):
            smtp_obj['to'] = smtp_data['to']
        if smtp_data.get('subject'):
            smtp_obj['subject'] = smtp_data['subject']
        if smtp_obj:
            record['smtp'] = smtp_obj

    # TCP flags (if meaningful)
    if protocol == 'TCP' and tcp_flags:
        flags = []
        flag_map = {'syn': 'S', 'ack': 'A', 'fin': 'F', 'rst': 'R', 'psh': 'P', 'urg': 'U'}
        for flag, abbrev in flag_map.items():
            if tcp_flags.get(flag):
                flags.append(abbrev)
        if flags:
            record['tcp_flags'] = ''.join(flags)

    # Session/Flow ID for correlation
    session_track = packet.get('session_tracking', {})
    flow_ctx = packet.get('flow_context', {})
    session_id = session_track.get('session_id') or flow_ctx.get('flow_id')
    if session_id:
        record['session_id'] = session_id

    # Bytes transferred (if significant)
    bytes_sent = flow_ctx.get('bytes_forward', 0) or 0
    bytes_recv = flow_ctx.get('bytes_backward', 0) or 0
    total_bytes = bytes_sent + bytes_recv

    if total_bytes > 0:
        record['bytes'] = total_bytes

    # Gaming traffic
    if parsed_app.get('gaming', {}).get('detected'):
        gaming = parsed_app['gaming']
        record['gaming_service'] = gaming.get('service', 'Unknown')

    return record


# ==================== OPTIMIZED WORKER ====================
def process_packet_line(line: str) -> Optional[dict]:
    """Process single packet line with error handling"""
    line = line.strip()
    if not line:
        return None

    try:
        packet = json.loads(line)
    except Exception:
        return None

    try:
        record = map_to_ids_schema(packet)
        if not record:
            return None
    except Exception as e:
        log.debug(f"Mapping error: {e}")
        return None

    # Advanced duplicate suppression
    is_dup, dup_reason = dup_filter.check_duplicate(record)
    if is_dup:
        return None

    # Log to ids.log (batched)
    ids_logger.write(json.dumps(record, separators=(',', ':'), ensure_ascii=False))

    return record


# ==================== PRODUCER (Enhanced Tail with Rotation Support) ====================
def tail_file(path: Path, queue: Queue, stop_event: Event, poll_interval: float):
    """Enhanced tail with 3-minute rotation support"""
    last_inode = None
    last_size = 0
    fh = None
    lineno = 0
    rotation_count = 0

    log.info(f"Starting enhanced tail on {path}")

    while not stop_event.is_set():
        try:
            if not path.exists():
                # Check if IDS log exists (previous rotation window)
                ids_log = path.parent / 'network_packets_ids.log'
                if ids_log.exists() and fh is None:
                    log.info(f"Primary log not found, processing IDS log: {ids_log}")
                    path = ids_log
                else:
                    time.sleep(poll_interval)
                    continue

            stat = path.stat()
            curr_inode = (stat.st_ino, stat.st_dev)
            curr_size = stat.st_size

            if fh is None:
                fh = open(path, 'r', encoding='utf-8', errors='replace')
                # Start from end for real-time processing
                fh.seek(0, 2)
                last_inode = curr_inode
                last_size = curr_size
                log.info(f"Opened {path} - starting from END (real-time mode)")

            # Detect rotation or truncation
            if curr_inode != last_inode or curr_size < last_size:
                rotation_count += 1
                log.info(f"Detected rotation #{rotation_count}, reopening {path}")
                fh.close()

                # Try to open new file
                if path.exists():
                    fh = open(path, 'r', encoding='utf-8', errors='replace')
                    fh.seek(0, 2)  # Start from end
                    last_inode = curr_inode
                    last_size = curr_size
                else:
                    fh = None
                    time.sleep(poll_interval)
                continue

            pos = fh.tell()
            line = fh.readline()

            if not line:
                # No new data, check for rotation
                time.sleep(poll_interval)
                fh.seek(pos)
                continue

            lineno += 1

            try:
                queue.put_nowait((line, lineno))
            except Full:
                # Queue full, log warning
                if lineno % 1000 == 0:
                    log.warning(f"Queue full at line {lineno}, processing slower")
                time.sleep(poll_interval * 2)

        except Exception as e:
            log.error(f"Tail error: {e}")
            if fh:
                fh.close()
                fh = None
            time.sleep(poll_interval)

    if fh:
        fh.close()

    log.info(f"Stopped tailing {path} (processed {lineno} lines, {rotation_count} rotations)")


# ==================== ENHANCED CONSUMER WITH BATCH PROCESSING ====================
def consumer_loop(queue: Queue, stop_event: Event, workers: int):
    """Enhanced consumer with batch processing and performance metrics"""
    stats = {
        'processed': 0,
        'written': 0,
        'duplicates': 0,
        'errors': 0,
        'batches': 0
    }

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix='ids_worker') as executor:
        futures = []
        last_flush = time.time()

        while not stop_event.is_set() or not queue.empty():
            try:
                item = queue.get(timeout=0.2)
            except Empty:
                # Force flush on timeout
                if time.time() - last_flush > BATCH_WRITE_TIMEOUT:
                    ids_logger.flush()
                    last_flush = time.time()
                continue

            line, lineno = item
            stats['processed'] += 1

            # Submit for processing
            future = executor.submit(process_packet_line, line)
            futures.append(future)

            # Batch completion check
            if len(futures) >= BATCH_WRITE_SIZE * 2:
                done_futures = []
                for f in futures:
                    if f.done():
                        try:
                            result = f.result()
                            if result:
                                stats['written'] += 1
                            else:
                                stats['duplicates'] += 1
                        except Exception as e:
                            stats['errors'] += 1
                            log.debug(f"Processing error: {e}")
                        done_futures.append(f)

                futures = [f for f in futures if f not in done_futures]

                # Force flush batch
                ids_logger.flush()
                last_flush = time.time()
                stats['batches'] += 1

        # Process remaining futures
        for f in futures:
            try:
                result = f.result(timeout=5)
                if result:
                    stats['written'] += 1
                else:
                    stats['duplicates'] += 1
            except Exception as e:
                stats['errors'] += 1
                log.debug(f"Final processing error: {e}")

    # Final flush
    ids_logger.flush()

    # Calculate performance metrics
    elapsed = time.time() - start_time
    pps = stats['processed'] / elapsed if elapsed > 0 else 0

    log.info(f"Consumer stats: {stats}")
    log.info(f"Performance: {pps:.2f} packets/sec, {elapsed:.2f} seconds total")


# ==================== STATS THREAD ====================
def stats_thread(stop_event: Event):
    """Print enhanced statistics every 30 seconds"""
    log.info("Started stats thread")

    last_stats = {'total_seen': 0, 'unique_logged': 0}

    while not stop_event.is_set():
        time.sleep(30)

        if stop_event.is_set():
            break

        try:
            ids_size = IDS_LOG.stat().st_size / 1024 / 1024 if IDS_LOG.exists() else 0
            stats = dup_filter.get_stats()

            # Calculate delta
            delta_total = stats['total_seen'] - last_stats['total_seen']
            delta_unique = stats['unique_logged'] - last_stats['unique_logged']
            rate = delta_total / 30.0  # per second

            last_stats['total_seen'] = stats['total_seen']
            last_stats['unique_logged'] = stats['unique_logged']

            log.info(
                f"📊 IDS: {ids_size:.1f}MB | "
                f"Rate: {rate:.1f} pkt/s | "
                f"Logged: {stats['unique_logged']:,} | "
                f"Dedup: {stats['dedup_rate']} | "
                f"Filter: {stats['filter_rate']} | "
                f"Conns: {stats['active_connections']:,}"
            )

            # Periodic cache cleanup
            dup_filter.periodic_cleanup(DUPLICATE_SUPPRESS_SECONDS)

        except Exception as e:
            log.debug(f"Stats error: {e}")

    log.info("Stopped stats thread")


# ==================== CACHE CLEANUP THREAD ====================
def cache_cleanup_thread(stop_event: Event):
    """Dedicated thread for cache maintenance"""
    log.info("Started cache cleanup thread")

    while not stop_event.is_set():
        time.sleep(CACHE_CLEANUP_INTERVAL)

        if stop_event.is_set():
            break

        try:
            # Cleanup deduplication cache
            dup_filter.periodic_cleanup(DUPLICATE_SUPPRESS_SECONDS)

            # Force batch flush
            ids_logger.flush()

            log.debug("Cache cleanup completed")

        except Exception as e:
            log.error(f"Cache cleanup error: {e}")

    log.info("Stopped cache cleanup thread")


# ==================== LOG ROTATION MONITOR THREAD ====================
def rotation_monitor_thread(stop_event: Event, input_path: Path):
    """Monitor for log rotation events"""
    log.info("Started rotation monitor thread")

    last_check = time.time()
    last_inode = None
    rotation_count = 0

    while not stop_event.is_set():
        time.sleep(LOG_ROTATION_CHECK_INTERVAL)

        if stop_event.is_set():
            break

        try:
            if input_path.exists():
                stat = input_path.stat()
                curr_inode = (stat.st_ino, stat.st_dev)

                if last_inode is not None and curr_inode != last_inode:
                    rotation_count += 1
                    log.info(f"🔄 Log rotation detected (#{rotation_count})")

                    # Force flush on rotation
                    ids_logger.flush()

                last_inode = curr_inode

            last_check = time.time()

        except Exception as e:
            log.debug(f"Rotation monitor error: {e}")

    log.info(f"Stopped rotation monitor (detected {rotation_count} rotations)")


# ==================== SIGNALS ====================
STOP_EVENT = Event()


def signal_handler(signum, frame):
    log.info(f"Received signal {signum}, shutting down...")
    STOP_EVENT.set()


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# ==================== MAIN ====================
def main():
    log.info("=" * 80)
    log.info("🛡️  SAFEOPS IDS/IPS Alert Logger - Enhanced Performance Edition")
    log.info("=" * 80)
    log.info(f"Input:  {INPUT_LOG}")
    log.info(f"Output: {IDS_LOG}")
    log.info(f"Config:")
    log.info(f"  - Workers: {WORKER_THREADS}")
    log.info(f"  - Queue size: {QUEUE_MAXSIZE}")
    log.info(f"  - Batch size: {BATCH_WRITE_SIZE}")
    log.info(f"  - Batch timeout: {BATCH_WRITE_TIMEOUT}s")
    log.info(f"  - Dedup strategy: {DEDUP_STRATEGY}")
    log.info(f"  - Dedup window: {DUPLICATE_SUPPRESS_SECONDS}s")
    log.info(f"  - Poll interval: {POLL_INTERVAL}s")
    log.info(f"Filters:")
    log.info(f"  - Skip handshakes: {SKIP_TCP_HANDSHAKES}")
    log.info(f"  - Skip close: {SKIP_TCP_CLOSE}")
    log.info(f"  - Skip ACKs: {SKIP_PURE_ACKS}")
    log.info(f"  - App layer only: {LOG_ONLY_APP_LAYER}")
    log.info(f"Mode: Real-time (starts from end of file)")
    log.info(f"IPv4 & IPv6: Supported")
    log.info("=" * 80)

    queue = Queue(maxsize=QUEUE_MAXSIZE)
    threads = []

    # Start consumer
    consumer = Thread(
        target=consumer_loop,
        args=(queue, STOP_EVENT, WORKER_THREADS),
        daemon=True,
        name='consumer'
    )
    consumer.start()
    threads.append(consumer)
    log.info("✅ Started consumer thread")

    # Start producer
    producer = Thread(
        target=tail_file,
        args=(INPUT_LOG, queue, STOP_EVENT, POLL_INTERVAL),
        daemon=True,
        name='producer'
    )
    producer.start()
    threads.append(producer)
    log.info("✅ Started producer thread")

    # Start stats thread
    stats = Thread(
        target=stats_thread,
        args=(STOP_EVENT,),
        daemon=True,
        name='stats'
    )
    stats.start()
    threads.append(stats)
    log.info("✅ Started stats thread")

    # Start cache cleanup thread
    cleanup = Thread(
        target=cache_cleanup_thread,
        args=(STOP_EVENT,),
        daemon=True,
        name='cleanup'
    )
    cleanup.start()
    threads.append(cleanup)
    log.info("✅ Started cache cleanup thread")

    # Start rotation monitor
    monitor = Thread(
        target=rotation_monitor_thread,
        args=(STOP_EVENT, INPUT_LOG),
        daemon=True,
        name='rotation_monitor'
    )
    monitor.start()
    threads.append(monitor)
    log.info("✅ Started rotation monitor thread")

    log.info("=" * 80)
    log.info("🚀 RUNNING - Press Ctrl+C to stop")
    log.info("=" * 80)

    # Main loop
    try:
        while not STOP_EVENT.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("\n⚠️  Keyboard interrupt")
        STOP_EVENT.set()

    # Shutdown
    log.info("🛑 Shutting down...")

    # Wait for threads with timeout
    for thread in threads:
        if thread and thread.is_alive():
            thread_name = thread.name if hasattr(thread, 'name') else 'unknown'
            log.info(f"Waiting for {thread_name} thread...")
            thread.join(timeout=10)

    # Final flush
    log.info("Flushing remaining data...")
    ids_logger.flush()

    # Final stats
    ids_size = IDS_LOG.stat().st_size / 1024 / 1024 if IDS_LOG.exists() else 0
    final_stats = dup_filter.get_stats()

    log.info("=" * 80)
    log.info("📊 FINAL STATISTICS")
    log.info("=" * 80)
    log.info(f"IDS Log Size:           {ids_size:.2f} MB")
    log.info(f"Total Packets Seen:     {final_stats['total_seen']:,}")
    log.info(f"Unique Logged:          {final_stats['unique_logged']:,}")
    log.info("")
    log.info("DEDUPLICATION BREAKDOWN:")
    log.info(f"  Connection Duplicates: {final_stats['connection_dups']:,} (same 5-tuple)")
    log.info(f"  Payload Duplicates:    {final_stats['payload_dups']:,} (same query/request)")
    log.info(f"  Deduplication Rate:    {final_stats['dedup_rate']}")
    log.info("")
    log.info("FILTERING BREAKDOWN:")
    log.info(f"  TCP Handshakes:        {final_stats['handshakes_filtered']:,} (SYN, SYN-ACK)")
    log.info(f"  TCP Close:             {final_stats['close_filtered']:,} (FIN, RST)")
    log.info(f"  Pure ACKs:             {final_stats['acks_filtered']:,}")
    log.info(f"  No App Layer:          {final_stats['no_app_filtered']:,}")
    log.info(f"  Filter Rate:           {final_stats['filter_rate']}")
    log.info("")
    log.info("CONNECTION TRACKING:")
    log.info(f"  Active Connections:    {final_stats['active_connections']:,}")
    log.info(f"  Expired/Cleaned:       {final_stats['expired_cleaned']:,}")
    log.info("=" * 80)
    log.info("✅ Shutdown complete")


if __name__ == '__main__':
    main()