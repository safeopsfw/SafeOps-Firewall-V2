#!/usr/bin/env python3
"""
firewall_writer.py — Enhanced Performance Enterprise Firewall Logger

NEW FEATURES:
- Support for updated network_packets.log JSON structure
- 3-minute log rotation compatibility
- Improved performance with batch processing
- Enhanced memory management
- Optimized for high-throughput scenarios

Processes network packet logs into concise firewall logs with:
- Essential fields: action, reason, timestamp, IPs, ports, protocol
- Additional analysis fields: direction, geo location, bytes, packets, TCP flags
- Enhanced deduplication with configurable strategies
- Timestamp in IST (Indian Standard Time)
- Optimized for security analysis and incident response

Input:  safeops/logs/network_packets.log (auto-rotates every 3 min)
Output: safeops/logs/firewall/firewall.log
"""

import os
import sys
import json
import time
import uuid
import socket
import signal
import argparse
import logging
import csv
import ipaddress
import hashlib
from datetime import datetime, timezone, timedelta
from threading import Event, Lock, Thread
from queue import Queue, Full, Empty
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Dict, Any, Tuple, List
from pathlib import Path
from collections import deque

# ==================== PATHS ====================
BASE_DIR = Path(__file__).resolve().parents[4]  # safeops/
LOGS_DIR = BASE_DIR / 'logs'
BACKEND_DIR = BASE_DIR / 'backend'
MODULES_DIR = BACKEND_DIR / 'modules'

# Input/Output
INPUT_LOG = LOGS_DIR / 'network_packets.log'
INPUT_IDS_LOG = LOGS_DIR / 'network_packets_ids.log'  # Previous 3-min window
FIREWALL_DIR = LOGS_DIR / 'firewall'
FIREWALL_LOG = FIREWALL_DIR / 'firewall.log'

# Geo & Rules
GEO_DIR = MODULES_DIR / 'Geo'
GEO_CSV = GEO_DIR / 'geo_master_full.csv'
NGFW_RULES = MODULES_DIR / 'firewall' / 'config' / 'firewall_engine_rules.json'

# Ensure directories
FIREWALL_DIR.mkdir(exist_ok=True)
GEO_DIR.mkdir(parents=True, exist_ok=True)

# ==================== ENHANCED CONFIGURATION ====================
DEVICE_ID = socket.gethostname()
WORKER_THREADS = 6  # Increased for better throughput
QUEUE_MAXSIZE = 20000  # Doubled for batch processing
POLL_INTERVAL = 0.05  # Faster polling (50ms)
DUPLICATE_SUPPRESS_SECONDS = 120.0  # 2 minutes
RELOAD_INTERVAL = 300.0  # 5 minutes

# Performance optimizations
BATCH_WRITE_SIZE = 100  # Write logs in batches
BATCH_WRITE_TIMEOUT = 1.0  # Max wait time for batch
LOG_ROTATION_CHECK_INTERVAL = 30  # Check rotation every 30s
CACHE_CLEANUP_INTERVAL = 60  # Cleanup caches every 60s

# Deduplication strategies
DEDUP_STRATEGY = 'connection'  # 'exact', 'connection', or 'flow'

# IST timezone offset (UTC+5:30)
IST_OFFSET = timedelta(hours=5, minutes=30)

# ==================== LOGGING ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
log = logging.getLogger('firewall_writer')


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
fw_logger = BatchLogger(FIREWALL_LOG, BATCH_WRITE_SIZE, BATCH_WRITE_TIMEOUT)


# ==================== ENHANCED DUPLICATE SUPPRESSION ====================
class EnhancedDuplicateFilter:
    """
    Multi-strategy deduplication filter with performance optimizations:
    - exact: Matches exact event_id
    - connection: Matches src_ip:src_port -> dst_ip:dst_port:protocol
    - flow: Matches src_ip -> dst_ip (ignores ports)

    Performance features:
    - LRU-style cache with automatic cleanup
    - Memory-efficient hash-based keys
    - Lock-free reads for better concurrency
    """

    def __init__(self, strategy='connection', max_cache_size=50000):
        self.strategy = strategy
        self.max_cache_size = max_cache_size
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.lock = Lock()
        self.stats = {
            'total': 0,
            'duplicates': 0,
            'unique': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }
        self.last_cleanup = time.time()

    def _generate_key(self, record: dict) -> str:
        """Generate deduplication key based on strategy"""
        if self.strategy == 'exact':
            return record.get('event_id', '')

        elif self.strategy == 'connection':
            # Full 5-tuple: src_ip:src_port -> dst_ip:dst_port:protocol
            src_ip = record.get('src_ip', '')
            dst_ip = record.get('dst_ip', '')
            src_port = record.get('src_port', 0)
            dst_port = record.get('dst_port', 0)
            protocol = record.get('protocol', '')

            key_str = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{protocol}"
            return hashlib.md5(key_str.encode()).hexdigest()[:16]  # Shorter hash

        elif self.strategy == 'flow':
            # IP pair only: src_ip -> dst_ip
            src_ip = record.get('src_ip', '')
            dst_ip = record.get('dst_ip', '')

            key_str = f"{src_ip}->{dst_ip}"
            return hashlib.md5(key_str.encode()).hexdigest()[:16]

        else:
            return record.get('event_id', '')

    def is_duplicate(self, record: dict, suppress_seconds: float) -> bool:
        """Check if record is duplicate based on strategy"""
        now = time.time()
        key = self._generate_key(record)

        if not key:
            self.stats['cache_misses'] += 1
            return False

        with self.lock:
            self.stats['total'] += 1

            cached = self.cache.get(key)

            if cached:
                self.stats['cache_hits'] += 1
                last_seen = cached['timestamp']

                if (now - last_seen) < suppress_seconds:
                    # Update stats
                    cached['count'] += 1
                    cached['timestamp'] = now  # Update for LRU
                    self.stats['duplicates'] += 1
                    return True

            # Not a duplicate or expired
            self.stats['cache_misses'] += 1
            self.cache[key] = {
                'timestamp': now,
                'count': 1,
                'first_seen': now
            }

            self.stats['unique'] += 1

            # Automatic cleanup if cache too large
            if len(self.cache) > self.max_cache_size:
                self._cleanup_cache_unsafe(now, suppress_seconds)

        return False

    def _cleanup_cache_unsafe(self, now: float, suppress_seconds: float):
        """Cleanup expired entries (must be called with lock held)"""
        cutoff = now - suppress_seconds * 2
        old_size = len(self.cache)

        # Remove expired entries
        self.cache = {k: v for k, v in self.cache.items()
                      if v['timestamp'] > cutoff}

        # If still too large, remove oldest entries (LRU)
        if len(self.cache) > self.max_cache_size:
            sorted_items = sorted(self.cache.items(),
                                  key=lambda x: x[1]['timestamp'])
            keep_count = int(self.max_cache_size * 0.8)  # Keep 80%
            self.cache = dict(sorted_items[-keep_count:])

        cleaned = old_size - len(self.cache)
        if cleaned > 0:
            log.debug(f"Cleaned {cleaned} cache entries")

    def periodic_cleanup(self, suppress_seconds: float):
        """Manual cleanup call for background thread"""
        now = time.time()

        # Only cleanup if needed
        if now - self.last_cleanup < CACHE_CLEANUP_INTERVAL:
            return

        with self.lock:
            self._cleanup_cache_unsafe(now, suppress_seconds)
            self.last_cleanup = now

    def get_stats(self) -> Dict[str, Any]:
        """Get deduplication statistics"""
        with self.lock:
            dedup_rate = (self.stats['duplicates'] / self.stats['total'] * 100) \
                if self.stats['total'] > 0 else 0

            hit_rate = (self.stats['cache_hits'] /
                        (self.stats['cache_hits'] + self.stats['cache_misses']) * 100) \
                if (self.stats['cache_hits'] + self.stats['cache_misses']) > 0 else 0

            return {
                'total_processed': self.stats['total'],
                'duplicates_filtered': self.stats['duplicates'],
                'unique_logged': self.stats['unique'],
                'deduplication_rate': f"{dedup_rate:.2f}%",
                'cache_size': len(self.cache),
                'cache_hit_rate': f"{hit_rate:.2f}%",
                'strategy': self.strategy
            }


dup_filter = EnhancedDuplicateFilter(strategy=DEDUP_STRATEGY)


# ==================== GEO INTELLIGENCE ====================
class GeoIntelligence:
    """Optimized geo intelligence with caching"""

    def __init__(self):
        self.index = []
        self.cache = {}  # IP -> geo info cache
        self.cache_lock = Lock()
        self.index_lock = Lock()
        self.mtime = None
        self.load()

    def load(self):
        if not GEO_CSV.exists():
            log.warning(f"Geo CSV not found: {GEO_CSV}")
            return

        try:
            mtime = GEO_CSV.stat().st_mtime
            if self.mtime == mtime:
                return

            tmp = []
            with open(GEO_CSV, 'r', encoding='utf-8', errors='replace') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    net_str = row.get('network') or row.get('cidr')
                    if not net_str:
                        continue

                    try:
                        net = ipaddress.ip_network(net_str.strip(), strict=False)
                        info = {
                            'country': (row.get('country') or '').strip(),
                            'country_code': (row.get('country_code') or '').strip(),
                            'isp': (row.get('organization') or row.get('org') or
                                    row.get('isp') or '').strip()
                        }
                        tmp.append((net, info))
                    except Exception:
                        continue

            # Sort by prefix length (most specific first)
            tmp.sort(key=lambda x: x[0].prefixlen, reverse=True)

            with self.index_lock:
                self.index = tmp
                self.mtime = mtime

            # Clear cache on reload
            with self.cache_lock:
                self.cache.clear()

            log.info(f"Loaded {len(tmp)} geo prefixes")

        except Exception as e:
            log.error(f"Failed to load geo data: {e}")

    def lookup(self, ip_str: str) -> Dict[str, Any]:
        if not ip_str:
            return {}

        # Check cache first
        with self.cache_lock:
            if ip_str in self.cache:
                return self.cache[ip_str].copy()

        try:
            ip = ipaddress.ip_address(ip_str)

            if ip.is_private:
                result = {'country': 'Private', 'country_code': 'XX', 'isp': 'Internal'}
                with self.cache_lock:
                    self.cache[ip_str] = result
                return result

            with self.index_lock:
                for net, info in self.index:
                    if ip.version == net.version and ip in net:
                        with self.cache_lock:
                            # Cache result (limit cache size)
                            if len(self.cache) > 10000:
                                # Remove 20% oldest entries (simple cleanup)
                                remove_count = len(self.cache) // 5
                                for old_ip in list(self.cache.keys())[:remove_count]:
                                    del self.cache[old_ip]

                            self.cache[ip_str] = info

                        return info.copy()
        except Exception:
            pass

        return {}


# ==================== FIREWALL RULES ====================
class FirewallRules:
    """Optimized firewall rules engine"""

    def __init__(self):
        self.rules = []
        self.lock = Lock()
        self.cache = {}  # Cache rule matches
        self.cache_lock = Lock()
        self.load()

    def load(self):
        if not NGFW_RULES.exists():
            log.warning(f"Firewall rules not found: {NGFW_RULES}")
            return

        try:
            with open(NGFW_RULES, 'r', encoding='utf-8') as f:
                data = json.load(f)
                rules = data.get('rules', []) if isinstance(data, dict) else data

            with self.lock:
                self.rules = rules if isinstance(rules, list) else []

            # Clear cache on reload
            with self.cache_lock:
                self.cache.clear()

            log.info(f"Loaded {len(self.rules)} firewall rules")

        except Exception as e:
            log.error(f"Failed to load firewall rules: {e}")

    def match(self, src_ip: str, dst_ip: str, dst_port: int,
              protocol: str) -> Optional[Dict[str, Any]]:

        # Generate cache key
        cache_key = f"{src_ip}:{dst_ip}:{dst_port}:{protocol}"

        # Check cache
        with self.cache_lock:
            if cache_key in self.cache:
                return self.cache[cache_key]

        # Match rules
        with self.lock:
            for rule in self.rules:
                if not rule.get('enabled', True):
                    continue

                if not self._match_ip(src_ip, rule.get('source', [])):
                    continue

                if not self._match_ip(dst_ip, rule.get('destination', [])):
                    continue

                if dst_port and rule.get('destination_port'):
                    ports = rule['destination_port']
                    if isinstance(ports, list):
                        if dst_port not in ports:
                            continue
                    elif dst_port != ports:
                        continue

                if protocol and rule.get('protocol'):
                    rule_proto = rule['protocol'].upper()
                    if rule_proto != protocol.upper() and rule_proto != 'ANY':
                        continue

                result = {
                    'rule_id': rule.get('id') or rule.get('rule_id'),
                    'rule_name': rule.get('name') or rule.get('rule_name'),
                    'action': rule.get('action', 'allow'),
                    'policy_name': rule.get('policy_id') or rule.get('policy_name')
                }

                # Cache result
                with self.cache_lock:
                    if len(self.cache) > 5000:  # Limit cache size
                        # Remove oldest 20%
                        remove_count = len(self.cache) // 5
                        for old_key in list(self.cache.keys())[:remove_count]:
                            del self.cache[old_key]

                    self.cache[cache_key] = result

                return result

        return None

    def _match_ip(self, ip_str: str, patterns: list) -> bool:
        if not patterns or 'any' in [str(p).lower() for p in patterns]:
            return True

        try:
            ip = ipaddress.ip_address(ip_str)
            for pattern in patterns:
                pattern = str(pattern).strip()
                if '/' in pattern:
                    net = ipaddress.ip_network(pattern, strict=False)
                    if ip in net:
                        return True
                elif pattern == ip_str:
                    return True
        except Exception:
            pass

        return False


# Initialize global instances
geo_intel = GeoIntelligence()
firewall_rules = FirewallRules()


# ==================== HELPERS ====================
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_int(value, default=None):
    try:
        return int(value) if value not in (None, '') else default
    except (ValueError, TypeError):
        return default


def to_ist(utc_timestamp: str) -> str:
    """Convert UTC timestamp to IST"""
    try:
        if 'Z' in utc_timestamp:
            utc_timestamp = utc_timestamp.replace('Z', '+00:00')

        dt = datetime.fromisoformat(utc_timestamp)
        ist_dt = dt + IST_OFFSET
        return ist_dt.strftime('%Y-%m-%d %H:%M:%S IST')
    except Exception:
        return utc_timestamp


def classify_direction(src_ip: str, dst_ip: str) -> str:
    """Classify traffic direction for security analysis"""
    try:
        src = ipaddress.ip_address(src_ip)
        dst = ipaddress.ip_address(dst_ip)

        if src.is_private and dst.is_private:
            return 'east-west'
        if src.is_private and not dst.is_private:
            return 'outbound'
        if not src.is_private and dst.is_private:
            return 'inbound'
        return 'north-south'

    except Exception:
        return 'unknown'


def determine_action(tcp_flags: dict, protocol: str,
                     rule_match: Optional[Dict]) -> Tuple[str, str]:
    """Determine firewall action and reason"""
    if rule_match:
        rule_action = rule_match.get('action', 'allow').lower()
        if rule_action in ('deny', 'drop', 'block'):
            return 'deny', f"Rule: {rule_match.get('rule_name', 'N/A')}"
        elif rule_action == 'reject':
            return 'reject', f"Rule: {rule_match.get('rule_name', 'N/A')}"
        else:
            return 'allow', f"Rule: {rule_match.get('rule_name', 'N/A')}"

    if isinstance(tcp_flags, dict):
        if tcp_flags.get('rst'):
            return 'drop', 'RST flag'
        if tcp_flags.get('fin'):
            return 'allow', 'FIN flag'
        if tcp_flags.get('syn') and not tcp_flags.get('ack'):
            return 'allow', 'SYN'
        if tcp_flags.get('syn') and tcp_flags.get('ack'):
            return 'allow', 'SYN-ACK'

    return 'allow', 'Implicit allow'


def format_tcp_flags(tcp_flags: dict) -> str:
    """Format TCP flags for analysis"""
    if not tcp_flags:
        return ''

    flags = []
    flag_map = {
        'syn': 'S', 'ack': 'A', 'fin': 'F',
        'rst': 'R', 'psh': 'P', 'urg': 'U'
    }

    for flag, abbrev in flag_map.items():
        if tcp_flags.get(flag):
            flags.append(abbrev)

    return ''.join(flags) if flags else ''


# ==================== OPTIMIZED SCHEMA MAPPER ====================
def map_to_firewall_analysis(packet: dict) -> dict:
    """
    Map packet to firewall schema optimized for security analysis.
    UPDATED: Support new JSON structure from network_packets.log

    Priority order of fields:
    1. action, reason (most important)
    2. timestamp_ist
    3. event_id
    4. src_ip, dst_ip
    5. src_port, dst_port
    6. protocol
    7. Additional analysis fields
    """

    layers = packet.get('layers', {})
    network = layers.get('network', {})
    transport = layers.get('transport', {})
    flow_ctx = packet.get('flow_context', {})

    # === TIMESTAMP ===
    ts = packet.get('timestamp', {})
    if isinstance(ts, dict):
        utc_iso = ts.get('iso8601') or now_iso()
    elif isinstance(ts, str):
        utc_iso = ts
    else:
        utc_iso = now_iso()

    ist_timestamp = to_ist(utc_iso)

    # === EVENT ID ===
    event_id = packet.get('packet_id') or f"fw-{uuid.uuid4().hex[:16]}"

    # === NETWORK BASICS ===
    src_ip = network.get('src_ip', '')
    dst_ip = network.get('dst_ip', '')
    src_port = safe_int(transport.get('src_port'))
    dst_port = safe_int(transport.get('dst_port'))

    # === PROTOCOL ===
    proto_num = network.get('protocol') or transport.get('protocol')
    protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
    protocol = protocol_map.get(proto_num, str(proto_num) if proto_num else 'UNKNOWN')

    # === RULE MATCHING (with caching) ===
    rule_match = firewall_rules.match(src_ip, dst_ip, dst_port, protocol)

    # === ACTION & REASON ===
    tcp_flags = transport.get('tcp_flags', {})
    action, reason = determine_action(tcp_flags, protocol, rule_match)

    # === BUILD RECORD (ORDERED) ===
    record = {
        'action': action,
        'reason': reason,
        'timestamp_ist': ist_timestamp,
        'event_id': event_id,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
    }

    # Add ports if they exist
    if src_port is not None:
        record['src_port'] = src_port
    if dst_port is not None:
        record['dst_port'] = dst_port

    record['protocol'] = protocol

    # === ADDITIONAL ANALYSIS FIELDS ===

    # Direction
    direction = classify_direction(src_ip, dst_ip)
    record['direction'] = direction

    # Geo Intelligence (with caching)
    src_geo = geo_intel.lookup(src_ip)
    dst_geo = geo_intel.lookup(dst_ip)

    if src_geo.get('country'):
        record['src_country'] = src_geo['country']
    if dst_geo.get('country'):
        record['dst_country'] = dst_geo['country']

    # ISP for external IPs
    try:
        if not ipaddress.ip_address(src_ip).is_private and src_geo.get('isp'):
            record['src_isp'] = src_geo['isp']
        if not ipaddress.ip_address(dst_ip).is_private and dst_geo.get('isp'):
            record['dst_isp'] = dst_geo['isp']
    except:
        pass

    # Bytes transferred
    bytes_sent = flow_ctx.get('bytes_forward', 0) or 0
    bytes_recv = flow_ctx.get('bytes_backward', 0) or 0

    if bytes_sent > 0:
        record['bytes_sent'] = bytes_sent
    if bytes_recv > 0:
        record['bytes_recv'] = bytes_recv

    total_bytes = bytes_sent + bytes_recv
    if total_bytes > 0:
        record['total_bytes'] = total_bytes

    # Packet counts
    pkts_sent = flow_ctx.get('packets_forward', 0) or 0
    pkts_recv = flow_ctx.get('packets_backward', 0) or 0

    if pkts_sent > 0:
        record['packets_sent'] = pkts_sent
    if pkts_recv > 0:
        record['packets_recv'] = pkts_recv

    # TCP Flags
    if protocol == 'TCP' and tcp_flags:
        flags_str = format_tcp_flags(tcp_flags)
        if flags_str:
            record['tcp_flags'] = flags_str

    # Connection state
    state = flow_ctx.get('tcp_state') or flow_ctx.get('flow_state')
    if state:
        record['connection_state'] = state

    # Flow duration
    duration = flow_ctx.get('flow_duration')
    if duration is not None and duration > 0:
        record['duration_sec'] = round(duration, 3)

    # Session/Flow ID
    session_track = packet.get('session_tracking', {})
    session_id = session_track.get('session_id') or flow_ctx.get('flow_id')
    if session_id:
        record['session_id'] = session_id

    # Rule information
    if rule_match:
        if rule_match.get('rule_id'):
            record['rule_id'] = rule_match['rule_id']
        if rule_match.get('policy_name'):
            record['policy_name'] = rule_match['policy_name']

    # Application detection
    parsed_app = packet.get('parsed_application', {})
    detected_proto = parsed_app.get('detected_protocol')
    if detected_proto and detected_proto != 'unknown':
        record['app_protocol'] = detected_proto

    # TLS information (from new structure)
    if parsed_app.get('tls'):
        tls_data = parsed_app['tls']

        # SNI
        client_hello = tls_data.get('client_hello', {})
        sni = client_hello.get('sni')
        if sni:
            record['tls_sni'] = sni

        # ALPN
        alpn = client_hello.get('alpn')
        if alpn:
            record['tls_alpn'] = ','.join(alpn) if isinstance(alpn, list) else str(alpn)

        # Decryption status
        decryption = tls_data.get('decryption', {})
        if decryption.get('decrypted'):
            record['tls_decrypted'] = True

    # HTTP information (from decrypted TLS or plain HTTP)
    if parsed_app.get('http'):
        http_data = parsed_app['http']

        if http_data.get('method'):
            record['http_method'] = http_data['method']

        if http_data.get('uri'):
            record['http_uri'] = http_data['uri']

        if http_data.get('host'):
            record['http_host'] = http_data['host']

    # Gaming traffic
    if parsed_app.get('gaming', {}).get('detected'):
        gaming = parsed_app['gaming']
        record['gaming_service'] = gaming.get('service', 'Unknown')

    # TTL
    ttl = network.get('ttl')
    if ttl:
        record['ttl'] = ttl

    # Process information
    process = flow_ctx.get('process', {})
    if process.get('name'):
        record['process_name'] = process['name']
    if process.get('pid'):
        record['process_pid'] = process['pid']

    return record


# ==================== OPTIMIZED WORKER ====================
def process_packet_line(line: str, suppress_seconds: float) -> Optional[dict]:
    """Process single packet line with error handling"""
    line = line.strip()
    if not line:
        return None

    try:
        packet = json.loads(line)
    except Exception:
        return None

    try:
        record = map_to_firewall_analysis(packet)
    except Exception as e:
        log.debug(f"Mapping failed: {e}")
        return None

    # Enhanced duplicate suppression
    if dup_filter.is_duplicate(record, suppress_seconds):
        return None

    # Write to firewall.log (batched)
    fw_logger.write(json.dumps(record, separators=(',', ':'), ensure_ascii=False))

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
                last_inode = curr_inode
                last_size = curr_size
                log.info(f"Opened {path}")

            # Detect rotation or truncation
            if curr_inode != last_inode or curr_size < last_size:
                rotation_count += 1
                log.info(f"Detected rotation #{rotation_count}, reopening {path}")
                fh.close()

                # Try to open new file
                if path.exists():
                    fh = open(path, 'r', encoding='utf-8', errors='replace')
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
def consumer_loop(queue: Queue, stop_event: Event, workers: int, suppress_seconds: float):
    """Enhanced consumer with batch processing and performance metrics"""
    stats = {
        'processed': 0,
        'written': 0,
        'duplicates': 0,
        'errors': 0,
        'batches': 0
    }

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix='fw_worker') as executor:
        futures = []
        last_flush = time.time()

        while not stop_event.is_set() or not queue.empty():
            try:
                item = queue.get(timeout=0.2)
            except Empty:
                # Force flush on timeout
                if time.time() - last_flush > BATCH_WRITE_TIMEOUT:
                    fw_logger.flush()
                    last_flush = time.time()
                continue

            line, lineno = item
            stats['processed'] += 1

            # Submit for processing
            future = executor.submit(process_packet_line, line, suppress_seconds)
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
                fw_logger.flush()
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
    fw_logger.flush()

    # Calculate performance metrics
    elapsed = time.time() - start_time
    pps = stats['processed'] / elapsed if elapsed > 0 else 0

    log.info(f"Consumer stats: {stats}")
    log.info(f"Performance: {pps:.2f} packets/sec, {elapsed:.2f} seconds total")


# ==================== RELOAD THREAD ====================
def reload_thread(stop_event: Event, interval: float):
    """Periodically reload geo and rules"""
    log.info("Started reload thread")

    while not stop_event.is_set():
        time.sleep(interval)

        if stop_event.is_set():
            break

        try:
            log.info("Reloading geo and firewall rules...")
            geo_intel.load()
            firewall_rules.load()
            log.info("Reload complete")
        except Exception as e:
            log.error(f"Reload error: {e}")

    log.info("Stopped reload thread")


# ==================== ENHANCED STATS THREAD ====================
def stats_thread(stop_event: Event):
    """Print enhanced statistics every 30 seconds"""
    log.info("Started stats thread")

    last_stats = {'total': 0, 'unique': 0}

    while not stop_event.is_set():
        time.sleep(30)

        if stop_event.is_set():
            break

        try:
            fw_size = FIREWALL_LOG.stat().st_size / 1024 / 1024 if FIREWALL_LOG.exists() else 0
            dedup_stats = dup_filter.get_stats()

            # Calculate delta
            delta_total = dedup_stats['total_processed'] - last_stats['total']
            delta_unique = dedup_stats['unique_logged'] - last_stats['unique']
            rate = delta_total / 30.0  # per second

            last_stats['total'] = dedup_stats['total_processed']
            last_stats['unique'] = dedup_stats['unique_logged']

            log.info(f"📊 Firewall: {fw_size:.1f}MB | "
                     f"Rate: {rate:.1f} pkt/s | "
                     f"Dedup: {dedup_stats['deduplication_rate']} "
                     f"({dedup_stats['unique_logged']}/{dedup_stats['total_processed']}) | "
                     f"Cache: {dedup_stats['cache_size']} | "
                     f"Hit Rate: {dedup_stats['cache_hit_rate']}")

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
            fw_logger.flush()

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
                    fw_logger.flush()

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
def build_parser():
    parser = argparse.ArgumentParser(
        description='SAFEOPS Firewall Logger - Enhanced Performance Edition'
    )
    parser.add_argument('--input', default=str(INPUT_LOG),
                        help=f'Input log file (default: {INPUT_LOG})')
    parser.add_argument('--workers', type=int, default=WORKER_THREADS,
                        help=f'Worker threads (default: {WORKER_THREADS})')
    parser.add_argument('--queue-size', type=int, default=QUEUE_MAXSIZE,
                        help=f'Queue size (default: {QUEUE_MAXSIZE})')
    parser.add_argument('--poll', type=float, default=POLL_INTERVAL,
                        help=f'Poll interval (default: {POLL_INTERVAL}s)')
    parser.add_argument('--dup-suppress', type=float, default=DUPLICATE_SUPPRESS_SECONDS,
                        help=f'Duplicate suppression (default: {DUPLICATE_SUPPRESS_SECONDS}s)')
    parser.add_argument('--dedup-strategy', choices=['exact', 'connection', 'flow'],
                        default=DEDUP_STRATEGY,
                        help=f'Deduplication strategy (default: {DEDUP_STRATEGY})')
    parser.add_argument('--reload-interval', type=float, default=RELOAD_INTERVAL,
                        help=f'Reload interval (default: {RELOAD_INTERVAL}s)')
    parser.add_argument('--batch-size', type=int, default=BATCH_WRITE_SIZE,
                        help=f'Batch write size (default: {BATCH_WRITE_SIZE})')
    parser.add_argument('--batch-timeout', type=float, default=BATCH_WRITE_TIMEOUT,
                        help=f'Batch write timeout (default: {BATCH_WRITE_TIMEOUT}s)')
    parser.add_argument('--start-at-end', action='store_true',
                        help='Start tailing from end of file')
    parser.add_argument('--stdin', action='store_true', help='Read from stdin')
    parser.add_argument('--no-cache-cleanup', action='store_true',
                        help='Disable automatic cache cleanup')
    parser.add_argument('--no-rotation-monitor', action='store_true',
                        help='Disable rotation monitoring')
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Update global batch settings
    global BATCH_WRITE_SIZE, BATCH_WRITE_TIMEOUT
    BATCH_WRITE_SIZE = args.batch_size
    BATCH_WRITE_TIMEOUT = args.batch_timeout

    # Update dedup strategy
    global dup_filter, fw_logger
    dup_filter = EnhancedDuplicateFilter(strategy=args.dedup_strategy)
    fw_logger = BatchLogger(FIREWALL_LOG, args.batch_size, args.batch_timeout)

    log.info("=" * 70)
    log.info("🔥 SAFEOPS Firewall Writer - Enhanced Performance Edition")
    log.info("=" * 70)
    log.info(f"Input:  {args.input}")
    log.info(f"Output: {FIREWALL_LOG}")
    log.info(f"Config:")
    log.info(f"  - Workers: {args.workers}")
    log.info(f"  - Queue size: {args.queue_size}")
    log.info(f"  - Batch size: {args.batch_size}")
    log.info(f"  - Batch timeout: {args.batch_timeout}s")
    log.info(f"  - Dedup strategy: {args.dedup_strategy}")
    log.info(f"  - Dedup window: {args.dup_suppress}s")
    log.info(f"  - Poll interval: {args.poll}s")
    log.info("=" * 70)

    # Initialize
    log.info("Loading geo and firewall rules...")
    geo_intel.load()
    firewall_rules.load()
    log.info("✅ Initialization complete")

    queue = Queue(maxsize=args.queue_size)
    threads = []

    # Start consumer
    consumer = Thread(
        target=consumer_loop,
        args=(queue, STOP_EVENT, args.workers, args.dup_suppress),
        daemon=True,
        name='consumer'
    )
    consumer.start()
    threads.append(consumer)
    log.info("✅ Started consumer thread")

    # Start producer
    if args.stdin:
        log.info("📥 Reading from stdin...")
        producer = None
        lineno = 0
        try:
            while not STOP_EVENT.is_set():
                line = sys.stdin.readline()
                if not line:
                    break
                lineno += 1
                try:
                    queue.put_nowait((line, lineno))
                except Full:
                    time.sleep(0.01)
        except KeyboardInterrupt:
            pass
    else:
        input_path = Path(args.input)
        producer = Thread(
            target=tail_file,
            args=(input_path, queue, STOP_EVENT, args.poll),
            daemon=True,
            name='producer'
        )
        producer.start()
        threads.append(producer)
        log.info(f"✅ Started producer thread")

    # Start reload thread
    reloader = Thread(
        target=reload_thread,
        args=(STOP_EVENT, args.reload_interval),
        daemon=True,
        name='reloader'
    )
    reloader.start()
    threads.append(reloader)
    log.info("✅ Started reload thread")

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

    # Start cache cleanup thread (optional)
    if not args.no_cache_cleanup:
        cleanup = Thread(
            target=cache_cleanup_thread,
            args=(STOP_EVENT,),
            daemon=True,
            name='cleanup'
        )
        cleanup.start()
        threads.append(cleanup)
        log.info("✅ Started cache cleanup thread")

    # Start rotation monitor (optional)
    if not args.no_rotation_monitor and not args.stdin:
        monitor = Thread(
            target=rotation_monitor_thread,
            args=(STOP_EVENT, Path(args.input)),
            daemon=True,
            name='rotation_monitor'
        )
        monitor.start()
        threads.append(monitor)
        log.info("✅ Started rotation monitor thread")

    log.info("=" * 70)
    log.info("🚀 RUNNING - Press Ctrl+C to stop")
    log.info("=" * 70)

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
    fw_logger.flush()

    # Final stats
    fw_size = FIREWALL_LOG.stat().st_size / 1024 / 1024 if FIREWALL_LOG.exists() else 0
    dedup_stats = dup_filter.get_stats()

    log.info("=" * 70)
    log.info("📊 FINAL STATISTICS")
    log.info("=" * 70)
    log.info(f"Firewall log: {fw_size:.2f} MB")
    log.info(f"Total processed: {dedup_stats['total_processed']:,}")
    log.info(f"Unique logged: {dedup_stats['unique_logged']:,}")
    log.info(f"Duplicates filtered: {dedup_stats['duplicates_filtered']:,}")
    log.info(f"Deduplication rate: {dedup_stats['deduplication_rate']}")
    log.info(f"Cache hit rate: {dedup_stats['cache_hit_rate']}")
    log.info(f"Strategy: {dedup_stats['strategy']}")
    log.info(f"Final cache size: {dedup_stats['cache_size']:,}")
    log.info("=" * 70)
    log.info("✅ Shutdown complete")


if __name__ == '__main__':
    main()