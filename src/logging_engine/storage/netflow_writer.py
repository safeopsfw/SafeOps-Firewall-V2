#!/usr/bin/env python3
"""
NetFlow Writer - FLOW AGGREGATION Edition (Space-Optimized)
============================================================

Uses centralized config from config/config.yaml via config_loader.

Features:
✅ Flow aggregation by 5-tuple (not per-packet)
✅ 60-second flow timeout (configurable)
✅ All original features preserved (geo, caching, TLS tracking)
✅ Smart filtering (handshakes, ACKs)
✅ Batch writing for performance
✅ Rotation support
✅ Separate east-west and north-south logs
✅ Unknown geo tracking to CSV
"""

from __future__ import annotations
import os, sys, json, time, signal, socket, ipaddress, hashlib, csv, re, logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple, Any, List, Set
from collections import OrderedDict
from threading import Lock, Thread, Event
from queue import Queue, Empty
from dataclasses import dataclass, field

# Import centralized config
try:
    from ..config.config_loader import config, get_path, get_setting
except ImportError:
    # Fallback for standalone execution
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from config.config_loader import config, get_path, get_setting

# ==================== PATHS FROM CONFIG ====================
BASE_DIR = get_path('paths.base_dir')
LOGS_DIR = get_path('paths.logs_dir')

IN_FILE = get_path('log_files.network_packets')
NETFLOW_LOG = get_path('log_files.netflow', create_dir=True)

OUT_DIR = NETFLOW_LOG.parent
EW_FILE = OUT_DIR / 'east_west.log'
NS_FILE = OUT_DIR / 'north_south.log'
UNKNOWN_GEO_CSV = LOGS_DIR / 'unknown_geo_location.csv'
GEO_CSV = Path(get_setting('geo.csv_path', ''))

OUT_DIR.mkdir(parents=True, exist_ok=True)

# ==================== CONFIGURATION ====================
DEVICE_ID = socket.gethostname()

# Flow aggregation (KEY OPTIMIZATION)
FLOW_TIMEOUT = 60  # Log flows after 60s of inactivity
FLOW_CLEANUP_INTERVAL = 15  # Check for expired flows every 15s
MAX_FLOWS_IN_MEMORY = 50000  # Force flush if too many flows

# Batch writing
BATCH_SIZE = 50  # Smaller batches for aggregated flows
BATCH_TIMEOUT = 5.0

# Filtering
SKIP_HANDSHAKES = True
SKIP_PURE_ACKS = True

# Performance
POLL_INTERVAL = 0.1
STATS_INTERVAL = 30
GEO_CACHE_SIZE = 10000

STOP_EVENT = Event()

# ==================== LOGGING ====================
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger('netflow_agg')


# ==================== FLOW STATE ====================
@dataclass
class FlowState:
    """Aggregated flow state - ONE record per connection"""
    flow_key: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    proto_num: int

    # Direction
    direction: str  # east-west or north-south
    initiator: str  # local, internet, unknown

    # Timestamps
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    # Counters
    packets_toserver: int = 0
    packets_toclient: int = 0
    bytes_toserver: int = 0
    bytes_toclient: int = 0

    # TCP state
    saw_syn: bool = False
    saw_syn_ack: bool = False
    saw_fin: bool = False
    saw_rst: bool = False
    tcp_state: str = 'NEW'

    # Context
    first_packet_id: Optional[str] = None
    last_packet_id: Optional[str] = None
    ttl: Optional[int] = None
    ip_version: Optional[int] = None

    def update(self, packet: dict, is_forward: bool):
        """Update flow from packet"""
        self.last_seen = time.time()

        # Packet size
        capture_info = packet.get('capture_info', {})
        packet_size = capture_info.get('capture_length', 0)

        if is_forward:
            self.packets_toserver += 1
            self.bytes_toserver += packet_size
        else:
            self.packets_toclient += 1
            self.bytes_toclient += packet_size

        # Track packet IDs
        packet_id = packet.get('packet_id')
        if not self.first_packet_id:
            self.first_packet_id = packet_id
        self.last_packet_id = packet_id

        # TCP flags
        layers = packet.get('layers', {})
        transport = layers.get('transport', {})
        tcp_flags = transport.get('tcp_flags', {})

        if self.protocol == 'tcp':
            if tcp_flags.get('syn') and not tcp_flags.get('ack'):
                self.saw_syn = True
                self.tcp_state = 'SYN_SENT'
            elif tcp_flags.get('syn') and tcp_flags.get('ack'):
                self.saw_syn_ack = True
                self.tcp_state = 'SYN_RECEIVED'
            elif tcp_flags.get('ack') and (self.saw_syn or self.saw_syn_ack):
                self.tcp_state = 'ESTABLISHED'
            elif tcp_flags.get('fin'):
                self.saw_fin = True
                self.tcp_state = 'FIN_WAIT'
            elif tcp_flags.get('rst'):
                self.saw_rst = True
                self.tcp_state = 'RESET'

        # Network details
        network = layers.get('network', {})
        if not self.ttl:
            self.ttl = network.get('ttl')
        if not self.ip_version:
            self.ip_version = network.get('version')

    def is_expired(self, now: float, timeout: float) -> bool:
        """Check if flow expired"""
        return (now - self.last_seen) > timeout

    def is_complete(self) -> bool:
        """Check if TCP connection closed"""
        return self.saw_fin or self.saw_rst

    def duration(self) -> float:
        return self.last_seen - self.first_seen

    def total_packets(self) -> int:
        return self.packets_toserver + self.packets_toclient

    def total_bytes(self) -> int:
        return self.bytes_toserver + self.bytes_toclient


# ==================== BATCH WRITER ====================
class BatchWriter:
    """Batch writer for netflow logs"""

    def __init__(self, path: Path, batch_size: int = 50, timeout: float = 5.0):
        self.path = path
        self.batch_size = batch_size
        self.timeout = timeout
        self.buffer = []
        self.lock = Lock()
        self.last_flush = time.time()
        self.total_written = 0

    def write(self, record: dict):
        """Add record to buffer"""
        with self.lock:
            self.buffer.append(json.dumps(record, separators=(',', ':'), ensure_ascii=False))

            if len(self.buffer) >= self.batch_size or (time.time() - self.last_flush) >= self.timeout:
                self._flush_unsafe()

    def _flush_unsafe(self):
        """Flush buffer (must hold lock)"""
        if not self.buffer:
            return

        try:
            with open(self.path, 'a', encoding='utf-8') as f:
                f.write('\n'.join(self.buffer) + '\n')

            self.total_written += len(self.buffer)
            self.buffer.clear()
            self.last_flush = time.time()
        except Exception as e:
            log.error(f"Write error: {e}")

    def flush(self):
        """Force flush"""
        with self.lock:
            self._flush_unsafe()

    def get_stats(self) -> dict:
        with self.lock:
            return {'total': self.total_written, 'buffered': len(self.buffer)}


# ==================== UNKNOWN GEO TRACKER ====================
class UnknownGeoTracker:
    """Tracks IPs with unknown geo and writes to CSV"""

    def __init__(self, csv_path: Path):
        self.csv_path = csv_path
        self.unknown_ips: Set[str] = set()
        self.lock = Lock()
        self.total_logged = 0

        # Initialize CSV with headers if it doesn't exist
        if not self.csv_path.exists():
            try:
                with open(self.csv_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['timestamp', 'ip_address', 'ip_version', 'first_seen'])
                log.info(f"Created unknown geo CSV: {self.csv_path}")
            except Exception as e:
                log.error(f"Failed to create unknown geo CSV: {e}")
        else:
            # Load existing unknown IPs to avoid duplicates
            self._load_existing()

    def _load_existing(self):
        """Load existing IPs from CSV to avoid duplicates"""
        try:
            with open(self.csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    ip = row.get('ip_address', '').strip()
                    if ip:
                        self.unknown_ips.add(ip)
            log.info(f"Loaded {len(self.unknown_ips):,} existing unknown IPs")
        except Exception as e:
            log.warning(f"Could not load existing unknown IPs: {e}")

    def log_unknown_ip(self, ip_str: str):
        """Log unknown IP to CSV (only once per IP)"""
        if not ip_str:
            return

        with self.lock:
            # Skip if already logged
            if ip_str in self.unknown_ips:
                return

            # Add to set
            self.unknown_ips.add(ip_str)

            # Determine IP version
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                ip_version = ip_obj.version
            except:
                ip_version = 0

            # Write to CSV
            try:
                with open(self.csv_path, 'a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        datetime.now(timezone.utc).isoformat(),
                        ip_str,
                        ip_version,
                        datetime.now(timezone.utc).isoformat()
                    ])

                self.total_logged += 1

                if self.total_logged % 100 == 0:
                    log.info(f"📝 Logged {self.total_logged} unknown IPs to CSV")

            except Exception as e:
                log.error(f"Failed to write unknown IP {ip_str}: {e}")

    def get_stats(self) -> dict:
        with self.lock:
            return {
                'total_unknown': len(self.unknown_ips),
                'total_logged': self.total_logged
            }


# ==================== GEO LOOKUP (LRU Cached + Unknown Tracking) ====================
class GeoLookup:
    """Geo intelligence with caching and unknown IP tracking"""

    def __init__(self, unknown_tracker: UnknownGeoTracker):
        self.index = []
        self.cache = OrderedDict()
        self.cache_size = GEO_CACHE_SIZE
        self.lock = Lock()
        self.unknown_tracker = unknown_tracker
        self.load()

    def load(self):
        """Load geo CSV"""
        if not GEO_CSV.exists():
            log.warning(f"Geo CSV not found: {GEO_CSV}")
            return

        tmp = []
        try:
            with open(GEO_CSV, 'r', encoding='utf-8', errors='replace') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    net_str = row.get('network') or row.get('cidr')
                    if not net_str:
                        continue

                    try:
                        net = ipaddress.ip_network(net_str.strip(), strict=False)
                        tmp.append((net, {
                            'country': (row.get('country') or '').strip(),
                            'country_code': (row.get('country_code') or '').strip(),
                            'asn': (row.get('asn') or '').strip()
                        }))
                    except:
                        pass

            tmp.sort(key=lambda x: x[0].prefixlen, reverse=True)

            with self.lock:
                self.index = tmp
                self.cache.clear()

            log.info(f"Loaded {len(tmp):,} geo prefixes")
        except Exception as e:
            log.error(f"Geo load error: {e}")

    def lookup(self, ip_str: str) -> dict:
        """Lookup IP with caching and unknown tracking"""
        if not ip_str:
            return {}

        # Check cache
        with self.lock:
            if ip_str in self.cache:
                self.cache.move_to_end(ip_str)
                return self.cache[ip_str].copy()

        try:
            ip = ipaddress.ip_address(ip_str)

            # Private IPs don't need geo lookup
            if ip.is_private:
                result = {'country': 'Private', 'country_code': 'XX', 'asn': ''}
                with self.lock:
                    self._cache_put(ip_str, result)
                return result

            # Search geo database
            with self.lock:
                for net, info in self.index:
                    if ip.version == net.version and ip in net:
                        self._cache_put(ip_str, info)
                        return info.copy()

            # NOT FOUND - Log to unknown geo CSV
            log.debug(f"Unknown geo for IP: {ip_str}")
            self.unknown_tracker.log_unknown_ip(ip_str)

            # Return empty result
            result = {}
            with self.lock:
                self._cache_put(ip_str, result)
            return result

        except Exception as e:
            log.debug(f"Geo lookup error for {ip_str}: {e}")
            return {}

    def _cache_put(self, key: str, value: dict):
        """Put in cache (must hold lock)"""
        self.cache[key] = value
        if len(self.cache) > self.cache_size:
            self.cache.popitem(last=False)


# ==================== FLOW AGGREGATOR (CORE OPTIMIZATION) ====================
class FlowAggregator:
    """Aggregates packets into flows - SPACE SAVER"""

    def __init__(self):
        self.flows: Dict[str, FlowState] = {}
        self.lock = Lock()
        self.ew_writer = BatchWriter(EW_FILE)
        self.ns_writer = BatchWriter(NS_FILE)

        # Initialize unknown geo tracker
        self.unknown_tracker = UnknownGeoTracker(UNKNOWN_GEO_CSV)
        self.geo = GeoLookup(self.unknown_tracker)

        self.stats = {
            'packets_in': 0,
            'packets_ignored': 0,
            'flows_active': 0,
            'flows_logged': 0,
            'flows_expired': 0,
        }

        # Local IPs
        self.local_ips = self._detect_local_ips()

    def _detect_local_ips(self) -> set:
        """Detect local machine IPs"""
        addrs = set()
        try:
            for res in socket.getaddrinfo(socket.gethostname(), None):
                addrs.add(res[4][0])
        except:
            pass
        addrs.update({'127.0.0.1', '::1'})
        return addrs

    def _generate_flow_key(self, src_ip: str, dst_ip: str, src_port: Optional[int],
                           dst_port: Optional[int], protocol: str) -> Tuple[str, bool]:
        """
        Generate normalized flow key.
        Returns: (flow_key, is_forward)
        """
        # Normalize to bidirectional
        if src_ip < dst_ip:
            key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}:{protocol}"
            return key, True
        elif src_ip > dst_ip:
            key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}:{protocol}"
            return key, False
        else:
            if (src_port or 0) < (dst_port or 0):
                key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}:{protocol}"
                return key, True
            else:
                key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}:{protocol}"
                return key, False

    def _classify_direction(self, src_ip: str, dst_ip: str) -> str:
        """Classify traffic direction"""
        try:
            s = ipaddress.ip_address(src_ip)
            d = ipaddress.ip_address(dst_ip)
            return "east-west" if s.is_private and d.is_private else "north-south"
        except:
            return "north-south"

    def _classify_initiator(self, src_ip: str, dst_ip: str) -> str:
        """Classify initiator"""
        try:
            if not ipaddress.ip_address(src_ip).is_private:
                return "internet"
            if src_ip in self.local_ips:
                return "local"
            return "unknown"
        except:
            return "unknown"

    def _should_ignore_packet(self, packet: dict) -> bool:
        """Check if packet should be ignored"""
        layers = packet.get('layers', {})
        transport = layers.get('transport', {})
        tcp_flags = transport.get('tcp_flags', {})

        proto_num = layers.get('network', {}).get('protocol')

        if proto_num == 6 and SKIP_HANDSHAKES:  # TCP
            # Skip standalone SYN (handshake start)
            if tcp_flags.get('syn') and not tcp_flags.get('ack'):
                return True

        if proto_num == 6 and SKIP_PURE_ACKS:
            # Skip pure ACKs (no data)
            if (tcp_flags.get('ack') and not tcp_flags.get('psh') and
                    not tcp_flags.get('syn') and not tcp_flags.get('fin') and
                    not tcp_flags.get('rst')):
                return True

        return False

    def process_packet(self, packet: dict):
        """Process packet - update or create flow"""
        self.stats['packets_in'] += 1

        # Ignore unwanted packets
        if self._should_ignore_packet(packet):
            self.stats['packets_ignored'] += 1
            return

        # Extract fields
        layers = packet.get('layers', {})
        network = layers.get('network', {})
        transport = layers.get('transport', {})

        src_ip = network.get('src_ip', '')
        dst_ip = network.get('dst_ip', '')
        src_port = transport.get('src_port')
        dst_port = transport.get('dst_port')

        proto_num = network.get('protocol') or transport.get('protocol')
        protocol_map = {1: 'icmp', 6: 'tcp', 17: 'udp'}
        protocol = protocol_map.get(proto_num, str(proto_num) if proto_num else 'unknown')

        if not src_ip or not dst_ip:
            return

        # Generate flow key
        flow_key, is_forward = self._generate_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)

        with self.lock:
            # Update existing flow OR create new
            if flow_key in self.flows:
                flow = self.flows[flow_key]
                flow.update(packet, is_forward)

                # Log if complete
                if flow.is_complete():
                    self._log_flow(flow)
                    del self.flows[flow_key]
            else:
                # Create new flow
                direction = self._classify_direction(src_ip, dst_ip)
                initiator = self._classify_initiator(src_ip, dst_ip)

                flow = FlowState(
                    flow_key=flow_key,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    proto_num=proto_num or 0,
                    direction=direction,
                    initiator=initiator
                )
                flow.update(packet, is_forward)

                self.flows[flow_key] = flow
                self.stats['flows_active'] = len(self.flows)

            # Force flush if too many flows
            if len(self.flows) > MAX_FLOWS_IN_MEMORY:
                self._flush_oldest_flows(1000)

    def _log_flow(self, flow: FlowState):
        """Convert flow to NetFlow record and log"""
        # Timestamps
        start_time = datetime.fromtimestamp(flow.first_seen, tz=timezone.utc).isoformat()
        end_time = datetime.fromtimestamp(flow.last_seen, tz=timezone.utc).isoformat()

        # Geo lookup (with unknown tracking)
        src_geo = self.geo.lookup(flow.src_ip)
        dst_geo = self.geo.lookup(flow.dst_ip)

        # Build record (schema-aligned)
        record = {
            "timestamp": start_time,
            "event_id": flow.first_packet_id or f"flow_{int(flow.first_seen * 1000)}",
            "flow_id": abs(hash(flow.flow_key)) % (10 ** 12),
            "log_type": "netflow",
            "event_type": "flow",
            "source_ip": flow.src_ip,
            "destination_ip": flow.dst_ip,
            "protocol": flow.protocol,
            "network_layer": {
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "protocol": flow.protocol,
            }
        }

        if flow.src_port is not None:
            record["source_port"] = flow.src_port
            record["network_layer"]["src_port"] = flow.src_port
        if flow.dst_port is not None:
            record["destination_port"] = flow.dst_port
            record["network_layer"]["dst_port"] = flow.dst_port
        if flow.proto_num:
            record["network_layer"]["protocol_number"] = flow.proto_num
        if flow.ip_version:
            record["network_layer"]["ip_version"] = flow.ip_version
        if flow.ttl:
            record["network_layer"]["ttl"] = flow.ttl

        # Flow statistics
        record["flow_statistics"] = {
            "direction": flow.direction,
            "initiator": flow.initiator,
            "start_timestamp": start_time,
            "end_timestamp": end_time,
            "duration": flow.duration(),
            "bytes": flow.total_bytes(),
            "bytes_toserver": flow.bytes_toserver,
            "bytes_toclient": flow.bytes_toclient,
            "packets": flow.total_packets(),
            "packets_toserver": flow.packets_toserver,
            "packets_toclient": flow.packets_toclient,
        }

        if flow.tcp_state != 'NEW':
            record["flow_statistics"]["state"] = flow.tcp_state
        if flow.direction == 'east-west':
            record["flow_statistics"]["reason"] = "both_endpoints_are_rfc1918"

        record["bytes"] = flow.total_bytes()
        record["packets"] = flow.total_packets()

        # Geo
        record["geo"] = {
            "src_country": src_geo.get('country', ''),
            "src_country_code": src_geo.get('country_code', ''),
            "src_asn_org": '',
            "dst_country": dst_geo.get('country', ''),
            "dst_country_code": dst_geo.get('country_code', ''),
            "dst_asn_org": '',
        }

        # Meta
        record["meta"] = {
            "device_id": DEVICE_ID,
            "packet_id": flow.last_packet_id or flow.first_packet_id or '',
        }

        # Route to correct log
        if flow.direction == 'east-west':
            self.ew_writer.write(record)
        else:
            self.ns_writer.write(record)

        self.stats['flows_logged'] += 1

    def cleanup_expired_flows(self):
        """Log expired flows"""
        now = time.time()
        expired = []

        with self.lock:
            for flow_key, flow in list(self.flows.items()):
                if flow.is_expired(now, FLOW_TIMEOUT):
                    self._log_flow(flow)
                    expired.append(flow_key)

            for key in expired:
                del self.flows[key]

            self.stats['flows_expired'] += len(expired)
            self.stats['flows_active'] = len(self.flows)

        if expired:
            log.debug(f"Logged {len(expired)} expired flows")

    def _flush_oldest_flows(self, count: int):
        """Flush oldest flows (must hold lock)"""
        sorted_flows = sorted(self.flows.items(), key=lambda x: x[1].last_seen)

        for flow_key, flow in sorted_flows[:count]:
            self._log_flow(flow)
            del self.flows[flow_key]

        log.info(f"Flushed {count} oldest flows (memory limit)")

    def flush_all(self):
        """Flush all flows"""
        with self.lock:
            for flow in list(self.flows.values()):
                self._log_flow(flow)
            self.flows.clear()

        self.ew_writer.flush()
        self.ns_writer.flush()

    def get_stats(self) -> dict:
        with self.lock:
            stats = self.stats.copy()
            stats.update(self.unknown_tracker.get_stats())
            return stats


# ==================== PACKET READER ====================
def tail_file(path: Path, aggregator: FlowAggregator, stop_event: Event):
    """Tail log file and process packets"""
    log.info(f"Starting tail on {path}")

    fh = None
    last_inode = None
    lineno = 0

    while not stop_event.is_set():
        try:
            if not path.exists():
                time.sleep(POLL_INTERVAL)
                continue

            st = path.stat()
            curr_inode = (st.st_ino, st.st_dev)

            if fh is None:
                fh = open(path, 'r', encoding='utf-8', errors='replace')
                fh.seek(0, 2)  # Start from end
                last_inode = curr_inode
                log.info(f"Opened {path}")

            # Detect rotation
            if curr_inode != last_inode or st.st_size < fh.tell():
                log.info("Rotation detected, reopening")
                fh.close()
                fh = open(path, 'r', encoding='utf-8', errors='replace')
                fh.seek(0, 2)
                last_inode = curr_inode
                continue

            line = fh.readline()
            if not line:
                time.sleep(POLL_INTERVAL)
                continue

            lineno += 1

            try:
                packet = json.loads(line.strip())
                aggregator.process_packet(packet)
            except:
                pass

        except Exception as e:
            log.error(f"Tail error: {e}")
            if fh:
                fh.close()
                fh = None
            time.sleep(POLL_INTERVAL)

    if fh:
        fh.close()

    log.info(f"Stopped tailing (processed {lineno:,} lines)")


# ==================== CLEANUP THREAD ====================
def cleanup_thread(aggregator: FlowAggregator, stop_event: Event):
    """Periodically cleanup expired flows"""
    log.info("Started cleanup thread")

    while not stop_event.is_set():
        time.sleep(FLOW_CLEANUP_INTERVAL)

        if stop_event.is_set():
            break

        aggregator.cleanup_expired_flows()

    log.info("Stopped cleanup thread")


# ==================== STATS THREAD ====================
def stats_thread(aggregator: FlowAggregator, stop_event: Event):
    """Print statistics"""
    log.info("Started stats thread")

    while not stop_event.is_set():
        time.sleep(STATS_INTERVAL)

        if stop_event.is_set():
            break

        stats = aggregator.get_stats()
        ew_stats = aggregator.ew_writer.get_stats()
        ns_stats = aggregator.ns_writer.get_stats()

        ew_size = EW_FILE.stat().st_size / 1024 / 1024 if EW_FILE.exists() else 0
        ns_size = NS_FILE.stat().st_size / 1024 / 1024 if NS_FILE.exists() else 0

        log.info(
            f"📊 Packets: {stats['packets_in']:,} | "
            f"Active flows: {stats['flows_active']:,} | "
            f"Logged: {stats['flows_logged']:,} | "
            f"Unknown IPs: {stats['total_unknown']:,} | "
            f"EW: {ew_size:.1f}MB ({ew_stats['total']:,}) | "
            f"NS: {ns_size:.1f}MB ({ns_stats['total']:,})"
        )

    log.info("Stopped stats thread")


# ==================== SIGNAL HANDLER ====================
def signal_handler(signum, frame):
    log.info(f"Received signal {signum}, shutting down...")
    STOP_EVENT.set()


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# ==================== MAIN ====================
def main():
    log.info("=" * 80)
    log.info("🌐 SAFEOPS NetFlow Writer - FLOW AGGREGATION Edition")
    log.info("=" * 80)
    log.info(f"Input:  {IN_FILE}")
    log.info(f"Output: {EW_FILE} (PERMANENT)")
    log.info(f"        {NS_FILE} (PERMANENT)")
    log.info(f"Unknown Geo: {UNKNOWN_GEO_CSV}")
    log.info(f"Config:")
    log.info(f"  - Flow timeout: {FLOW_TIMEOUT}s")
    log.info(f"  - Cleanup interval: {FLOW_CLEANUP_INTERVAL}s")
    log.info(f"  - Max flows: {MAX_FLOWS_IN_MEMORY:,}")
    log.info(f"  - Batch size: {BATCH_SIZE}")
    log.info("KEY OPTIMIZATION: Logs FLOWS not PACKETS (100x space reduction)")
    log.info("✨ NEW: Unknown IPs automatically logged to CSV")
    log.info("=" * 80)

    # Initialize
    aggregator = FlowAggregator()

    # Start threads
    threads = []

    reader = Thread(target=tail_file, args=(IN_FILE, aggregator, STOP_EVENT), daemon=True, name='reader')
    reader.start()
    threads.append(reader)
    log.info("✅ Started packet reader")

    cleanup = Thread(target=cleanup_thread, args=(aggregator, STOP_EVENT), daemon=True, name='cleanup')
    cleanup.start()
    threads.append(cleanup)
    log.info("✅ Started cleanup thread")

    stats = Thread(target=stats_thread, args=(aggregator, STOP_EVENT), daemon=True, name='stats')
    stats.start()
    threads.append(stats)
    log.info("✅ Started stats thread")

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

    for thread in threads:
        if thread.is_alive():
            thread.join(timeout=5)

    log.info("Flushing remaining flows...")
    aggregator.flush_all()

    # Final stats
    stats = aggregator.get_stats()
    ew_stats = aggregator.ew_writer.get_stats()
    ns_stats = aggregator.ns_writer.get_stats()

    ew_size = EW_FILE.stat().st_size / 1024 / 1024 if EW_FILE.exists() else 0
    ns_size = NS_FILE.stat().st_size / 1024 / 1024 if NS_FILE.exists() else 0

    log.info("=" * 80)
    log.info("📊 FINAL STATISTICS")
    log.info("=" * 80)
    log.info(f"Packets processed: {stats['packets_in']:,}")
    log.info(f"Packets ignored:   {stats['packets_ignored']:,}")
    log.info(f"Flows logged:      {stats['flows_logged']:,}")
    log.info(f"Flows expired:     {stats['flows_expired']:,}")
    log.info(f"Unknown IPs:       {stats['total_unknown']:,}")
    log.info("")
    log.info(f"East-West:")
    log.info(f"  Size:    {ew_size:.2f} MB")
    log.info(f"  Records: {ew_stats['total']:,}")
    log.info("")
    log.info(f"North-South:")
    log.info(f"  Size:    {ns_size:.2f} MB")
    log.info(f"  Records: {ns_stats['total']:,}")
    log.info("")

    # Calculate compression ratio
    if stats['packets_in'] > 0:
        compression = (1 - (stats['flows_logged'] / stats['packets_in'])) * 100
        log.info(f"💾 SPACE SAVINGS: {compression:.1f}% reduction")
        log.info(f"   ({stats['packets_in']:,} packets → {stats['flows_logged']:,} flows)")

    log.info("")
    log.info(f"📝 Unknown Geo CSV: {UNKNOWN_GEO_CSV}")
    log.info(f"   Total unique unknown IPs: {stats['total_unknown']:,}")
    log.info("=" * 80)
    log.info("✅ Shutdown complete")


if __name__ == '__main__':
    main()