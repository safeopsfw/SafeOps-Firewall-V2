from __future__ import annotations
import argparse
import time
import datetime
import pytz
import struct
import socket
import os
import sys
import json
import traceback
from pathlib import Path
from typing import Optional, Iterable, Tuple, Dict, Any, Generator, List, Union

# Define IST timezone (user/project timezone)
IST = pytz.timezone('Asia/Kolkata')

# Try importing project utilities (helpers/crypto). Fall back to local import path if executed standalone.
try:
    from ..utils.helpers import enrich_domain, enrich_geo, enrich_abuse_ip, enrich_virustotal, store_hashes  # type: ignore
    from ..utils.crypto import sha1_hex, sha256_hex  # type: ignore
except Exception:
    current_dir = Path(__file__).resolve().parent
    utils_dir = current_dir.parent / 'utils'
    if utils_dir.exists():
        sys.path.insert(0, str(utils_dir))
    try:
        from helpers import enrich_domain, enrich_geo, enrich_abuse_ip, enrich_virustotal, store_hashes  # type: ignore
        from crypto import sha1_hex, sha256_hex  # type: ignore
    except Exception:
        # Define minimal fallbacks so module can run without all helpers (tests/dev)
        def enrich_domain(x): return {}
        def enrich_geo(x): return {}
        def enrich_abuse_ip(x): return {}
        def enrich_virustotal(x): return {}
        def store_hashes(*args, **kwargs): return None
        def sha1_hex(s: str) -> str:
            import hashlib
            return hashlib.sha1(s.encode('utf-8')).hexdigest()
        def sha256_hex(s: str) -> str:
            import hashlib
            return hashlib.sha256(s.encode('utf-8')).hexdigest()

# jsonschema is required for validation
try:
    import jsonschema
    from jsonschema import Draft7Validator
except Exception:
    print("Error: jsonschema package is required. Install with: pip install jsonschema")
    sys.exit(1)

# Lazy presence flags for optional parsers
_HAS_SCAPY = None
_HAS_DPKT = None

def lazy_has_scapy() -> bool:
    global _HAS_SCAPY
    if _HAS_SCAPY is None:
        try:
            import scapy.all  # noqa: F401
            _HAS_SCAPY = True
        except Exception:
            _HAS_SCAPY = False
    return _HAS_SCAPY

def lazy_has_dpkt() -> bool:
    global _HAS_DPKT
    if _HAS_DPKT is None:
        try:
            import dpkt  # noqa: F401
            _HAS_DPKT = True
        except Exception:
            _HAS_DPKT = False
    return _HAS_DPKT

def _find_project_root(name: str = "safeops") -> Path:
    """Walk upwards to find the project root folder named `name`."""
    this = Path(__file__).resolve()
    for parent in this.parents:
        if parent.name == name:
            return parent
    # fallback to current working dir
    return Path.cwd()

def _create_missing_file(file_path: Path, content: str, file_type: str) -> bool:
    """Create a missing file with default content if it doesn't exist."""
    if file_path.exists():
        return False
    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Created {file_type} file: {file_path}")
        return True
    except Exception as e:
        print(f"Failed to create {file_type} file {file_path}: {e}")
        return False

def _load_schema(project_root: Path) -> Dict[str, Any]:
    """Load JSON schema for firewall logs, create it if missing (keeps old filename firewall_schema.json)."""
    schema_dir = project_root / 'backend' / 'modules' / 'logging_engine' / 'config' / 'schemas'
    schema_path = schema_dir / 'firewall_schema.json'
    if not schema_path.exists():
        # Write the full firewall schema (production-ready) as default content
        default_schema = {
          "$schema": "http://json-schema.org/draft-07/schema#",
          "title": "Firewall Full Schema",
          "description": "Comprehensive schema for firewall logs: policy/rule events, NAT, session metrics, interfaces/zones, threat intel and enrichments.",
          "type": "object",
          "required": ["timestamp", "event_id", "log_source", "action", "network"],
          "properties": {
            "timestamp": { "type": "string", "format": "date-time", "description": "UTC ISO8601 timestamp of event." },
            "event_id": { "type": "string", "description": "Unique event identifier." },
            "flow_id": { "type": ["integer","string"], "description": "Optional flow/session id for correlation (from firewall or external flow engine)." },
            "log_source": { "type": "string", "description": "Device/sensor name (e.g., fw-01)." },
            "log_type": { "type": "string", "enum": ["firewall", "fw_event"], "description": "Log type." },
            "version": { "type": "string", "description": "Schema version." },

            "network": {
              "type": "object",
              "required": ["src_ip", "dst_ip", "protocol"],
              "properties": {
                "src_ip": { "type": "string" },
                "dst_ip": { "type": "string" },
                "src_port": { "type": ["integer","null"] },
                "dst_port": { "type": ["integer","null"] },
                "protocol": { "type": "string", "description": "TCP/UDP/ICMP or numeric protocol." },
                "protocol_number": { "type": "integer" },
                "ip_version": { "type": "integer", "enum": [4,6] },
                "bytes": { "type": "integer", "minimum": 0, "description": "Total bytes observed for session/event." },
                "packets": { "type": "integer", "minimum": 0, "description": "Total packets observed." },
                "tcp_flags": { "type": "string", "description": "Observed TCP flags (aggregated, e.g., SYN,ACK,FIN)." },
                "ttl": { "type": "integer" }
              }
            },

            "action": {
              "type": "string",
              "enum": ["allow", "accept", "deny", "drop", "reject", "log"],
              "description": "Firewall decision for the flow."
            },

            "policy": {
              "type": "object",
              "properties": {
                "policy_id": { "type": ["integer","string"], "description": "Policy identifier." },
                "rule_id": { "type": ["integer","string"], "description": "Rule identifier." },
                "rule_name": { "type": "string" },
                "rule_description": { "type": "string" },
                "matched_service": { "type": "string", "description": "Service or application matched (e.g., HTTPS)." },
                "hit_count": { "type": "integer", "description": "Rule/hit count (if provided)." }
              }
            },

            "interfaces_zones": {
              "type": "object",
              "properties": {
                "interface_in": { "type": "string" },
                "interface_out": { "type": "string" },
                "zone_src": { "type": "string" },
                "zone_dst": { "type": "string" },
                "vlan": { "type": "integer" }
              }
            },

            "nat": {
              "type": "object",
              "properties": {
                "nat_type": { "type": "string", "enum": ["static", "dynamic", "pat", "snat", "dnat", "none"] },
                "src_translated_ip": { "type": "string" },
                "src_translated_port": { "type": ["integer","null"] },
                "dst_translated_ip": { "type": "string" },
                "dst_translated_port": { "type": ["integer","null"] },
                "original_src_ip": { "type": "string" },
                "original_src_port": { "type": ["integer","null"] },
                "original_dst_ip": { "type": "string" },
                "original_dst_port": { "type": ["integer","null"] }
              }
            },

            "session": {
              "type": "object",
              "properties": {
                "session_id": { "type": ["string","integer"], "description": "Device session identifier." },
                "start_timestamp": { "type": "string", "format": "date-time" },
                "end_timestamp": { "type": "string", "format": "date-time" },
                "duration": { "type": "number", "minimum": 0 },
                "state": { "type": "string", "description": "Session state (e.g., ESTABLISHED, TIME_WAIT)." },
                "termination_reason": { "type": "string" }
              }
            },

            "user": {
              "type": "object",
              "properties": {
                "src_user": { "type": "string" },
                "dst_user": { "type": "string" },
                "identity_type": { "type": "string", "description": "e.g., AD, local, RADIUS" }
              }
            },

            "application": {
              "type": "object",
              "properties": {
                "app_id": { "type": ["string","integer"] },
                "app_name": { "type": "string" },
                "app_risk": { "type": "string" },
                "app_category": { "type": "string" }
              }
            },

            "threat_intel": {
              "type": "object",
              "properties": {
                "ioc_matches": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "ioc_type": { "type": "string" },
                      "ioc_value": { "type": "string" },
                      "source": { "type": "string" },
                      "confidence": { "type": "integer" }
                    }
                  }
                },
                "reputation_score": { "type": "integer", "minimum": 0, "maximum": 100 },
                "malware_family": { "type": "string" }
              }
            },

            "geolocation": {
              "type": "object",
              "properties": {
                "src_country": { "type": "string" },
                "src_country_code": { "type": "string" },
                "src_region": { "type": "string" },
                "src_city": { "type": "string" },
                "dst_country": { "type": "string" },
                "dst_country_code": { "type": "string" },
                "dst_region": { "type": "string" },
                "dst_city": { "type": "string" },
                "src_asn": { "type": "integer" },
                "dst_asn": { "type": "integer" },
                "src_as_org": { "type": "string" },
                "dst_as_org": { "type": "string" }
              }
            },

            "fw_metadata": {
              "type": "object",
              "properties": {
                "device_model": { "type": "string" },
                "device_os": { "type": "string" },
                "ingest_pipeline": { "type": "string" },
                "parsed_by": { "type": "string" },
                "raw_message": { "type": "string" }
              }
            },

            "related": {
              "type": "object",
              "properties": {
                "related_event_ids": { "type": "array", "items": { "type": "string" } },
                "correlation_key": { "type": "string" }
              }
            },

            "meta": {
              "type": "object",
              "properties": {
                "validation_error": { "type": ["string","null"] },
                "notes": { "type": "string" }
              }
            }
          },
          "additionalProperties": False
        }
        _create_missing_file(schema_path, json.dumps(default_schema, indent=2), "schema")
    # load
    try:
        with open(schema_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Failed to load schema {schema_path}: {e}")
        return {}

def _load_config(project_root: Path) -> Dict[str, Any]:
    """Load config.yaml, create it if missing. Minimal defaults provided if yaml not available."""
    config_path = project_root / 'backend' / 'modules' / 'logging_engine' / 'config' / 'config.yaml'
    if not config_path.exists():
        _create_missing_file(
            config_path,
            """# Default config.yaml for SafeOps
logging:
  network_raw:
    path: logs/network_raw.log
    rotation: time
    time_interval: 120
  ngfw:
    path: logs/ngfw.log
    rotation: size
    size_limit: 100MB
    backups: 5
  ids:
    path: logs/ids_logs.log
    rotation: size
    size_limit: 100MB
    backups: 5
threat_intel:
  domain:
    enabled: true
    path: backend/modules/Domain/phishing_master.csv
  geo: {enabled: false}
  abuseip: {enabled: false}
  virustotal: {enabled: false}
""",
            "configuration"
        )
    try:
        import yaml  # type: ignore
        with open(config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}
    except Exception:
        # fallback defaults
        return {"threat_intel": {"domain": {"enabled": True}, "geo": {"enabled": False}, "abuseip": {"enabled": False}, "virustotal": {"enabled": False}}}

def _cli_status_check() -> None:
    """
    Check the environment, configuration, and log paths, print status.
    Creates missing files (config.yaml, firewall_schema.json, phishing_master.csv, logs, hashes directory) if needed.
    """
    try:
        project_root = _find_project_root()
        print(f"\n=== pcap_parser.py Status Check (Project Root: {project_root}) ===")
        print(f"Checked at: {datetime.datetime.now(IST).isoformat()}")

        # Dependency checks (avoid shadowing module names by not importing them into local scope)
        import importlib
        def _has_module(name: str) -> bool:
            return importlib.util.find_spec(name) is not None

        print("\nDependencies:")
        # core modules expected to be present (we only check availability)
        core_checks = [
            ("jsonschema", "jsonschema"),
            ("yaml (PyYAML)", "yaml")
        ]
        for label, modname in core_checks:
            print(f" - {label}: {'Available' if _has_module(modname) else 'Missing'}")

        # helpers & crypto modules (project-local)
        try:
            from helpers import enrich_domain, enrich_geo, enrich_abuse_ip, enrich_virustotal, store_hashes  # type: ignore
            print(" - helpers (enrich_domain, enrich_geo, enrich_abuse_ip, enrich_virustotal, store_hashes): Available")
        except Exception:
            print(" - helpers: Missing (fallbacks will be used)")

        try:
            from crypto import sha1_hex, sha256_hex  # type: ignore
            print(" - crypto (sha1_hex, sha256_hex): Available")
        except Exception:
            print(" - crypto: Missing (fallbacks will be used)")

        print(f" - scapy: {'Available' if lazy_has_scapy() else 'Missing (optional)'}")
        print(f" - dpkt: {'Available' if lazy_has_dpkt() else 'Missing (optional)'}")

        # Check configuration files
        config_dir = project_root / 'backend' / 'modules' / 'logging_engine' / 'config'
        logs_dir = project_root / 'logs'
        ti_dir = project_root / 'backend' / 'modules' / 'Domain'
        print("\nConfiguration Files:")
        for config_file in [config_dir / 'config.yaml', config_dir / 'schemas' / 'firewall_schema.json']:
            if not config_file.exists():
                if 'firewall_schema.json' in config_file.name:
                    _load_schema(project_root)
                else:
                    _load_config(project_root)
            status = "Exists" if config_file.exists() else "Missing"
            size = config_file.stat().st_size if config_file.exists() else 0
            try:
                mtime = datetime.datetime.fromtimestamp(config_file.stat().st_mtime, tz=IST).isoformat()
            except Exception:
                mtime = "N/A"
            print(f" - {config_file}: {status} (Size: {size} bytes, Last Modified: {mtime})")

        # Check logs directory and some default files
        print("\nLogs Directory:")
        if not logs_dir.exists():
            _create_missing_file(logs_dir / "placeholder.txt", "# Placeholder\n", "logs directory")
        logs_dir_status = "Exists" if logs_dir.exists() else "Missing"
        logs_dir_writable = "Yes" if logs_dir.exists() and os.access(logs_dir, os.W_OK) else "No"
        print(f" - {logs_dir}: {logs_dir_status} (Writable: {logs_dir_writable})")

        # Check hashes directory
        hash_dir = logs_dir / "hashes"
        if not hash_dir.exists():
            _create_missing_file(hash_dir / "placeholder.txt", "# Placeholder\n", "hashes directory")
        hash_dir_status = "Exists" if hash_dir.exists() else "Missing"
        hash_dir_writable = "Yes" if hash_dir.exists() and os.access(hash_dir, os.W_OK) else "No"
        print(f" - {hash_dir}: {hash_dir_status} (Writable: {hash_dir_writable})")

        # Check log files
        print("\nLog Files (safeops/logs/):")
        log_files = [
            ("network_raw.log", "log"),
            ("network_raw_errors.log", "log"),
            ("ngfw.log", "log"),
            ("ngfw_errors.log", "log"),
            ("ngfw_processed.log", "log"),
            ("ngfw_windows.log", "log"),
            ("ids_logs.log", "log")
        ]
        for log, _ in log_files:
            log_path = logs_dir / log
            if not log_path.exists():
                _create_missing_file(log_path, "# Placeholder log file\n", "log")
            status = "Exists" if log_path.exists() else "Missing"
            size = log_path.stat().st_size if log_path.exists() else 0
            try:
                mtime = datetime.datetime.fromtimestamp(log_path.stat().st_mtime, tz=IST).isoformat()
            except Exception:
                mtime = "N/A"
            writable = "Yes" if log_path.exists() and os.access(log_path, os.W_OK) else "No"
            print(f" - {log}: {status} (Size: {size} bytes, Last Modified: {mtime}, Writable: {writable})")

        # Check TI CSV (Domain only, as it's enabled in defaults)
        print("\nThreat Intelligence CSVs:")
        ti_path = ti_dir / 'phishing_master.csv'
        if not ti_path.exists():
            _create_missing_file(
                ti_path,
                "domain,category,source,timestamp\nexample.com,phishing,manual,2025-09-17T20:49:00+05:30\n",
                "threat intelligence"
            )
        status = "Exists" if ti_path.exists() else "Missing (Required for Domain TI)"
        size = ti_path.stat().st_size if ti_path.exists() else 0
        try:
            mtime = datetime.datetime.fromtimestamp(ti_path.stat().st_mtime, tz=IST).isoformat()
        except Exception:
            mtime = "N/A"
        print(f" - Domain ({ti_path}): {status} (Size: {size} bytes, Last Modified: {mtime})")

        # Summary
        issues = []
        if not (config_dir / 'config.yaml').exists():
            issues.append("config.yaml is missing")
        if not (config_dir / 'schemas' / 'firewall_schema.json').exists():
            issues.append("firewall_schema.json is missing")
        if not logs_dir.exists():
            issues.append("Logs directory (safeops/logs/) is missing")
        elif not os.access(logs_dir, os.W_OK):
            issues.append("Logs directory (safeops/logs/) is not writable")
        if not hash_dir.exists():
            issues.append("Hashes directory (safeops/logs/hashes/) is missing")
        elif not os.access(hash_dir, os.W_OK):
            issues.append("Hashes directory (safeops/logs/hashes/) is not writable")
        if not ti_path.exists():
            issues.append("phishing_master.csv is missing (required for enabled Domain TI)")
        for log, _ in log_files:
            log_path = logs_dir / log
            if log_path.exists() and not os.access(log_path, os.W_OK):
                issues.append(f"{log} is not writable")
        if not issues:
            print("\nStatus: All good! pcap_parser.py environment looks ready.")
            return
        else:
            print("\nStatus: Issues found:")
            for issue in issues:
                print(f" - {issue}")
            return

    except Exception as e:
        # Use global traceback module (not shadowed)
        print(f"Fatal error in status check: {e}")
        print(f"Traceback:\n{traceback.format_exc()}")
        return


# Load FIREWALL schema at import time so we can validate events
PROJECT_ROOT = _find_project_root()
FIREWALL_SCHEMA = _load_schema(PROJECT_ROOT)
_FIREWALL_VALIDATOR = Draft7Validator(FIREWALL_SCHEMA) if FIREWALL_SCHEMA else None

def _iso8601_from_epoch(epoch_secs: float) -> str:
    return datetime.datetime.fromtimestamp(epoch_secs, tz=IST).isoformat()

def _make_flow_id(src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str, start_ts: Optional[Union[int, float]]) -> str:
    ts_part = str(int(start_ts)) if start_ts is not None else "0"
    base = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}-{ts_part}"
    return sha1_hex(base)

def _tcp_flags_string(flags_int: int) -> Optional[str]:
    names = []
    if flags_int & 0x80: names.append("CWR")
    if flags_int & 0x40: names.append("ECE")
    if flags_int & 0x20: names.append("URG")
    if flags_int & 0x10: names.append("ACK")
    if flags_int & 0x08: names.append("PSH")
    if flags_int & 0x04: names.append("RST")
    if flags_int & 0x02: names.append("SYN")
    if flags_int & 0x01: names.append("FIN")
    return ",".join(names) if names else None

def _print_json(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, indent=2))
    sys.stdout.write("\n")
    sys.stdout.flush()

def _eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def _add_if_nonempty(out: Dict[str, Any], key: str, value: Any) -> None:
    """Helper: Add field only if non-empty/None."""
    if value is None:
        return
    if isinstance(value, dict) and not value:
        return
    if isinstance(value, (str, list)) and not value:
        return
    out[key] = value

def validate_event_against_schema(event: Dict[str, Any]) -> Dict[str, Any]:
    """Validate an event against the loaded firewall schema. Add meta.validation_error if invalid."""
    meta = event.setdefault("meta", {})
    if not _FIREWALL_VALIDATOR:
        meta["validation_error"] = "No schema loaded"
        return event
    errors = sorted(_FIREWALL_VALIDATOR.iter_errors(event), key=lambda e: e.path)
    if not errors:
        meta.pop("validation_error", None)
        return event
    # Aggregate errors into a single string
    msgs = []
    for err in errors:
        loc = ".".join([str(x) for x in err.path]) if err.path else "root"
        msgs.append(f"{loc}: {err.message}")
    meta["validation_error"] = "; ".join(msgs)
    return event

def parse_packet_minimal(raw_bytes: bytes, ts: Optional[float] = None) -> Dict[str, Any]:
    """
    Minimal parser: expects Ethernet + IPv4 payload. Extracts basic 5-tuple, protocol number, tcp flags, length.
    Produces an event compatible with firewall_schema.json (best-effort).
    """
    parsed_by = "minimal"
    ts_val = ts if ts is not None else time.time()
    iso_ts = _iso8601_from_epoch(ts_val)
    dummy_src = "0.0.0.0"
    dummy_dst = "0.0.0.0"
    out: Dict[str, Any] = {
        "timestamp": iso_ts,
        "event_id": sha1_hex(str(ts_val) + (raw_bytes[:128].hex() if isinstance(raw_bytes, (bytes, bytearray)) else str(raw_bytes))),
        "flow_id": None,
        "log_source": "minimal_parser",
        "log_type": "firewall",
        "event_type": "fw_event",
        "version": "1.0",
        "network": {
            "src_ip": dummy_src,
            "dst_ip": dummy_dst,
            "src_port": None,
            "dst_port": None,
            "protocol": "unknown",
            "protocol_number": None,
            "ip_version": 4,
            "bytes": len(raw_bytes) if isinstance(raw_bytes, (bytes, bytearray)) else 0,
            "packets": 1,
            "ttl": None
        },
        "action": "log",
        "policy": {},
        "interfaces_zones": {},
        "nat": {},
        "session": {},
        "threat_intel": {},
        "geolocation": {},
        "fw_metadata": {},
        "meta": {"parsed_by": parsed_by}
    }

    # Validate minimal length
    if not isinstance(raw_bytes, (bytes, bytearray)) or len(raw_bytes) < 34:
        out["meta"]["notes"] = "raw too short or not bytes"
        return validate_event_against_schema(out)

    try:
        eth_type = struct.unpack("!H", raw_bytes[12:14])[0]
    except Exception:
        out["meta"]["notes"] = "failed to unpack ethertype"
        return validate_event_against_schema(out)

    # Only parse IPv4 here (minimal parser). If not IPv4, mark and return.
    if eth_type != 0x0800:
        out["network"]["protocol"] = "non-ip"
        out["meta"]["notes"] = f"ether type {hex(eth_type)} not IPv4"
        return validate_event_against_schema(out)

    # Parse IPv4 header (minimal)
    ip_header = raw_bytes[14:34]
    if len(ip_header) < 20:
        out["meta"]["notes"] = "incomplete ip header"
        return validate_event_against_schema(out)

    ver_ihl = ip_header[0]
    ihl = (ver_ihl & 0x0F) * 4
    protocol = ip_header[9]
    try:
        src_ip = socket.inet_ntoa(ip_header[12:16])
        dst_ip = socket.inet_ntoa(ip_header[16:20])
    except Exception:
        src_ip = dummy_src
        dst_ip = dummy_dst

    out["network"]["protocol_number"] = int(protocol)
    out["network"]["src_ip"] = src_ip
    out["network"]["dst_ip"] = dst_ip
    out["network"]["ip_version"] = 4

    # L4 parsing for TCP/UDP minimal
    l4_offset = 14 + ihl
    if protocol == 6 and len(raw_bytes) >= l4_offset + 14:  # TCP
        try:
            src_port, dst_port, seq, ack, offset_reserved_flags = struct.unpack("!HHIIB", raw_bytes[l4_offset:l4_offset+13] + b'\x00')
            # offset_reserved_flags is actually 1 byte here because of packing trick; better fallback
        except Exception:
            # fallback: extract first 4 bytes for ports
            try:
                src_port, dst_port = struct.unpack("!HH", raw_bytes[l4_offset:l4_offset+4])
            except Exception:
                src_port, dst_port = None, None
        # tcp flags generally at byte l4_offset+13 (offset depends on header length) - best-effort:
        if len(raw_bytes) > l4_offset + 13:
            flags_byte = raw_bytes[l4_offset + 13]
            flags_str = _tcp_flags_string(flags_byte)
        else:
            flags_str = None
        out["network"]["protocol"] = "TCP"
        out["network"]["src_port"] = src_port
        out["network"]["dst_port"] = dst_port
        out["network"]["tcp_flags"] = flags_str
    elif protocol == 17 and len(raw_bytes) >= l4_offset + 8:  # UDP
        try:
            src_port, dst_port = struct.unpack("!HH", raw_bytes[l4_offset:l4_offset+4])
        except Exception:
            src_port, dst_port = None, None
        out["network"]["protocol"] = "UDP"
        out["network"]["src_port"] = src_port
        out["network"]["dst_port"] = dst_port
    elif protocol == 1:  # ICMP
        out["network"]["protocol"] = "ICMP"
        # no ports
    else:
        out["network"]["protocol"] = f"proto:{protocol}"

    # Create flow_id from parsed tuple
    try:
        out["flow_id"] = _make_flow_id(out["network"]["src_ip"] or dummy_src,
                                       out["network"].get("src_port") or 0,
                                       out["network"]["dst_ip"] or dummy_dst,
                                       out["network"].get("dst_port") or 0,
                                       str(out["network"].get("protocol_number") or out["network"].get("protocol") or "unknown"),
                                       ts_val)
    except Exception:
        out["flow_id"] = sha1_hex(str(ts_val) + str(out["network"]))

    # Add minimal fw_metadata
    out["fw_metadata"]["parsed_by"] = parsed_by
    out["meta"]["parsed_by"] = parsed_by

    # Best-effort enrichments (non-blocking)
    try:
        if out["network"]["src_ip"]:
            out["geolocation"].update(enrich_geo(out["network"]["src_ip"]) or {})
        if out["network"]["dst_ip"]:
            out["geolocation"].update(enrich_geo(out["network"]["dst_ip"]) or {})
    except Exception:
        # don't fail parsing for enrichment errors
        out["meta"].setdefault("notes", "")
        out["meta"]["notes"] += " geo-enrich-failed"

    # Validate against schema and return
    return validate_event_against_schema(out)

# Example function: process raw bytes generator and print validated JSON
def process_and_print_packets(raw_packet_iter: Iterable[Tuple[bytes, Optional[float]]]) -> None:
    for raw, ts in raw_packet_iter:
        try:
            evt = parse_packet_minimal(raw, ts=ts)
            _print_json(evt)
        except Exception as e:
            _eprint("Failed to parse packet:", e)
            _eprint(traceback.format_exc())

# Small helper to read a raw pcap file using available libs (scapy preferred, dpkt fallback, else raw chunks)
def read_pcap_bytes(path: Path) -> Generator[Tuple[bytes, float], None, None]:
    """Yield tuples (raw_bytes, ts). Tries scapy, then dpkt, else yields raw file bytes once."""
    if lazy_has_scapy():
        try:
            from scapy.all import rdpcap  # type: ignore
            pkts = rdpcap(str(path))
            for p in pkts:
                try:
                    raw = bytes(p)
                    ts = float(getattr(p, 'time', time.time()))
                    yield raw, ts
                except Exception:
                    continue
            return
        except Exception:
            pass
    if lazy_has_dpkt():
        try:
            import dpkt  # type: ignore
            with open(path, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                for ts, buf in pcap:
                    yield buf, float(ts)
            return
        except Exception:
            pass
    # Last resort: read whole file as single raw blob
    try:
        with open(path, 'rb') as f:
            data = f.read()
            yield data, time.time()
    except Exception:
        return

def _example_unit_test_event() -> Dict[str, Any]:
    """Return an example firewall event (useful for unit tests)."""
    now = time.time()
    event = {
        "timestamp": _iso8601_from_epoch(now),
        "event_id": sha1_hex(str(now) + "example"),
        "flow_id": sha1_hex("10.0.0.5:54321-198.51.100.10:80-TCP-0"),
        "log_source": "fw-01",
        "log_type": "firewall",
        "event_type": "fw_event",
        "network": {
            "src_ip": "10.0.0.5",
            "dst_ip": "198.51.100.10",
            "src_port": 54321,
            "dst_port": 80,
            "protocol": "TCP",
            "protocol_number": 6,
            "ip_version": 4,
            "bytes": 1500,
            "packets": 10,
            "tcp_flags": "SYN,ACK",
            "ttl": 64
        },
        "action": "deny",
        "policy": {
            "policy_id": "p-1234",
            "rule_id": "r-900",
            "rule_name": "Block-HTTP-From-X",
            "matched_service": "HTTP"
        },
        "interfaces_zones": {
            "interface_in": "ge-0/0/1",
            "interface_out": "ge-0/0/2",
            "zone_src": "internal",
            "zone_dst": "dmz",
            "vlan": 100
        },
        "nat": {
            "nat_type": "dnat",
            "src_translated_ip": "203.0.113.50",
            "src_translated_port": None
        },
        "session": {
            "session_id": "s-1001",
            "start_timestamp": _iso8601_from_epoch(now - 5),
            "end_timestamp": _iso8601_from_epoch(now),
            "duration": 5.0,
            "state": "TERMINATED",
            "termination_reason": "policy-drop"
        },
        "threat_intel": {
            "ioc_matches": [
                {"ioc_type": "ip", "ioc_value": "198.51.100.10", "source": "phishing_master", "confidence": 80}
            ],
            "reputation_score": 20
        },
        "geolocation": {
            "src_country": "Private",
            "dst_country": "Exampleland",
            "src_asn": None,
            "dst_asn": 64512
        },
        "fw_metadata": {
            "device_model": "Acme-FW-1000",
            "device_os": "acme-os-9.1",
            "ingest_pipeline": "pcap_parser_minimal",
            "parsed_by": "minimal",
            "raw_message": ""
        },
        "meta": {
            "parsed_by": "example_unit",
            "validation_error": None
        }
    }
    return validate_event_against_schema(event)

def main() -> None:
    parser = argparse.ArgumentParser(description="pcap_parser (updated) - parse raw pcap or run status checks")
    parser.add_argument("--status", action="store_true", help="Run environment/status checks and create default schema/config if missing")
    parser.add_argument("--pcap", type=str, help="Path to pcap to parse (optional)")
    parser.add_argument("--example", action="store_true", help="Print example validated event")
    args = parser.parse_args()

    if args.status:
        _cli_status_check()
        return

    if args.example:
        evt = _example_unit_test_event()
        _print_json(evt)
        return

    if args.pcap:
        p = Path(args.pcap)
        if not p.exists():
            print(f"PCAP path {p} does not exist.")
            return
        for raw, ts in read_pcap_bytes(p):
            evt = parse_packet_minimal(raw, ts=ts)
            _print_json(evt)
        return

    # default: show help
    parser.print_help()

if __name__ == "__main__":
    main()
