"""
Compact JSON-lines serializer for SafeOps logging_engine.

Improvements:
- Normalizes datetime objects to ISO8601 via .isoformat() (UTC if tz-aware).
- Keeps deterministic hashing (stable JSON used for hash).
- Uses atomic_write from helpers.py for atomic file writes.
- Integrates with crypto.py for SHA1 hashing.
- Standalone mode checks configuration, dependencies, log paths, and phishing_master.csv status.
- Creates missing configuration, log, and TI files with default content.
- Windows-compatible, designed for SafeOps pipeline: capture -> parse -> serialize -> write.

CLI:
- --demo: Run demo serialization.
- --status: Check configuration, dependencies, and log paths, print status, create missing files.

Design notes:
- Thread-safe, minimal resource usage.
- Formats data for writers (netflow_writer.py, firewall_writer.py, ids_writer.py) and hash storage.
- Compatible with Windows (uses windows_adapter.py, docker-compose.windows.yml).
- Handles import errors and file creation gracefully for standalone execution.
"""
from __future__ import annotations
import json
import datetime
from pathlib import Path
import argparse
import sys
import os
from typing import Dict, Any, Iterable, Optional

# Fix imports for standalone execution
try:
    from ..utils.helpers import atomic_write
    from ..utils.crypto import sha1_hex
except ImportError:
    # Add utils/ directory to sys.path for standalone execution
    current_dir = Path(__file__).resolve().parent
    utils_dir = current_dir.parent / 'utils'
    if utils_dir.exists():
        sys.path.insert(0, str(utils_dir))
    try:
        from helpers import atomic_write
        from crypto import sha1_hex
    except ImportError as e:
        print(f"Error: Cannot import helpers.py or crypto.py: {e}")
        print("Ensure they are in safeops/backend/modules/logging_engine/utils/")
        sys.exit(1)

def _escape_string_for_single_line(s: str) -> str:
    return s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")

def _normalize_datetime(obj: Any) -> Any:
    """
    Convert datetime objects to ISO8601 strings (preserve timezone if present).
    """
    if isinstance(obj, datetime.datetime):
        if obj.tzinfo is None:
            obj = obj.replace(tzinfo=datetime.UTC)
        return obj.isoformat()
    return obj

def _sanitize_obj(obj: Any) -> Any:
    """
    Recursively sanitize:
    - Convert datetimes to ISO strings.
    - Escape newline/tab characters in strings.
    - Convert non-serializable objects to strings.
    """
    if obj is None:
        return None
    obj = _normalize_datetime(obj)
    if isinstance(obj, str):
        return _escape_string_for_single_line(obj)
    if isinstance(obj, (int, float, bool)):
        return obj
    if isinstance(obj, (list, tuple)):
        return [_sanitize_obj(v) for v in obj]
    if isinstance(obj, dict):
        return {str(k): _sanitize_obj(v) for k, v in obj.items()}
    try:
        return str(obj)
    except Exception:
        return repr(obj)

def _stable_json_dumps(obj: Dict[str, Any]) -> str:
    """
    Stable compact JSON used for hashing (deterministic order).
    """
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False, sort_keys=True)

def _compact_json_dumps(obj: Dict[str, Any]) -> str:
    """
    Compact JSON for final output. Uses sort_keys=True for deterministic output.
    """
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False, sort_keys=True)

def serialize_json_line(
    record: Dict[str, Any],
    add_hash: bool = False,
    source: Optional[str] = None,
    add_ts: bool = False
) -> str:
    """
    Serialize single record to one-line JSON.

    - Datetime objects are converted to ISO8601 strings.
    - Strings have embedded newlines/tabs escaped.
    - If add_hash=True, a deterministic sha1 hex is injected under "_hash".
    """
    if not isinstance(record, dict):
        raise TypeError("serialize_json_line expects a dict as 'record'")

    working: Dict[str, Any] = dict(record)  # shallow copy
    if source is not None:
        working["_source"] = source
    if add_ts:
        working["_ts"] = datetime.datetime.now(datetime.UTC).isoformat()

    sanitized = _sanitize_obj(working)
    stable_json = _stable_json_dumps(sanitized)
    if add_hash:
        sanitized["_hash"] = sha1_hex(stable_json)
        stable_json = _stable_json_dumps(sanitized)

    return _compact_json_dumps(sanitized)

def serialize_json_lines(
    records: Iterable[Dict[str, Any]],
    add_hash: bool = False,
    source: Optional[str] = None,
    add_ts: bool = False
) -> List[str]:
    return [
        serialize_json_line(rec, add_hash=add_hash, source=source, add_ts=add_ts)
        for rec in records
    ]

def write_jsonl(
    path: str,
    records: Iterable[Dict[str, Any]],
    mode: str = "a",
    add_hash: bool = False,
    source: Optional[str] = None,
    add_ts: bool = False,
    encoding: str = "utf-8",
) -> None:
    if mode not in ("a", "w"):
        raise ValueError("mode must be 'a' or 'w'")
    lines = serialize_json_lines(records, add_hash=add_hash, source=source, add_ts=add_ts)
    with open(path, mode + "t", encoding=encoding) as fh:
        for line in lines:
            fh.write(line)
            fh.write("\n")

def atomic_write_jsonl(
    path: str,
    records: Iterable[Dict[str, Any]],
    add_hash: bool = False,
    source: Optional[str] = None,
    add_ts: bool = False,
    encoding: str = "utf-8",
) -> None:
    """
    Atomically write JSONL using helpers.atomic_write.
    """
    lines = serialize_json_lines(records, add_hash=add_hash, source=source, add_ts=add_ts)
    data = "\n".join(lines).encode(encoding)
    atomic_write(path, data)

def _find_project_root(name: str = "safeops") -> Optional[Path]:
    """Walk upwards to find the project root folder named `name`."""
    this = Path(__file__).resolve()
    for parent in this.parents:
        if parent.name == name:
            return parent
    return None

def _default_paths():
    """Return (config_dir, logs_dir, ti_dir) based on project layout."""
    project_root = _find_project_root()
    if project_root:
        config_dir = project_root / 'backend' / 'modules' / 'logging_engine' / 'config'
        logs_dir = project_root / 'logs'
        ti_dir = project_root / 'backend' / 'modules' / 'Domain'
    else:
        try:
            base = Path(__file__).resolve().parents[3]
            config_dir = base / 'config'
            logs_dir = base / 'logs'
            ti_dir = base / 'backend' / 'modules' / 'Domain'
        except Exception:
            config_dir = Path('.') / 'config'
            logs_dir = Path('.') / 'logs'
            ti_dir = Path('.') / 'backend' / 'modules' / 'Domain'
    return config_dir, logs_dir, ti_dir

def _create_missing_file(file_path: Path, content: str, file_type: str) -> bool:
    """
    Create a missing file with default content if it doesn't exist.
    Returns True if created, False if it exists or creation fails.
    """
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

def _cli_status_check() -> None:
    """
    Check the environment, configuration, and log paths, print status.
    Creates missing files (config.yaml, logging.yaml, phishing_master.csv, logs) if needed.
    """
    try:
        # Ensure datetime is the module, not shadowed
        import datetime as dt_module
        print("\n=== json_line_serializer.py Status Check ===")
        print(f"Checked at: {dt_module.datetime.now(dt_module.UTC).isoformat()}")

        # Check dependencies
        print("\nDependencies:")
        try:
            import json, datetime, hashlib, tempfile, os
            print(" - Standard libraries (json, datetime, hashlib, tempfile, os): Available")
        except ImportError as e:
            print(f" - Standard libraries: Missing ({e})")
            return
        try:
            from helpers import atomic_write
            print(" - helpers.atomic_write: Available")
        except ImportError as e:
            print(f" - helpers.atomic_write: Missing ({e})")
            return
        try:
            from crypto import sha1_hex
            print(" - crypto.sha1_hex: Available")
        except ImportError as e:
            print(f" - crypto.sha1_hex: Missing ({e})")
            return

        # Check and create configuration files
        config_dir, logs_dir, ti_dir = _default_paths()
        print("\nConfiguration Files:")
        config_files = [
            (config_dir / 'config.yaml',
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
threat_intel:
  domain:
    enabled: true
    path: backend/modules/Domain/phishing_master.csv
  geo: {enabled: false}
  abuseip: {enabled: false}
  virustotal: {enabled: false}
""", "configuration"),
            (config_dir / 'logging.yaml',
             """# Default logging.yaml for SafeOps
version: 1
handlers:
  network_raw:
    class: logging.handlers.TimedRotatingFileHandler
    filename: logs/network_raw.log
    when: S
    interval: 120
  ngfw:
    class: logging.handlers.RotatingFileHandler
    filename: logs/ngfw.log
    maxBytes: 104857600
    backupCount: 5
""", "logging configuration")
        ]
        for config_file, default_content, file_type in config_files:
            if not config_file.exists():
                _create_missing_file(config_file, default_content, file_type)
            status = "Exists" if config_file.exists() else "Missing"
            size = config_file.stat().st_size if config_file.exists() else 0
            try:
                mtime = dt_module.datetime.fromtimestamp(config_file.stat().st_mtime, tz=dt_module.UTC).isoformat()
            except Exception:
                mtime = "N/A"
            print(f" - {config_file.name}: {status} (Size: {size} bytes, Last Modified: {mtime})")

        # Check and create logs directory
        print("\nLogs Directory:")
        if not logs_dir.exists():
            try:
                logs_dir.mkdir(parents=True, exist_ok=True)
                print(f"Created logs directory: {logs_dir}")
            except Exception as e:
                print(f"Failed to create logs directory {logs_dir}: {e}")
        logs_dir_status = "Exists" if logs_dir.exists() else "Missing"
        logs_dir_writable = "Yes" if logs_dir.exists() and os.access(logs_dir, os.W_OK) else "No"
        print(f" - {logs_dir}: {logs_dir_status} (Writable: {logs_dir_writable})")

        # Check and create log files
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
        for log, file_type in log_files:
            log_path = logs_dir / log
            if not log_path.exists():
                _create_missing_file(log_path, "# Placeholder log file\n", file_type)
            status = "Exists" if log_path.exists() else "Missing"
            size = log_path.stat().st_size if log_path.exists() else 0
            try:
                mtime = dt_module.datetime.fromtimestamp(log_path.stat().st_mtime, tz=dt_module.UTC).isoformat()
            except Exception:
                mtime = "N/A"
            writable = "Yes" if log_path.exists() and os.access(log_path, os.W_OK) else "No"
            print(f" - {log}: {status} (Size: {size} bytes, Last Modified: {mtime}, Writable: {writable})")

        # Check and create TI CSV (Domain only, as it's enabled)
        print("\nThreat Intelligence CSVs:")
        ti_path = ti_dir / 'phishing_master.csv'
        if not ti_path.exists():
            _create_missing_file(ti_path,
                "domain,category,source,timestamp\nexample.com,phishing,manual,2025-09-16T00:00:00+00:00\n",
                "threat intelligence")
        status = "Exists" if ti_path.exists() else "Missing (Required for Domain TI)"
        size = ti_path.stat().st_size if ti_path.exists() else 0
        try:
            mtime = dt_module.datetime.fromtimestamp(ti_path.stat().st_mtime, tz=dt_module.UTC).isoformat()
        except Exception:
            mtime = "N/A"
        print(f" - Domain (backend/modules/Domain/phishing_master.csv): {status} (Size: {size} bytes, Last Modified: {mtime}, Status: Enabled)")

        # Summary
        issues = []
        if not (config_dir / 'config.yaml').exists():
            issues.append("config.yaml is missing")
        if not (config_dir / 'logging.yaml').exists():
            issues.append("logging.yaml is missing")
        if not logs_dir.exists():
            issues.append("Logs directory (safeops/logs/) is missing")
        elif not os.access(logs_dir, os.W_OK):
            issues.append("Logs directory (safeops/logs/) is not writable")
        if not ti_path.exists():
            issues.append("phishing_master.csv is missing (required for enabled Domain TI)")
        for log, _ in log_files:
            log_path = logs_dir / log
            if log_path.exists() and not os.access(log_path, os.W_OK):
                issues.append(f"{log} is not writable")
        if not issues:
            print("\nStatus: All good! json_line_serializer.py is ready for use.")
        else:
            print("\nStatus: Issues found:")
            for issue in issues:
                print(f" - {issue}")
        print("\n=== End of Status Check ===")

    except Exception as e:
        print(f"Error in status check: {e}")
        print("Please verify imports and environment configuration.")
        sys.exit(1)

def _demo_print():
    try:
        import datetime as dt_module
        sample = {
            "event": "login",
            "user": "alice",
            "message": "User logged in\\nfrom web\\tendpoint",
            "count": 1,
            "ts": dt_module.datetime.now(dt_module.UTC)
        }
        print("Original sample:")
        print(sample)
        print("\nSerialized (no hash, no ts):")
        print(serialize_json_line(sample))
        print("\nSerialized (with _source, _hash, and _ts):")
        print(serialize_json_line(sample, add_hash=True, source="pcap_parser", add_ts=True))
    except Exception as e:
        print(f"Error in demo print: {e}")
        sys.exit(1)

__all__ = [
    "serialize_json_line",
    "serialize_json_lines",
    "write_jsonl",
    "atomic_write_jsonl",
]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="json_line_serializer.py utility")
    parser.add_argument('--demo', action='store_true', help='Run demo serialization')
    parser.add_argument('--status', action='store_true', help='Check configuration and dependencies, create missing files, print status')
    args = parser.parse_args()

    if args.demo:
        _demo_print()
    else:
        _cli_status_check()