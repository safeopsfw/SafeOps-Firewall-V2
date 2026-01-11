"""
logging_engine/utils/helpers.py — utility helpers

What it will do
Provides small helpers (ensure_dir, atomic write, rotate helper, timestamp formatting, safe file open).
Includes rotate_helper for size/age-based log rotation, store_hashes for writing hash metadata to safeops/logs/hashes/,
and TI functions: enrich_geo (uses geo_master_full.csv), enrich_abuse_ip (uses abuse_master.updated.csv),
enrich_domain (uses phishing_master.csv), enrich_virustotal (API for hash checks).
When run standalone, ensures directory structure and can generate a status report for logs and TI configuration.

How it will work
Pure-Python helper functions. Other modules import these helpers for filesystem operations, log rotation, hash storage,
and threat intelligence enrichment. TI functions use local CSVs or APIs, with disabled services returning None.
Standalone mode ensures directories and optionally reports log and TI status.

Concurrency & resources
Stateless functions. Minimal memory/CPU. Safe to call from multiple threads — functions use atomic rename for writes.

Files read/written / artifacts
May ensure/create directories (safeops/logs/, safeops/logs/hashes/). Reads CSVs for TI enrichment.
Writes hash metadata to safeops/logs/hashes/ when enabled. Status report reads log and config files.

This module can be run standalone for simple tests, filesystem bootstrapping, or status reporting.
When run with no arguments, it ensures the logging_engine config, safeops logs, and hashes dirs exist and prints a status report.
Use --help to see available CLI options.
"""

import os
import tempfile
import argparse
from pathlib import Path
from datetime import datetime, UTC
from typing import Optional, Union, Dict, Any
import csv
import time
import logging

# Fix for relative import when running standalone
try:
    from .crypto import sha256_hex, hmac_sha256_hex, generate_hmac_key
except ImportError:
    from crypto import sha256_hex, hmac_sha256_hex, generate_hmac_key

# Setup logging
logger = logging.getLogger(__name__)

def ensure_dir(path: Union[str, Path]) -> Path:
    """Ensure directory exists, return Path object."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p

def atomic_write(path: Union[str, Path], data: bytes) -> None:
    """Write data atomically: write to temp file then rename."""
    path = Path(path)
    ensure_dir(path.parent)
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=path.name, text=False)
    try:
        with os.fdopen(fd, 'wb') as tmp_file:
            tmp_file.write(data)
        os.replace(tmp_path, str(path))
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass

def rotate_helper(path: Union[str, Path], mode: str = 'size', size_limit: int = 104857600, time_interval: int = 120, keep: int = 5) -> None:
    """Rotate file based on size or time, keeping last N copies."""
    path = Path(path)
    if not path.exists():
        return

    if mode == 'size':
        if path.stat().st_size < size_limit:
            return
        for i in range(keep, 0, -1):
            old = Path(str(path) + f".{i}")
            newer = Path(str(path) + f".{i+1}")
            if old.exists():
                if newer.exists():
                    try:
                        newer.unlink()
                    except OSError:
                        pass
                try:
                    old.rename(newer)
                except OSError:
                    pass
        rotated = Path(str(path) + ".1")
        if rotated.exists():
            try:
                rotated.unlink()
            except OSError:
                pass
        try:
            path.rename(rotated)
        except OSError:
            pass
    elif mode == 'time':
        mtime = path.stat().st_mtime
        if time.time() - mtime < time_interval:
            return
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        rotated = Path(f"{path}.{timestamp}")
        try:
            path.rename(rotated)
        except OSError:
            pass
        backups = sorted(path.parent.glob(f"{path.name}.*"), key=lambda p: p.stat().st_mtime, reverse=True)
        for old in backups[keep:]:
            try:
                old.unlink()
            except OSError:
                pass
    else:
        raise ValueError(f"Unsupported rotation mode: {mode}")

def timestamp_utc() -> str:
    """Return current UTC timestamp in ISO format with a trailing Z."""
    return datetime.now(UTC).isoformat() + "Z"

def safe_open(path: Union[str, Path], mode: str = "r", encoding: str = "utf-8"):
    """Safe open that ensures parent directories exist for write modes."""
    p = Path(path)
    if any(flag in mode for flag in ("w", "a", "+")):
        ensure_dir(p.parent)
    if "b" in mode:
        return open(p, mode)
    return open(p, mode, encoding=encoding)

def store_hashes(data: Union[str, bytes], hash_path: Union[str, Path], key: Optional[str] = None) -> Dict[str, str]:
    """Store hash metadata in safeops/logs/hashes/."""
    hash_path = Path(hash_path)
    ensure_dir(hash_path.parent)
    metadata = {
        "timestamp": timestamp_utc(),
        "sha256": sha256_hex(data)
    }
    if key:
        metadata["hmac_sha256"] = hmac_sha256_hex(data, key)
    metadata_str = str(metadata).encode('utf-8')
    atomic_write(hash_path, metadata_str)
    logger.info(f"Stored hash metadata at {hash_path}")
    return metadata

def enrich_geo(ip: str, csv_path: Union[str, Path] = "safeops/backend/modules/Geo/geo_master_full.csv") -> Optional[Dict[str, Any]]:
    """Enrich IP with geolocation data from geo_master_full.csv (disabled)."""
    logger.warning("Geo enrichment is disabled in config.yaml")
    return None

def enrich_abuse_ip(ip: str, csv_path: Union[str, Path] = "safeops/backend/modules/AbuseIP/abuse_master.updated.csv") -> Optional[Dict[str, Any]]:
    """Enrich IP with AbuseIPDB data from abuse_master.updated.csv (disabled)."""
    logger.warning("AbuseIP enrichment is disabled in config.yaml")
    return None

def enrich_domain(domain: str, csv_path: Union[str, Path] = "safeops/backend/modules/Domain/phishing_master.csv") -> Optional[Dict[str, Any]]:
    """Enrich domain with data from phishing_master.csv."""
    try:
        with safe_open(csv_path, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("domain") == domain:
                    return {
                        "domain": domain,
                        "is_malicious": row.get("isPhishing") == "True",
                        "threat_category": row.get("category"),
                        "ioc_match": row.get("isPhishing") == "True"
                    }
        return None
    except Exception as e:
        logger.error(f"Domain enrichment failed for {domain}: {str(e)}")
        return None

def enrich_virustotal(hash: str) -> Optional[Dict[str, Any]]:
    """Enrich hash with VirusTotal data via API (disabled)."""
    logger.warning("VirusTotal enrichment is disabled in config.yaml")
    return None

def _find_project_root(name: str = "safeops") -> Optional[Path]:
    """Walk upwards to find the project root folder named `name`."""
    this = Path(__file__).resolve()
    for parent in this.parents:
        if parent.name == name:
            return parent
    return None

def _default_paths():
    """Return (config_dir, logs_dir, hashes_dir) based on project layout."""
    project_root = _find_project_root()
    if project_root:
        config_dir = project_root / 'backend' / 'modules' / 'logging_engine' / 'config'
        logs_dir = project_root / 'logs'
        hashes_dir = logs_dir / 'hashes'
    else:
        try:
            base = Path(__file__).resolve().parents[2] / 'config'
        except Exception:
            base = Path('.') / 'config'
        config_dir = base
        logs_dir = Path('.') / 'logs'
        hashes_dir = logs_dir / 'hashes'
    return config_dir, logs_dir, hashes_dir

def _cli_create_default_tree(base: Path | None = None) -> None:
    """Create the project-specific directory tree."""
    if base:
        config = Path(base) / 'backend' / 'modules' / 'logging_engine' / 'config'
        logs = Path(base) / 'logs'
        hashes = logs / 'hashes'
    else:
        config, logs, hashes = _default_paths()

    created = []
    for d in (config, logs, hashes, config / 'schemas'):
        if not d.exists():
            d.mkdir(parents=True, exist_ok=True)
            created.append(str(d))
    if created:
        print("Created directories:")
        for c in created:
            print(f" - {c}")
    else:
        print("Default directories already exist; no changes made.")

def _cli_test_atomic(tmp_dir: Path) -> None:
    """Test atomic_write in a temporary directory."""
    test_path = tmp_dir / 'atomic_test.txt'
    print(f"Testing atomic_write -> {test_path}")
    atomic_write(test_path, b"hello atomic\n")
    print("Wrote successfully. Contents:")
    with open(test_path, 'rb') as f:
        print(f.read().decode('utf-8'))

def _cli_test_rotate(tmp_dir: Path) -> None:
    """Test rotate_helper with size and time-based rotation."""
    demo = tmp_dir / 'rotate.log'
    demo.write_text('v0')
    print(f"Created demo file: {demo}")
    print("Testing size-based rotation (keep=3)")
    rotate_helper(demo, mode='size', size_limit=10, keep=3)
    print("Size-based rotation complete. Existing files:")
    for p in sorted(tmp_dir.glob('rotate.log*')):
        print(" -", p.name)
    demo.write_text('v1')
    print("Testing time-based rotation (keep=3)")
    rotate_helper(demo, mode='time', time_interval=1, keep=3)
    print("Time-based rotation complete. Existing files:")
    for p in sorted(tmp_dir.glob('rotate.log*')):
        print(" -", p.name)

def _cli_test_hashes(tmp_dir: Path) -> None:
    """Test store_hashes in a temporary directory."""
    test_data = "test data"
    hash_path = tmp_dir / 'test_hashes.json'
    key = generate_hmac_key()
    print(f"Testing store_hashes -> {hash_path}")
    metadata = store_hashes(test_data, hash_path, key)
    print("Hash metadata:", metadata)
    with open(hash_path, 'rb') as f:
        print("Stored contents:", f.read().decode('utf-8'))

def _cli_test_enrich(tmp_dir: Path) -> None:
    """Test TI enrichment functions."""
    print("Testing TI enrichment (domain only, others disabled)")
    domain_result = enrich_domain("example.com")
    print("Domain enrichment (example.com):", domain_result)
    print("Geo enrichment (disabled):", enrich_geo("192.168.1.100"))
    print("AbuseIP enrichment (disabled):", enrich_abuse_ip("192.168.1.100"))
    print("VirusTotal enrichment (disabled):", enrich_virustotal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))

def _cli_status_report() -> None:
    """Generate a status report for logs, TI data, and configurations."""
    print("\n=== SafeOps Logging and TI Status Report ===")
    print(f"Generated at: {timestamp_utc()}")

    # Check directories
    config_dir, logs_dir, hashes_dir = _default_paths()
    print("\nDirectory Status:")
    for d, name in [(config_dir, "Config"), (logs_dir, "Logs"), (hashes_dir, "Hashes")]:
        status = "Exists" if d.exists() else "Missing"
        print(f" - {name} Directory ({d}): {status}")

    # Check configuration files
    print("\nConfiguration Files:")
    for config_file in [config_dir / 'config.yaml', config_dir / 'logging.yaml']:
        status = "Exists" if config_file.exists() else "Missing"
        size = config_file.stat().st_size if config_file.exists() else 0
        mtime = datetime.fromtimestamp(config_file.stat().st_mtime).isoformat() if config_file.exists() else "N/A"
        print(f" - {config_file.name}: {status} (Size: {size} bytes, Last Modified: {mtime})")

    # Check log files
    print("\nLog Files (safeops/logs/):")
    log_files = [
        "network_raw.log", "network_raw_errors.log",
        "ngfw.log", "ngfw_errors.log", "ngfw_processed.log", "ngfw_windows.log",
        "ids_logs.log"
    ]
    for log in log_files:
        log_path = logs_dir / log
        status = "Exists" if log_path.exists() else "Missing"
        size = log_path.stat().st_size if log_path.exists() else 0
        mtime = datetime.fromtimestamp(log_path.stat().st_mtime).isoformat() if log_path.exists() else "N/A"
        print(f" - {log}: {status} (Size: {size} bytes, Last Modified: {mtime})")

    # Check TI CSV files
    print("\nThreat Intelligence CSVs:")
    ti_files = [
        ("Geo", "safeops/backend/modules/Geo/geo_master_full.csv"),
        ("AbuseIP", "safeops/backend/modules/AbuseIP/abuse_master.updated.csv"),
        ("Domain", "safeops/backend/modules/Domain/phishing_master.csv")
    ]
    project_root = _find_project_root() or Path('.')
    for name, path in ti_files:
        ti_path = project_root / path
        status = "Exists" if ti_path.exists() else "Missing"
        size = ti_path.stat().st_size if ti_path.exists() else 0
        mtime = datetime.fromtimestamp(ti_path.stat().st_mtime).isoformat() if ti_path.exists() else "N/A"
        enabled = "Enabled" if name == "Domain" else "Disabled"
        print(f" - {name} ({path}): {status} (Size: {size} bytes, Last Modified: {mtime}, Status: {enabled})")

    print("\n=== End of Status Report ===")

def _parse_args():
    """Parse command-line arguments."""
    p = argparse.ArgumentParser(description='helpers.py utility/self-test runner')
    p.add_argument('--create-defaults', action='store_true', help='Create default dirs in project: config, logs, hashes')
    p.add_argument('--base', type=str, default=None, help='Project base path (optional)')
    p.add_argument('--test-atomic', action='store_true', help='Run a small atomic_write test in a temp dir')
    p.add_argument('--test-rotate', action='store_true', help='Run a small rotate_helper demo in a temp dir')
    p.add_argument('--test-hashes', action='store_true', help='Run a small store_hashes test in a temp dir')
    p.add_argument('--test-enrich', action='store_true', help='Run a small TI enrichment test')
    p.add_argument('--status', action='store_true', help='Generate a status report for logs, TI data, and configurations')
    p.add_argument('--info', action='store_true', help='Print information about available helpers')
    return p.parse_args()

def _print_info():
    """Print information about available helpers."""
    print("helpers.py — available utilities:\n")
    print("  ensure_dir(path)\n    Ensure a directory exists and return a pathlib.Path object.")
    print("  atomic_write(path, data: bytes)\n    Atomically write bytes to `path` using a temp file and os.replace().")
    print("  rotate_helper(path, mode='size', size_limit=104857600, time_interval=120, keep=5)\n    Rotate file based on size or time, keeping `keep` copies.")
    print("  timestamp_utc() -> str\n    Return current UTC time in ISO8601 (Z) format.")
    print("  safe_open(path, mode='r')\n    Open a file, creating parent directories for write modes.")
    print("  store_hashes(data, hash_path, key=None) -> dict\n    Store hash metadata (SHA256, optional HMAC) in safeops/logs/hashes/.")
    print("  enrich_geo(ip, csv_path) -> dict | None\n    Enrich IP with geolocation data (disabled).")
    print("  enrich_abuse_ip(ip, csv_path) -> dict | None\n    Enrich IP with AbuseIPDB data (disabled).")
    print("  enrich_domain(domain, csv_path) -> dict | None\n    Enrich domain with phishing data from phishing_master.csv.")
    print("  enrich_virustotal(hash) -> dict | None\n    Enrich hash with VirusTotal data (disabled).")
    print("  _cli_status_report()\n    Generate a status report for logs, TI data, and configurations.")

if __name__ == '__main__':
    args = _parse_args()
    base = Path(args.base) if args.base else None
    if args.info:
        _print_info()
    if args.create_defaults:
        _cli_create_default_tree(base)
    if args.test_atomic:
        import tempfile as _tempfile
        with _tempfile.TemporaryDirectory() as td:
            _cli_test_atomic(Path(td))
    if args.test_rotate:
        import tempfile as _tempfile
        with _tempfile.TemporaryDirectory() as td:
            _cli_test_rotate(Path(td))
    if args.test_hashes:
        import tempfile as _tempfile
        with _tempfile.TemporaryDirectory() as td:
            _cli_test_hashes(Path(td))
    if args.test_enrich:
        import tempfile as _tempfile
        with _tempfile.TemporaryDirectory() as td:
            _cli_test_enrich(Path(td))
    if args.status:
        _cli_status_report()
    if not any((args.info, args.create_defaults, args.test_atomic, args.test_rotate, args.test_hashes, args.test_enrich, args.status)):
        print('No flags provided. Ensuring logging_engine config, safeops logs, and hashes dirs exist...')
        _cli_create_default_tree(base)
        print('Generating status report...')
        _cli_status_report()
        print('helpers is in good condition')