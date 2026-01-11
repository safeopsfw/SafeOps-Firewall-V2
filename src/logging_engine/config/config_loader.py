#!/usr/bin/env python3
"""
config_loader.py — Centralized Configuration Loader for SafeOps FV2

All modules should import this to get paths and settings:
    from config.config_loader import config, get_path, get_setting

Example:
    from config.config_loader import config
    
    log_path = config['log_files']['network_packets']
    payload_size = config['capture']['payload_size']
"""

import os
import yaml
from pathlib import Path
from typing import Any, Optional

# Find config file relative to this file
CONFIG_DIR = Path(__file__).resolve().parent
CONFIG_FILE = CONFIG_DIR / 'config.yaml'

# Global config cache
_config_cache: Optional[dict] = None


def load_config(config_path: Optional[Path] = None) -> dict:
    """
    Load configuration from YAML file.
    
    Args:
        config_path: Optional path to config file. Defaults to config.yaml in same directory.
    
    Returns:
        Configuration dictionary
    """
    global _config_cache
    
    if _config_cache is not None and config_path is None:
        return _config_cache
    
    path = config_path or CONFIG_FILE
    
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    
    with open(path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    
    if config_path is None:
        _config_cache = config
    
    return config


def get_path(key: str, create_dir: bool = False) -> Path:
    """
    Get a path from configuration.
    
    Args:
        key: Dot-separated key like 'log_files.network_packets' or 'paths.logs_dir'
        create_dir: If True, create parent directories if they don't exist
    
    Returns:
        Path object
    """
    config = load_config()
    
    # Navigate nested keys
    value = config
    for part in key.split('.'):
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            raise KeyError(f"Config key not found: {key}")
    
    path = Path(value)
    
    if create_dir:
        # Create directory (or parent directory if it's a file path)
        if '.' in path.name:  # Looks like a file
            path.parent.mkdir(parents=True, exist_ok=True)
        else:
            path.mkdir(parents=True, exist_ok=True)
    
    return path


def get_setting(key: str, default: Any = None) -> Any:
    """
    Get a setting from configuration.
    
    Args:
        key: Dot-separated key like 'capture.payload_size' or 'rotation.interval_seconds'
        default: Default value if key not found
    
    Returns:
        Setting value
    """
    config = load_config()
    
    # Navigate nested keys
    value = config
    for part in key.split('.'):
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return default
    
    return value


def reload_config():
    """Force reload configuration from disk."""
    global _config_cache
    _config_cache = None
    return load_config()


# Pre-load config on import
try:
    config = load_config()
except FileNotFoundError:
    config = {}
    print(f"Warning: Config file not found at {CONFIG_FILE}")


# Convenience exports
__all__ = [
    'config',
    'load_config',
    'get_path',
    'get_setting',
    'reload_config',
    'CONFIG_FILE',
]


if __name__ == '__main__':
    # Test config loading
    print(f"Config file: {CONFIG_FILE}")
    print(f"Config loaded: {bool(config)}")
    
    if config:
        print("\n=== Paths ===")
        print(f"Base dir: {get_path('paths.base_dir')}")
        print(f"Logs dir: {get_path('paths.logs_dir')}")
        print(f"Network packets: {get_path('log_files.network_packets')}")
        
        print("\n=== Capture Settings ===")
        print(f"Payload size: {get_setting('capture.payload_size')}")
        print(f"Interfaces: {get_setting('capture.interfaces')}")
        
        print("\n=== Rotation ===")
        print(f"Interval: {get_setting('rotation.interval_seconds')}s")
        
        print("\n✅ Config loader working!")
