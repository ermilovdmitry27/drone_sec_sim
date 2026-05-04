#!/usr/bin/env python3
"""
Shared configuration loader and validator for drone-sec-sim.

This module provides a centralized way to:
- Load configuration from JSON files
- Validate against JSON Schema
- Provide sensible defaults
- Support environment variable overrides

Usage:
    from tools.config_loader import load_config, validate_config
    
    config = load_config("sim_stack.json")
    validated = validate_config(config)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

try:
    import jsonschema

    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False

SCHEMA_PATH = Path(__file__).parent / "sim_stack_schema.json"


class ConfigError(Exception):
    """Raised when configuration is invalid."""
    pass


class ConfigNotFoundError(ConfigError):
    """Raised when config file is not found."""
    pass


class ConfigValidationError(ConfigError):
    """Raised when config fails schema validation."""
    pass


def load_config(
    path: str | Path = "sim_stack.json",
    validate: bool = True,
    env_prefix: str = "DRONE_SEC_SIM_",
) -> dict[str, Any]:
    """
    Load and optionally validate configuration from JSON file.
    
    Args:
        path: Path to config file (default: sim_stack.json)
        validate: Whether to validate against schema (default: True)
        env_prefix: Prefix for environment variable overrides
        
    Returns:
        Configuration dictionary
        
    Raises:
        ConfigNotFoundError: If config file doesn't exist
        ConfigValidationError: If config fails schema validation
    """
    config_path = Path(path)
    
    if not config_path.exists():
        raise ConfigNotFoundError(f"Config file not found: {config_path}")
    
    try:
        with config_path.open("r", encoding="utf-8") as f:
            config = json.load(f)
    except json.JSONDecodeError as e:
        raise ConfigError(f"Invalid JSON in {path}: {e}")
    
    # Apply environment variable overrides
    config = _apply_env_overrides(config, env_prefix)
    
    # Validate against schema
    if validate:
        validate_config(config)
    
    return config


def validate_config(config: dict[str, Any], schema_path: Path | None = None) -> dict[str, Any]:
    """
    Validate configuration against JSON Schema.
    
    Args:
        config: Configuration dictionary to validate
        schema_path: Optional path to custom schema
        
    Returns:
        Validated configuration dictionary
        
    Raises:
        ConfigValidationError: If validation fails
    """
    if not HAS_JSONSCHEMA:
        print("[config_loader] jsonschema not installed, skipping validation")
        return config
    
    schema_file = schema_path or SCHEMA_PATH
    
    if not schema_file.exists():
        print(f"[config_loader] Schema not found: {schema_file}, skipping validation")
        return config
    
    try:
        schema = json.loads(schema_file.read_text())
    except json.JSONDecodeError as e:
        raise ConfigError(f"Invalid JSON schema: {e}")
    
    try:
        jsonschema.validate(instance=config, schema=schema)
    except jsonschema.ValidationError as e:
        path = ".".join(str(p) for p in e.path) if e.path else "root"
        raise ConfigValidationError(
            f"Validation error at '{path}': {e.message}"
        )
    except jsonschema.SchemaError as e:
        raise ConfigError(f"Invalid schema: {e}")
    
    return config


def _apply_env_overrides(config: dict[str, Any], prefix: str) -> dict[str, Any]:
    """Apply environment variable overrides to config."""
    result = dict(config)
    
    # Simple env overrides for known config keys
    env_mappings = {
        "PX4_DIR": ("px4_dir", str),
        "QGC_PATH": ("qgc_path", str),
        "LOG_DIR": ("log_dir", str),
        "SIEM_URL": ("siem_url", str),
        "ACTIVE_RESPONSE": ("active_response", bool),
        "ENABLE_GATEWAY": ("enable_gateway", bool),
        "GATEWAY_ENFORCE": ("gateway_enforce", bool),
    }
    
    for env_key, (config_key, type_fn) in env_mappings.items():
        full_env_key = f"{prefix}{env_key}"
        env_value = os.environ.get(full_env_key)
        if env_value is not None:
            try:
                result[config_key] = type_fn(env_value)
            except (ValueError, TypeError):
                pass  # Skip invalid values
    
    return result


def get_default_config() -> dict[str, Any]:
    """Return default configuration values."""
    return {
        "px4_dir": "/home/user/PX4-Autopilot",
        "deployment_mode": "sitl",
        "model": "gz_x500",
        "world": "",
        "headless": False,
        "qgc_path": "/home/user/QGroundControl.AppImage",
        "enable_gateway": True,
        "gateway_upstream_port": 14540,
        "gateway_client_port": 14541,
        "gateway_gcs_upstream_port": 14550,
        "gateway_gcs_client_port": 14552,
        "gateway_enforce": True,
        "gateway_block_serial_control": True,
        "active_response": False,
        "siem_url": "",
        "authorized_client_hosts": ["127.0.0.1"],
        "mavlink_encryption_key_hex": "",
        "require_encrypted_clients": False,
        "operator_token_hashes": {},
        "require_operator_auth": False,
        "log_dir": "logs",
    }


if __name__ == "__main__":
    import sys
    
    # CLI for quick config validation
    config_file = sys.argv[1] if len(sys.argv) > 1 else "sim_stack.json"
    
    try:
        config = load_config(config_file)
        print(f"✓ Config loaded and validated: {config_file}")
        print(f"  px4_dir: {config.get('px4_dir', 'n/a')}")
        print(f"  model: {config.get('model', 'n/a')}")
        print(f"  enable_gateway: {config.get('enable_gateway', False)}")
    except ConfigError as e:
        print(f"✗ Config error: {e}")
        sys.exit(1)