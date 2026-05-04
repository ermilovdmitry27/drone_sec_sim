#!/usr/bin/env python3
"""
Validate sim_stack.json against JSON Schema.

Usage:
    python tools/validate_sim_stack.py [sim_stack.json]
    python tools/validate_sim_stack.py  # defaults to sim_stack.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import jsonschema
except ImportError:
    print("jsonschema not installed. Install with: pip install jsonschema")
    sys.exit(1)


SCHEMA_PATH = Path(__file__).parent / "sim_stack_schema.json"


def validate(config_path: str = "sim_stack.json") -> bool:
    """Validate config file against schema. Returns True if valid."""
    schema = json.loads(SCHEMA_PATH.read_text())
    config = json.loads(Path(config_path).read_text())

    try:
        jsonschema.validate(instance=config, schema=schema)
        print(f"✓ {config_path} is valid")
        return True
    except jsonschema.ValidationError as e:
        print(f"✗ Validation error in {config_path}:")
        print(f"  Path: {'.'.join(str(p) for p in e.path)}")
        print(f"  Error: {e.message}")
        return False
    except jsonschema.SchemaError as e:
        print(f"✗ Invalid schema: {e.message}")
        return False


if __name__ == "__main__":
    config_file = sys.argv[1] if len(sys.argv) > 1 else "sim_stack.json"
    if not Path(config_file).exists():
        print(f"Config file not found: {config_file}")
        sys.exit(1)
    success = validate(config_file)
    sys.exit(0 if success else 1)
