"""
Example: Run threat coverage scenarios programmatically

This example shows how to run threat coverage scenarios
from Python code instead of CLI.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path


async def main() -> None:
    """Run threat coverage scenarios."""
    scenarios_dir = Path(__file__).parent.parent / "scenarios"
    sys.path.insert(0, str(scenarios_dir.parent))

    try:
        from scenarios.run_threat_coverage import main as run_coverage
    except ImportError:
        print("Could not import run_threat_coverage module.")
        sys.exit(1)

    print("Running threat coverage scenarios...")
    print("Use CLI for full control:")
    print("  python scenarios/run_threat_coverage.py --all --limit 5")


if __name__ == "__main__":
    asyncio.run(main())
