"""
Example: Run Security Monitor with minimal configuration

This example shows how to start the Security Monitor
with basic settings for development/testing.
"""

from __future__ import annotations

import asyncio
import sys


async def main() -> None:
    """Run a minimal Security Monitor instance."""
    try:
        from security_agent.app import SecurityMonitorApp
    except ImportError:
        print("security_agent module not found. Make sure you're in the project root.")
        sys.exit(1)

    app = SecurityMonitorApp(
        system_address="udp://:14540",
        log_dir="logs",
        active_response=False,
    )

    print("Starting Security Monitor...")
    print("Press Ctrl+C to stop.")

    try:
        await app.run()
    except KeyboardInterrupt:
        print("\nStopping Security Monitor.")


if __name__ == "__main__":
    asyncio.run(main())
