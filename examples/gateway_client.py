"""
Example: Connect to MAVLink Gateway as a client

This example demonstrates how to connect to the Security Monitor's
MAVLink gateway and send/receive messages.
"""

from __future__ import annotations

import asyncio
import sys


async def main() -> None:
    """Connect to gateway and listen for telemetry."""
    try:
        from mavsdk import System
    except ImportError:
        print("mavsdk not installed. Install with: pip install mavsdk")
        sys.exit(1)

    # Connect to gateway client port (default: 14541)
    drone = System(system_address="udp://:14541")

    print("Connecting to gateway on udp://:14541...")
    async for state in drone.core.connection_state():
        if state.is_connected:
            print("Connected to gateway!")
            break

    print("Listening for telemetry...")
    async for battery in drone.telemetry.battery():
        print(f"Battery: {battery.remaining_percent:.0%} ({battery.voltage_v:.1f}V)")
        break  # Just show one reading

    print("Done.")


if __name__ == "__main__":
    asyncio.run(main())
