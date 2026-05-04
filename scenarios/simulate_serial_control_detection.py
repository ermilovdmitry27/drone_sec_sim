from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security_agent.detector import ThreatDetector
from security_agent.models import CommandEvent, VehicleSnapshot
from security_agent.risk_engine import RiskEngine


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Safely emulate detection of a MAVLink SERIAL_CONTROL attempt without "
            "sending any message to PX4"
        ),
    )
    parser.add_argument(
        "--blocked",
        action="store_true",
        help="Mark the emulated SERIAL_CONTROL event as blocked by the gateway",
    )
    parser.add_argument(
        "--armed",
        action="store_true",
        help="Emulate a vehicle state where PX4 is armed",
    )
    parser.add_argument(
        "--flight-mode",
        default="HOLD",
        help="Emulated flight mode used for risk assessment",
    )
    parser.add_argument(
        "--altitude",
        type=float,
        default=0.0,
        help="Emulated relative altitude in meters",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    snapshot = VehicleSnapshot(
        is_connected=True,
        is_armed=args.armed,
        flight_mode=args.flight_mode,
        relative_altitude_m=args.altitude,
    )
    event = CommandEvent(
        direction="client_to_px4",
        channel="api_gateway",
        endpoint="127.0.0.1:9999",
        message_id=126,
        message_name="SERIAL_CONTROL",
        category="serial_control",
        blocked=args.blocked,
        details={
            "device": 10,
            "device_name": "SERIAL_CONTROL_DEV_SHELL",
            "flags": 6,
            "timeout_ms": 0,
            "baudrate": 0,
            "count": 0,
            "shell_device": True,
        },
    )

    detector = ThreatDetector()
    risk_engine = RiskEngine()
    findings = detector.analyze(event, snapshot)

    print("Это безопасная эмуляция события детектора. PX4 и MAVLink не используются.")
    print(json.dumps(event.to_record(), ensure_ascii=False, indent=2))
    for finding in findings:
        assessment = risk_engine.assess(finding, snapshot)
        print(json.dumps(finding.to_record(), ensure_ascii=False, indent=2))
        print(json.dumps(assessment.to_record(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
