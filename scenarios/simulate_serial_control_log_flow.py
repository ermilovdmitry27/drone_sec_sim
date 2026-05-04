from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security_agent.audit import AuditLogger
from security_agent.detector import ThreatDetector
from security_agent.models import CommandEvent, VehicleSnapshot
from security_agent.risk_engine import RiskEngine


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Safely emulate the full logging flow for a MAVLink SERIAL_CONTROL event "
            "without sending any message to PX4 or the gateway"
        ),
    )
    parser.add_argument(
        "--log-dir",
        default="logs/safe_emulation",
        help="Directory where emulated protocol and security logs will be written",
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

    audit = AuditLogger(args.log_dir)
    detector = ThreatDetector()
    risk_engine = RiskEngine()

    audit.log_command_event(event)
    findings = detector.analyze(event, snapshot)
    assessments = []
    for finding in findings:
        audit.log_security_event(finding)
        assessment = risk_engine.assess(finding, snapshot)
        audit.log_assessment(assessment)
        assessments.append(assessment)

    print("Это безопасная эмуляция полного пути логирования. PX4 и gateway не используются.")
    print(f"log_dir={Path(args.log_dir).resolve()}")
    print(json.dumps(event.to_record(), ensure_ascii=False, indent=2))
    for finding, assessment in zip(findings, assessments):
        print(json.dumps(finding.to_record(), ensure_ascii=False, indent=2))
        print(json.dumps(assessment.to_record(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
