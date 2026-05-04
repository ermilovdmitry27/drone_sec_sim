from __future__ import annotations

import unittest

from security_agent.detector import ThreatDetector
from security_agent.models import CommandEvent, LinkMetricsEvent, TelemetryEvent, VehicleSnapshot


class ThreatDetectorTest(unittest.TestCase):
    def test_detects_position_jump_when_armed(self) -> None:
        detector = ThreatDetector()
        snapshot = VehicleSnapshot(is_armed=True, flight_mode="MISSION", relative_altitude_m=10.0)
        first = TelemetryEvent(
            name="position",
            value={"latitude_deg": 55.0, "longitude_deg": 37.0, "relative_altitude_m": 10.0},
            timestamp=10.0,
        )
        second = TelemetryEvent(
            name="position",
            value={"latitude_deg": 55.002, "longitude_deg": 37.0, "relative_altitude_m": 10.0},
            timestamp=11.0,
        )

        self.assertEqual(detector.analyze(first, snapshot), [])
        findings = detector.analyze(second, snapshot)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "position_jump")
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_detects_blocked_serial_shell_access(self) -> None:
        detector = ThreatDetector()
        snapshot = VehicleSnapshot()
        event = CommandEvent(
            direction="client_to_px4",
            channel="api_gateway",
            endpoint="127.0.0.1:14541",
            message_id=126,
            message_name="SERIAL_CONTROL",
            category="serial_control",
            blocked=True,
            details={"shell_device": True, "device": 10, "device_name": "SERIAL_CONTROL_DEV_SHELL"},
            timestamp=1.0,
        )

        findings = detector.analyze(event, snapshot)
        rule_ids = {finding.rule_id for finding in findings}

        self.assertIn("serial_shell_access_attempt", rule_ids)
        self.assertIn("gateway_blocked_command", rule_ids)

    def test_detects_link_loss(self) -> None:
        detector = ThreatDetector()
        snapshot = VehicleSnapshot(is_armed=True, flight_mode="MISSION", relative_altitude_m=15.0)
        event = LinkMetricsEvent(
            channel="api_px4_inbound",
            packets=30,
            bytes_total=4096,
            messages=20,
            estimated_loss_ratio=0.2,
            idle_for_s=0.5,
            sources=1,
            timestamp=5.0,
        )

        findings = detector.analyze(event, snapshot)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "link_loss")
        self.assertEqual(findings[0].severity, "HIGH")

    def test_detects_gateway_access_policy_block(self) -> None:
        detector = ThreatDetector()
        snapshot = VehicleSnapshot()
        event = CommandEvent(
            direction="client_to_px4",
            channel="api_gateway",
            endpoint="192.0.2.10:14541",
            message_id=-1,
            message_name="ACCESS_POLICY",
            category="access_policy",
            blocked=True,
            details={"access_policy": "unauthorized_host"},
            timestamp=1.0,
        )

        findings = detector.analyze(event, snapshot)
        rule_ids = {finding.rule_id for finding in findings}

        self.assertIn("gateway_access_policy_block", rule_ids)
        self.assertIn("gateway_blocked_command", rule_ids)


if __name__ == "__main__":
    unittest.main()
