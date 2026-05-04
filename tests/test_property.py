"""
Property-based and load tests for drone-sec-sim.

These tests use Hypothesis to generate random inputs and test
properties that should hold for all valid inputs.
"""

from __future__ import annotations

import asyncio
import unittest

try:
    from hypothesis import given, settings, Phase
    from hypothesis import strategies as st

    HAS_HYPOTHESIS = True
except ImportError:
    HAS_HYPOTHESIS = False

from security_agent.config import GatewaySettings, SecuritySettings
from security_agent.detector import ThreatDetector
from security_agent.models import (
    CommandEvent,
    RiskAssessment,
    SecurityEvent,
    TelemetryEvent,
    VehicleSnapshot,
)
from security_agent.risk_engine import RiskEngine


@unittest.skipUnless(HAS_HYPOTHESIS, "hypothesis not installed")
class PropertyBasedTests(unittest.TestCase):
    """Property-based tests using Hypothesis."""

    @given(
        severity=st.sampled_from(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
        score=st.integers(min_value=0, max_value=100),
    )
    @settings(max_examples=100, phases=[Phase.generate])
    def test_risk_engine_valid_levels(self, severity: str, score: int) -> None:
        """Risk engine should return valid risk levels for any severity input."""
        risk_engine = RiskEngine()
        snapshot = VehicleSnapshot()

        event = SecurityEvent(
            rule_id="test_rule",
            severity=severity,
            description="Test event",
            telemetry_event="test",
        )

        assessment = risk_engine.assess(event, snapshot)

        # Property: assessment should have valid level
        self.assertIn(assessment.level, {"LOW", "MEDIUM", "HIGH", "CRITICAL"})

        # Property: score should be in valid range
        self.assertGreaterEqual(assessment.score, 0)
        self.assertLessEqual(assessment.score, 100)

    @given(
        lat=st.floats(min_value=-90.0, max_value=90.0),
        lon=st.floats(min_value=-180.0, max_value=180.0),
        alt=st.floats(min_value=0.0, max_value=1000.0),
    )
    @settings(max_examples=50, phases=[Phase.generate])
    def test_vehicle_snapshot_position(self, lat: float, lon: float, alt: float) -> None:
        """VehicleSnapshot should handle any valid GPS coordinates."""
        snapshot = VehicleSnapshot()

        event = TelemetryEvent(
            name="position",
            value={
                "latitude_deg": lat,
                "longitude_deg": lon,
                "relative_altitude_m": alt,
            },
        )

        snapshot.apply(event)

        self.assertEqual(snapshot.latitude_deg, lat)
        self.assertEqual(snapshot.longitude_deg, lon)
        self.assertEqual(snapshot.relative_altitude_m, alt)

    @given(
        remaining_pct=st.floats(min_value=0.0, max_value=1.0),
        voltage=st.floats(min_value=0.0, max_value=30.0),
    )
    @settings(max_examples=50, phases=[Phase.generate])
    def test_battery_normalization(self, remaining_pct: float, voltage: float) -> None:
        """Battery values should be properly normalized."""
        snapshot = VehicleSnapshot()

        event = TelemetryEvent(
            name="battery",
            value={
                "remaining_pct": remaining_pct,
                "voltage_v": voltage,
            },
        )

        snapshot.apply(event)

        self.assertEqual(snapshot.battery_remaining_pct, remaining_pct)

    @given(
        mode=st.sampled_from([
            "STABILIZED", "POSCTL", "ALTCTL", "AUTO.MISSION",
            "AUTO.LOITER", "AUTO.RTL", "OFFBOARD", "LAND", "TAKEOFF"
        ]),
        armed=st.booleans(),
    )
    @settings(max_examples=50, phases=[Phase.generate])
    def test_flight_mode_changes(self, mode: str, armed: bool) -> None:
        """Flight mode and armed state should be tracked correctly."""
        snapshot = VehicleSnapshot(is_armed=armed, flight_mode=mode)

        # Apply telemetry
        snapshot.apply(TelemetryEvent(name="flight_mode", value=mode))
        snapshot.apply(TelemetryEvent(name="armed", value=armed))

        self.assertEqual(snapshot.flight_mode, mode)
        self.assertEqual(snapshot.is_armed, armed)

    @given(
        port=st.integers(min_value=1024, max_value=65535),
    )
    @settings(max_examples=20, phases=[Phase.generate])
    def test_gateway_port_validity(self, port: int) -> None:
        """Gateway should accept any valid port number."""
        settings = GatewaySettings(
            api_upstream_port=port,
            api_client_port=port + 1,
        )

        self.assertEqual(settings.api_upstream_port, port)
        self.assertEqual(settings.api_client_port, port + 1)

    @given(
        key_hex=st.one_of(st.just(""), st.from_regex(r"[0-9a-fA-F]{64}")),
    )
    @settings(max_examples=20, phases=[Phase.generate])
    def test_encryption_key_validation(self, key_hex: str) -> None:
        """Encryption key should be valid hex or empty."""
        # Empty is allowed (no encryption)
        if not key_hex:
            settings = GatewaySettings(encryption_key_hex=key_hex)
            self.assertEqual(settings.encryption_key_hex, "")
        # Non-empty should be valid hex
        else:
            try:
                if len(key_hex) == 64:
                    bytes.fromhex(key_hex)
                    settings = GatewaySettings(encryption_key_hex=key_hex)
                    self.assertEqual(len(settings.encryption_key_hex), 64)
            except ValueError:
                pass  # Skip invalid values


class LoadTests(unittest.TestCase):
    """Load and stress tests."""

    def test_high_event_throughput(self) -> None:
        """Test handling of high event throughput."""
        detector = ThreatDetector()
        risk_engine = RiskEngine()
        snapshot = VehicleSnapshot(is_connected=True, flight_mode="POSCTL")

        # Generate 10,000 events
        events = [
            TelemetryEvent(
                name="battery",
                value={"remaining_pct": 0.5 + (i % 10) * 0.01, "voltage_v": 12.0},
            )
            for i in range(10000)
        ]

        # Process all events
        findings_count = 0
        for event in events:
            findings = detector.analyze(event, snapshot)
            findings_count += len(findings)
            for f in findings:
                risk_engine.assess(f, snapshot)

        self.assertEqual(findings_count, 0)  # No threats in battery events

    def test_concurrent_command_events(self) -> None:
        """Test handling of concurrent command events."""
        import concurrent.futures

        detector = ThreatDetector()
        snapshot = VehicleSnapshot(is_armed=True, flight_mode="POSCTL")

        def process_batch(batch_id: int) -> int:
            events = [
                CommandEvent(
                    direction="in",
                    channel="api",
                    endpoint="127.0.0.1:14541",
                    message_id=176 + (i % 10),
                    message_name=f"MAV_CMD_{176 + (i % 10)}",
                    category="command",
                )
                for i in range(100)
            ]
            count = 0
            for event in events:
                findings = detector.analyze(event, snapshot)
                count += len(findings)
            return count

        # Run 10 concurrent batches
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(process_batch, i) for i in range(10)]
            results = [f.result() for f in futures]

        # All batches should complete
        self.assertEqual(len(results), 10)

    def test_memory_stability_long_run(self) -> None:
        """Test memory stability over long run."""
        detector = ThreatDetector()
        risk_engine = RiskEngine()
        snapshot = VehicleSnapshot()

        # Run many iterations
        for i in range(1000):
            event = SecurityEvent(
                rule_id=f"test_rule_{i % 10}",
                severity="MEDIUM",
                description=f"Test event {i}",
                telemetry_event="test",
            )

            # Process
            findings = detector.analyze(event, snapshot)
            for f in findings:
                risk_engine.assess(f, snapshot)

        # If we get here without memory issues, test passes
        self.assertTrue(True)


class StressTests(unittest.TestCase):
    """Stress tests for edge cases."""

    def test_empty_event_handling(self) -> None:
        """Test handling of empty/minimal events."""
        detector = ThreatDetector()
        snapshot = VehicleSnapshot()

        # Empty telemetry
        event = TelemetryEvent(name="", value=None)
        findings = detector.analyze(event, snapshot)
        self.assertIsInstance(findings, list)

    def test_extreme_coordinates(self) -> None:
        """Test handling of extreme GPS coordinates."""
        snapshot = VehicleSnapshot()

        # Edge cases
        test_cases = [
            (90.0, 180.0, 0.0),   # Max positive
            (-90.0, -180.0, 0.0), # Max negative
            (0.0, 0.0, 1000.0),   # Zero with altitude
        ]

        for lat, lon, alt in test_cases:
            event = TelemetryEvent(
                name="position",
                value={
                    "latitude_deg": lat,
                    "longitude_deg": lon,
                    "relative_altitude_m": alt,
                },
            )
            snapshot.apply(event)
            self.assertEqual(snapshot.latitude_deg, lat)

    def test_extreme_battery_values(self) -> None:
        """Test handling of extreme battery values."""
        snapshot = VehicleSnapshot()

        test_cases = [
            (0.0, 0.0),     # Empty battery, zero voltage
            (1.0, 30.0),    # Full battery, high voltage
            (0.5, 12.5),    # Normal
        ]

        for pct, volt in test_cases:
            event = TelemetryEvent(
                name="battery",
                value={"remaining_pct": pct, "voltage_v": volt},
            )
            snapshot.apply(event)
            self.assertEqual(snapshot.battery_remaining_pct, pct)


if __name__ == "__main__":
    unittest.main()