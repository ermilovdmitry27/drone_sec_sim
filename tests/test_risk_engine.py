from __future__ import annotations

import unittest

from security_agent.models import SecurityEvent, VehicleSnapshot
from security_agent.risk_engine import RiskEngine


class RiskEngineTest(unittest.TestCase):
    def test_high_risk_airborne_recommends_hold(self) -> None:
        event = SecurityEvent(
            rule_id="position_jump",
            severity="MEDIUM",
            description="test",
            telemetry_event="position",
        )
        snapshot = VehicleSnapshot(is_armed=True, flight_mode="MISSION", relative_altitude_m=20.0)

        assessment = RiskEngine().assess(event, snapshot)

        self.assertEqual(assessment.level, "HIGH")
        self.assertEqual(assessment.recommended_action, "hold_position")

    def test_critical_airborne_recommends_return_or_land(self) -> None:
        event = SecurityEvent(
            rule_id="position_jump",
            severity="CRITICAL",
            description="test",
            telemetry_event="position",
        )
        snapshot = VehicleSnapshot(is_armed=True, flight_mode="MISSION", relative_altitude_m=20.0)

        assessment = RiskEngine().assess(event, snapshot)

        self.assertEqual(assessment.level, "CRITICAL")
        self.assertEqual(assessment.recommended_action, "return_or_land")


if __name__ == "__main__":
    unittest.main()
