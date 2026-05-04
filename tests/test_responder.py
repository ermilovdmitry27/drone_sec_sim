from __future__ import annotations

import unittest

from security_agent.config import GatewayControl
from security_agent.models import RiskAssessment, SecurityEvent, VehicleSnapshot
from security_agent.responder import Responder


class _FakeAction:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def hold(self) -> None:
        self.calls.append("hold")

    async def return_to_launch(self) -> None:
        self.calls.append("return_to_launch")

    async def land(self) -> None:
        self.calls.append("land")


class _FakeDrone:
    def __init__(self) -> None:
        self.action = _FakeAction()


def assessment(action: str, endpoint: str | None = None) -> RiskAssessment:
    return RiskAssessment(
        level="HIGH",
        score=80,
        reason="test",
        recommended_action=action,
        phase="MISSION",
        security_event=SecurityEvent(
            rule_id="test_rule",
            severity="HIGH",
            description="test",
            telemetry_event="test",
            evidence={"endpoint": endpoint} if endpoint else {},
        ),
    )


class ResponderTest(unittest.IsolatedAsyncioTestCase):
    async def test_dry_run_does_not_call_drone_action(self) -> None:
        drone = _FakeDrone()
        responder = Responder(drone, dry_run=True)
        snapshot = VehicleSnapshot(is_armed=True, flight_mode="MISSION", relative_altitude_m=10.0)

        await responder.execute(assessment("hold_position"), snapshot)

        self.assertEqual(drone.action.calls, [])

    async def test_hold_position_calls_hold_when_active(self) -> None:
        drone = _FakeDrone()
        responder = Responder(drone, dry_run=False)
        snapshot = VehicleSnapshot(is_armed=True, flight_mode="MISSION", relative_altitude_m=10.0)

        await responder.execute(assessment("hold_position"), snapshot)

        self.assertEqual(drone.action.calls, ["hold"])

    async def test_return_or_land_calls_rtl_in_airborne_phase(self) -> None:
        drone = _FakeDrone()
        responder = Responder(drone, dry_run=False)
        snapshot = VehicleSnapshot(is_armed=True, flight_mode="MISSION", relative_altitude_m=10.0)

        await responder.execute(assessment("return_or_land"), snapshot)

        self.assertEqual(drone.action.calls, ["return_to_launch"])

    async def test_block_command_source_updates_gateway_control(self) -> None:
        drone = _FakeDrone()
        control = GatewayControl()
        responder = Responder(drone, dry_run=False, gateway_control=control)
        snapshot = VehicleSnapshot()

        await responder.execute(assessment("block_command_source", endpoint="127.0.0.1:14541"), snapshot)

        self.assertTrue(control.is_blocked("127.0.0.1:14541"))

    async def test_lockdown_updates_gateway_control(self) -> None:
        drone = _FakeDrone()
        control = GatewayControl()
        responder = Responder(drone, dry_run=False, gateway_control=control)
        snapshot = VehicleSnapshot()

        await responder.execute(assessment("lockdown"), snapshot)

        self.assertTrue(control.lockdown)


if __name__ == "__main__":
    unittest.main()
