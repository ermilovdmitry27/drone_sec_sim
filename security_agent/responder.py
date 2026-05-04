from __future__ import annotations

from mavsdk import System

from .config import GatewayControl
from .models import RiskAssessment, VehicleSnapshot


class Responder:
    def __init__(
        self,
        drone: System,
        dry_run: bool = True,
        gateway_control: GatewayControl | None = None,
    ) -> None:
        self.drone = drone
        self.dry_run = dry_run
        self.gateway_control = gateway_control

    async def execute(
        self,
        assessment: RiskAssessment,
        snapshot: VehicleSnapshot,
    ) -> None:
        action = assessment.recommended_action
        if action in {"log_only", "alert_operator"}:
            return

        print(f"[RESPONSE] action={action} dry_run={self.dry_run}")
        if self.dry_run:
            return

        try:
            if action == "block_command_source":
                self._block_command_source(assessment)
            elif action == "lockdown":
                self._enable_lockdown()
            elif action == "hold_position":
                await self.drone.action.hold()
            elif action == "return_or_land":
                if snapshot.phase() in {"MISSION", "AIRBORNE", "RETURN"}:
                    await self.drone.action.return_to_launch()
                else:
                    await self.drone.action.land()
        except Exception as exc:
            print(f"[RESPONSE][ERROR] Не удалось выполнить {action}: {exc}")

    def _block_command_source(self, assessment: RiskAssessment) -> None:
        if self.gateway_control is None:
            print("[RESPONSE][ERROR] Gateway control недоступен для block_command_source")
            return
        endpoint = assessment.security_event.evidence.get("endpoint")
        if not isinstance(endpoint, str) or not endpoint:
            print("[RESPONSE][ERROR] В событии нет endpoint для block_command_source")
            return
        self.gateway_control.block_endpoint(endpoint)
        print(f"[RESPONSE] blocked_endpoint={endpoint}")

    def _enable_lockdown(self) -> None:
        if self.gateway_control is None:
            print("[RESPONSE][ERROR] Gateway control недоступен для lockdown")
            return
        self.gateway_control.enable_lockdown()
        print("[RESPONSE] gateway_lockdown=True")
