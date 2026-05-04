from __future__ import annotations

from mavsdk import System

from .models import RiskAssessment, VehicleSnapshot


class Responder:
    def __init__(self, drone: System, dry_run: bool = True) -> None:
        self.drone = drone
        self.dry_run = dry_run

    async def execute(
        self,
        assessment: RiskAssessment,
        snapshot: VehicleSnapshot,
    ) -> None:
        action = assessment.recommended_action
        if action in {"log_only", "alert_operator", "block_command_source", "lockdown"}:
            return

        print(f"[RESPONSE] action={action} dry_run={self.dry_run}")
        if self.dry_run:
            return

        try:
            if action == "hold_position":
                await self.drone.action.hold()
            elif action == "return_or_land":
                if snapshot.phase() in {"MISSION", "AIRBORNE", "RETURN"}:
                    await self.drone.action.return_to_launch()
                else:
                    await self.drone.action.land()
        except Exception as exc:
            print(f"[RESPONSE][ERROR] Не удалось выполнить {action}: {exc}")
