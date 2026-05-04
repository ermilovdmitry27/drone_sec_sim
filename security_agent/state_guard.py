from __future__ import annotations

import asyncio
import hashlib
import json

from mavsdk import System

from .config import SecuritySettings
from .models import SecurityEvent


class StateGuard:
    def __init__(
        self,
        drone: System,
        event_queue: asyncio.Queue[object],
        settings: SecuritySettings,
    ) -> None:
        self.drone = drone
        self.event_queue = event_queue
        self.settings = settings
        self.param_snapshot: dict[str, float | int | str] | None = None
        self.mission_hash: str | None = None

    async def run(self) -> None:
        tasks = [
            asyncio.create_task(self._watch_params()),
            asyncio.create_task(self._watch_mission()),
        ]
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _watch_params(self) -> None:
        while True:
            try:
                snapshot = await self._snapshot_params()
                if self.param_snapshot is None:
                    self.param_snapshot = snapshot
                elif snapshot != self.param_snapshot:
                    changed = self._diff_dict(self.param_snapshot, snapshot)
                    changed_names = list(changed.keys())
                    severity = (
                        "HIGH"
                        if any(name in self.settings.critical_params for name in changed_names)
                        else "MEDIUM"
                    )
                    await self.event_queue.put(
                        SecurityEvent(
                            rule_id="px4_param_changed",
                            severity=severity,
                            description="Обнаружено изменение параметров PX4",
                            telemetry_event="state_guard.params",
                            evidence={
                                "changed_params": changed,
                                "critical_change": any(
                                    name in self.settings.critical_params for name in changed_names
                                ),
                            },
                        )
                    )
                    self.param_snapshot = snapshot
            except Exception as exc:
                await self.event_queue.put(
                    SecurityEvent(
                        rule_id="param_monitor_error",
                        severity="LOW",
                        description="StateGuard не смог получить параметры PX4",
                        telemetry_event="state_guard.params",
                        evidence={"error": str(exc)},
                    )
                )
            await asyncio.sleep(self.settings.param_poll_interval_s)

    async def _watch_mission(self) -> None:
        while True:
            try:
                mission_hash, summary = await self._snapshot_mission()
                if self.mission_hash is None:
                    self.mission_hash = mission_hash
                elif mission_hash != self.mission_hash:
                    await self.event_queue.put(
                        SecurityEvent(
                            rule_id="mission_plan_changed",
                            severity="HIGH",
                            description="Обнаружено изменение миссии PX4",
                            telemetry_event="state_guard.mission",
                            evidence=summary,
                        )
                    )
                    self.mission_hash = mission_hash
            except Exception as exc:
                await self.event_queue.put(
                    SecurityEvent(
                        rule_id="mission_monitor_error",
                        severity="LOW",
                        description="StateGuard не смог получить текущую миссию PX4",
                        telemetry_event="state_guard.mission",
                        evidence={"error": str(exc)},
                    )
                )
            await asyncio.sleep(self.settings.mission_poll_interval_s)

    async def _snapshot_params(self) -> dict[str, float | int | str]:
        all_params = await self.drone.param.get_all_params()
        snapshot: dict[str, float | int | str] = {}

        for param in all_params.int_params:
            snapshot[param.name] = int(param.value)
        for param in all_params.float_params:
            snapshot[param.name] = round(float(param.value), 6)
        for param in all_params.custom_params:
            snapshot[param.name] = str(param.value)

        return snapshot

    async def _snapshot_mission(self) -> tuple[str, dict[str, object]]:
        mission_plan = await self.drone.mission.download_mission()
        items = mission_plan.mission_items
        if not items:
            return self.settings.mission_hash_empty, {"mission_items": 0}

        normalized_items = [
            {
                "latitude_deg": round(float(item.latitude_deg), 7),
                "longitude_deg": round(float(item.longitude_deg), 7),
                "relative_altitude_m": round(float(item.relative_altitude_m), 2),
                "speed_m_s": round(float(item.speed_m_s), 2),
                "yaw_deg": round(float(item.yaw_deg), 2),
            }
            for item in items
        ]
        digest = hashlib.sha256(
            json.dumps(normalized_items, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return digest, {
            "mission_items": len(items),
            "mission_digest": digest,
            "preview": normalized_items[:3],
        }

    def _diff_dict(
        self,
        previous: dict[str, float | int | str],
        current: dict[str, float | int | str],
    ) -> dict[str, dict[str, float | int | str | None]]:
        changed: dict[str, dict[str, float | int | str | None]] = {}
        keys = set(previous) | set(current)

        for key in keys:
            old = previous.get(key)
            new = current.get(key)
            if old != new:
                changed[key] = {"old": old, "new": new}
            if len(changed) >= 10:
                break

        return changed
