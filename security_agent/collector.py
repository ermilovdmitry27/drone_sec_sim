from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable

from mavsdk import System

from .models import TelemetryEvent

Normalizer = Callable[[Any], TelemetryEvent]
KeyBuilder = Callable[[TelemetryEvent], Any]
StreamFactory = Callable[[], Awaitable[Any]]


class TelemetryCollector:
    def __init__(
        self,
        drone: System,
        event_queue: asyncio.Queue[TelemetryEvent],
        system_address: str,
    ) -> None:
        self.drone = drone
        self.event_queue = event_queue
        self.system_address = system_address

    async def wait_until_connected(self) -> None:
        print(f"Ищу PX4 на {self.system_address} ...")
        async for state in self.drone.core.connection_state():
            if state.is_connected:
                print("PX4 найден")
                return

    async def run(self) -> None:
        tasks = [
            asyncio.create_task(
                self._watch_stream(
                    self.drone.telemetry.flight_mode,
                    self._normalize_flight_mode,
                    lambda event: event.value,
                )
            ),
            asyncio.create_task(
                self._watch_stream(
                    self.drone.telemetry.armed,
                    self._normalize_armed,
                    lambda event: event.value,
                )
            ),
            asyncio.create_task(
                self._watch_stream(
                    self.drone.telemetry.position,
                    self._normalize_position,
                    lambda event: (
                        round(event.value["latitude_deg"], 6),
                        round(event.value["longitude_deg"], 6),
                        round(event.value["relative_altitude_m"], 1),
                    ),
                    throttle_seconds=1.0,
                )
            ),
            asyncio.create_task(
                self._watch_stream(
                    self.drone.telemetry.battery,
                    self._normalize_battery,
                    lambda event: round(event.value["remaining_pct"], 2),
                    throttle_seconds=2.0,
                )
            ),
            asyncio.create_task(
                self._watch_stream(
                    self.drone.telemetry.gps_info,
                    self._normalize_gps_info,
                    lambda event: (
                        event.value["fix_type"],
                        event.value["num_satellites"],
                    ),
                )
            ),
            asyncio.create_task(
                self._watch_stream(
                    self.drone.telemetry.health,
                    self._normalize_health,
                    lambda event: (
                        event.value["global_position_ok"],
                        event.value["home_position_ok"],
                    ),
                )
            ),
        ]

        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _watch_stream(
        self,
        stream_factory: Callable[[], Any],
        normalize: Normalizer,
        key_builder: KeyBuilder,
        throttle_seconds: float = 0.0,
    ) -> None:
        last_key = object()
        async for raw_value in stream_factory():
            event = normalize(raw_value)
            key = key_builder(event)
            if key == last_key:
                continue
            last_key = key
            await self.event_queue.put(event)
            if throttle_seconds:
                await asyncio.sleep(throttle_seconds)

    def _normalize_flight_mode(self, mode: Any) -> TelemetryEvent:
        return TelemetryEvent(
            name="flight_mode",
            value=str(mode),
        )

    def _normalize_armed(self, armed: bool) -> TelemetryEvent:
        return TelemetryEvent(
            name="armed",
            value=bool(armed),
        )

    def _normalize_position(self, position: Any) -> TelemetryEvent:
        return TelemetryEvent(
            name="position",
            value={
                "latitude_deg": float(position.latitude_deg),
                "longitude_deg": float(position.longitude_deg),
                "relative_altitude_m": float(position.relative_altitude_m),
            },
        )

    def _normalize_battery(self, battery: Any) -> TelemetryEvent:
        return TelemetryEvent(
            name="battery",
            value={
                "remaining_pct": float(battery.remaining_percent),
                "voltage_v": float(battery.voltage_v),
            },
        )

    def _normalize_gps_info(self, gps_info: Any) -> TelemetryEvent:
        fix_type = getattr(gps_info.fix_type, "value", gps_info.fix_type)
        return TelemetryEvent(
            name="gps_info",
            value={
                "fix_type": int(fix_type),
                "num_satellites": int(gps_info.num_satellites),
            },
        )

    def _normalize_health(self, health: Any) -> TelemetryEvent:
        return TelemetryEvent(
            name="health",
            value={
                "global_position_ok": bool(health.is_global_position_ok),
                "home_position_ok": bool(health.is_home_position_ok),
            },
        )
