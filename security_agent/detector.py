from __future__ import annotations

from collections import defaultdict, deque
from math import asin, cos, radians, sin, sqrt

from .models import CommandEvent, LinkMetricsEvent, SecurityEvent, TelemetryEvent, VehicleSnapshot


class ThreatDetector:
    def __init__(self) -> None:
        self.mode_changes = deque(maxlen=10)
        self.arm_toggles = deque(maxlen=10)
        self.last_position: tuple[float, float, float, float] | None = None
        self.command_bursts: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=20))
        self.arm_command_bursts: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=20))
        self.cooldowns: dict[str, float] = defaultdict(float)

    def analyze(
        self,
        event: TelemetryEvent | CommandEvent | LinkMetricsEvent,
        snapshot: VehicleSnapshot,
    ) -> list[SecurityEvent]:
        findings: list[SecurityEvent] = []

        if isinstance(event, TelemetryEvent):
            if event.name == "flight_mode":
                findings.extend(self._detect_mode_flapping(event, snapshot))
            elif event.name == "armed":
                findings.extend(self._detect_arm_flapping(event, snapshot))
            elif event.name == "position":
                findings.extend(self._detect_position_jump(event, snapshot))
            elif event.name == "gps_info":
                findings.extend(self._detect_gps_degradation(event, snapshot))
            elif event.name == "health":
                findings.extend(self._detect_health_loss(event, snapshot))
            elif event.name == "battery":
                findings.extend(self._detect_low_battery(event, snapshot))
        elif isinstance(event, CommandEvent):
            findings.extend(self._detect_command_stream_anomalies(event, snapshot))
        elif isinstance(event, LinkMetricsEvent):
            findings.extend(self._detect_link_anomalies(event, snapshot))

        return findings

    def _detect_mode_flapping(
        self,
        event: TelemetryEvent,
        snapshot: VehicleSnapshot,
    ) -> list[SecurityEvent]:
        self.mode_changes.append(event.timestamp)
        if not snapshot.is_armed:
            return []
        if len(self.mode_changes) < 4:
            return []
        if event.timestamp - self.mode_changes[-4] > 10:
            return []
        if not self._allow("mode_flapping", event.timestamp, cooldown=20):
            return []
        return [
            SecurityEvent(
                rule_id="mode_flapping",
                severity="MEDIUM",
                description="Подозрительно частая смена режима полета",
                telemetry_event=event.name,
                evidence={
                    "flight_mode": event.value,
                    "phase": snapshot.phase(),
                },
            )
        ]

    def _detect_arm_flapping(
        self,
        event: TelemetryEvent,
        snapshot: VehicleSnapshot,
    ) -> list[SecurityEvent]:
        self.arm_toggles.append(event.timestamp)
        if len(self.arm_toggles) < 4:
            return []
        if event.timestamp - self.arm_toggles[-4] > 15:
            return []
        if not self._allow("arm_flapping", event.timestamp, cooldown=20):
            return []
        return [
            SecurityEvent(
                rule_id="arm_flapping",
                severity="HIGH",
                description="Обнаружена серия команд arm/disarm",
                telemetry_event=event.name,
                evidence={
                    "armed": event.value,
                    "phase": snapshot.phase(),
                },
            )
        ]

    def _detect_position_jump(
        self,
        event: TelemetryEvent,
        snapshot: VehicleSnapshot,
    ) -> list[SecurityEvent]:
        lat = event.value["latitude_deg"]
        lon = event.value["longitude_deg"]
        alt = event.value["relative_altitude_m"]

        if self.last_position is None:
            self.last_position = (event.timestamp, lat, lon, alt)
            return []

        previous_ts, prev_lat, prev_lon, prev_alt = self.last_position
        self.last_position = (event.timestamp, lat, lon, alt)

        if not snapshot.is_armed:
            return []

        dt = event.timestamp - previous_ts
        if dt <= 0 or dt > 3:
            return []

        distance_m = self._distance_m(prev_lat, prev_lon, lat, lon)
        altitude_delta_m = abs(alt - prev_alt)
        if distance_m < 30 and altitude_delta_m < 15:
            return []
        if not self._allow("position_jump", event.timestamp, cooldown=15):
            return []
        severity = "CRITICAL" if distance_m >= 100 else "HIGH"
        return [
            SecurityEvent(
                rule_id="position_jump",
                severity=severity,
                description="Обнаружен резкий скачок координат/высоты",
                telemetry_event=event.name,
                evidence={
                    "distance_m": round(distance_m, 1),
                    "altitude_delta_m": round(altitude_delta_m, 1),
                    "phase": snapshot.phase(),
                },
            )
        ]

    def _detect_gps_degradation(
        self,
        event: TelemetryEvent,
        snapshot: VehicleSnapshot,
    ) -> list[SecurityEvent]:
        fix_type = event.value["fix_type"]
        satellites = event.value["num_satellites"]
        if not snapshot.is_armed:
            return []
        if fix_type >= 3 and satellites >= 6:
            return []
        if not self._allow("gps_degraded", event.timestamp, cooldown=20):
            return []
        return [
            SecurityEvent(
                rule_id="gps_degraded",
                severity="MEDIUM",
                description="Снижение качества GPS/навигации",
                telemetry_event=event.name,
                evidence={
                    "fix_type": fix_type,
                    "num_satellites": satellites,
                    "phase": snapshot.phase(),
                },
            )
        ]

    def _detect_health_loss(
        self,
        event: TelemetryEvent,
        snapshot: VehicleSnapshot,
    ) -> list[SecurityEvent]:
        global_ok = event.value["global_position_ok"]
        home_ok = event.value["home_position_ok"]
        if not snapshot.is_armed:
            return []
        if global_ok and home_ok:
            return []
        if not self._allow("health_loss", event.timestamp, cooldown=20):
            return []
        return [
            SecurityEvent(
                rule_id="health_loss",
                severity="HIGH",
                description="Потеря доверия к навигационному состоянию PX4",
                telemetry_event=event.name,
                evidence={
                    "global_position_ok": global_ok,
                    "home_position_ok": home_ok,
                    "phase": snapshot.phase(),
                },
            )
        ]

    def _detect_low_battery(
        self,
        event: TelemetryEvent,
        snapshot: VehicleSnapshot,
    ) -> list[SecurityEvent]:
        remaining_pct = event.value["remaining_pct"]
        if not snapshot.is_armed:
            return []
        if remaining_pct > 0.2:
            return []
        if not self._allow("battery_low", event.timestamp, cooldown=30):
            return []
        return [
            SecurityEvent(
                rule_id="battery_low",
                severity="MEDIUM",
                description="Критически низкий уровень заряда в активном полете",
                telemetry_event=event.name,
                evidence={
                    "remaining_pct": round(remaining_pct, 2),
                    "phase": snapshot.phase(),
                },
            )
        ]

    def _allow(self, rule_id: str, timestamp: float, cooldown: float) -> bool:
        if timestamp < self.cooldowns[rule_id]:
            return False
        self.cooldowns[rule_id] = timestamp + cooldown
        return True

    def _detect_command_stream_anomalies(
        self,
        event: CommandEvent,
        snapshot: VehicleSnapshot,
    ) -> list[SecurityEvent]:
        findings: list[SecurityEvent] = []
        endpoint_key = f"{event.endpoint}:{event.category}"
        burst = self.command_bursts[endpoint_key]
        burst.append(event.timestamp)

        if len(burst) >= 6 and event.timestamp - burst[-6] <= 5:
            rule_id = f"command_burst:{event.endpoint}"
            if self._allow(rule_id, event.timestamp, cooldown=20):
                findings.append(
                    SecurityEvent(
                        rule_id="command_burst",
                        severity="HIGH",
                        description="Обнаружен всплеск управляющих MAVLink-команд",
                        telemetry_event=event.message_name,
                        evidence={
                            "endpoint": event.endpoint,
                            "category": event.category,
                            "phase": snapshot.phase(),
                        },
                    )
                )

        if event.category == "param_write":
            severity = "CRITICAL" if event.blocked else "HIGH"
            findings.append(
                SecurityEvent(
                    rule_id="param_write_attempt",
                    severity=severity,
                    description="Зафиксирована попытка изменения параметров PX4",
                    telemetry_event=event.message_name,
                    evidence={
                        "endpoint": event.endpoint,
                        "param_name": event.param_name,
                        "blocked": event.blocked,
                    },
                )
            )

        if event.category == "mission_write":
            severity = "CRITICAL" if event.blocked else "HIGH"
            findings.append(
                SecurityEvent(
                    rule_id="mission_write_attempt",
                    severity=severity,
                    description="Зафиксирована попытка изменения миссии PX4",
                    telemetry_event=event.message_name,
                    evidence={
                        "endpoint": event.endpoint,
                        "message_name": event.message_name,
                        "blocked": event.blocked,
                    },
                )
            )

        if event.category == "serial_control":
            shell_device = bool(event.details.get("shell_device"))
            rule_id = "serial_shell_access_attempt" if shell_device else "serial_control_attempt"
            severity = "CRITICAL" if shell_device else "HIGH"
            description = (
                "Зафиксирована попытка доступа к shell через MAVLink SERIAL_CONTROL"
                if shell_device
                else "Зафиксирована попытка управления последовательным интерфейсом через MAVLink SERIAL_CONTROL"
            )
            findings.append(
                SecurityEvent(
                    rule_id=rule_id,
                    severity=severity,
                    description=description,
                    telemetry_event=event.message_name,
                    evidence={
                        "endpoint": event.endpoint,
                        "blocked": event.blocked,
                        "device": event.details.get("device"),
                        "device_name": event.details.get("device_name"),
                        "count": event.details.get("count"),
                    },
                )
            )

        if event.command_id == 400:
            arm_burst = self.arm_command_bursts[event.endpoint]
            arm_burst.append(event.timestamp)
            if len(arm_burst) >= 4 and event.timestamp - arm_burst[-4] <= 10:
                rule_id = f"arm_command_burst:{event.endpoint}"
                if self._allow(rule_id, event.timestamp, cooldown=20):
                    findings.append(
                        SecurityEvent(
                            rule_id="arm_command_burst",
                            severity="HIGH",
                            description="Серия команд arm/disarm обнаружена на уровне MAVLink-потока",
                            telemetry_event=event.message_name,
                            evidence={
                                "endpoint": event.endpoint,
                                "blocked": event.blocked,
                            },
                        )
                    )

        if event.blocked:
            rule_id = f"blocked_command:{event.endpoint}:{event.message_name}"
            if self._allow(rule_id, event.timestamp, cooldown=10):
                findings.append(
                    SecurityEvent(
                        rule_id="gateway_blocked_command",
                        severity="CRITICAL",
                        description="Защитный MAVLink gateway заблокировал управляющее сообщение",
                        telemetry_event=event.message_name,
                        evidence={
                            "endpoint": event.endpoint,
                            "category": event.category,
                            "message_name": event.message_name,
                        },
                    )
                )

        return findings

    def _detect_link_anomalies(
        self,
        event: LinkMetricsEvent,
        snapshot: VehicleSnapshot,
    ) -> list[SecurityEvent]:
        findings: list[SecurityEvent] = []

        if event.messages >= 20 and event.estimated_loss_ratio >= 0.1:
            rule_id = f"link_loss:{event.channel}"
            if self._allow(rule_id, event.timestamp, cooldown=20):
                findings.append(
                    SecurityEvent(
                        rule_id="link_loss",
                        severity="MEDIUM" if snapshot.phase() == "GROUND" else "HIGH",
                        description="Повышенный уровень потерь в MAVLink-канале",
                        telemetry_event="link_metrics",
                        evidence={
                            "channel": event.channel,
                            "loss_ratio": round(event.estimated_loss_ratio, 3),
                            "idle_for_s": round(event.idle_for_s, 2),
                        },
                    )
                )

        if snapshot.is_connected and event.idle_for_s >= 3:
            rule_id = f"link_idle:{event.channel}"
            if self._allow(rule_id, event.timestamp, cooldown=15):
                findings.append(
                    SecurityEvent(
                        rule_id="link_idle",
                        severity="MEDIUM" if snapshot.phase() == "GROUND" else "HIGH",
                        description="Обнаружен простой или задержка в MAVLink-канале",
                        telemetry_event="link_metrics",
                        evidence={
                            "channel": event.channel,
                            "idle_for_s": round(event.idle_for_s, 2),
                            "loss_ratio": round(event.estimated_loss_ratio, 3),
                        },
                    )
                )

        return findings

    def _distance_m(
        self,
        lat1: float,
        lon1: float,
        lat2: float,
        lon2: float,
    ) -> float:
        earth_radius_m = 6_371_000.0
        d_lat = radians(lat2 - lat1)
        d_lon = radians(lon2 - lon1)
        a = (
            sin(d_lat / 2) ** 2
            + cos(radians(lat1)) * cos(radians(lat2)) * sin(d_lon / 2) ** 2
        )
        return 2 * earth_radius_m * asin(sqrt(a))
