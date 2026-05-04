from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def now_ts() -> float:
    return datetime.now(tz=timezone.utc).timestamp()


def iso_ts(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


@dataclass
class TelemetryEvent:
    name: str
    value: Any
    timestamp: float = field(default_factory=now_ts)
    source: str = "px4.telemetry"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_record(self) -> dict[str, Any]:
        return {
            "type": "telemetry",
            "name": self.name,
            "value": self.value,
            "source": self.source,
            "timestamp": self.timestamp,
            "timestamp_iso": iso_ts(self.timestamp),
            "metadata": self.metadata,
        }


@dataclass
class SecurityEvent:
    rule_id: str
    severity: str
    description: str
    telemetry_event: str
    timestamp: float = field(default_factory=now_ts)
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_record(self) -> dict[str, Any]:
        return {
            "type": "security_event",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "description": self.description,
            "telemetry_event": self.telemetry_event,
            "timestamp": self.timestamp,
            "timestamp_iso": iso_ts(self.timestamp),
            "evidence": self.evidence,
        }


@dataclass
class CommandEvent:
    direction: str
    channel: str
    endpoint: str
    message_id: int
    message_name: str
    category: str
    command_id: int | None = None
    command_name: str | None = None
    param_name: str | None = None
    blocked: bool = False
    timestamp: float = field(default_factory=now_ts)
    details: dict[str, Any] = field(default_factory=dict)

    def to_record(self) -> dict[str, Any]:
        return {
            "type": "command_event",
            "direction": self.direction,
            "channel": self.channel,
            "endpoint": self.endpoint,
            "message_id": self.message_id,
            "message_name": self.message_name,
            "category": self.category,
            "command_id": self.command_id,
            "command_name": self.command_name,
            "param_name": self.param_name,
            "blocked": self.blocked,
            "timestamp": self.timestamp,
            "timestamp_iso": iso_ts(self.timestamp),
            "details": self.details,
        }


@dataclass
class LinkMetricsEvent:
    channel: str
    packets: int
    bytes_total: int
    messages: int
    estimated_loss_ratio: float
    idle_for_s: float
    sources: int
    timestamp: float = field(default_factory=now_ts)

    def to_record(self) -> dict[str, Any]:
        return {
            "type": "link_metrics",
            "channel": self.channel,
            "packets": self.packets,
            "bytes_total": self.bytes_total,
            "messages": self.messages,
            "estimated_loss_ratio": self.estimated_loss_ratio,
            "idle_for_s": self.idle_for_s,
            "sources": self.sources,
            "timestamp": self.timestamp,
            "timestamp_iso": iso_ts(self.timestamp),
        }


@dataclass
class ThreatCoverageEvent:
    threat_id: str
    threat: str
    attack_method: str
    coverage_mode: str
    emulation_profile: str
    asset_group_name: str
    flow_ids: list[str]
    native_anchor: str
    project_rules: list[str]
    component_note: str
    timestamp: float = field(default_factory=now_ts)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_record(self) -> dict[str, Any]:
        return {
            "type": "threat_coverage",
            "threat_id": self.threat_id,
            "threat": self.threat,
            "attack_method": self.attack_method,
            "coverage_mode": self.coverage_mode,
            "emulation_profile": self.emulation_profile,
            "asset_group_name": self.asset_group_name,
            "flow_ids": self.flow_ids,
            "native_anchor": self.native_anchor,
            "project_rules": self.project_rules,
            "component_note": self.component_note,
            "timestamp": self.timestamp,
            "timestamp_iso": iso_ts(self.timestamp),
            "metadata": self.metadata,
        }


@dataclass
class RiskAssessment:
    level: str
    score: int
    reason: str
    recommended_action: str
    phase: str
    security_event: SecurityEvent
    timestamp: float = field(default_factory=now_ts)

    def to_record(self) -> dict[str, Any]:
        return {
            "type": "risk_assessment",
            "level": self.level,
            "score": self.score,
            "reason": self.reason,
            "recommended_action": self.recommended_action,
            "phase": self.phase,
            "timestamp": self.timestamp,
            "timestamp_iso": iso_ts(self.timestamp),
            "security_event": self.security_event.to_record(),
        }


@dataclass
class VehicleSnapshot:
    is_connected: bool = False
    is_armed: bool = False
    flight_mode: str = "UNKNOWN"
    latitude_deg: float | None = None
    longitude_deg: float | None = None
    relative_altitude_m: float | None = None
    battery_remaining_pct: float | None = None
    gps_fix_type: int | None = None
    gps_satellites: int | None = None
    global_position_ok: bool | None = None
    home_position_ok: bool | None = None
    last_update_ts: float | None = None

    def apply(self, event: TelemetryEvent) -> None:
        self.last_update_ts = event.timestamp

        if event.name == "armed":
            self.is_armed = bool(event.value)
        elif event.name == "flight_mode":
            self.flight_mode = str(event.value)
        elif event.name == "position":
            self.latitude_deg = event.value.get("latitude_deg")
            self.longitude_deg = event.value.get("longitude_deg")
            self.relative_altitude_m = event.value.get("relative_altitude_m")
        elif event.name == "battery":
            self.battery_remaining_pct = event.value.get("remaining_pct")
        elif event.name == "gps_info":
            self.gps_fix_type = event.value.get("fix_type")
            self.gps_satellites = event.value.get("num_satellites")
        elif event.name == "health":
            self.global_position_ok = event.value.get("global_position_ok")
            self.home_position_ok = event.value.get("home_position_ok")

    def phase(self) -> str:
        mode = self.flight_mode.upper()
        altitude = self.relative_altitude_m or 0.0

        if not self.is_armed:
            return "GROUND"
        if mode in {"LAND"}:
            return "LANDING"
        if mode in {"RETURN_TO_LAUNCH", "RETURN", "RTL"}:
            return "RETURN"
        if mode in {"MISSION", "OFFBOARD"}:
            return "MISSION"
        if altitude > 1.5:
            return "AIRBORNE"
        return "TAKEOFF_PREP"
