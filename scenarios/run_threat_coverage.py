from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security_agent.audit import AuditLogger
from security_agent.config import SecuritySettings
from security_agent.detector import ThreatDetector
from security_agent.models import (
    CommandEvent,
    LinkMetricsEvent,
    SecurityEvent,
    TelemetryEvent,
    ThreatCoverageEvent,
    VehicleSnapshot,
    now_ts,
)
from security_agent.risk_engine import RiskEngine
from threat_coverage import CATALOG_JSON, load_catalog


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create coverage artifacts for every threat row from the threat mapping file "
            "using confirmed native scenarios or proxy emulation profiles."
        )
    )
    parser.add_argument(
        "--catalog",
        default=str(CATALOG_JSON),
        help="Path to threat coverage catalog JSON",
    )
    parser.add_argument(
        "--threat-id",
        action="append",
        help="Specific threat ID to emulate. Repeat the option to select several IDs.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Process every row from the threat coverage catalog",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Optional limit after filtering; useful for smoke runs",
    )
    parser.add_argument(
        "--log-dir",
        default="logs/threat_coverage",
        help="Directory where threat coverage and emulated logs will be written",
    )
    parser.add_argument(
        "--emit-profile-events",
        action="store_true",
        help="Emit detector/audit events for each profile in addition to threat_coverage.jsonl",
    )
    return parser.parse_args()


def select_entries(entries: list[dict], args: argparse.Namespace) -> list[dict]:
    if args.all:
        selected = entries
    elif args.threat_id:
        wanted = set(args.threat_id)
        selected = [entry for entry in entries if entry["threat_id"] in wanted]
    else:
        raise SystemExit("Укажите --all или хотя бы один --threat-id")
    if args.limit > 0:
        return selected[: args.limit]
    return selected


def log_findings(
    audit: AuditLogger,
    risk_engine: RiskEngine,
    findings: list[SecurityEvent],
    snapshot: VehicleSnapshot,
) -> None:
    for finding in findings:
        assessment = risk_engine.assess(finding, snapshot)
        audit.log_security_event(finding)
        audit.log_assessment(assessment)


def process_telemetry_event(
    audit: AuditLogger,
    detector: ThreatDetector,
    risk_engine: RiskEngine,
    snapshot: VehicleSnapshot,
    event: TelemetryEvent,
) -> None:
    snapshot.apply(event)
    audit.log_telemetry(event, snapshot)
    log_findings(audit, risk_engine, detector.analyze(event, snapshot), snapshot)


def process_command_event(
    audit: AuditLogger,
    detector: ThreatDetector,
    risk_engine: RiskEngine,
    snapshot: VehicleSnapshot,
    event: CommandEvent,
) -> None:
    audit.log_command_event(event)
    log_findings(audit, risk_engine, detector.analyze(event, snapshot), snapshot)


def process_link_event(
    audit: AuditLogger,
    detector: ThreatDetector,
    risk_engine: RiskEngine,
    snapshot: VehicleSnapshot,
    event: LinkMetricsEvent,
) -> None:
    audit.log_link_metrics(event)
    log_findings(audit, risk_engine, detector.analyze(event, snapshot), snapshot)


def log_direct_security_event(
    audit: AuditLogger,
    risk_engine: RiskEngine,
    snapshot: VehicleSnapshot,
    event: SecurityEvent,
) -> None:
    audit.log_security_event(event)
    audit.log_assessment(risk_engine.assess(event, snapshot))


def operator_workstation_proxy(audit: AuditLogger, entry: dict) -> None:
    detector = ThreatDetector()
    risk_engine = RiskEngine()
    snapshot = VehicleSnapshot(is_connected=True, is_armed=False, flight_mode="HOLD")
    base_ts = now_ts()
    for idx in range(6):
        event = CommandEvent(
            direction="client_to_px4",
            channel="qgc_gateway",
            endpoint="127.0.0.1:14552",
            message_id=76,
            message_name="COMMAND_LONG",
            category="command",
            command_id=400,
            command_name="MAV_CMD_COMPONENT_ARM_DISARM",
            blocked=False,
            timestamp=base_ts + idx * 0.5,
            details={"source_profile": entry["emulation_profile"], "threat_id": entry["threat_id"]},
        )
        process_command_event(audit, detector, risk_engine, snapshot, event)


def server_monitoring_proxy(audit: AuditLogger, entry: dict) -> None:
    detector = ThreatDetector()
    risk_engine = RiskEngine()
    snapshot = VehicleSnapshot(is_connected=True, is_armed=False, flight_mode="HOLD")
    base_ts = now_ts()
    command = CommandEvent(
        direction="client_to_px4",
        channel="api_gateway",
        endpoint="127.0.0.1:14541",
        message_id=23,
        message_name="PARAM_SET",
        category="param_write",
        param_name="MPC_XY_CRUISE",
        blocked=False,
        timestamp=base_ts,
        details={"param_value": 12.0, "source_profile": entry["emulation_profile"], "threat_id": entry["threat_id"]},
    )
    process_command_event(audit, detector, risk_engine, snapshot, command)
    direct = SecurityEvent(
        rule_id="px4_param_changed",
        severity="HIGH" if "MPC_XY_CRUISE" in SecuritySettings().critical_params else "MEDIUM",
        description="Эмуляция изменения критичного параметра PX4 по каталогу угроз",
        telemetry_event="state_guard.params",
        evidence={
            "changed_params": {"MPC_XY_CRUISE": {"old": 10.0, "new": 12.0}},
            "critical_change": True,
            "source_profile": entry["emulation_profile"],
            "threat_id": entry["threat_id"],
        },
        timestamp=base_ts + 0.2,
    )
    log_direct_security_event(audit, risk_engine, snapshot, direct)


def peripheral_navigation_proxy(audit: AuditLogger, entry: dict) -> None:
    detector = ThreatDetector()
    risk_engine = RiskEngine()
    snapshot = VehicleSnapshot(is_connected=True)
    base_ts = now_ts()
    bootstrap = [
        TelemetryEvent(name="flight_mode", value="MISSION", timestamp=base_ts, metadata={"threat_id": entry["threat_id"]}),
        TelemetryEvent(name="armed", value=True, timestamp=base_ts + 0.05, metadata={"threat_id": entry["threat_id"]}),
        TelemetryEvent(
            name="position",
            value={"latitude_deg": 55.0, "longitude_deg": 37.0, "relative_altitude_m": 20.0},
            timestamp=base_ts + 0.1,
            metadata={"threat_id": entry["threat_id"]},
        ),
        TelemetryEvent(
            name="position",
            value={"latitude_deg": 55.0015, "longitude_deg": 37.0015, "relative_altitude_m": 45.0},
            timestamp=base_ts + 1.0,
            metadata={"threat_id": entry["threat_id"]},
        ),
        TelemetryEvent(
            name="gps_info",
            value={"fix_type": 2, "num_satellites": 4},
            timestamp=base_ts + 1.1,
            metadata={"threat_id": entry["threat_id"]},
        ),
        TelemetryEvent(
            name="health",
            value={"global_position_ok": False, "home_position_ok": False},
            timestamp=base_ts + 1.2,
            metadata={"threat_id": entry["threat_id"]},
        ),
        TelemetryEvent(
            name="battery",
            value={"remaining_pct": 0.15, "voltage_v": 14.2},
            timestamp=base_ts + 1.3,
            metadata={"threat_id": entry["threat_id"]},
        ),
    ]
    for event in bootstrap:
        process_telemetry_event(audit, detector, risk_engine, snapshot, event)


def storage_integrity_proxy(audit: AuditLogger, entry: dict) -> None:
    detector = ThreatDetector()
    risk_engine = RiskEngine()
    snapshot = VehicleSnapshot(is_connected=True, is_armed=False, flight_mode="HOLD")
    base_ts = now_ts()
    command = CommandEvent(
        direction="client_to_px4",
        channel="api_gateway",
        endpoint="127.0.0.1:14541",
        message_id=44,
        message_name="MISSION_COUNT",
        category="mission_write",
        blocked=False,
        timestamp=base_ts,
        details={"count": 2, "source_profile": entry["emulation_profile"], "threat_id": entry["threat_id"]},
    )
    process_command_event(audit, detector, risk_engine, snapshot, command)
    direct = SecurityEvent(
        rule_id="mission_plan_changed",
        severity="HIGH",
        description="Эмуляция изменения миссии PX4 по каталогу угроз",
        telemetry_event="state_guard.mission",
        evidence={
            "mission_items": 2,
            "mission_digest": f"proxy-{entry['threat_id']}",
            "preview": [
                {"latitude_deg": 55.0, "longitude_deg": 37.0, "relative_altitude_m": 20.0},
                {"latitude_deg": 55.0001, "longitude_deg": 37.0001, "relative_altitude_m": 20.0},
            ],
            "source_profile": entry["emulation_profile"],
            "threat_id": entry["threat_id"],
        },
        timestamp=base_ts + 0.2,
    )
    log_direct_security_event(audit, risk_engine, snapshot, direct)


def companion_control_proxy(audit: AuditLogger, entry: dict) -> None:
    detector = ThreatDetector()
    risk_engine = RiskEngine()
    snapshot = VehicleSnapshot(is_connected=True, is_armed=False, flight_mode="HOLD")
    base_ts = now_ts()
    events = [
        CommandEvent(
            direction="client_to_px4",
            channel="api_gateway",
            endpoint="127.0.0.1:14541",
            message_id=23,
            message_name="PARAM_SET",
            category="param_write",
            param_name="MPC_XY_CRUISE",
            blocked=False,
            timestamp=base_ts,
            details={"param_value": 11.0, "threat_id": entry["threat_id"]},
        ),
        CommandEvent(
            direction="client_to_px4",
            channel="api_gateway",
            endpoint="127.0.0.1:14541",
            message_id=44,
            message_name="MISSION_COUNT",
            category="mission_write",
            blocked=False,
            timestamp=base_ts + 0.5,
            details={"count": 2, "threat_id": entry["threat_id"]},
        ),
    ]
    for idx in range(6):
        events.append(
            CommandEvent(
                direction="client_to_px4",
                channel="api_gateway",
                endpoint="127.0.0.1:14541",
                message_id=76,
                message_name="COMMAND_LONG",
                category="command",
                command_id=400,
                command_name="MAV_CMD_COMPONENT_ARM_DISARM",
                blocked=False,
                timestamp=base_ts + 1.0 + idx * 0.4,
                details={"threat_id": entry["threat_id"]},
            )
        )
    for event in events:
        process_command_event(audit, detector, risk_engine, snapshot, event)


def power_support_proxy(audit: AuditLogger, entry: dict) -> None:
    detector = ThreatDetector()
    risk_engine = RiskEngine()
    snapshot = VehicleSnapshot(is_connected=True)
    base_ts = now_ts()
    bootstrap = [
        TelemetryEvent(name="flight_mode", value="MISSION", timestamp=base_ts, metadata={"threat_id": entry["threat_id"]}),
        TelemetryEvent(name="armed", value=True, timestamp=base_ts + 0.05, metadata={"threat_id": entry["threat_id"]}),
        TelemetryEvent(
            name="battery",
            value={"remaining_pct": 0.1, "voltage_v": 13.8},
            timestamp=base_ts + 0.1,
            metadata={"threat_id": entry["threat_id"]},
        ),
    ]
    for event in bootstrap:
        process_telemetry_event(audit, detector, risk_engine, snapshot, event)


def link_channel_proxy(audit: AuditLogger, entry: dict) -> None:
    detector = ThreatDetector()
    risk_engine = RiskEngine()
    snapshot = VehicleSnapshot(is_connected=True, is_armed=True, flight_mode="MISSION", relative_altitude_m=10.0)
    base_ts = now_ts()
    link_event = LinkMetricsEvent(
        channel="gcs_gateway",
        packets=25,
        bytes_total=2048,
        messages=25,
        estimated_loss_ratio=0.2,
        idle_for_s=3.5,
        sources=1,
        timestamp=base_ts,
    )
    process_link_event(audit, detector, risk_engine, snapshot, link_event)
    blocked_event = CommandEvent(
        direction="client_to_px4",
        channel="gcs_gateway",
        endpoint="127.0.0.1:14552",
        message_id=126,
        message_name="SERIAL_CONTROL",
        category="serial_control",
        blocked=True,
        timestamp=base_ts + 0.2,
        details={
            "device": 10,
            "device_name": "SERIAL_CONTROL_DEV_SHELL",
            "flags": 6,
            "count": 0,
            "shell_device": True,
            "threat_id": entry["threat_id"],
        },
    )
    process_command_event(audit, detector, risk_engine, snapshot, blocked_event)


PROFILE_HANDLERS = {
    "operator_workstation_proxy": operator_workstation_proxy,
    "server_monitoring_proxy": server_monitoring_proxy,
    "peripheral_navigation_proxy": peripheral_navigation_proxy,
    "storage_integrity_proxy": storage_integrity_proxy,
    "companion_control_proxy": companion_control_proxy,
    "power_support_proxy": power_support_proxy,
    "link_channel_proxy": link_channel_proxy,
}


def emulate_entry(audit: AuditLogger, entry: dict, emit_profile_events: bool) -> None:
    coverage_event = ThreatCoverageEvent(
        threat_id=entry["threat_id"],
        threat=entry["threat"],
        attack_method=entry["attack_method"],
        coverage_mode=entry["coverage_mode"],
        emulation_profile=entry["emulation_profile"],
        asset_group_name=entry["asset_group_name"],
        flow_ids=entry["flow_ids"],
        native_anchor=entry["native_anchor"],
        project_rules=entry["project_rules"],
        component_note=entry["component_note"],
        metadata={
            "row_no": entry["row_no"],
            "actuality": entry["actuality"],
            "top_level_group": entry["top_level_group"],
            "asset_group_code": entry["asset_group_code"],
            "method_code": entry["method_code"],
            "passport_asset": entry["passport_asset"],
        },
    )
    audit.log_threat_coverage_event(coverage_event)
    if emit_profile_events:
        PROFILE_HANDLERS[entry["emulation_profile"]](audit, entry)


def main() -> None:
    args = parse_args()
    entries = load_catalog(Path(args.catalog))
    selected = select_entries(entries, args)
    audit = AuditLogger(args.log_dir)
    for entry in selected:
        emulate_entry(audit, entry, args.emit_profile_events)
    print(f"processed={len(selected)} log_dir={Path(args.log_dir).resolve()}")


if __name__ == "__main__":
    main()
