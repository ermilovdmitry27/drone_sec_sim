from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent
SOURCE_CSV = PROJECT_ROOT / "docs" / "full_mapping_extended_rows.csv"
CATALOG_CSV = PROJECT_ROOT / "docs" / "threat_coverage_catalog.csv"
CATALOG_JSON = PROJECT_ROOT / "scenarios" / "threat_coverage_catalog.json"


PROFILE_CONFIGS: dict[str, dict[str, Any]] = {
    "operator_workstation_proxy": {
        "asset_group_name": "АРМ оператора / наземная станция",
        "coverage_mode": "proxy_emulation",
        "native_anchor": "scenarios/attack_arm_disarm_flap.py",
        "project_rules": ["command_burst", "arm_command_burst", "gateway_blocked_command"],
        "component_note": (
            "Покрытие строится через подтвержденный операторский контур "
            "QGroundControl -> MavlinkGateway -> PX4 SITL."
        ),
    },
    "server_monitoring_proxy": {
        "asset_group_name": "Сервер мониторинга / PX4 SITL / SecurityMonitorApp",
        "coverage_mode": "proxy_emulation",
        "native_anchor": "scenarios/attack_param_tamper.py",
        "project_rules": ["param_write_attempt", "px4_param_changed", "mission_write_attempt"],
        "component_note": (
            "Покрытие строится через подтвержденные модули TelemetryCollector, "
            "StateGuard, ThreatDetector, RiskEngine и AuditLogger."
        ),
    },
    "peripheral_navigation_proxy": {
        "asset_group_name": "Периферия / навигация / исполнительные каналы модели",
        "coverage_mode": "proxy_emulation_with_component_gap",
        "native_anchor": "scenarios/attack_navigation_excursion.py",
        "project_rules": ["position_jump", "gps_degraded", "health_loss", "battery_low"],
        "component_note": (
            "В проекте отдельно подтверждены только navsat, imu, magnetometer, "
            "air_pressure и 4 motor channels; полный состав периферии из исходного "
            "файла не подтвержден."
        ),
    },
    "storage_integrity_proxy": {
        "asset_group_name": "Хранилище конфигурации, миссии и журналов",
        "coverage_mode": "proxy_emulation",
        "native_anchor": "scenarios/attack_mission_overwrite.py",
        "project_rules": ["mission_write_attempt", "mission_plan_changed", "px4_param_changed"],
        "component_note": (
            "Покрытие строится через подтвержденные JSONL-журналы, снимки "
            "параметров PX4 и контроль миссии в StateGuard."
        ),
    },
    "companion_control_proxy": {
        "asset_group_name": "Companion / API-контур / условный IoT-компонент",
        "coverage_mode": "proxy_emulation_with_component_gap",
        "native_anchor": "scenarios/attack_param_tamper.py",
        "project_rules": ["command_burst", "param_write_attempt", "mission_write_attempt"],
        "component_note": (
            "Отдельный IoT-компонент в проекте не подтвержден; покрытие строится "
            "через подтвержденный API-канал MavlinkGateway."
        ),
    },
    "power_support_proxy": {
        "asset_group_name": "Обеспечивающие системы / питание",
        "coverage_mode": "proxy_emulation_with_component_gap",
        "native_anchor": "",
        "project_rules": ["battery_low"],
        "component_note": (
            "В проекте подтверждены battery telemetry и 4 motor channels; полная "
            "инфраструктура питания и наземного обеспечения из исходного файла "
            "не подтверждена."
        ),
    },
    "link_channel_proxy": {
        "asset_group_name": "Физические линии связи / MAVLink-канал",
        "coverage_mode": "proxy_emulation",
        "native_anchor": "scenarios/simulate_serial_control_log_flow.py",
        "project_rules": ["link_idle", "link_loss", "gateway_blocked_command"],
        "component_note": (
            "Покрытие строится через подтвержденный MAVLink/UDP-канал и метрики "
            "MavlinkGateway; не все физические линии из исходного файла "
            "смоделированы напрямую."
        ),
    },
}


ASSET_GROUP_TO_PROFILE = {
    "1": "operator_workstation_proxy",
    "2": "server_monitoring_proxy",
    "3": "peripheral_navigation_proxy",
    "4": "storage_integrity_proxy",
    "5": "companion_control_proxy",
    "7": "power_support_proxy",
    "12": "link_channel_proxy",
}


def parse_flow_ids(flow_value: str) -> list[str]:
    if not flow_value or flow_value.startswith("Я не могу"):
        return []
    return [item.strip() for item in flow_value.split(",") if item.strip()]


def threat_parts(threat_id: str) -> tuple[str, str, str]:
    parts = threat_id.split(".")
    top_level = parts[1] if len(parts) > 1 else ""
    asset_group = parts[2] if len(parts) > 2 else ""
    method_code = parts[3] if len(parts) > 3 else ""
    return top_level, asset_group, method_code


def build_catalog_row(source_row: dict[str, str]) -> dict[str, Any]:
    top_level, asset_group, method_code = threat_parts(source_row["ID"])
    profile = ASSET_GROUP_TO_PROFILE.get(asset_group, "operator_workstation_proxy")
    config = PROFILE_CONFIGS[profile]
    return {
        "row_no": source_row["№"],
        "threat_id": source_row["ID"],
        "top_level_group": top_level,
        "asset_group_code": asset_group,
        "method_code": method_code,
        "threat": source_row["Угроза"],
        "attack_method": source_row["Атака / способ"],
        "passport_asset": source_row["Элемент техпаспорта БАС"],
        "flow_ids": parse_flow_ids(source_row["Информационный поток"]),
        "actuality": source_row["Актуальность"],
        "coverage_mode": config["coverage_mode"],
        "emulation_profile": profile,
        "asset_group_name": config["asset_group_name"],
        "native_anchor": config["native_anchor"],
        "project_rules": config["project_rules"],
        "component_note": config["component_note"],
    }


def load_source_rows(source_path: Path = SOURCE_CSV) -> list[dict[str, str]]:
    with source_path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle, delimiter=";"))


def build_catalog_rows(source_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    return [build_catalog_row(row) for row in source_rows]


def write_catalog(rows: list[dict[str, Any]], csv_path: Path = CATALOG_CSV, json_path: Path = CATALOG_JSON) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "row_no",
        "threat_id",
        "top_level_group",
        "asset_group_code",
        "method_code",
        "asset_group_name",
        "threat",
        "attack_method",
        "passport_asset",
        "flow_ids",
        "actuality",
        "coverage_mode",
        "emulation_profile",
        "native_anchor",
        "project_rules",
        "component_note",
    ]

    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, delimiter=";", fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for row in rows:
            csv_row = row.copy()
            csv_row["flow_ids"] = ", ".join(row["flow_ids"])
            csv_row["project_rules"] = ", ".join(row["project_rules"])
            writer.writerow(csv_row)

    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(rows, handle, ensure_ascii=False, indent=2)


def load_catalog(json_path: Path = CATALOG_JSON) -> list[dict[str, Any]]:
    with json_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)
