from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a verifiable architecture report for the SITL security stand",
    )
    parser.add_argument(
        "--config",
        default=str(PROJECT_ROOT / "sim_stack.json"),
        help="Path to sim stack configuration",
    )
    parser.add_argument(
        "--format",
        choices=("json", "md"),
        default="json",
        help="Output format",
    )
    return parser.parse_args()


def load_config(path: str) -> dict:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def resolve_path(value: str | None) -> Path | None:
    if not value:
        return None
    path = Path(value)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path


def evaluate_hardware_validation(
    target_platform: dict[str, Any],
    validation_config: dict[str, Any],
) -> dict[str, Any]:
    evidence_path = resolve_path(validation_config.get("hardware_evidence_path"))
    evidence = load_json(evidence_path) if evidence_path else None
    checks = (evidence or {}).get("required_checks", {})
    expected_airframe = target_platform.get("airframe")
    expected_fc = target_platform.get("flight_controller")
    platform = (evidence or {}).get("platform", {})
    required_check_names = (
        "power_on",
        "qgc_manual_link",
        "telemetry_stream",
        "arm_disarm",
        "mission_roundtrip",
        "parameter_roundtrip",
        "failsafe_observed",
    )
    all_checks_passed = all(bool(checks.get(name, False)) for name in required_check_names)
    platform_matches = (
        platform.get("airframe") == expected_airframe
        and platform.get("flight_controller") == expected_fc
    )
    validated = bool(
        evidence
        and evidence.get("status") == "passed"
        and platform_matches
        and all_checks_passed
    )
    return {
        "evidence_path": str(evidence_path) if evidence_path else None,
        "evidence_present": evidence is not None,
        "status": evidence.get("status") if evidence else "missing",
        "platform_matches_target": platform_matches if evidence else False,
        "all_required_checks_passed": all_checks_passed if evidence else False,
        "validated": validated,
    }


def evaluate_determinism(validation_config: dict[str, Any]) -> dict[str, Any]:
    report_path = resolve_path(validation_config.get("determinism_report_path"))
    report = load_json(report_path) if report_path else None
    return {
        "report_path": str(report_path) if report_path else None,
        "report_present": report is not None,
        "status": report.get("status") if report else "missing",
        "run_count": report.get("run_count") if report else 0,
        "repeatable_under_test": bool(report and report.get("repeatable_under_test", False)),
    }


def evaluate_gz_model_spec(validation_config: dict[str, Any], configured_model: str) -> dict[str, Any]:
    spec_path = resolve_path(validation_config.get("gz_model_spec_path"))
    spec = load_json(spec_path) if spec_path else None
    return {
        "spec_path": str(spec_path) if spec_path else None,
        "spec_present": spec is not None,
        "configured_make_target_matches": bool(
            spec and spec.get("configured_make_target") == configured_model
        ),
        "px4_sim_model_default": spec.get("px4_sim_model_default") if spec else None,
        "sensor_count": len((spec or {}).get("sensors", [])),
        "actuator_count": len((spec or {}).get("actuators", [])),
        "sensor_types": list((spec or {}).get("sensor_types", [])),
    }


def build_report(config: dict) -> dict:
    deployment_mode = str(config.get("deployment_mode", "sitl"))
    model = str(config.get("model", "unknown"))
    enable_gateway = bool(config.get("enable_gateway", True))
    active_response = bool(config.get("active_response", False))
    target_platform = config.get("target_platform") or {}
    validation_config = config.get("validation") or {}
    hardware_validation = evaluate_hardware_validation(target_platform, validation_config)
    determinism = evaluate_determinism(validation_config)
    gz_model_spec = evaluate_gz_model_spec(validation_config, model)

    return {
        "deployment": {
            "mode": deployment_mode,
            "sitl_model": model,
            "is_sitl": deployment_mode.lower() == "sitl",
        },
        "target_platform": {
            "airframe": target_platform.get("airframe"),
            "flight_controller": target_platform.get("flight_controller"),
            "hardware_validated_declared": bool(target_platform.get("hardware_validated", False)),
            "hardware_validated_effective": hardware_validation["validated"],
        },
        "validation": {
            "hardware": hardware_validation,
            "determinism": determinism,
            "gz_model_spec": gz_model_spec,
        },
        "security_architecture": {
            "external_supervisory_layer": True,
            "gateway_enabled": enable_gateway,
            "continuous_telemetry_monitoring": True,
            "parameter_integrity_control": True,
            "mission_integrity_control": True,
            "anomaly_detection": True,
            "risk_assessment": True,
            "response_module_present": True,
            "active_response_enabled": active_response,
            "response_mode": "active" if active_response else "dry_run",
        },
        "claim_status": {
            "autonomy_of_autopilot_preserved": "not_proven_by_code",
            "determinism_of_autopilot_proven": "not_proven_by_code",
            "determinism_under_repeated_test": determinism["status"],
            "physical_uav_behavior_assessed": False,
            "sitl_model_behavior_assessed": bool(
                deployment_mode.lower() == "sitl" and gz_model_spec["spec_present"]
            ),
            "holybro_x500_v2_runtime_validated": bool(
                target_platform.get("airframe") == "Holybro X500 v2"
                and hardware_validation["validated"]
            ),
            "pixhawk_6c_runtime_validated": bool(
                target_platform.get("flight_controller") == "Pixhawk 6C"
                and hardware_validation["validated"]
            ),
        },
    }


def render_markdown(report: dict) -> str:
    deployment = report["deployment"]
    target = report["target_platform"]
    validation = report["validation"]
    architecture = report["security_architecture"]
    claim_status = report["claim_status"]

    lines = [
        "# Architecture Verification Report",
        "",
        "## Deployment",
        "",
        f"- `mode`: `{deployment['mode']}`",
        f"- `sitl_model`: `{deployment['sitl_model']}`",
        f"- `is_sitl`: `{deployment['is_sitl']}`",
        "",
        "## Target Platform",
        "",
        f"- `airframe`: `{target['airframe']}`",
        f"- `flight_controller`: `{target['flight_controller']}`",
        f"- `hardware_validated_declared`: `{target['hardware_validated_declared']}`",
        f"- `hardware_validated_effective`: `{target['hardware_validated_effective']}`",
        "",
        "## Validation",
        "",
        f"- `hardware_evidence_present`: `{validation['hardware']['evidence_present']}`",
        f"- `hardware_validation_status`: `{validation['hardware']['status']}`",
        f"- `hardware_platform_matches_target`: `{validation['hardware']['platform_matches_target']}`",
        f"- `hardware_all_required_checks_passed`: `{validation['hardware']['all_required_checks_passed']}`",
        f"- `determinism_report_present`: `{validation['determinism']['report_present']}`",
        f"- `determinism_status`: `{validation['determinism']['status']}`",
        f"- `determinism_run_count`: `{validation['determinism']['run_count']}`",
        f"- `determinism_repeatable_under_test`: `{validation['determinism']['repeatable_under_test']}`",
        f"- `gz_model_spec_present`: `{validation['gz_model_spec']['spec_present']}`",
        f"- `gz_model_configured_make_target_matches`: `{validation['gz_model_spec']['configured_make_target_matches']}`",
        f"- `gz_model_px4_sim_model_default`: `{validation['gz_model_spec']['px4_sim_model_default']}`",
        f"- `gz_model_sensor_count`: `{validation['gz_model_spec']['sensor_count']}`",
        f"- `gz_model_actuator_count`: `{validation['gz_model_spec']['actuator_count']}`",
        "",
        "## Security Architecture",
        "",
        f"- `external_supervisory_layer`: `{architecture['external_supervisory_layer']}`",
        f"- `gateway_enabled`: `{architecture['gateway_enabled']}`",
        f"- `continuous_telemetry_monitoring`: `{architecture['continuous_telemetry_monitoring']}`",
        f"- `parameter_integrity_control`: `{architecture['parameter_integrity_control']}`",
        f"- `mission_integrity_control`: `{architecture['mission_integrity_control']}`",
        f"- `anomaly_detection`: `{architecture['anomaly_detection']}`",
        f"- `risk_assessment`: `{architecture['risk_assessment']}`",
        f"- `response_module_present`: `{architecture['response_module_present']}`",
        f"- `active_response_enabled`: `{architecture['active_response_enabled']}`",
        f"- `response_mode`: `{architecture['response_mode']}`",
        "",
        "## Claim Status",
        "",
        f"- `autonomy_of_autopilot_preserved`: `{claim_status['autonomy_of_autopilot_preserved']}`",
        f"- `determinism_of_autopilot_proven`: `{claim_status['determinism_of_autopilot_proven']}`",
        f"- `determinism_under_repeated_test`: `{claim_status['determinism_under_repeated_test']}`",
        f"- `physical_uav_behavior_assessed`: `{claim_status['physical_uav_behavior_assessed']}`",
        f"- `sitl_model_behavior_assessed`: `{claim_status['sitl_model_behavior_assessed']}`",
        f"- `holybro_x500_v2_runtime_validated`: `{claim_status['holybro_x500_v2_runtime_validated']}`",
        f"- `pixhawk_6c_runtime_validated`: `{claim_status['pixhawk_6c_runtime_validated']}`",
    ]
    return "\n".join(lines)


def main() -> None:
    args = parse_args()
    report = build_report(load_config(args.config))
    if args.format == "md":
        print(render_markdown(report))
        return
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
