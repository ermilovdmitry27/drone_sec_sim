from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract a verifiable gz_x500 model specification into the project",
    )
    parser.add_argument(
        "--config",
        default=str(PROJECT_ROOT / "sim_stack.json"),
        help="Path to sim stack configuration",
    )
    parser.add_argument(
        "--output",
        default=str(PROJECT_ROOT / "validation" / "gz_x500_model_spec.json"),
        help="Path to output JSON specification",
    )
    return parser.parse_args()


def load_config(path: str) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def first_text(parent: ET.Element, path: str) -> str | None:
    node = parent.find(path)
    if node is None or node.text is None:
        return None
    return node.text.strip()


def to_number(text: str | None) -> int | float | None:
    if text is None:
        return None
    try:
        value = float(text)
    except ValueError:
        return None
    return int(value) if value.is_integer() else value


def parse_airframe_script(path: Path) -> dict[str, Any]:
    rotor_count = None
    px4_sim_model_default = None
    for line in path.read_text(encoding="utf-8").splitlines():
        sim_match = re.search(r"PX4_SIM_MODEL=\$\{PX4_SIM_MODEL:=([^}]+)\}", line)
        if sim_match:
            px4_sim_model_default = sim_match.group(1)
        rotor_match = re.search(r"param set-default CA_ROTOR_COUNT (\d+)", line)
        if rotor_match:
            rotor_count = int(rotor_match.group(1))
    return {
        "px4_sim_model_default": px4_sim_model_default,
        "rotor_count": rotor_count,
    }


def parse_sensors(path: Path) -> list[dict[str, Any]]:
    root = ET.parse(path).getroot()
    sensors: list[dict[str, Any]] = []
    for link in root.findall(".//link"):
        link_name = link.attrib.get("name")
        for sensor in link.findall("sensor"):
            sensors.append(
                {
                    "name": sensor.attrib.get("name"),
                    "type": sensor.attrib.get("type"),
                    "parent_link": link_name,
                    "update_rate_hz": to_number(first_text(sensor, "update_rate")),
                    "frame_id": first_text(sensor, "gz_frame_id"),
                }
            )
    return sensors


def parse_actuators(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    root = ET.parse(path).getroot()
    actuators: list[dict[str, Any]] = []
    support_plugins: list[dict[str, Any]] = []
    for plugin in root.findall(".//plugin"):
        filename = plugin.attrib.get("filename")
        name = plugin.attrib.get("name")
        if filename == "gz-sim-multicopter-motor-model-system":
            actuators.append(
                {
                    "joint_name": first_text(plugin, "jointName"),
                    "link_name": first_text(plugin, "linkName"),
                    "motor_number": to_number(first_text(plugin, "motorNumber")),
                    "turning_direction": first_text(plugin, "turningDirection"),
                    "command_sub_topic": first_text(plugin, "commandSubTopic"),
                    "motor_type": first_text(plugin, "motorType"),
                    "max_rot_velocity": to_number(first_text(plugin, "maxRotVelocity")),
                }
            )
        else:
            support_plugins.append(
                {
                    "filename": filename,
                    "name": name,
                }
            )
    return actuators, support_plugins


def build_spec(config: dict[str, Any]) -> dict[str, Any]:
    px4_dir = Path(str(config["px4_dir"]))
    configured_make_target = str(config.get("model", "unknown"))
    validation = config.get("validation") or {}

    airframe_script = px4_dir / "ROMFS/px4fmu_common/init.d-posix/airframes/4001_gz_x500"
    model_sdf = px4_dir / "Tools/simulation/gz/models/x500/model.sdf"
    base_model_sdf = px4_dir / "Tools/simulation/gz/models/x500_base/model.sdf"

    airframe_data = parse_airframe_script(airframe_script)
    sensors = parse_sensors(base_model_sdf)
    actuators, support_plugins = parse_actuators(model_sdf)

    return {
        "configured_make_target": configured_make_target,
        "validation_path": validation.get("gz_model_spec_path"),
        "source_files": {
            "airframe_script": str(airframe_script),
            "model_sdf": str(model_sdf),
            "base_model_sdf": str(base_model_sdf),
        },
        "px4_sim_model_default": airframe_data["px4_sim_model_default"],
        "rotor_count_declared": airframe_data["rotor_count"],
        "sensor_types": sorted({sensor["type"] for sensor in sensors if sensor.get("type")}),
        "sensors": sensors,
        "actuators": actuators,
        "support_plugins": support_plugins,
    }


def main() -> None:
    args = parse_args()
    config = load_config(args.config)
    spec = build_spec(config)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(spec, handle, ensure_ascii=False, indent=2)
    print(json.dumps(spec, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
