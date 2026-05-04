from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Assess repeatability of repeated scenario runs from JSONL logs",
    )
    parser.add_argument(
        "--run-dir",
        action="append",
        required=True,
        help="Run directory that contains protocol_events.jsonl and security_events.jsonl",
    )
    parser.add_argument(
        "--output",
        default=str(PROJECT_ROOT / "validation" / "determinism_report.json"),
        help="Path to output report JSON",
    )
    parser.add_argument(
        "--scenario",
        default="unspecified",
        help="Scenario label for the compared runs",
    )
    return parser.parse_args()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.exists():
        return records
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def normalize_protocol(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for record in records:
        if record.get("type") != "command_event":
            continue
        normalized.append(
            {
                "type": record.get("type"),
                "direction": record.get("direction"),
                "channel": record.get("channel"),
                "message_id": record.get("message_id"),
                "message_name": record.get("message_name"),
                "category": record.get("category"),
                "command_id": record.get("command_id"),
                "command_name": record.get("command_name"),
                "param_name": record.get("param_name"),
                "blocked": record.get("blocked"),
                "details": record.get("details", {}),
            }
        )
    return normalized


def normalize_security(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for record in records:
        if record.get("type") != "security_event":
            continue
        normalized.append(
            {
                "type": record.get("type"),
                "rule_id": record.get("rule_id"),
                "severity": record.get("severity"),
                "description": record.get("description"),
                "telemetry_event": record.get("telemetry_event"),
                "evidence": record.get("evidence", {}),
            }
        )
    return normalized


def digest_records(records: list[dict[str, Any]]) -> str:
    payload = json.dumps(records, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def build_run_summary(run_dir: Path) -> dict[str, Any]:
    protocol_records = normalize_protocol(load_jsonl(run_dir / "protocol_events.jsonl"))
    security_records = normalize_security(load_jsonl(run_dir / "security_events.jsonl"))
    return {
        "run_dir": str(run_dir),
        "protocol_count": len(protocol_records),
        "security_count": len(security_records),
        "protocol_digest": digest_records(protocol_records),
        "security_digest": digest_records(security_records),
        "protocol_records": protocol_records,
        "security_records": security_records,
    }


def build_report(run_dirs: list[Path], scenario: str) -> dict[str, Any]:
    runs = [build_run_summary(run_dir) for run_dir in run_dirs]
    protocol_digests = {run["protocol_digest"] for run in runs}
    security_digests = {run["security_digest"] for run in runs}

    protocol_identical = len(protocol_digests) == 1
    security_identical = len(security_digests) == 1
    repeatable_under_test = protocol_identical and security_identical

    return {
        "scenario": scenario,
        "run_count": len(runs),
        "protocol_sequence_identical": protocol_identical,
        "security_sequence_identical": security_identical,
        "repeatable_under_test": repeatable_under_test,
        "status": "repeatable_under_test" if repeatable_under_test else "divergent_runs",
        "runs": [
            {
                "run_dir": run["run_dir"],
                "protocol_count": run["protocol_count"],
                "security_count": run["security_count"],
                "protocol_digest": run["protocol_digest"],
                "security_digest": run["security_digest"],
            }
            for run in runs
        ],
    }


def main() -> None:
    args = parse_args()
    run_dirs = [Path(run_dir).resolve() for run_dir in args.run_dir]
    report = build_report(run_dirs, args.scenario)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
