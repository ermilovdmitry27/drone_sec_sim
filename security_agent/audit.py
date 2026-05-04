from __future__ import annotations

import json
from pathlib import Path

from .models import (
    CommandEvent,
    LinkMetricsEvent,
    RiskAssessment,
    SecurityEvent,
    TelemetryEvent,
    ThreatCoverageEvent,
    VehicleSnapshot,
)


class AuditLogger:
    def __init__(self, log_dir: str) -> None:
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.telemetry_path = self.log_dir / "telemetry.jsonl"
        self.security_path = self.log_dir / "security_events.jsonl"
        self.protocol_path = self.log_dir / "protocol_events.jsonl"
        self.coverage_path = self.log_dir / "threat_coverage.jsonl"

    def log_telemetry(self, event: TelemetryEvent, snapshot: VehicleSnapshot) -> None:
        record = event.to_record()
        record["snapshot_phase"] = snapshot.phase()
        self._append(self.telemetry_path, record)

    def log_security_event(self, event: SecurityEvent) -> None:
        self._append(self.security_path, event.to_record())

    def log_assessment(self, assessment: RiskAssessment) -> None:
        self._append(self.security_path, assessment.to_record())

    def log_command_event(self, event: CommandEvent) -> None:
        self._append(self.protocol_path, event.to_record())

    def log_link_metrics(self, event: LinkMetricsEvent) -> None:
        self._append(self.protocol_path, event.to_record())

    def log_threat_coverage_event(self, event: ThreatCoverageEvent) -> None:
        self._append(self.coverage_path, event.to_record())

    def _append(self, path: Path, record: dict) -> None:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
