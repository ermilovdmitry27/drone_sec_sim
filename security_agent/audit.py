from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

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
    def __init__(self, log_dir: str, siem_url: str | None = None) -> None:
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.telemetry_path = self.log_dir / "telemetry.jsonl"
        self.security_path = self.log_dir / "security_events.jsonl"
        self.protocol_path = self.log_dir / "protocol_events.jsonl"
        self.coverage_path = self.log_dir / "threat_coverage.jsonl"
        self.siem_url = siem_url or None
        self.last_hashes = {
            path: self._load_last_hash(path)
            for path in (
                self.telemetry_path,
                self.security_path,
                self.protocol_path,
                self.coverage_path,
            )
        }

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

    def _append(self, path: Path, record: dict[str, Any]) -> None:
        record = dict(record)
        previous_hash = self.last_hashes.get(path)
        record["audit_prev_hash"] = previous_hash
        record["audit_hash"] = self._record_hash(record)
        self.last_hashes[path] = record["audit_hash"]
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._send_to_siem(path, record)

    def _load_last_hash(self, path: Path) -> str | None:
        if not path.exists():
            return None
        last_hash = None
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    last_hash = json.loads(line).get("audit_hash")
                except json.JSONDecodeError:
                    last_hash = None
        return last_hash

    def _record_hash(self, record: dict[str, Any]) -> str:
        canonical = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _send_to_siem(self, path: Path, record: dict[str, Any]) -> None:
        if not self.siem_url:
            return
        payload = dict(record)
        payload["audit_log"] = path.name
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            self.siem_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=2):
                return
        except (OSError, urllib.error.URLError) as exc:
            print(f"[SIEM][ERROR] Не удалось отправить событие в SIEM: {exc}")
