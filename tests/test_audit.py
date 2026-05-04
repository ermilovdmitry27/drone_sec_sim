from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security_agent.audit import AuditLogger
from security_agent.models import SecurityEvent


class AuditLoggerTest(unittest.TestCase):
    def test_writes_hash_chain_to_security_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            logger = AuditLogger(tmp_dir)

            logger.log_security_event(
                SecurityEvent(
                    rule_id="first",
                    severity="LOW",
                    description="first event",
                    telemetry_event="test",
                )
            )
            logger.log_security_event(
                SecurityEvent(
                    rule_id="second",
                    severity="HIGH",
                    description="second event",
                    telemetry_event="test",
                )
            )

            records = [
                json.loads(line)
                for line in (Path(tmp_dir) / "security_events.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertIsNone(records[0]["audit_prev_hash"])
        self.assertEqual(records[1]["audit_prev_hash"], records[0]["audit_hash"])
        self.assertEqual(len(records[0]["audit_hash"]), 64)

    def test_sends_security_event_to_siem_endpoint(self) -> None:
        class _Response:
            def __enter__(self) -> "_Response":
                return self

            def __exit__(self, *args: object) -> None:
                return None

        captured: list[dict] = []

        def fake_urlopen(request, timeout: int):
            self.assertEqual(timeout, 2)
            captured.append(json.loads(request.data.decode("utf-8")))
            return _Response()

        with patch("security_agent.audit.urllib.request.urlopen", side_effect=fake_urlopen):
            with tempfile.TemporaryDirectory() as tmp_dir:
                logger = AuditLogger(tmp_dir, siem_url="http://siem.example/events")
                logger.log_security_event(
                    SecurityEvent(
                        rule_id="siem_test",
                        severity="MEDIUM",
                        description="siem event",
                        telemetry_event="test",
                    )
                )

        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0]["rule_id"], "siem_test")
        self.assertEqual(captured[0]["audit_log"], "security_events.jsonl")


if __name__ == "__main__":
    unittest.main()
