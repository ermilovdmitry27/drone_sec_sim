"""
Example: Create a custom threat detector

This example shows how to extend the ThreatDetector
with custom detection rules.
"""

from __future__ import annotations

from security_agent.detector import ThreatDetector
from security_agent.models import SecurityEvent, TelemetryEvent, VehicleSnapshot


class CustomThreatDetector(ThreatDetector):
    """Extended detector with custom rules."""

    def analyze(
        self, event: object, snapshot: VehicleSnapshot
    ) -> list[SecurityEvent]:
        """Analyze events with custom rules."""
        findings = super().analyze(event, snapshot)

        if isinstance(event, TelemetryEvent):
            if event.name == "battery" and event.value.get("remaining_pct", 1.0) < 0.15:
                findings.append(
                    SecurityEvent(
                        rule_id="custom_low_battery",
                        severity="CRITICAL",
                        description="Battery below 15% - custom rule triggered",
                        telemetry_event="battery",
                        evidence={"remaining_pct": event.value.get("remaining_pct")},
                    )
                )

        return findings


if __name__ == "__main__":
    print("Custom detector example - import and use CustomThreatDetector")
    print("Example usage:")
    print("  detector = CustomThreatDetector()")
    print("  findings = detector.analyze(event, snapshot)")
