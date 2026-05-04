from __future__ import annotations

import asyncio
import unittest
from io import StringIO
from unittest.mock import MagicMock, patch

from security_agent.app import SecurityMonitorApp
from security_agent.config import GatewaySettings, SecuritySettings
from security_agent.models import (
    CommandEvent,
    LinkMetricsEvent,
    SecurityEvent,
    TelemetryEvent,
)


class SecurityMonitorAppInitTest(unittest.TestCase):
    def test_default_initialization(self) -> None:
        app = SecurityMonitorApp()
        self.assertEqual(app.system_address, "udp://:14540")
        self.assertEqual(app.log_dir, "logs")
        self.assertFalse(app.active_response)
        self.assertIsNone(app.siem_url)
        self.assertIsInstance(app.security_settings, SecuritySettings)

    def test_custom_initialization(self) -> None:
        settings = SecuritySettings()
        app = SecurityMonitorApp(
            system_address="udp://:14550",
            log_dir="custom_logs",
            active_response=True,
            siem_url="http://siem:8080",
            security_settings=settings,
        )
        self.assertEqual(app.system_address, "udp://:14550")
        self.assertEqual(app.log_dir, "custom_logs")
        self.assertTrue(app.active_response)
        self.assertEqual(app.siem_url, "http://siem:8080")
        self.assertIs(settings, app.security_settings)


class SecurityMonitorAppPrintMethodsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.app = SecurityMonitorApp()

    def test_print_telemetry_flight_mode(self) -> None:
        event = TelemetryEvent(name="flight_mode", value="POSCTL")
        with patch("builtins.print") as mock_print:
            self.app._print_telemetry(event)
            mock_print.assert_called_once_with("[MODE] POSCTL")

    def test_print_telemetry_armed(self) -> None:
        event = TelemetryEvent(name="armed", value=True)
        with patch("builtins.print") as mock_print:
            self.app._print_telemetry(event)
            mock_print.assert_called_once_with("[ARMED] True")

    def test_print_telemetry_position(self) -> None:
        event = TelemetryEvent(
            name="position",
            value={
                "latitude_deg": 55.755826,
                "longitude_deg": 37.617300,
                "relative_altitude_m": 10.5,
            },
        )
        with patch("builtins.print") as mock_print:
            self.app._print_telemetry(event)
            output = str(mock_print.call_args)
            self.assertIn("POS", output)
            self.assertIn("55.755826", output)

    def test_print_telemetry_battery(self) -> None:
        event = TelemetryEvent(
            name="battery",
            value={"remaining_pct": 0.85, "voltage_v": 12.5},
        )
        with patch("builtins.print") as mock_print:
            self.app._print_telemetry(event)
            output = str(mock_print.call_args)
            self.assertIn("BAT", output)
            self.assertIn("85%", output)

    def test_print_telemetry_gps_info(self) -> None:
        event = TelemetryEvent(
            name="gps_info",
            value={"fix_type": 3, "num_satellites": 12},
        )
        with patch("builtins.print") as mock_print:
            self.app._print_telemetry(event)
            output = str(mock_print.call_args)
            self.assertIn("GPS", output)
            self.assertIn("fix=3", output)

    def test_print_telemetry_health(self) -> None:
        event = TelemetryEvent(
            name="health",
            value={"global_position_ok": True, "home_position_ok": False},
        )
        with patch("builtins.print") as mock_print:
            self.app._print_telemetry(event)
            output = str(mock_print.call_args)
            self.assertIn("HEALTH", output)
            self.assertIn("global_ok=True", output)

    def test_print_command_event_basic(self) -> None:
        event = CommandEvent(
            direction="in",
            channel="api",
            endpoint="127.0.0.1:14541",
            message_id=400,
            message_name="MAV_CMD_PARAM_SET",
            category="param_write",
        )
        with patch("builtins.print") as mock_print:
            self.app._print_command_event(event)
            output = str(mock_print.call_args)
            self.assertIn("CMD", output)
            self.assertIn("MAV_CMD_PARAM_SET", output)

    def test_print_command_event_blocked(self) -> None:
        event = CommandEvent(
            direction="in",
            channel="api",
            endpoint="127.0.0.1:14541",
            message_id=400,
            message_name="MAV_CMD_PARAM_SET",
            category="param_write",
            blocked=True,
        )
        with patch("builtins.print") as mock_print:
            self.app._print_command_event(event)
            output = str(mock_print.call_args)
            self.assertIn("blocked=True", output)

    def test_print_link_metrics(self) -> None:
        event = LinkMetricsEvent(
            channel="api",
            packets=1000,
            bytes_total=50000,
            messages=800,
            estimated_loss_ratio=0.05,
            idle_for_s=1.5,
            sources=2,
        )
        with patch("builtins.print") as mock_print:
            self.app._print_link_metrics(event)
            output = str(mock_print.call_args)
            self.assertIn("LINK", output)
            self.assertIn("packets=1000", output)

    def test_print_finding(self) -> None:
        security_event = SecurityEvent(
            rule_id="param_write_blocked",
            severity="HIGH",
            description="Попытка изменения параметра заблокирована",
            telemetry_event="command",
        )
        assessment = MagicMock()
        assessment.level = "HIGH"
        assessment.score = 85
        assessment.recommended_action = "ALERT"

        with patch("builtins.print") as mock_print:
            self.app._print_finding(security_event, assessment)
            calls = [str(call) for call in mock_print.call_args_list]
            self.assertTrue(any("SECURITY" in c for c in calls))


if __name__ == "__main__":
    unittest.main()
