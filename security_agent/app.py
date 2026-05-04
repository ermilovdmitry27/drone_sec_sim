from __future__ import annotations

import asyncio

from mavsdk import System

from .config import GatewaySettings, SecuritySettings
from .audit import AuditLogger
from .collector import TelemetryCollector
from .detector import ThreatDetector
from .gateway import MavlinkGateway
from .models import (
    CommandEvent,
    LinkMetricsEvent,
    RiskAssessment,
    SecurityEvent,
    TelemetryEvent,
    VehicleSnapshot,
    iso_ts,
)
from .responder import Responder
from .risk_engine import RiskEngine
from .state_guard import StateGuard


class SecurityMonitorApp:
    def __init__(
        self,
        system_address: str = "udp://:14540",
        log_dir: str = "logs",
        active_response: bool = False,
        gateway_settings: GatewaySettings | None = None,
        security_settings: SecuritySettings | None = None,
    ) -> None:
        self.system_address = system_address
        self.log_dir = log_dir
        self.active_response = active_response
        self.gateway_settings = gateway_settings
        self.security_settings = security_settings or SecuritySettings()
        self.event_queue: asyncio.Queue[object] = asyncio.Queue()
        self.snapshot = VehicleSnapshot()

    async def run(self) -> None:
        gateway = None
        if self.gateway_settings:
            gateway = MavlinkGateway(self.gateway_settings, self.event_queue)
            await gateway.start()

        drone = System()
        await drone.connect(system_address=self.system_address)

        collector = TelemetryCollector(drone, self.event_queue, self.system_address)
        detector = ThreatDetector()
        risk_engine = RiskEngine()
        responder = Responder(drone, dry_run=not self.active_response)
        audit = AuditLogger(self.log_dir)
        state_guard = StateGuard(drone, self.event_queue, self.security_settings)

        await collector.wait_until_connected()
        self.snapshot.is_connected = True
        print(
            "Security monitor запущен: "
            f"system_address={self.system_address} active_response={self.active_response}"
        )
        if self.gateway_settings:
            print(
                "QGroundControl подключайте вручную через Comm Links -> UDP: "
                f"{self.gateway_settings.qgc_manual_link_host}:{self.gateway_settings.gcs_client_port}"
            )

        collector_task = asyncio.create_task(collector.run())
        state_guard_task = asyncio.create_task(state_guard.run())
        try:
            while True:
                event = await self.event_queue.get()
                findings: list[SecurityEvent] = []

                if isinstance(event, TelemetryEvent):
                    self.snapshot.apply(event)
                    self._print_telemetry(event)
                    audit.log_telemetry(event, self.snapshot)
                    findings.extend(detector.analyze(event, self.snapshot))
                elif isinstance(event, CommandEvent):
                    self._print_command_event(event)
                    audit.log_command_event(event)
                    findings.extend(detector.analyze(event, self.snapshot))
                elif isinstance(event, LinkMetricsEvent):
                    self._print_link_metrics(event)
                    audit.log_link_metrics(event)
                    findings.extend(detector.analyze(event, self.snapshot))
                elif isinstance(event, SecurityEvent):
                    findings.append(event)

                for security_event in findings:
                    assessment = risk_engine.assess(security_event, self.snapshot)
                    self._print_finding(security_event, assessment)
                    audit.log_security_event(security_event)
                    audit.log_assessment(assessment)
                    await responder.execute(assessment, self.snapshot)
        finally:
            collector_task.cancel()
            state_guard_task.cancel()
            await asyncio.gather(
                collector_task,
                state_guard_task,
                return_exceptions=True,
            )
            if gateway:
                await gateway.stop()

    def _print_telemetry(self, event: TelemetryEvent) -> None:
        if event.name == "flight_mode":
            print(f"[MODE] {event.value}")
            return
        if event.name == "armed":
            print(f"[ARMED] {event.value}")
            return
        if event.name == "position":
            print(
                "[POS] "
                f"lat={event.value['latitude_deg']:.6f} "
                f"lon={event.value['longitude_deg']:.6f} "
                f"rel_alt={event.value['relative_altitude_m']:.1f}m"
            )
            return
        if event.name == "battery":
            print(
                "[BAT] "
                f"remaining={event.value['remaining_pct'] * 100:.0f}% "
                f"voltage={event.value['voltage_v']:.2f}V"
            )
            return
        if event.name == "gps_info":
            print(
                "[GPS] "
                f"fix={event.value['fix_type']} "
                f"sat={event.value['num_satellites']}"
            )
            return
        if event.name == "health":
            print(
                "[HEALTH] "
                f"global_ok={event.value['global_position_ok']} "
                f"home_ok={event.value['home_position_ok']}"
            )

    def _print_command_event(self, event: CommandEvent) -> None:
        details = []
        if event.command_name:
            details.append(f"command={event.command_name}")
        if event.param_name:
            details.append(f"param={event.param_name}")
        if event.details.get("device_name"):
            details.append(f"device={event.details['device_name']}")
        if event.details.get("count") is not None:
            details.append(f"count={event.details['count']}")
        if event.blocked:
            details.append("blocked=True")
        detail_line = " ".join(details)
        print(
            "[CMD] "
            f"channel={event.channel} endpoint={event.endpoint} "
            f"message={event.message_name} category={event.category}"
            + (f" {detail_line}" if detail_line else "")
        )

    def _print_link_metrics(self, event: LinkMetricsEvent) -> None:
        print(
            "[LINK] "
            f"channel={event.channel} packets={event.packets} "
            f"messages={event.messages} loss={event.estimated_loss_ratio:.3f} "
            f"idle={event.idle_for_s:.1f}s sources={event.sources}"
        )

    def _print_finding(
        self,
        security_event: SecurityEvent,
        assessment: RiskAssessment,
    ) -> None:
        print(
            "[SECURITY] "
            f"time={iso_ts(security_event.timestamp)} "
            f"rule={security_event.rule_id} "
            f"severity={security_event.severity} "
            f"risk={assessment.level}:{assessment.score} "
            f"action={assessment.recommended_action}"
        )
        print(f"[SECURITY] {security_event.description}")
