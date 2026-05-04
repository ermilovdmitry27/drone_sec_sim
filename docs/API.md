# Security Agent API Documentation

## Overview



The `security_agent` package provides a modular security monitoring system for PX4-based drones. It includes telemetry collection, threat detection, risk assessment, and automated response capabilities.

## Modules

### `app.py` - Security Monitor Application

Main application class that orchestrates all security monitoring components.

**Class: `SecurityMonitorApp`**

```python
SecurityMonitorApp(
    system_address: str = "udp://:14540",
    log_dir: str = "logs",
    active_response: bool = False,
    siem_url: str | None = None,
    gateway_settings: GatewaySettings | None = None,
    security_settings: SecuritySettings | None = None,
) -> None
```

Methods:
- `async run() -> None` - Main entry point, starts all components and event loop
- `_print_telemetry(event: TelemetryEvent) -> None` - Print telemetry events
- `_print_command_event(event: CommandEvent) -> None` - Print command events
- `_print_link_metrics(event: LinkMetricsEvent) -> None` - Print link metrics
- `_print_finding(event: SecurityEvent, assessment: RiskAssessment) -> None` - Print security findings

---

### `collector.py` - Telemetry Collection

Collects telemetry data from the drone via MAVSDK.

**Class: `TelemetryCollector`**

```python
TelemetryCollector(
    drone: System,
    event_queue: asyncio.Queue[TelemetryEvent],
    system_address: str,
) -> None
```

Methods:
- `async wait_until_connected() -> None` - Wait for drone connection
- `async run() -> None` - Start collecting telemetry (flight mode, armed, position, battery, GPS, health)
- `async _watch_stream(...)` - Internal stream watcher with throttling and deduplication

Normalizer methods (convert MAVSDK types to `TelemetryEvent`):
- `_normalize_flight_mode(mode: Any) -> TelemetryEvent`
- `_normalize_armed(armed: bool) -> TelemetryEvent`
- `_normalize_position(position: Any) -> TelemetryEvent`
- `_normalize_battery(battery: Any) -> TelemetryEvent`
- `_normalize_gps_info(gps_info: Any) -> TelemetryEvent`
- `_normalize_health(health: Any) -> TelemetryEvent`

---

### `detector.py` - Threat Detection

Analyzes events and detects security threats.

**Class: `ThreatDetector`**

```python
ThreatDetector() -> None
```

Methods:
- `analyze(event: object, snapshot: VehicleSnapshot) -> list[SecurityEvent]` - Analyze an event and return security findings

---

### `gateway.py` - MAVLink Gateway

Filters and optionally encrypts MAVLink traffic between drone and clients.

**Class: `MavlinkGateway`**

```python
MavlinkGateway(
    settings: GatewaySettings,
    event_queue: asyncio.Queue[object],
    control: GatewayControl | None = None,
) -> None
```

Methods:
- `async start() -> None` - Start the gateway
- `async stop() -> None` - Stop the gateway
- `_should_block(message: dict) -> bool` - Check if a message should be blocked
- `_policy_decision(...)` - Make access control decisions
- `_wrap_server_datagram(...)` - Wrap outgoing datagrams
- `_unwrap_client_datagram(...)` - Unwrap incoming datagrams

---

### `risk_engine.py` - Risk Assessment

Calculates risk scores and recommends actions based on security events.

**Class: `RiskEngine`**

```python
RiskEngine() -> None
```

Methods:
- `assess(event: SecurityEvent, snapshot: VehicleSnapshot) -> RiskAssessment` - Assess risk level and recommend action

---

### `responder.py` - Automated Response

Executes automated responses to security threats.

**Class: `Responder`**

```python
Responder(
    drone: System,
    dry_run: bool = True,
    gateway_control: GatewayControl | None = None,
) -> None
```

Methods:
- `async execute(assessment: RiskAssessment, snapshot: VehicleSnapshot) -> None` - Execute response action

---

### `state_guard.py` - Parameter and Mission Monitoring

Monitors PX4 parameters and mission plans for unauthorized changes.

**Class: `StateGuard`**

```python
StateGuard(
    drone: System,
    event_queue: asyncio.Queue[object],
    settings: SecuritySettings,
) -> None
```

Methods:
- `async run() -> None` - Start monitoring (params + mission)
- `async _watch_params() -> None` - Monitor parameter changes
- `async _watch_mission() -> None` - Monitor mission changes
- `async _snapshot_params() -> dict` - Snapshot current parameters
- `async _snapshot_mission() -> tuple[str, dict]` - Snapshot and hash current mission
- `_diff_dict(previous, current) -> dict` - Calculate parameter differences

---

### `audit.py` - Audit Logging

Logs security events with SHA-256 hash chain for integrity verification.

**Class: `AuditLogger`**

```python
AuditLogger(
    log_dir: str = "logs",
    siem_url: str | None = None,
) -> None
```

Methods:
- `log_telemetry(event: TelemetryEvent, snapshot: VehicleSnapshot) -> None`
- `log_security_event(event: SecurityEvent) -> None`
- `log_assessment(assessment: RiskAssessment) -> None`
- `log_command_event(event: CommandEvent) -> None`
- `log_link_metrics(event: LinkMetricsEvent) -> None`
- `close() -> None` - Close log files

---

### `models.py` - Data Models

Dataclasses for all event types and state.

**Dataclasses:**
- `TelemetryEvent` - Telemetry data (flight mode, position, battery, etc.)
- `SecurityEvent` - Security threat finding
- `CommandEvent` - MAVLink command/parameter write
- `LinkMetricsEvent` - Network link quality metrics
- `ThreatCoverageEvent` - Threat coverage scenario record
- `RiskAssessment` - Risk score and recommended action
- `VehicleSnapshot` - Current vehicle state

**Helper functions:**
- `now_ts() -> float` - Current UTC timestamp
- `iso_ts(timestamp: float) -> str` - Format timestamp as ISO 8601

---

### `config.py` - Configuration

Configuration dataclasses for all components.

**Classes:**
- `GatewayControl` - Runtime gateway control (blocked endpoints, lockdown)
- `GatewaySettings` - Gateway configuration (ports, filtering, encryption)
- `SecuritySettings` - Security monitor settings (poll intervals, critical params)

---

## Quick Start

```python
from security_agent.app import SecurityMonitorApp

app = SecurityMonitorApp(
    system_address="udp://:14540",
    log_dir="logs",
    active_response=False,
)
# await app.run()  # In an async context
```
