"""
Benchmark tests for Security Monitor components.

These tests measure performance of critical operations:
- Threat detection latency
- Event queue throughput
- Risk assessment speed
"""

from __future__ import annotations

import asyncio
import time
import unittest
from unittest.mock import AsyncMock, MagicMock

from security_agent.app import SecurityMonitorApp
from security_agent.config import GatewaySettings, SecuritySettings
from security_agent.detector import ThreatDetector
from security_agent.models import (
    CommandEvent,
    SecurityEvent,
    TelemetryEvent,
    VehicleSnapshot,
)
from security_agent.risk_engine import RiskEngine


class DetectorBenchmarkTest(unittest.TestCase):
    """Benchmark threat detector performance."""

    def test_detection_latency(self) -> None:
        """Measure time to analyze 1000 telemetry events."""
        detector = ThreatDetector()
        snapshot = VehicleSnapshot(is_connected=True, flight_mode="POSCTL")

        events = []
        for i in range(1000):
            events.append(
                TelemetryEvent(
                    name="battery",
                    value={"remaining_pct": 0.5 + (i % 10) * 0.01, "voltage_v": 12.0},
                )
            )

        start = time.perf_counter()
        total_findings = 0
        for event in events:
            findings = detector.analyze(event, snapshot)
            total_findings += len(findings)
        elapsed = time.perf_counter() - start

        events_per_second = 1000 / elapsed
        print(f"\n[Benchmark] Detector: {events_per_second:.0f} events/sec ({elapsed:.3f}s for 1000 events)")
        self.assertGreater(events_per_second, 1000)  # Should process at least 1000 events/sec

    def test_command_detection_latency(self) -> None:
        """Measure time to analyze command events."""
        detector = ThreatDetector()
        snapshot = VehicleSnapshot(is_armed=True, flight_mode="POSCTL")

        events = []
        for i in range(100):
            events.append(
                CommandEvent(
                    direction="in",
                    channel="api",
                    endpoint="127.0.0.1:14541",
                    message_id=176 + (i % 10),
                    message_name=f"MAV_CMD_{176 + (i % 10)}",
                    category="command",
                )
            )

        start = time.perf_counter()
        for event in events:
            detector.analyze(event, snapshot)
        elapsed = time.perf_counter() - start

        events_per_second = 100 / elapsed
        print(f"\n[Benchmark] Command detection: {events_per_second:.0f} cmds/sec ({elapsed:.3f}s for 100 commands)")
        self.assertGreater(events_per_second, 500)


class RiskEngineBenchmarkTest(unittest.TestCase):
    """Benchmark risk engine performance."""

    def test_assessment_speed(self) -> None:
        """Measure time to assess 1000 security events."""
        risk_engine = RiskEngine()
        snapshot = VehicleSnapshot(is_connected=True, flight_mode="POSCTL")

        events = []
        for i in range(1000):
            events.append(
                SecurityEvent(
                    rule_id=f"test_rule_{i % 10}",
                    severity="MEDIUM",
                    description=f"Test event {i}",
                    telemetry_event="test",
                )
            )

        start = time.perf_counter()
        for event in events:
            risk_engine.assess(event, snapshot)
        elapsed = time.perf_counter() - start

        assessments_per_second = 1000 / elapsed
        print(f"\n[Benchmark] Risk assessment: {assessments_per_second:.0f} assessments/sec ({elapsed:.3f}s for 1000)")
        self.assertGreater(assessments_per_second, 5000)


class EventQueueBenchmarkTest(unittest.TestCase):
    """Benchmark event queue throughput."""

    def test_queue_throughput(self) -> None:
        """Measure event queue put/get throughput."""
        queue: asyncio.Queue[object] = asyncio.Queue(maxsize=10000)

        async def producer() -> None:
            for i in range(5000):
                await queue.put(TelemetryEvent(name="test", value=i))
                await asyncio.sleep(0)  # Yield control

        async def consumer() -> int:
            count = 0
            while count < 5000:
                await queue.get()
                count += 1
            return count

        async def run_benchmark() -> tuple[float, int]:
            queue._unfinished_tasks = 0  # Reset
            start = time.perf_counter()
            producer_task = asyncio.create_task(producer())
            consumer_task = asyncio.create_task(consumer())
            await asyncio.gather(producer_task, consumer_task)
            elapsed = time.perf_counter() - start
            return elapsed, consumer_task.result()

        elapsed, count = asyncio.run(run_benchmark())

        throughput = count / elapsed
        print(f"\n[Benchmark] Event queue: {throughput:.0f} events/sec ({elapsed:.3f}s for {count} events)")
        self.assertGreater(throughput, 10000)  # Should handle at least 10k events/sec


class FullPipelineBenchmarkTest(unittest.TestCase):
    """Benchmark full detection pipeline."""

    def test_pipeline_latency(self) -> None:
        """Measure end-to-end latency: event -> detection -> assessment."""
        detector = ThreatDetector()
        risk_engine = RiskEngine()
        snapshot = VehicleSnapshot(is_armed=True, flight_mode="POSCTL")

        event = CommandEvent(
            direction="in",
            channel="api",
            endpoint="127.0.0.1:14541",
            message_id=400,
            message_name="MAV_CMD_PARAM_SET",
            category="param_write",
        )

        # Warm-up
        for _ in range(10):
            findings = detector.analyze(event, snapshot)
            for f in findings:
                risk_engine.assess(f, snapshot)

        # Benchmark
        iterations = 100
        start = time.perf_counter()
        for _ in range(iterations):
            findings = detector.analyze(event, snapshot)
            for f in findings:
                risk_engine.assess(f, snapshot)
        elapsed = time.perf_counter() - start

        latency_ms = (elapsed / iterations) * 1000
        print(f"\n[Benchmark] Pipeline latency: {latency_ms:.2f}ms per event ({iterations} iterations)")
        self.assertLess(latency_ms, 10.0)  # Should be under 10ms per event


if __name__ == "__main__":
    unittest.main()
