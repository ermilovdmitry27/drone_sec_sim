from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock

from security_agent.collector import TelemetryCollector
from security_agent.models import TelemetryEvent


class TelemetryCollectorInitTest(unittest.TestCase):
    def test_initialization(self) -> None:
        drone = MagicMock()
        queue: asyncio.Queue[object] = asyncio.Queue()
        collector = TelemetryCollector(drone, queue, "udp://:14540")
        self.assertEqual(collector.system_address, "udp://:14540")
        self.assertIs(collector.drone, drone)
        self.assertIs(collector.event_queue, queue)


class TelemetryCollectorNormalizerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.drone = MagicMock()
        self.queue: asyncio.Queue[object] = asyncio.Queue()
        self.collector = TelemetryCollector(self.drone, self.queue, "udp://:14540")

    def test_normalize_flight_mode(self) -> None:
        mode = "POSCTL"
        event = self.collector._normalize_flight_mode(mode)
        self.assertIsInstance(event, TelemetryEvent)
        self.assertEqual(event.name, "flight_mode")
        self.assertEqual(event.value, "POSCTL")

    def test_normalize_armed_true(self) -> None:
        event = self.collector._normalize_armed(True)
        self.assertEqual(event.name, "armed")
        self.assertTrue(event.value)

    def test_normalize_armed_false(self) -> None:
        event = self.collector._normalize_armed(False)
        self.assertFalse(event.value)

    def test_normalize_position(self) -> None:
        position = MagicMock()
        position.latitude_deg = 55.755826
        position.longitude_deg = 37.617300
        position.relative_altitude_m = 10.5

        event = self.collector._normalize_position(position)
        self.assertEqual(event.name, "position")
        self.assertEqual(event.value["latitude_deg"], 55.755826)
        self.assertEqual(event.value["longitude_deg"], 37.617300)
        self.assertEqual(event.value["relative_altitude_m"], 10.5)

    def test_normalize_battery(self) -> None:
        battery = MagicMock()
        battery.remaining_percent = 0.85
        battery.voltage_v = 12.5

        event = self.collector._normalize_battery(battery)
        self.assertEqual(event.name, "battery")
        self.assertEqual(event.value["remaining_pct"], 0.85)
        self.assertEqual(event.value["voltage_v"], 12.5)

    def test_normalize_gps_info_with_fix_type_value(self) -> None:
        gps_info = MagicMock()
        gps_info.fix_type = MagicMock(value=3)
        gps_info.num_satellites = 12

        event = self.collector._normalize_gps_info(gps_info)
        self.assertEqual(event.name, "gps_info")
        self.assertEqual(event.value["fix_type"], 3)
        self.assertEqual(event.value["num_satellites"], 12)

    def test_normalize_gps_info_with_int_fix_type(self) -> None:
        gps_info = MagicMock()
        gps_info.fix_type = 3
        gps_info.num_satellites = 12

        event = self.collector._normalize_gps_info(gps_info)
        self.assertEqual(event.value["fix_type"], 3)

    def test_normalize_health(self) -> None:
        health = MagicMock()
        health.is_global_position_ok = True
        health.is_home_position_ok = False

        event = self.collector._normalize_health(health)
        self.assertEqual(event.name, "health")
        self.assertTrue(event.value["global_position_ok"])
        self.assertFalse(event.value["home_position_ok"])


class TelemetryCollectorWatchStreamTest(unittest.TestCase):
    def test_watch_stream_throttle_and_dedup(self) -> None:
        async def run_test() -> None:
            queue: asyncio.Queue[object] = asyncio.Queue()
            drone = MagicMock()
            collector = TelemetryCollector(drone, queue, "udp://:14540")

            call_count = 0
            events = []

            async def mock_stream():
                nonlocal call_count
                for value in ["A", "A", "B", "B", "B", "C"]:
                    call_count += 1
                    yield value

            def normalize(value: str) -> TelemetryEvent:
                return TelemetryEvent(name="test", value=value)

            def key_builder(event: TelemetryEvent) -> str:
                return str(event.value)

            await collector._watch_stream(
                lambda: mock_stream(),
                normalize,
                key_builder,
                throttle_seconds=0.01,
            )

            while not queue.empty():
                events.append(await queue.get())

            self.assertEqual(len(events), 3)
            self.assertEqual(events[0].value, "A")
            self.assertEqual(events[1].value, "B")
            self.assertEqual(events[2].value, "C")

        asyncio.run(run_test())


if __name__ == "__main__":
    unittest.main()
