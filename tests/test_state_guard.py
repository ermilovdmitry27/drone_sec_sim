from __future__ import annotations

import asyncio
import hashlib
import json
import unittest
from unittest.mock import AsyncMock, MagicMock

from security_agent.config import SecuritySettings
from security_agent.models import SecurityEvent
from security_agent.state_guard import StateGuard


class StateGuardInitTest(unittest.TestCase):
    def test_initialization(self) -> None:
        drone = MagicMock()
        queue: asyncio.Queue[object] = asyncio.Queue()
        settings = SecuritySettings()
        guard = StateGuard(drone, queue, settings)
        self.assertIs(guard.drone, drone)
        self.assertIs(guard.event_queue, queue)
        self.assertIs(guard.settings, settings)
        self.assertIsNone(guard.param_snapshot)
        self.assertIsNone(guard.mission_hash)


class StateGuardDiffDictTest(unittest.TestCase):
    def setUp(self) -> None:
        self.drone = MagicMock()
        self.queue: asyncio.Queue[object] = asyncio.Queue()
        self.guard = StateGuard(self.drone, self.queue, SecuritySettings())

    def test_no_diff(self) -> None:
        previous = {"PARAM1": 1, "PARAM2": 2.5, "PARAM3": "abc"}
        current = {"PARAM1": 1, "PARAM2": 2.5, "PARAM3": "abc"}
        diff = self.guard._diff_dict(previous, current)
        self.assertEqual(len(diff), 0)

    def test_single_change(self) -> None:
        previous = {"PARAM1": 1, "PARAM2": 2.5}
        current = {"PARAM1": 1, "PARAM2": 3.0}
        diff = self.guard._diff_dict(previous, current)
        self.assertEqual(len(diff), 1)
        self.assertIn("PARAM2", diff)
        self.assertEqual(diff["PARAM2"]["old"], 2.5)
        self.assertEqual(diff["PARAM2"]["new"], 3.0)

    def test_multiple_changes(self) -> None:
        previous = {"PARAM1": 1, "PARAM2": 2.5, "PARAM3": "abc"}
        current = {"PARAM1": 2, "PARAM2": 2.5, "PARAM3": "def"}
        diff = self.guard._diff_dict(previous, current)
        self.assertEqual(len(diff), 2)
        self.assertIn("PARAM1", diff)
        self.assertIn("PARAM3", diff)

    def test_new_param(self) -> None:
        previous = {"PARAM1": 1}
        current = {"PARAM1": 1, "PARAM2": 2.5}
        diff = self.guard._diff_dict(previous, current)
        self.assertEqual(len(diff), 1)
        self.assertIn("PARAM2", diff)
        self.assertIsNone(diff["PARAM2"]["old"])
        self.assertEqual(diff["PARAM2"]["new"], 2.5)

    def test_removed_param(self) -> None:
        previous = {"PARAM1": 1, "PARAM2": 2.5}
        current = {"PARAM1": 1}
        diff = self.guard._diff_dict(previous, current)
        self.assertEqual(len(diff), 1)
        self.assertIn("PARAM2", diff)
        self.assertEqual(diff["PARAM2"]["old"], 2.5)
        self.assertIsNone(diff["PARAM2"]["new"])

    def test_diff_limit(self) -> None:
        previous = {f"PARAM{i}": i for i in range(20)}
        current = {f"PARAM{i}": i + 1 for i in range(20)}
        diff = self.guard._diff_dict(previous, current)
        self.assertEqual(len(diff), 10)


class StateGuardSnapshotParamsTest(unittest.TestCase):
    def test_snapshot_params(self) -> None:
        async def run_test() -> None:
            drone = MagicMock()
            queue: asyncio.Queue[object] = asyncio.Queue()
            guard = StateGuard(drone, queue, SecuritySettings())

            int_param = MagicMock()
            int_param.name = "INT_PARAM"
            int_param.value = 42

            float_param = MagicMock()
            float_param.name = "FLT_PARAM"
            float_param.value = 3.14159

            custom_param = MagicMock()
            custom_param.name = "CUST_PARAM"
            custom_param.value = "hello"

            all_params = MagicMock()
            all_params.int_params = [int_param]
            all_params.float_params = [float_param]
            all_params.custom_params = [custom_param]

            drone.param.get_all_params = AsyncMock(return_value=all_params)

            snapshot = await guard._snapshot_params()

            self.assertEqual(snapshot["INT_PARAM"], 42)
            self.assertEqual(snapshot["FLT_PARAM"], 3.14159)
            self.assertEqual(snapshot["CUST_PARAM"], "hello")

        asyncio.run(run_test())


class StateGuardSnapshotMissionTest(unittest.TestCase):
    def test_empty_mission(self) -> None:
        async def run_test() -> None:
            drone = MagicMock()
            queue: asyncio.Queue[object] = asyncio.Queue()
            settings = SecuritySettings()
            guard = StateGuard(drone, queue, settings)

            mission_plan = MagicMock()
            mission_plan.mission_items = []
            drone.mission.download_mission = AsyncMock(return_value=mission_plan)

            mission_hash, summary = await guard._snapshot_mission()

            self.assertEqual(mission_hash, settings.mission_hash_empty)
            self.assertEqual(summary["mission_items"], 0)

        asyncio.run(run_test())

    def test_non_empty_mission(self) -> None:
        async def run_test() -> None:
            drone = MagicMock()
            queue: asyncio.Queue[object] = asyncio.Queue()
            guard = StateGuard(drone, queue, SecuritySettings())

            item = MagicMock()
            item.latitude_deg = 55.755826
            item.longitude_deg = 37.617300
            item.relative_altitude_m = 10.5
            item.speed_m_s = 5.0
            item.yaw_deg = 0.0

            mission_plan = MagicMock()
            mission_plan.mission_items = [item]
            drone.mission.download_mission = AsyncMock(return_value=mission_plan)

            mission_hash, summary = await guard._snapshot_mission()

            self.assertNotEqual(mission_hash, "")
            self.assertEqual(summary["mission_items"], 1)
            self.assertIn("mission_digest", summary)
            self.assertIn("preview", summary)

            expected_normalized = {
                "latitude_deg": 55.755826,
                "longitude_deg": 37.6173,
                "relative_altitude_m": 10.5,
                "speed_m_s": 5.0,
                "yaw_deg": 0.0,
            }
            digest = hashlib.sha256(
                json.dumps([expected_normalized], sort_keys=True).encode("utf-8")
            ).hexdigest()
            self.assertEqual(mission_hash, digest)

        asyncio.run(run_test())


class StateGuardWatchParamsTest(unittest.TestCase):
    def test_param_change_detection(self) -> None:
        async def run_test() -> None:
            drone = MagicMock()
            queue: asyncio.Queue[object] = asyncio.Queue()
            settings = SecuritySettings(param_poll_interval_s=0.01)
            guard = StateGuard(drone, queue, settings)

            call_count = 0

            async def mock_get_all_params():
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    all_params = MagicMock()
                    all_params.int_params = [MagicMock(name="TEST_PARAM", value=1)]
                    all_params.float_params = []
                    all_params.custom_params = []
                    return all_params
                else:
                    all_params = MagicMock()
                    all_params.int_params = [MagicMock(name="TEST_PARAM", value=2)]
                    all_params.float_params = []
                    all_params.custom_params = []
                    return all_params

            drone.param.get_all_params = mock_get_all_params
            drone.mission.download_mission = AsyncMock(return_value=MagicMock(mission_items=[]))

            watch_task = asyncio.create_task(guard._watch_params())
            await asyncio.sleep(0.05)
            watch_task.cancel()
            try:
                await watch_task
            except asyncio.CancelledError:
                pass

            events = []
            while not queue.empty():
                events.append(await queue.get())

            param_events = [e for e in events if isinstance(e, SecurityEvent) and e.rule_id == "px4_param_changed"]
            self.assertGreaterEqual(len(param_events), 1)

        asyncio.run(run_test())


if __name__ == "__main__":
    unittest.main()
