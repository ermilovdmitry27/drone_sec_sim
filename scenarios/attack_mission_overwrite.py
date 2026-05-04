from __future__ import annotations

import argparse
import asyncio


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Upload a replacement mission to PX4 to test mission integrity controls",
    )
    parser.add_argument(
        "--system-address",
        default="udpout://127.0.0.1:14541",
        help="MAVSDK system address for the MAVLink gateway client port",
    )
    parser.add_argument(
        "--offset",
        type=float,
        default=0.00015,
        help="Latitude/longitude offset for generated mission waypoints",
    )
    parser.add_argument(
        "--altitude",
        type=float,
        default=20.0,
        help="Relative altitude for generated mission items",
    )
    return parser.parse_args()


async def wait_until_connected(drone) -> None:
    print("Ожидание подключения к PX4 ...")
    async for state in drone.core.connection_state():
        if state.is_connected:
            print("PX4 найден")
            return


async def get_position(drone):
    async for position in drone.telemetry.position():
        return position
    raise RuntimeError("Не удалось получить позицию")


async def main() -> None:
    try:
        from mavsdk import System
        from mavsdk.mission import MissionItem, MissionPlan
    except ModuleNotFoundError:
        print(
            "Не найден пакет mavsdk. Запустите сценарий через виртуальное окружение:\n"
            "source .venv/bin/activate && python scenarios/attack_mission_overwrite.py"
        )
        return

    args = parse_args()
    drone = System()
    await drone.connect(system_address=args.system_address)
    await wait_until_connected(drone)

    position = await get_position(drone)
    base_lat = float(position.latitude_deg)
    base_lon = float(position.longitude_deg)

    mission_items = [
        MissionItem(
            base_lat + args.offset,
            base_lon,
            args.altitude,
            5.0,
            True,
            float("nan"),
            float("nan"),
            MissionItem.CameraAction.NONE,
            float("nan"),
            float("nan"),
            float("nan"),
            float("nan"),
            float("nan"),
            MissionItem.VehicleAction.NONE,
        ),
        MissionItem(
            base_lat,
            base_lon + args.offset,
            args.altitude,
            5.0,
            True,
            float("nan"),
            float("nan"),
            MissionItem.CameraAction.NONE,
            float("nan"),
            float("nan"),
            float("nan"),
            float("nan"),
            float("nan"),
            MissionItem.VehicleAction.NONE,
        ),
    ]
    mission_plan = MissionPlan(mission_items)
    print(f"Загрузка новой миссии из {len(mission_items)} точек")
    await drone.mission.upload_mission(mission_plan)
    print("Миссия загружена")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nСценарий остановлен")
