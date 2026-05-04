from __future__ import annotations

import argparse
import asyncio


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send aggressive offboard velocity commands to create a navigation anomaly",
    )
    parser.add_argument(
        "--system-address",
        default="udpout://127.0.0.1:14541",
        help="MAVSDK system address for the MAVLink gateway client port",
    )
    parser.add_argument(
        "--velocity-x",
        type=float,
        default=12.0,
        help="Forward velocity in m/s",
    )
    parser.add_argument(
        "--velocity-y",
        type=float,
        default=8.0,
        help="Right velocity in m/s",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=4.0,
        help="Duration of the offboard command in seconds",
    )
    return parser.parse_args()


async def wait_until_connected(drone) -> None:
    print("Ожидание подключения к PX4 ...")
    async for state in drone.core.connection_state():
        if state.is_connected:
            print("PX4 найден")
            return


async def main() -> None:
    try:
        from mavsdk import System
        from mavsdk.offboard import OffboardError, VelocityNedYaw
    except ModuleNotFoundError:
        print(
            "Не найден пакет mavsdk. Запустите сценарий через виртуальное окружение:\n"
            "source .venv/bin/activate && python scenarios/attack_navigation_excursion.py"
        )
        return

    args = parse_args()
    drone = System()
    await drone.connect(system_address=args.system_address)
    await wait_until_connected(drone)

    print("Отправка агрессивных offboard-команд. Используйте только на взлетевшем аппарате.")
    await drone.offboard.set_velocity_ned(
        VelocityNedYaw(args.velocity_x, args.velocity_y, 0.0, 0.0)
    )
    try:
        await drone.offboard.start()
        await asyncio.sleep(args.duration)
    except OffboardError as exc:
        print(f"Не удалось включить offboard: {exc}")
    finally:
        await drone.offboard.set_velocity_ned(VelocityNedYaw(0.0, 0.0, 0.0, 0.0))
        try:
            await drone.offboard.stop()
        except Exception:
            pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nСценарий остановлен")
