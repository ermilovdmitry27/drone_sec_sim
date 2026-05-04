from __future__ import annotations

import argparse
import asyncio


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Simulate suspicious repeated arm/disarm commands against PX4 SITL",
    )
    parser.add_argument(
        "--system-address",
        default="udpout://127.0.0.1:14541",
        help="MAVSDK system address for the MAVLink gateway client port",
    )
    parser.add_argument(
        "--cycles",
        type=int,
        default=4,
        help="Number of arm/disarm cycles",
    )
    parser.add_argument(
        "--pause",
        type=float,
        default=1.0,
        help="Pause in seconds between commands",
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
    except ModuleNotFoundError:
        print(
            "Не найден пакет mavsdk. Запустите сценарий через виртуальное окружение:\n"
            "source .venv/bin/activate && python scenarios/attack_arm_disarm_flap.py"
        )
        return

    args = parse_args()
    drone = System()
    await drone.connect(system_address=args.system_address)
    await wait_until_connected(drone)

    print(
        "Запуск сценария suspicious arm/disarm. "
        "Используйте его на земле, до взлета."
    )
    await asyncio.sleep(3)

    for index in range(1, args.cycles + 1):
        try:
            print(f"[{index}/{args.cycles}] ARM")
            await drone.action.arm()
        except Exception as exc:
            print(f"Команда ARM завершилась ошибкой: {exc}")
        await asyncio.sleep(args.pause)

        try:
            print(f"[{index}/{args.cycles}] DISARM")
            await drone.action.disarm()
        except Exception as exc:
            print(f"Команда DISARM завершилась ошибкой: {exc}")
        await asyncio.sleep(args.pause)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nСценарий остановлен")
