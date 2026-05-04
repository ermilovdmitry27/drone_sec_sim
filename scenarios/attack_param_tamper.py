from __future__ import annotations

import argparse
import asyncio


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Change a PX4 parameter through MAVSDK to test security controls",
    )
    parser.add_argument(
        "--system-address",
        default="udpout://127.0.0.1:14541",
        help="MAVSDK system address for the MAVLink gateway client port",
    )
    parser.add_argument(
        "--param-name",
        default="MPC_XY_CRUISE",
        help="PX4 parameter to tamper with",
    )
    parser.add_argument(
        "--delta",
        type=float,
        default=2.0,
        help="Delta added to the current parameter value",
    )
    parser.add_argument(
        "--restore-delay",
        type=float,
        default=5.0,
        help="Delay before restoring the original parameter value",
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
            "source .venv/bin/activate && python scenarios/attack_param_tamper.py"
        )
        return

    args = parse_args()
    drone = System()
    await drone.connect(system_address=args.system_address)
    await wait_until_connected(drone)

    try:
        original_int = await drone.param.get_param_int(args.param_name)
        new_value = int(original_int + args.delta)
        print(f"Изменение int-параметра {args.param_name}: {original_int} -> {new_value}")
        await drone.param.set_param_int(args.param_name, new_value)
        await asyncio.sleep(args.restore_delay)
        print(f"Восстановление {args.param_name}: {new_value} -> {original_int}")
        await drone.param.set_param_int(args.param_name, original_int)
        return
    except Exception:
        pass

    original_float = await drone.param.get_param_float(args.param_name)
    new_value = original_float + args.delta
    print(f"Изменение float-параметра {args.param_name}: {original_float} -> {new_value}")
    await drone.param.set_param_float(args.param_name, new_value)
    await asyncio.sleep(args.restore_delay)
    print(f"Восстановление {args.param_name}: {new_value} -> {original_float}")
    await drone.param.set_param_float(args.param_name, original_float)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nСценарий остановлен")
