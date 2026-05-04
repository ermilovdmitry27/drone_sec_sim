import argparse
import asyncio


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Security monitor for PX4 SITL / Gazebo / QGroundControl",
    )
    parser.add_argument(
        "--system-address",
        default="udp://:14540",
        help="MAVSDK system address for PX4",
    )
    parser.add_argument(
        "--log-dir",
        default="logs",
        help="Directory for telemetry and security logs",
    )
    parser.add_argument(
        "--active-response",
        action="store_true",
        help="Allow the agent to send active mitigation commands to PX4",
    )
    parser.add_argument(
        "--enable-gateway",
        action="store_true",
        help="Start inline MAVLink gateway/proxy for command inspection",
    )
    parser.add_argument(
        "--gateway-upstream-port",
        type=int,
        default=14540,
        help="Port where PX4 sends Offboard/API MAVLink telemetry to the gateway",
    )
    parser.add_argument(
        "--gateway-client-port",
        type=int,
        default=14541,
        help="Port where companion/attacker clients connect to the gateway",
    )
    parser.add_argument(
        "--gateway-gcs-upstream-port",
        type=int,
        default=14550,
        help="Port where PX4 sends GCS MAVLink telemetry to the gateway",
    )
    parser.add_argument(
        "--gateway-gcs-client-port",
        type=int,
        default=14552,
        help="Port where QGroundControl should connect via a manual UDP link",
    )
    parser.add_argument(
        "--gateway-enforce",
        action="store_true",
        help="Allow the gateway to block mission, parameter and SERIAL_CONTROL traffic",
    )
    parser.add_argument(
        "--gateway-block-serial-control",
        action="store_true",
        help="Block MAVLink SERIAL_CONTROL messages in the gateway",
    )
    return parser.parse_args()


async def main() -> None:
    try:
        from security_agent.app import SecurityMonitorApp
        from security_agent.config import GatewaySettings, SecuritySettings
    except ModuleNotFoundError as exc:
        if exc.name == "mavsdk":
            print(
                "Не найден пакет mavsdk. Запустите monitor через виртуальное окружение:\n"
                "source .venv/bin/activate && python monitor.py"
            )
            return
        raise

    args = parse_args()
    gateway_settings = None
    system_address = args.system_address

    if args.enable_gateway:
        gateway_settings = GatewaySettings(
            api_upstream_port=args.gateway_upstream_port,
            api_client_port=args.gateway_client_port,
            gcs_upstream_port=args.gateway_gcs_upstream_port,
            gcs_client_port=args.gateway_gcs_client_port,
            block_param_writes=args.gateway_enforce,
            block_mission_writes=args.gateway_enforce,
            block_serial_control=args.gateway_enforce or args.gateway_block_serial_control,
        )
        system_address = gateway_settings.client_system_address

    app = SecurityMonitorApp(
        system_address=system_address,
        log_dir=args.log_dir,
        active_response=args.active_response,
        gateway_settings=gateway_settings,
        security_settings=SecuritySettings(),
    )
    await app.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nОстановка security monitor")
