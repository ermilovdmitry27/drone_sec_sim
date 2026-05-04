import argparse
import asyncio
import hashlib
import os


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
    parser.add_argument(
        "--siem-url",
        default=os.environ.get("DRONE_SEC_SIM_SIEM_URL", ""),
        help="Optional SIEM HTTP endpoint for JSON audit events",
    )
    parser.add_argument(
        "--authorized-client-host",
        action="append",
        default=[],
        help="Authorized MAVLink client host. Repeat to allow several hosts. Use '*' only for lab-only open access.",
    )
    parser.add_argument(
        "--mavlink-encryption-key-hex",
        default=os.environ.get("DRONE_SEC_SIM_MAVLINK_KEY_HEX", ""),
        help="Optional AES key as hex for encrypted MAVLink client datagrams",
    )
    parser.add_argument(
        "--require-encrypted-clients",
        action="store_true",
        help="Reject unencrypted MAVLink client datagrams when gateway encryption is configured",
    )
    parser.add_argument(
        "--operator-token-hash",
        action="append",
        default=[],
        metavar="OPERATOR_ID:SHA256_HEX",
        help="Authorized operator token hash. Repeat to add several operators.",
    )
    parser.add_argument(
        "--operator-token",
        action="append",
        default=[],
        metavar="OPERATOR_ID:TOKEN",
        help="Lab-only operator token; converted to SHA-256 in memory. Prefer --operator-token-hash.",
    )
    parser.add_argument(
        "--require-operator-auth",
        action="store_true",
        help="Reject client datagrams unless they use the authenticated encrypted wrapper",
    )
    return parser.parse_args()


def parse_operator_hashes(raw_hashes: list[str], raw_tokens: list[str]) -> dict[str, str]:
    operator_hashes: dict[str, str] = {}
    for raw in raw_hashes:
        operator_id, token_hash = split_operator_secret(raw, "--operator-token-hash")
        if len(token_hash) != 64 or any(char not in "0123456789abcdefABCDEF" for char in token_hash):
            raise SystemExit("--operator-token-hash value must be a SHA-256 hex digest")
        operator_hashes[operator_id] = token_hash.lower()
    for raw in raw_tokens:
        operator_id, token = split_operator_secret(raw, "--operator-token")
        operator_hashes[operator_id] = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return operator_hashes


def split_operator_secret(raw: str, option_name: str) -> tuple[str, str]:
    if ":" not in raw:
        raise SystemExit(f"{option_name} must use OPERATOR_ID:VALUE format")
    operator_id, value = raw.split(":", 1)
    if not operator_id or not value:
        raise SystemExit(f"{option_name} must include both operator id and value")
    return operator_id, value


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
        authorized_client_hosts = tuple(args.authorized_client_host or ["127.0.0.1"])
        operator_token_hashes = parse_operator_hashes(args.operator_token_hash, args.operator_token)
        gateway_settings = GatewaySettings(
            api_upstream_port=args.gateway_upstream_port,
            api_client_port=args.gateway_client_port,
            gcs_upstream_port=args.gateway_gcs_upstream_port,
            gcs_client_port=args.gateway_gcs_client_port,
            block_param_writes=args.gateway_enforce,
            block_mission_writes=args.gateway_enforce,
            block_serial_control=args.gateway_enforce or args.gateway_block_serial_control,
            authorized_client_hosts=authorized_client_hosts,
            encryption_key_hex=args.mavlink_encryption_key_hex,
            require_encrypted_clients=args.require_encrypted_clients,
            operator_token_hashes=operator_token_hashes,
            require_operator_auth=args.require_operator_auth,
        )
        system_address = gateway_settings.client_system_address

    app = SecurityMonitorApp(
        system_address=system_address,
        log_dir=args.log_dir,
        active_response=args.active_response,
        siem_url=args.siem_url or None,
        gateway_settings=gateway_settings,
        security_settings=SecuritySettings(),
    )
    await app.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nОстановка security monitor")
