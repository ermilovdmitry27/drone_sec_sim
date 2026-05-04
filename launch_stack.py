from __future__ import annotations

import argparse
import ctypes
import fcntl
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent


class _Flock(ctypes.Structure):
    _fields_ = [
        ("l_type", ctypes.c_short),
        ("l_whence", ctypes.c_short),
        ("l_start", ctypes.c_longlong),
        ("l_len", ctypes.c_longlong),
        ("l_pid", ctypes.c_int),
    ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Launch PX4 SITL + Gazebo + QGroundControl + Security Monitor",
    )
    parser.add_argument(
        "--config",
        default=str(PROJECT_ROOT / "sim_stack.json"),
        help="Path to JSON configuration file",
    )
    parser.add_argument(
        "--px4-dir",
        help="Override PX4-Autopilot directory",
    )
    parser.add_argument(
        "--qgc-path",
        help="Optional QGroundControl AppImage path",
    )
    return parser.parse_args()


def load_config(path: str) -> dict:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def start_process(command: list[str], cwd: str | None = None, env: dict[str, str] | None = None) -> subprocess.Popen:
    return subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        start_new_session=True,
    )


def build_px4_env() -> dict[str, str]:
    env = os.environ.copy()
    venv_bin = str((PROJECT_ROOT / ".venv" / "bin").resolve())
    path_entries = env.get("PATH", "").split(os.pathsep)
    filtered_entries = [entry for entry in path_entries if Path(entry).resolve().as_posix() != venv_bin]
    env["PATH"] = os.pathsep.join(filtered_entries)
    env.pop("VIRTUAL_ENV", None)
    env.pop("PYTHONHOME", None)
    env.pop("PYTHONPATH", None)
    return env


def terminate_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)


def px4_server_running(instance: int = 0) -> bool:
    lock_path = f"/tmp/px4_lock-{instance}"
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o666)
    try:
        flock = _Flock()
        flock.l_type = fcntl.F_WRLCK
        flock.l_whence = os.SEEK_SET
        flock.l_start = 0
        flock.l_len = 0
        flock.l_pid = 0

        libc = ctypes.CDLL(None, use_errno=True)
        result = libc.fcntl(fd, fcntl.F_GETLK, ctypes.byref(flock))
        if result == -1:
            errno_value = ctypes.get_errno()
            raise OSError(errno_value, os.strerror(errno_value), lock_path)

        return flock.l_type != fcntl.F_UNLCK
    finally:
        os.close(fd)


def main() -> int:
    args = parse_args()
    config = load_config(args.config)

    px4_dir = os.path.expanduser(args.px4_dir or config["px4_dir"])
    deployment_mode = str(config.get("deployment_mode", "sitl"))
    model = config["model"]
    target_platform = config.get("target_platform") or {}
    world = config.get("world", "")
    headless = bool(config.get("headless", False))
    qgc_path = args.qgc_path or config.get("qgc_path") or ""
    log_dir = config.get("log_dir", "logs")
    enable_gateway = bool(config.get("enable_gateway", True))
    gateway_upstream_port = int(config.get("gateway_upstream_port", 14540))
    gateway_client_port = int(config.get("gateway_client_port", 14541))
    gateway_gcs_upstream_port = int(config.get("gateway_gcs_upstream_port", 14550))
    gateway_gcs_client_port = int(config.get("gateway_gcs_client_port", 14552))
    gateway_enforce = bool(config.get("gateway_enforce", False))
    gateway_block_serial_control = bool(config.get("gateway_block_serial_control", False))
    active_response = bool(config.get("active_response", False))

    processes: list[subprocess.Popen] = []
    monitor_command = [
        str(PROJECT_ROOT / ".venv/bin/python"),
        str((PROJECT_ROOT / "monitor.py").resolve()),
        "--log-dir",
        log_dir,
    ]
    if active_response:
        monitor_command.append("--active-response")
    if enable_gateway:
        monitor_command.extend(
            [
                "--enable-gateway",
                "--gateway-upstream-port",
                str(gateway_upstream_port),
                "--gateway-client-port",
                str(gateway_client_port),
                "--gateway-gcs-upstream-port",
                str(gateway_gcs_upstream_port),
                "--gateway-gcs-client-port",
                str(gateway_gcs_client_port),
            ]
        )
        if gateway_enforce:
            monitor_command.append("--gateway-enforce")
        if gateway_block_serial_control and not gateway_enforce:
            monitor_command.append("--gateway-block-serial-control")

    px4_command = ["make", "px4_sitl", model]
    px4_env = build_px4_env()
    if headless:
        px4_env["HEADLESS"] = "1"
    if world:
        px4_env["PX4_GZ_WORLD"] = world

    try:
        if px4_server_running(instance=0):
            print(
                "PX4 SITL не будет запущен: другой PX4 server уже держит lock "
                "/tmp/px4_lock-0 для instance 0.\n"
                "Остановите предыдущий PX4 SITL процесс и повторите запуск."
            )
            return 1

        print(
            "Профиль развёртывания: "
            f"deployment_mode={deployment_mode} model={model} "
            f"gateway={enable_gateway} active_response={active_response}"
        )
        if target_platform:
            print(
                "Целевая аппаратная платформа: "
                f"airframe={target_platform.get('airframe', 'n/a')} "
                f"flight_controller={target_platform.get('flight_controller', 'n/a')} "
                f"hardware_validated={bool(target_platform.get('hardware_validated', False))}"
            )

        print(f"Старт PX4 SITL: {model}")
        px4_process = start_process(px4_command, cwd=px4_dir, env=px4_env)
        processes.append(px4_process)
        time.sleep(5)
        if px4_process.poll() is not None:
            print(
                "PX4 завершился на этапе сборки или старта. "
                "Security Monitor и QGroundControl запускаться не будут."
            )
            return 1

        print("Старт Security Monitor")
        processes.append(start_process(monitor_command, cwd=str(PROJECT_ROOT)))

        if qgc_path:
            expanded_qgc_path = os.path.expanduser(qgc_path)
            print("Старт QGroundControl")
            processes.append(start_process([expanded_qgc_path], cwd=str(PROJECT_ROOT)))
            print(
                "В QGroundControl отключите AutoConnect UDP и создайте Comm Link UDP "
                f"на 127.0.0.1:{gateway_gcs_client_port}"
            )
        else:
            print("QGroundControl не задан в конфиге, пропускаю запуск.")

        print("Стенд запущен. Нажмите Ctrl+C для остановки.")
        while True:
            time.sleep(1)
            for process in processes:
                if process.poll() is not None:
                    print(f"Процесс завершился раньше времени: pid={process.pid}")
                    return 1
    except KeyboardInterrupt:
        print("\nОстановка стенда")
        return 0
    finally:
        for process in reversed(processes):
            terminate_process(process)


if __name__ == "__main__":
    sys.exit(main())
