from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field
from typing import Any

from .config import GatewaySettings
from .models import CommandEvent, LinkMetricsEvent, now_ts

MAVLINK_V1_MAGIC = 0xFE
MAVLINK_V2_MAGIC = 0xFD

MESSAGE_NAMES = {
    11: "SET_MODE",
    23: "PARAM_SET",
    38: "MISSION_WRITE_PARTIAL_LIST",
    39: "MISSION_ITEM",
    44: "MISSION_COUNT",
    45: "MISSION_CLEAR_ALL",
    73: "MISSION_ITEM_INT",
    75: "COMMAND_INT",
    76: "COMMAND_LONG",
    126: "SERIAL_CONTROL",
}

MISSION_MESSAGE_IDS = {38, 39, 44, 45, 73}
PARAM_MESSAGE_IDS = {23}

COMMAND_NAMES = {
    20: "NAV_RETURN_TO_LAUNCH",
    21: "NAV_LAND",
    22: "NAV_TAKEOFF",
    176: "DO_SET_MODE",
    300: "MISSION_START",
    400: "COMPONENT_ARM_DISARM",
}

SERIAL_CONTROL_DEVICE_NAMES = {
    0: "SERIAL_CONTROL_DEV_TELEM1",
    1: "SERIAL_CONTROL_DEV_TELEM2",
    2: "SERIAL_CONTROL_DEV_GPS1",
    3: "SERIAL_CONTROL_DEV_GPS2",
    10: "SERIAL_CONTROL_DEV_SHELL",
    100: "SERIAL_CONTROL_SERIAL0",
    101: "SERIAL_CONTROL_SERIAL1",
    102: "SERIAL_CONTROL_SERIAL2",
    103: "SERIAL_CONTROL_SERIAL3",
    104: "SERIAL_CONTROL_SERIAL4",
    105: "SERIAL_CONTROL_SERIAL5",
    106: "SERIAL_CONTROL_SERIAL6",
    107: "SERIAL_CONTROL_SERIAL7",
    108: "SERIAL_CONTROL_SERIAL8",
    109: "SERIAL_CONTROL_SERIAL9",
}


@dataclass
class ChannelStats:
    packets: int = 0
    bytes_total: int = 0
    messages: int = 0
    lost_messages: int = 0
    last_rx_ts: float = field(default_factory=now_ts)
    sources: set[str] = field(default_factory=set)


class _PortProtocol(asyncio.DatagramProtocol):
    def __init__(self, owner: "MavlinkGateway", channel: str) -> None:
        self.owner = owner
        self.channel = channel
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        self.owner.register_transport(self.channel, self.transport)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        asyncio.create_task(self.owner.handle_datagram(self.channel, data, addr))


class MavlinkGateway:
    def __init__(self, settings: GatewaySettings, event_queue: asyncio.Queue[object]) -> None:
        self.settings = settings
        self.event_queue = event_queue
        self.loop = asyncio.get_running_loop()
        self.transports: dict[str, asyncio.DatagramTransport] = {}
        self.protocols: list[_PortProtocol] = []
        self.px4_endpoints: dict[str, tuple[str, int] | None] = {
            "api": None,
            "gcs": None,
        }
        self.client_endpoints: dict[str, dict[tuple[str, int], float]] = {
            "api": {},
            "gcs": {},
        }
        self.channel_stats: dict[str, ChannelStats] = {
            "api_px4_inbound": ChannelStats(),
            "api_client_inbound": ChannelStats(),
            "gcs_px4_inbound": ChannelStats(),
            "gcs_client_inbound": ChannelStats(),
        }
        self.last_seq: dict[tuple[str, int, int], int] = {}
        self.report_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        await self._bind_listener(
            "api_px4_inbound",
            self.settings.api_upstream_host,
            self.settings.api_upstream_port,
        )
        await self._bind_listener(
            "api_client_inbound",
            self.settings.api_client_host,
            self.settings.api_client_port,
        )
        await self._bind_listener(
            "gcs_px4_inbound",
            self.settings.gcs_upstream_host,
            self.settings.gcs_upstream_port,
        )
        self.report_task = asyncio.create_task(self._report_metrics())
        print(
            "MAVLink gateway запущен: "
            f"API PX4->{self.settings.api_upstream_port}, API clients->{self.settings.api_client_port}, "
            f"GCS PX4->{self.settings.gcs_upstream_port}, QGC clients->{self.settings.gcs_client_port}"
        )

    async def stop(self) -> None:
        if self.report_task:
            self.report_task.cancel()
            await asyncio.gather(self.report_task, return_exceptions=True)
        for transport in self.transports.values():
            transport.close()

    def register_transport(self, channel: str, transport: asyncio.DatagramTransport) -> None:
        self.transports[channel] = transport

    async def _bind_listener(self, channel: str, host: str, port: int) -> None:
        protocol = _PortProtocol(self, channel)
        self.protocols.append(protocol)
        await self.loop.create_datagram_endpoint(
            lambda: protocol,
            local_addr=(host, port),
        )

    async def handle_datagram(
        self,
        channel: str,
        data: bytes,
        addr: tuple[str, int],
    ) -> None:
        now = now_ts()
        if channel == "gcs_px4_inbound" and self._is_gcs_client(addr):
            await self._handle_client_datagram("gcs", "gcs_client_inbound", data, addr, now)
            return

        frames = self._parse_frames(data)
        self._update_stats(channel, addr, data, frames, now)

        if channel.endswith("px4_inbound"):
            route = self._route_for_channel(channel)
            self.px4_endpoints[route] = addr
            self._expire_clients(route, now)
            await self._forward_to_clients(route, data)
            return

        route = self._route_for_channel(channel)
        await self._handle_client_datagram(route, channel, data, addr, now)

    def _update_stats(
        self,
        channel: str,
        addr: tuple[str, int],
        data: bytes,
        frames: list[dict[str, Any]],
        now: float,
    ) -> None:
        stats = self.channel_stats[channel]
        stats.packets += 1
        stats.bytes_total += len(data)
        stats.messages += len(frames)
        stats.last_rx_ts = now
        stats.sources.add(f"{addr[0]}:{addr[1]}")

        for frame in frames:
            key = (channel, frame["sysid"], frame["compid"])
            previous = self.last_seq.get(key)
            current = frame["seq"]
            if previous is not None:
                gap = (current - previous) % 256
                if 0 < gap < 128:
                    stats.lost_messages += max(0, gap - 1)
            self.last_seq[key] = current

    async def _report_metrics(self) -> None:
        while True:
            await asyncio.sleep(self.settings.report_interval_s)
            now = now_ts()
            for channel, stats in self.channel_stats.items():
                total = stats.messages + stats.lost_messages
                loss_ratio = stats.lost_messages / total if total else 0.0
                event = LinkMetricsEvent(
                    channel=channel,
                    packets=stats.packets,
                    bytes_total=stats.bytes_total,
                    messages=stats.messages,
                    estimated_loss_ratio=loss_ratio,
                    idle_for_s=max(0.0, now - stats.last_rx_ts),
                    sources=len(stats.sources),
                )
                await self.event_queue.put(event)

    async def _handle_client_datagram(
        self,
        route: str,
        channel: str,
        data: bytes,
        addr: tuple[str, int],
        now: float,
    ) -> None:
        frames = self._parse_frames(data)
        self._update_stats(channel, addr, data, frames, now)

        self.client_endpoints[route][addr] = now
        observations = self._build_command_events(route, addr, frames, now)
        blocked = any(event.blocked for event in observations)
        for event in observations:
            await self.event_queue.put(event)

        if blocked or self.px4_endpoints[route] is None:
            return

        upstream_transport = self.transports.get(self._px4_channel(route))
        if upstream_transport:
            upstream_transport.sendto(data, self.px4_endpoints[route])

    async def _forward_to_clients(self, route: str, data: bytes) -> None:
        if route == "gcs":
            transport = self.transports.get("gcs_px4_inbound")
            if not transport:
                return
            qgc_endpoint = (self.settings.qgc_manual_link_host, self.settings.gcs_client_port)
            transport.sendto(data, qgc_endpoint)
            return

        client_transport = self.transports.get(self._client_channel(route))
        if client_transport:
            for client_addr in self.client_endpoints[route]:
                client_transport.sendto(data, client_addr)

    def _expire_clients(self, route: str, now: float) -> None:
        expired = [
            endpoint
            for endpoint, last_seen in self.client_endpoints[route].items()
            if now - last_seen > self.settings.client_ttl_s
        ]
        for endpoint in expired:
            self.client_endpoints[route].pop(endpoint, None)

    def _build_command_events(
        self,
        route: str,
        addr: tuple[str, int],
        frames: list[dict[str, Any]],
        timestamp: float,
    ) -> list[CommandEvent]:
        events: list[CommandEvent] = []
        endpoint = f"{addr[0]}:{addr[1]}"
        channel_name = "qgc_gateway" if route == "gcs" else "api_gateway"

        for frame in frames:
            parsed = self._interpret_frame(frame)
            if parsed is None:
                continue
            category = parsed["category"]
            blocked = self._should_block(parsed)
            events.append(
                CommandEvent(
                    direction="client_to_px4",
                    channel=channel_name,
                    endpoint=endpoint,
                    message_id=frame["message_id"],
                    message_name=parsed["message_name"],
                    category=category,
                    command_id=parsed.get("command_id"),
                    command_name=parsed.get("command_name"),
                    param_name=parsed.get("param_name"),
                    blocked=blocked,
                    timestamp=timestamp,
                    details=parsed.get("details", {}),
                )
            )

        return events

    def _route_for_channel(self, channel: str) -> str:
        if channel.startswith("gcs_"):
            return "gcs"
        return "api"

    def _is_gcs_client(self, addr: tuple[str, int]) -> bool:
        return addr[1] == self.settings.gcs_client_port

    def _px4_channel(self, route: str) -> str:
        return f"{route}_px4_inbound"

    def _client_channel(self, route: str) -> str:
        return f"{route}_client_inbound"

    def _should_block(self, parsed: dict[str, Any]) -> bool:
        if parsed["category"] == "param_write" and self.settings.block_param_writes:
            return True
        if parsed["category"] == "mission_write" and self.settings.block_mission_writes:
            return True
        if parsed["category"] == "serial_control" and self.settings.block_serial_control:
            return True
        command_id = parsed.get("command_id")
        if command_id is not None and command_id in self.settings.blocked_command_ids:
            return True
        return False

    def _interpret_frame(self, frame: dict[str, Any]) -> dict[str, Any] | None:
        payload = frame["payload"]
        message_id = frame["message_id"]
        message_name = MESSAGE_NAMES.get(message_id, f"MSG_{message_id}")

        if message_id in PARAM_MESSAGE_IDS and len(payload) >= 22:
            raw_name = payload[6:22].split(b"\x00", 1)[0]
            param_name = raw_name.decode("ascii", errors="ignore")
            param_value = struct.unpack_from("<f", payload, 0)[0]
            return {
                "category": "param_write",
                "message_name": message_name,
                "param_name": param_name,
                "details": {"param_value": round(param_value, 4)},
            }

        if message_id in MISSION_MESSAGE_IDS:
            details: dict[str, Any] = {}
            if message_id == 44 and len(payload) >= 2:
                details["count"] = int(struct.unpack_from("<H", payload, 0)[0])
            elif message_id in {39, 73} and len(payload) >= 30:
                details["seq"] = int(struct.unpack_from("<H", payload, 28)[0])
            elif message_id == 38 and len(payload) >= 4:
                details["start_index"] = int(struct.unpack_from("<H", payload, 0)[0])
                details["end_index"] = int(struct.unpack_from("<H", payload, 2)[0])
            return {
                "category": "mission_write",
                "message_name": message_name,
                "details": details,
            }

        if message_id == 126 and len(payload) >= 9:
            device = int(payload[0])
            flags = int(payload[1])
            timeout_ms = int(struct.unpack_from("<H", payload, 2)[0])
            baudrate = int(struct.unpack_from("<I", payload, 4)[0])
            count = int(payload[8])
            device_name = SERIAL_CONTROL_DEVICE_NAMES.get(device, f"SERIAL_CONTROL_DEV_{device}")
            return {
                "category": "serial_control",
                "message_name": message_name,
                "details": {
                    "device": device,
                    "device_name": device_name,
                    "flags": flags,
                    "timeout_ms": timeout_ms,
                    "baudrate": baudrate,
                    "count": count,
                    "shell_device": device == 10,
                },
            }

        if message_id in {75, 76} and len(payload) >= 30:
            command_id = int(struct.unpack_from("<H", payload, 28)[0])
            return {
                "category": "command",
                "message_name": message_name,
                "command_id": command_id,
                "command_name": COMMAND_NAMES.get(command_id, f"MAV_CMD_{command_id}"),
            }

        if message_id == 11 and len(payload) >= 6:
            custom_mode = int(struct.unpack_from("<I", payload, 0)[0])
            base_mode = int(payload[5])
            return {
                "category": "mode_change",
                "message_name": message_name,
                "details": {
                    "custom_mode": custom_mode,
                    "base_mode": base_mode,
                },
            }

        return None

    def _parse_frames(self, data: bytes) -> list[dict[str, Any]]:
        frames: list[dict[str, Any]] = []
        index = 0
        length = len(data)

        while index < length:
            magic = data[index]
            if magic not in {MAVLINK_V1_MAGIC, MAVLINK_V2_MAGIC}:
                index += 1
                continue

            if magic == MAVLINK_V1_MAGIC:
                if index + 6 > length:
                    break
                payload_len = data[index + 1]
                frame_len = 6 + payload_len + 2
                if index + frame_len > length:
                    break
                frames.append(
                    {
                        "seq": data[index + 2],
                        "sysid": data[index + 3],
                        "compid": data[index + 4],
                        "message_id": data[index + 5],
                        "payload": data[index + 6 : index + 6 + payload_len],
                    }
                )
                index += frame_len
                continue

            if index + 10 > length:
                break
            payload_len = data[index + 1]
            incompat_flags = data[index + 2]
            signature_len = 13 if incompat_flags & 0x01 else 0
            frame_len = 10 + payload_len + 2 + signature_len
            if index + frame_len > length:
                break
            message_id = (
                data[index + 7]
                | (data[index + 8] << 8)
                | (data[index + 9] << 16)
            )
            frames.append(
                {
                    "seq": data[index + 4],
                    "sysid": data[index + 5],
                    "compid": data[index + 6],
                    "message_id": message_id,
                    "payload": data[index + 10 : index + 10 + payload_len],
                }
            )
            index += frame_len

        return frames
