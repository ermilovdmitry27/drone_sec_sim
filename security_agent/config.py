from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping


@dataclass
class GatewayControl:
    blocked_endpoints: set[str] = field(default_factory=set)
    lockdown: bool = False

    def block_endpoint(self, endpoint: str) -> None:
        self.blocked_endpoints.add(endpoint)

    def enable_lockdown(self) -> None:
        self.lockdown = True

    def is_blocked(self, endpoint: str) -> bool:
        return endpoint in self.blocked_endpoints


@dataclass
class GatewaySettings:
    api_upstream_host: str = "0.0.0.0"
    api_upstream_port: int = 14540
    api_client_host: str = "0.0.0.0"
    api_client_port: int = 14541
    gcs_upstream_host: str = "0.0.0.0"
    gcs_upstream_port: int = 14550
    gcs_client_host: str = "0.0.0.0"
    gcs_client_port: int = 14552
    report_interval_s: float = 5.0
    client_ttl_s: float = 30.0
    block_param_writes: bool = False
    block_mission_writes: bool = False
    block_serial_control: bool = False
    blocked_command_ids: tuple[int, ...] = ()
    authorized_client_hosts: tuple[str, ...] = ("127.0.0.1",)
    encryption_key_hex: str = ""
    require_encrypted_clients: bool = False
    operator_token_hashes: Mapping[str, str] = field(default_factory=dict)
    require_operator_auth: bool = False

    @property
    def client_system_address(self) -> str:
        return f"udpout://127.0.0.1:{self.api_client_port}"

    @property
    def qgc_manual_link_host(self) -> str:
        return "127.0.0.1"


@dataclass
class SecuritySettings:
    param_poll_interval_s: float = 5.0
    mission_poll_interval_s: float = 5.0
    critical_params: tuple[str, ...] = (
        "COM_OBL_RC_ACT",
        "NAV_RCL_ACT",
        "GF_ACTION",
        "GF_MAX_HOR_DIST",
        "RTL_RETURN_ALT",
        "MPC_XY_CRUISE",
    )
    mission_hash_empty: str = field(default="empty")
