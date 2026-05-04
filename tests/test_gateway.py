from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from security_agent.config import GatewaySettings
from security_agent.gateway import AUTHENTICATED_DATAGRAM_MAGIC, AES_GCM_NONCE_BYTES, MavlinkGateway


class MavlinkGatewayTest(unittest.TestCase):
    def test_blocking_policy_respects_gateway_settings(self) -> None:
        async def run_case() -> None:
            gateway = MavlinkGateway(
                GatewaySettings(
                    block_param_writes=True,
                    block_mission_writes=True,
                    block_serial_control=True,
                    blocked_command_ids=(400,),
                ),
                asyncio.Queue(),
            )

            self.assertTrue(gateway._should_block({"category": "param_write"}))
            self.assertTrue(gateway._should_block({"category": "mission_write"}))
            self.assertTrue(gateway._should_block({"category": "serial_control"}))
            self.assertTrue(gateway._should_block({"category": "command", "command_id": 400}))
            self.assertFalse(gateway._should_block({"category": "command", "command_id": 176}))

        asyncio.run(run_case())

    def test_access_policy_blocks_unauthorized_host(self) -> None:
        async def run_case() -> None:
            gateway = MavlinkGateway(
                GatewaySettings(authorized_client_hosts=("127.0.0.1",)),
                asyncio.Queue(),
            )

            blocked, reason = gateway._policy_decision(
                "192.0.2.10:14541",
                ("192.0.2.10", 14541),
                encrypted=False,
                crypto_error="",
            )

            self.assertTrue(blocked)
            self.assertEqual(reason, "unauthorized_host")

        asyncio.run(run_case())

    def test_requires_encrypted_clients_when_configured(self) -> None:
        async def run_case() -> None:
            gateway = MavlinkGateway(
                GatewaySettings(
                    authorized_client_hosts=("127.0.0.1",),
                    encryption_key_hex="00" * 32,
                    require_encrypted_clients=True,
                ),
                asyncio.Queue(),
            )

            blocked, reason = gateway._policy_decision(
                "127.0.0.1:14541",
                ("127.0.0.1", 14541),
                encrypted=False,
                crypto_error="",
            )

            self.assertTrue(blocked)
            self.assertEqual(reason, "encryption_required")

        asyncio.run(run_case())

    def test_encrypts_and_decrypts_client_datagrams(self) -> None:
        async def run_case() -> None:
            gateway = MavlinkGateway(
                GatewaySettings(encryption_key_hex="11" * 32),
                asyncio.Queue(),
            )
            plaintext = b"\xfe\x00\x01\x01\x01\x0b\x00\x00"

            ciphertext = gateway._wrap_server_datagram("api", ("127.0.0.1", 14541), plaintext)
            self.assertEqual(ciphertext, plaintext)

            gateway.encrypted_client_endpoints["api"].add(("127.0.0.1", 14541))
            ciphertext = gateway._wrap_server_datagram("api", ("127.0.0.1", 14541), plaintext)
            decrypted, encrypted, operator_id, error = gateway._unwrap_client_datagram(ciphertext)

            self.assertTrue(encrypted)
            self.assertIsNone(operator_id)
            self.assertEqual(error, "")
            self.assertEqual(decrypted, plaintext)

        asyncio.run(run_case())

    def test_authenticated_datagram_accepts_valid_operator_token(self) -> None:
        async def run_case() -> None:
            token = "secret-token"
            gateway = MavlinkGateway(
                GatewaySettings(
                    encryption_key_hex="22" * 32,
                    require_operator_auth=True,
                    operator_token_hashes={
                        "operator-1": hashlib.sha256(token.encode("utf-8")).hexdigest(),
                    },
                ),
                asyncio.Queue(),
            )
            payload = b"\xfe\x00\x01\x01\x01\x0b\x00\x00"
            datagram = authenticated_datagram("22" * 32, "operator-1", token, payload)

            decrypted, encrypted, operator_id, error = gateway._unwrap_client_datagram(datagram)

            self.assertTrue(encrypted)
            self.assertEqual(operator_id, "operator-1")
            self.assertEqual(error, "")
            self.assertEqual(decrypted, payload)

        asyncio.run(run_case())

    def test_authenticated_datagram_rejects_invalid_operator_token(self) -> None:
        async def run_case() -> None:
            gateway = MavlinkGateway(
                GatewaySettings(
                    encryption_key_hex="33" * 32,
                    require_operator_auth=True,
                    operator_token_hashes={
                        "operator-1": hashlib.sha256(b"expected").hexdigest(),
                    },
                ),
                asyncio.Queue(),
            )
            datagram = authenticated_datagram("33" * 32, "operator-1", "wrong", b"payload")

            decrypted, encrypted, operator_id, error = gateway._unwrap_client_datagram(datagram)

            self.assertEqual(decrypted, b"")
            self.assertTrue(encrypted)
            self.assertIsNone(operator_id)
            self.assertEqual(error, "operator_auth_failed")

        asyncio.run(run_case())


def authenticated_datagram(key_hex: str, operator_id: str, token: str, payload: bytes) -> bytes:
    aesgcm = AESGCM(bytes.fromhex(key_hex))
    nonce = os.urandom(AES_GCM_NONCE_BYTES)
    envelope = {
        "operator_id": operator_id,
        "token": token,
        "payload_b64": base64.b64encode(payload).decode("ascii"),
    }
    plaintext = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    return AUTHENTICATED_DATAGRAM_MAGIC + nonce + aesgcm.encrypt(
        nonce,
        plaintext,
        AUTHENTICATED_DATAGRAM_MAGIC,
    )


if __name__ == "__main__":
    unittest.main()
