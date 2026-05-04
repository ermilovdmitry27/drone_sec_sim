from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"DSEC1"
AUTH_MAGIC = b"DSEC2"
NONCE_BYTES = 12


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Encrypt or decrypt one MAVLink UDP datagram with AES-GCM")
    parser.add_argument("mode", choices=["encrypt", "decrypt"])
    parser.add_argument("--key-hex", required=True, help="AES key as 32, 48 or 64 hex characters")
    parser.add_argument("--input", required=True, help="Input datagram file")
    parser.add_argument("--output", required=True, help="Output datagram file")
    parser.add_argument("--operator-id", help="Operator id for authenticated DSEC2 datagrams")
    parser.add_argument("--operator-token", help="Operator token for authenticated DSEC2 datagrams")
    return parser.parse_args()


def aesgcm_from_hex(key_hex: str) -> AESGCM:
    key = bytes.fromhex(key_hex)
    if len(key) not in {16, 24, 32}:
        raise ValueError("key must be 16, 24 or 32 bytes after hex decoding")
    return AESGCM(key)


def encrypt(
    aesgcm: AESGCM,
    payload: bytes,
    operator_id: str | None = None,
    operator_token: str | None = None,
) -> bytes:
    nonce = os.urandom(NONCE_BYTES)
    if operator_id or operator_token:
        if not operator_id or not operator_token:
            raise ValueError("--operator-id and --operator-token must be used together")
        envelope = {
            "operator_id": operator_id,
            "token": operator_token,
            "payload_b64": base64.b64encode(payload).decode("ascii"),
        }
        plaintext = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        return AUTH_MAGIC + nonce + aesgcm.encrypt(nonce, plaintext, AUTH_MAGIC)
    return MAGIC + nonce + aesgcm.encrypt(nonce, payload, MAGIC)


def decrypt(aesgcm: AESGCM, payload: bytes) -> bytes:
    if not payload.startswith(MAGIC):
        if payload.startswith(AUTH_MAGIC):
            magic = AUTH_MAGIC
        else:
            raise ValueError("encrypted datagram magic is missing")
    else:
        magic = MAGIC
    header_len = len(magic) + NONCE_BYTES
    if len(payload) <= header_len:
        raise ValueError("encrypted datagram is truncated")
    nonce = payload[len(magic) : header_len]
    ciphertext = payload[header_len:]
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, magic)
    except InvalidTag as exc:
        raise ValueError("encrypted datagram authentication failed") from exc
    if magic == AUTH_MAGIC:
        envelope = json.loads(plaintext.decode("utf-8"))
        return base64.b64decode(str(envelope["payload_b64"]), validate=True)
    return plaintext


def main() -> int:
    args = parse_args()
    aesgcm = aesgcm_from_hex(args.key_hex)
    payload = Path(args.input).read_bytes()
    output = (
        encrypt(aesgcm, payload, operator_id=args.operator_id, operator_token=args.operator_token)
        if args.mode == "encrypt"
        else decrypt(aesgcm, payload)
    )
    Path(args.output).write_bytes(output)
    print(args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
