from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify SHA-256 hash-chain fields in JSONL audit logs")
    parser.add_argument("paths", nargs="+", help="JSONL audit log paths to verify")
    return parser.parse_args()


def record_hash(record: dict[str, Any]) -> str:
    canonical = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_path(path: Path) -> list[str]:
    errors: list[str] = []
    previous_hash = None

    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"{path}:{line_no}: invalid JSON: {exc}")
                continue

            actual_hash = record.pop("audit_hash", None)
            actual_previous = record.get("audit_prev_hash")
            expected_hash = record_hash(record)

            if actual_previous != previous_hash:
                errors.append(
                    f"{path}:{line_no}: audit_prev_hash mismatch "
                    f"expected={previous_hash!r} actual={actual_previous!r}"
                )
            if actual_hash != expected_hash:
                errors.append(
                    f"{path}:{line_no}: audit_hash mismatch "
                    f"expected={expected_hash!r} actual={actual_hash!r}"
                )
            previous_hash = actual_hash

    return errors


def main() -> int:
    args = parse_args()
    errors: list[str] = []
    for raw_path in args.paths:
        path = Path(raw_path)
        if not path.exists():
            errors.append(f"{path}: file does not exist")
            continue
        errors.extend(verify_path(path))

    if errors:
        for error in errors:
            print(error)
        return 1

    print(f"verified={len(args.paths)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
