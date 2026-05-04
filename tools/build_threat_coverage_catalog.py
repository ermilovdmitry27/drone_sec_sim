from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from threat_coverage import build_catalog_rows, load_source_rows, write_catalog


def main() -> None:
    rows = build_catalog_rows(load_source_rows())
    write_catalog(rows)
    print(f"catalog_rows={len(rows)}")


if __name__ == "__main__":
    main()
