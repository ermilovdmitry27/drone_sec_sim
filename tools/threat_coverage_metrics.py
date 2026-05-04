#!/usr/bin/env python3
"""
Calculate threat coverage metrics from threat coverage catalog and test results.

Usage:
    python tools/threat_coverage_metrics.py
    python tools/threat_coverage_metrics.py --catalog scenarios/threat_coverage_catalog.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

DEFAULT_CATALOG = Path(__file__).parent.parent / "scenarios" / "threat_coverage_catalog.json"
DEFAULT_RUN_LOG = Path(__file__).parent.parent / "logs" / "threat_coverage_all" / "threat_coverage.jsonl"


def load_catalog(catalog_path: Path) -> list[dict]:
    """Load threat coverage catalog."""
    if not catalog_path.exists():
        print(f"Catalog not found: {catalog_path}")
        sys.exit(1)
    return json.loads(catalog_path.read_text())


def load_run_results(run_log_path: Path) -> set[str]:
    """Load threat IDs from a completed run log."""
    threat_ids = set()
    if not run_log_path.exists():
        return threat_ids
    for line in run_log_path.read_text().splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get("type") == "threat_coverage":
            threat_ids.add(record.get("threat_id", ""))
    return threat_ids


def calculate_metrics(catalog: list[dict], covered_ids: set[str]) -> dict:
    """Calculate coverage metrics."""
    total = len(catalog)
    covered = len(covered_ids)
    percentage = (covered / total * 100) if total > 0 else 0.0

    # Group by category
    by_category: dict[str, dict] = {}
    for entry in catalog:
        category = entry.get("asset_group_name", "unknown")
        if category not in by_category:
            by_category[category] = {"total": 0, "covered": 0}
        by_category[category]["total"] += 1
        if entry.get("threat_id") in covered_ids:
            by_category[category]["covered"] += 1

    return {
        "total_threats": total,
        "covered_threats": covered,
        "coverage_percentage": round(percentage, 1),
        "by_category": by_category,
    }


def print_metrics(metrics: dict) -> None:
    """Print metrics in human-readable format."""
    print("=" * 60)
    print("THREAT COVERAGE METRICS")
    print("=" * 60)
    print(f"Total threats in catalog: {metrics['total_threats']}")
    print(f"Covered threats: {metrics['covered_threats']}")
    print(f"Coverage: {metrics['coverage_percentage']}%")
    print()
    print("Coverage by category:")
    print("-" * 40)
    for category, data in sorted(metrics["by_category"].items()):
        pct = (data["covered"] / data["total"] * 100) if data["total"] > 0 else 0.0
        print(f"  {category:<30} {data['covered']:>3}/{data['total']:<3} ({pct:5.1f}%)")
    print("=" * 60)


def save_metrics_json(metrics: dict, output_path: Path) -> None:
    """Save metrics as JSON for CI consumption."""
    output_path.write_text(json.dumps(metrics, indent=2))
    print(f"\nMetrics saved to: {output_path}")


if __name__ == "__main__":
    catalog_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_CATALOG
    run_log_path = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_RUN_LOG

    catalog = load_catalog(catalog_path)
    covered_ids = load_run_results(run_log_path)

    metrics = calculate_metrics(catalog, covered_ids)
    print_metrics(metrics)

    # Save metrics for CI
    output_dir = Path(__file__).parent.parent / "logs"
    output_dir.mkdir(exist_ok=True)
    save_metrics_json(metrics, output_dir / "threat_coverage_metrics.json")

    # Exit with error if coverage is below threshold
    if metrics["coverage_percentage"] < 50.0:
        print("\nWarning: Coverage is below 50%!")
        sys.exit(1)
