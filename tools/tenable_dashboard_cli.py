#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mva_engine.tenable_dashboards import (  # noqa: E402
    build_adhoc_dashboard,
    build_monthly_comparison,
    MonthlySnapshot,
    load_monthly_snapshot,
)
from mva_engine.tenable_normalizer import load_findings  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Build MVA dashboard data from scanner CSV exports.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    adhoc = subparsers.add_parser("adhoc", help="Build a simple adhoc dashboard from one scanner CSV.")
    adhoc.add_argument("csv", help="Tenable.sc, Tenable.io, Qualys, or supported scanner CSV path")
    adhoc.add_argument("--output", default="output/dashboard_json/adhoc_dashboard.json", help="Output JSON path")

    monthly = subparsers.add_parser("monthly", help="Build monthly comparison dashboards from two or more scanner CSVs.")
    monthly.add_argument(
        "--snapshot",
        action="append",
        required=True,
        help='Monthly snapshot in the form "Month YYYY=/path/to/export.csv". Provide at least two.',
    )
    monthly.add_argument(
        "--approach",
        choices=("auto", "same-source", "mixed-tenable"),
        default="auto",
        help="auto accepts any supported normalized source, same-source requires one scanner/export family, mixed-tenable allows Tenable.sc and Tenable.io month files together.",
    )
    monthly.add_argument("--output", default="output/dashboard_json/monthly_dashboard.json", help="Output JSON path")

    args = parser.parse_args()

    if args.command == "adhoc":
        findings = load_findings(args.csv)
        dashboard = build_adhoc_dashboard(findings)
        write_json(args.output, dashboard)
        return 0

    if args.command == "monthly":
        snapshots = [parse_snapshot_arg(snapshot) for snapshot in args.snapshot]
        validate_monthly_approach(snapshots, args.approach)
        dashboard = build_monthly_comparison(snapshots)
        write_json(args.output, dashboard)
        return 0

    return 1


def parse_snapshot_arg(value: str):
    if "=" not in value:
        raise SystemExit(f'Invalid --snapshot "{value}". Use "Month YYYY=/path/to/export.csv".')
    month, path = value.split("=", 1)
    return load_monthly_snapshot(path.strip(), month=month.strip())


def validate_monthly_approach(snapshots: list[MonthlySnapshot], approach: str) -> None:
    if approach == "auto":
        return

    sources = {
        finding.source_tool
        for snapshot in snapshots
        for finding in snapshot.findings
    }
    if approach == "same-source" and len(sources) > 1:
        raise SystemExit(
            "same-source monthly comparison requires all month files to come from the same detected source. "
            f"Detected: {', '.join(sorted(sources))}."
        )

    if approach == "mixed-tenable":
        invalid_sources = sources - {"tenable_sc", "tenable_io"}
        if invalid_sources:
            raise SystemExit(
                "mixed-tenable monthly comparison only accepts Tenable.sc and Tenable.io files. "
                f"Invalid detected source(s): {', '.join(sorted(invalid_sources))}."
            )


def write_json(output_path: str | Path, payload: dict[str, object]) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(path)


if __name__ == "__main__":
    raise SystemExit(main())
