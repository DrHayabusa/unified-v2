#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mva_engine.tenable_dashboards import build_adhoc_dashboard, build_monthly_comparison, load_monthly_snapshot
from mva_engine.tenable_normalizer import calculate_patch_priority, detect_source, load_findings
from tools.generate_crowdstrike_samples import REMEDIATION_ASSET_HEADERS, VULNERABILITY_HEADERS


CS_DIR = ROOT / "samples" / "crowdstrike_100_row"
VALIDATION_DIR = ROOT / "output" / "validation"


@dataclass
class ReleaseValidator:
    checks: list[dict[str, object]] = field(default_factory=list)

    def check(self, label: str, condition: bool, actual: object = None) -> None:
        self.checks.append({"label": label, "passed": bool(condition), "actual": actual})

    @property
    def passed(self) -> int:
        return sum(1 for check in self.checks if check["passed"])

    @property
    def failed(self) -> list[dict[str, object]]:
        return [check for check in self.checks if not check["passed"]]


def main() -> int:
    started = time.perf_counter()
    validator = ReleaseValidator()
    validate_crowdstrike_samples(validator)
    validate_priority_matrix(validator)
    validate_monthly_dashboard(validator)
    validate_existing_sources(validator)
    performance = validate_80k_rows(validator)

    VALIDATION_DIR.mkdir(parents=True, exist_ok=True)
    elapsed = round(time.perf_counter() - started, 3)
    summary = {
        "status": "PASS" if not validator.failed else "FAIL",
        "checks_passed": validator.passed,
        "checks_failed": len(validator.failed),
        "checks_total": len(validator.checks),
        "elapsed_seconds": elapsed,
        "performance_80000_rows": performance,
        "failures": validator.failed,
    }
    (VALIDATION_DIR / "release_validation.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (VALIDATION_DIR / "RELEASE_VALIDATION.md").write_text(render_markdown(summary), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 1 if validator.failed else 0


def validate_crowdstrike_samples(validator: ReleaseValidator) -> None:
    detailed_files = {
        "crowdstrike_vulnerabilities_april_2026_100plus.csv": (110, "crowdstrike_vulnerabilities"),
        "crowdstrike_vulnerabilities_may_2026_100plus.csv": (130, "crowdstrike_vulnerabilities"),
        "crowdstrike_vulnerabilities_june_2026_100plus.csv": (135, "crowdstrike_vulnerabilities"),
        "crowdstrike_vulnerabilities_july_2026_100plus.csv": (130, "crowdstrike_vulnerabilities"),
        "crowdstrike_vulnerability_per_asset_july_2026_100plus.csv": (120, "crowdstrike_vulnerabilities"),
    }
    for filename, (expected_rows, expected_source) in detailed_files.items():
        validate_raw_file(validator, CS_DIR / filename, VULNERABILITY_HEADERS, expected_rows, expected_source)

    validate_raw_file(
        validator,
        CS_DIR / "crowdstrike_remediation_per_assets_july_2026_100plus.csv",
        REMEDIATION_ASSET_HEADERS,
        100,
        "crowdstrike_remediation_assets",
    )

    detailed = load_findings(CS_DIR / "crowdstrike_vulnerabilities_july_2026_100plus.csv")
    aggregate = load_findings(CS_DIR / "crowdstrike_remediation_per_assets_july_2026_100plus.csv")
    validator.check("Detailed export excludes closed rows", len(detailed) == 120, len(detailed))
    validator.check("Detailed export maps exploit availability", sum(f.exploit_available for f in detailed) == 47)
    validator.check("Detailed export maps CISA KEV", sum(f.cisa_kev for f in detailed) == 11)
    validator.check("Detailed export maps internet exposure", sum(f.internet_exposed for f in detailed) == 24)
    validator.check("Aggregate export preserves weighted Count", sum(f.record_count for f in aggregate) == 542)
    validator.check("Aggregate export maps 45 distinct assets", len({f.dns_name for f in aggregate}) == 45)
    validator.check("All exposure scores are within 0-1000", all(0 <= f.asset_exposure <= 1000 for f in detailed + aggregate))
    validator.check("All normalized findings have P1-P4", all(f.patch_priority in {"P1", "P2", "P3", "P4"} for f in detailed + aggregate))


def validate_raw_file(
    validator: ReleaseValidator,
    path: Path,
    expected_headers: list[str],
    expected_rows: int,
    expected_source: str,
) -> None:
    validator.check(f"Sample exists: {path.name}", path.exists())
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        actual_headers = next(reader)
        rows = list(reader)
    validator.check(f"Header count: {path.name}", len(actual_headers) == len(expected_headers), len(actual_headers))
    for index, expected_header in enumerate(expected_headers):
        actual = actual_headers[index] if index < len(actual_headers) else None
        validator.check(f"{path.name} header {index + 1}: {expected_header}", actual == expected_header, actual)
    validator.check(f"Raw row count: {path.name}", len(rows) == expected_rows, len(rows))
    validator.check(f"Source detection: {path.name}", detect_source(actual_headers) == expected_source, detect_source(actual_headers))


def validate_priority_matrix(validator: ReleaseValidator) -> None:
    matrix = {
        ("Critical", True): "P1",
        ("High", True): "P1",
        ("Medium", True): "P2",
        ("Low", True): "P2",
        ("Critical", False): "P2",
        ("High", False): "P2",
        ("Medium", False): "P3",
        ("Low", False): "P4",
    }
    for inputs, expected in matrix.items():
        actual = calculate_patch_priority(*inputs)
        validator.check(f"Priority matrix {inputs[0]} exploit={inputs[1]}", actual == expected, actual)


def validate_monthly_dashboard(validator: ReleaseValidator) -> None:
    snapshots = [
        load_monthly_snapshot(CS_DIR / f"crowdstrike_vulnerabilities_{month}_2026_100plus.csv", f"{month.title()} 2026")
        for month in ("april", "may", "june", "july")
    ]
    dashboard = build_monthly_comparison(snapshots)
    total_open = dashboard["total_open_vulnerabilities"]
    patched = dashboard["total_vulnerabilities_patched_last_month"]
    priorities = dashboard["total_open_by_patch_priority"]
    insights = dashboard["crowdstrike_insights"]

    validator.check("Monthly current open", total_open["total_open"] == 120, total_open["total_open"])
    validator.check("Monthly new findings", total_open["new_vulnerabilities"] == 20, total_open["new_vulnerabilities"])
    validator.check("Monthly not closed", total_open["not_closed_from_previous_months"] == 100)
    validator.check("Monthly total-open identity", total_open["new_vulnerabilities"] + total_open["not_closed_from_previous_months"] == total_open["total_open"])
    validator.check("Discovery trend", [row["discovered_count"] for row in dashboard["trend_discovered_last_3_months"]] == [30, 25, 20])
    validator.check("Patched trend", [row["remediated_count"] for row in dashboard["trend_remediated_last_3_months"]] == [20, 20, 25])
    validator.check("Latest patched count", patched["patched_count"] == 25, patched["patched_count"])
    validator.check("Latest patched formula", patched["previous_month_open"] + patched["new_vulnerabilities_identified_this_month"] - patched["current_month_open"] == patched["patched_count"])
    validator.check("Priority distribution", priorities == {"P1": 24, "P2": 59, "P3": 18, "P4": 19}, priorities)
    validator.check("Priority distribution totals current open", sum(priorities.values()) == 120)
    validator.check("CrowdStrike exploit insight", insights["exploit_available"] == 47)
    validator.check("CrowdStrike KEV insight", insights["cisa_kev"] == 11)
    validator.check("CrowdStrike internet-exposed insight", insights["internet_exposed"] == 24)
    validator.check("CrowdStrike critical-assets insight", insights["critical_assets"] == 12)

    for priority, buckets in dashboard["total_open_by_age_and_patch_priority"].items():
        values = [buckets[">7 days"], buckets[">30 days"], buckets[">60 days"], buckets[">180 days (6+ months)"]]
        validator.check(f"{priority} age buckets are cumulative", values == sorted(values, reverse=True), values)


def validate_existing_sources(validator: ReleaseValidator) -> None:
    regression_samples = [
        ("Tenable.sc", ROOT / "samples/tenable_100_row/tenable_sc_july_2026_100plus.csv", "tenable_sc"),
        ("Tenable.io", ROOT / "samples/tenable_100_row/tenable_io_july_2026_100plus.csv", "tenable_io"),
        ("Qualys monthly", ROOT / "samples/qualys_100_row/qualys_monthly_july_2026_100plus.csv", "qualys_monthly"),
        ("Qualys adhoc", ROOT / "samples/qualys_100_row/qualys_adhoc_july_2026_100plus.csv", "qualys_adhoc"),
    ]
    for label, path, source in regression_samples:
        findings = load_findings(path)
        validator.check(f"{label} regression sample loads", len(findings) >= 100, len(findings))
        validator.check(f"{label} source mapping remains intact", findings[0].source_tool == source, findings[0].source_tool)
        validator.check(f"{label} report priorities remain valid", all(f.patch_priority in {"P1", "P2", "P3", "P4"} for f in findings))
    io_findings = load_findings(regression_samples[1][1])
    validator.check("Tenable.io native vulnerability age is retained", all(f.vulnerability_age_days is not None for f in io_findings))


def validate_80k_rows(validator: ReleaseValidator) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="mva-release-") as temp_dir:
        path = Path(temp_dir) / "crowdstrike_80000_rows.csv"
        write_80k_csv(path)
        file_size_mb = round(path.stat().st_size / 1024 / 1024, 2)
        load_started = time.perf_counter()
        findings = load_findings(path)
        load_seconds = round(time.perf_counter() - load_started, 3)
        dashboard_started = time.perf_counter()
        dashboard = build_adhoc_dashboard(findings)
        dashboard_seconds = round(time.perf_counter() - dashboard_started, 3)

    validator.check("80,000-row file normalizes every row", len(findings) == 80_000, len(findings))
    validator.check("80,000-row dashboard total", dashboard["total_vulnerabilities"] == 80_000, dashboard["total_vulnerabilities"])
    validator.check("80,000-row severity totals", sum(dashboard["severity_counts"].values()) == 80_000)
    validator.check("80,000-row priority totals", sum(dashboard["patch_priority_counts"].values()) == 80_000)
    validator.check("80,000-row distinct assets", dashboard["distinct_assets"] == 2_000, dashboard["distinct_assets"])
    validator.check("80,000-row top assets generated", len(dashboard["top_10_affected_assets"]) == 10)
    return {
        "rows": 80_000,
        "csv_size_mb": file_size_mb,
        "normalization_seconds": load_seconds,
        "dashboard_seconds": dashboard_seconds,
        "total_seconds": round(load_seconds + dashboard_seconds, 3),
    }


def write_80k_csv(path: Path) -> None:
    severities = ("Critical", "High", "Medium", "Low")
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=VULNERABILITY_HEADERS)
        writer.writeheader()
        for index in range(80_000):
            host_index = index % 2_000
            severity = severities[index % 4]
            writer.writerow(
                {
                    "Hostname": f"load-asset-{host_index:04d}.corp.example",
                    "LocalIP": f"10.{40 + host_index // 256}.{host_index % 256}.{20 + index % 200}",
                    "HostType": "Server",
                    "OSVersion": "Windows Server 2022",
                    "Product": "Enterprise Application",
                    "CVE ID": f"CVE-2026-{10000 + index}",
                    "CVE Description": "Synthetic release load-test vulnerability",
                    "Status": "Open",
                    "Severity": severity,
                    "Created Date": "2026-01-15",
                    "Base Score": {"Critical": "9.8", "High": "8.1", "Medium": "6.4", "Low": "3.7"}[severity],
                    "CVSS Version": "3.1",
                    "References": "https://nvd.nist.gov/",
                    "Recommended Remediations": "Apply the vendor security update.",
                    "Remediation Links": "https://nvd.nist.gov/",
                    "Host ID": f"HOST-{host_index:04d}",
                    "Exploit status label": "Exploit available" if index % 3 == 0 else "No known exploit",
                    "Platform": "Windows",
                    "ExPRT Rating": "Critical" if index % 5 == 0 else "Medium",
                    "Is Suppressed": "No",
                    "Is CISA KEV": "Yes" if index % 17 == 0 else "No",
                    "Internet exposure": "Yes" if index % 7 == 0 else "No",
                    "Vulnerability ID": f"CS-LOAD-{index:08d}",
                    "Last Scan Time": "2026-07-31T02:00:00Z",
                    "Asset Criticality": "Critical" if host_index % 10 == 0 else "Medium",
                    "Patch Publication Date": "2026-01-10",
                    "Instance state": "Active",
                }
            )


def render_markdown(summary: dict[str, object]) -> str:
    performance = summary["performance_80000_rows"]
    return f"""# MVA Unified Agent Release Validation

Status: **{summary['status']}**

| Validation | Result |
|---|---:|
| Checks passed | {summary['checks_passed']} / {summary['checks_total']} |
| Checks failed | {summary['checks_failed']} |
| Full validation time | {summary['elapsed_seconds']} seconds |
| 80,000-row CSV size | {performance['csv_size_mb']} MB |
| 80,000-row normalization | {performance['normalization_seconds']} seconds |
| 80,000-row dashboard build | {performance['dashboard_seconds']} seconds |

The suite validates every supplied CrowdStrike raw field, all three CrowdStrike export selections, the approved priority matrix, exact four-month movement formulas, age buckets, CrowdStrike exposure signals, and SC/IO/Qualys regressions.
"""


if __name__ == "__main__":
    raise SystemExit(main())
