from __future__ import annotations

import calendar
from collections import Counter
from dataclasses import dataclass, replace
from datetime import date, datetime
from pathlib import Path
from typing import Iterable

from .tenable_normalizer import (
    AGE_BUCKETS,
    NormalizedFinding,
    age_bucket_flags,
    age_in_days,
    load_findings,
    parse_date,
)


PRIORITIES = ["P1", "P2", "P3", "P4"]
SEVERITIES = ["Critical", "High", "Medium", "Low", "Info", "Unknown"]


@dataclass(frozen=True)
class MonthlySnapshot:
    month: str
    findings: list[NormalizedFinding]
    report_date: date


def build_adhoc_dashboard(findings: Iterable[NormalizedFinding]) -> dict[str, object]:
    rows = list(findings)
    severity_counts = _ordered_weighted_counter(rows, "severity", SEVERITIES)
    priority_counts = _ordered_weighted_counter(rows, "patch_priority", PRIORITIES)
    asset_counts: Counter[str] = Counter()
    product_counts: Counter[str] = Counter()
    remediation_counts: Counter[str] = Counter()
    for finding in rows:
        asset_counts[_asset_label(finding)] += finding.record_count
        if finding.product:
            product_counts[finding.product] += finding.record_count
        if finding.remediation:
            remediation_counts[finding.vulnerability_name or finding.remediation] += finding.record_count

    total = _weighted_total(rows)
    distinct_assets = len({_asset_label(finding) for finding in rows})
    exploit_available = sum(finding.record_count for finding in rows if finding.exploit_available)
    cisa_kev = sum(finding.record_count for finding in rows if finding.cisa_kev)
    internet_exposed = sum(finding.record_count for finding in rows if finding.internet_exposed)
    export_types = sorted({finding.export_type for finding in rows if finding.export_type})

    return {
        "total_vulnerabilities": total,
        "distinct_assets": distinct_assets,
        "exploit_available": exploit_available,
        "cisa_kev": cisa_kev,
        "internet_exposed": internet_exposed,
        "detected_export_types": export_types,
        "severity_counts": severity_counts,
        "patch_priority_counts": priority_counts,
        "top_10_affected_assets": [
            {"asset": asset, "vulnerability_count": count}
            for asset, count in asset_counts.most_common(10)
        ],
        "top_products": [
            {"product": product, "vulnerability_count": count}
            for product, count in product_counts.most_common(10)
        ],
        "top_recommended_remediations": [
            {"remediation": remediation, "vulnerability_count": count}
            for remediation, count in remediation_counts.most_common(10)
        ],
    }


def build_monthly_comparison(snapshots: list[MonthlySnapshot]) -> dict[str, object]:
    if len(snapshots) < 2:
        raise ValueError("Monthly comparison requires at least two monthly snapshots")

    ordered = sorted(snapshots, key=lambda snapshot: snapshot.report_date)
    previous = ordered[-2]
    current = ordered[-1]

    previous_by_key = _dedupe_by_key(previous.findings)
    current_by_key = _dedupe_by_key(current.findings)

    previous_keys = set(previous_by_key)
    current_keys = set(current_by_key)
    all_keys = previous_keys | current_keys
    new_count = sum(
        max(0, current_by_key.get(key, _EMPTY_FINDING).record_count - previous_by_key.get(key, _EMPTY_FINDING).record_count)
        for key in all_keys
    )
    carried_forward_count = sum(
        min(current_by_key[key].record_count, previous_by_key[key].record_count)
        for key in current_keys & previous_keys
    )
    patched_count = sum(
        max(0, previous_by_key.get(key, _EMPTY_FINDING).record_count - current_by_key.get(key, _EMPTY_FINDING).record_count)
        for key in all_keys
    )

    current_findings = list(current_by_key.values())
    previous_total = _weighted_total(previous_by_key.values())
    current_total = _weighted_total(current_by_key.values())
    patched_formula_value = previous_total + new_count - current_total
    crowdstrike_insights = _build_crowdstrike_insights(current_findings)

    dashboard = {
        "trend_discovered_last_3_months": _build_discovery_trend(ordered[-3:]),
        "trend_remediated_last_3_months": _build_remediated_trend(ordered[-4:]),
        "total_open_vulnerabilities": {
            "total_open": current_total,
            "new_vulnerabilities": new_count,
            "not_closed_from_previous_months": carried_forward_count,
        },
        "total_open_by_patch_priority": _ordered_weighted_counter(current_findings, "patch_priority", PRIORITIES),
        "total_open_by_age_and_patch_priority": _build_age_priority_matrix(
            current_findings,
            current.report_date,
        ),
        "total_vulnerabilities_patched_last_month": {
            "previous_month": previous.month,
            "current_month": current.month,
            "previous_month_open": previous_total,
            "new_vulnerabilities_identified_this_month": new_count,
            "current_month_open": current_total,
            "patched_count": max(0, patched_formula_value),
            "patched_count_by_key_diff": patched_count,
            "formula": "previous_month_open + new_vulnerabilities_identified_this_month - current_month_open",
        },
        "uploaded_months": [snapshot.month for snapshot in ordered],
    }
    if crowdstrike_insights:
        dashboard["crowdstrike_insights"] = crowdstrike_insights
    return dashboard


def load_monthly_snapshot(csv_path: str | Path, month: str | None = None) -> MonthlySnapshot:
    findings = load_findings(csv_path)
    report_date = parse_report_month(month) if month else infer_report_date(findings)
    return MonthlySnapshot(
        month=month or report_date.strftime("%B %Y"),
        findings=findings,
        report_date=report_date,
    )


def infer_report_date(findings: Iterable[NormalizedFinding]) -> date:
    observed_dates = [
        parsed.date()
        for finding in findings
        if (parsed := parse_date(finding.last_observed))
    ]
    if observed_dates:
        return max(observed_dates)
    return date.today()


def _build_discovery_trend(snapshots: list[MonthlySnapshot]) -> list[dict[str, object]]:
    trend = []
    for snapshot in snapshots:
        month_start = snapshot.report_date.replace(day=1)
        discovered_count = 0
        for finding in _dedupe_by_key(snapshot.findings).values():
            discovered = parse_date(finding.first_discovered)
            if discovered and discovered.date().replace(day=1) == month_start:
                discovered_count += finding.record_count
        trend.append({"month": snapshot.month, "discovered_count": discovered_count})
    return trend


def _build_remediated_trend(snapshots: list[MonthlySnapshot]) -> list[dict[str, object]]:
    trend = []
    for previous, current in zip(snapshots, snapshots[1:]):
        previous_by_key = _dedupe_by_key(previous.findings)
        current_by_key = _dedupe_by_key(current.findings)
        all_keys = set(previous_by_key) | set(current_by_key)
        trend.append({
            "month": current.month,
            "remediated_count": sum(
                max(0, previous_by_key.get(key, _EMPTY_FINDING).record_count - current_by_key.get(key, _EMPTY_FINDING).record_count)
                for key in all_keys
            ),
        })
    return trend[-3:]


def _build_age_priority_matrix(findings: list[NormalizedFinding], as_of: date) -> dict[str, dict[str, int]]:
    matrix: dict[str, dict[str, int]] = {
        priority: {bucket: 0 for bucket in AGE_BUCKETS}
        for priority in PRIORITIES
    }

    for finding in findings:
        priority = finding.patch_priority if finding.patch_priority in PRIORITIES else "P4"
        flags = age_bucket_flags(age_in_days(finding, as_of=as_of))
        for bucket, is_in_bucket in flags.items():
            if is_in_bucket:
                matrix[priority][bucket] += finding.record_count

    return matrix


def _ordered_counter(values: Iterable[str], order: list[str]) -> dict[str, int]:
    counts = Counter(values)
    return {key: counts.get(key, 0) for key in order}


def _ordered_weighted_counter(
    findings: Iterable[NormalizedFinding],
    attribute: str,
    order: list[str],
) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for finding in findings:
        counts[getattr(finding, attribute)] += finding.record_count
    return {key: counts.get(key, 0) for key in order}


def _dedupe_by_key(findings: Iterable[NormalizedFinding]) -> dict[str, NormalizedFinding]:
    deduped: dict[str, NormalizedFinding] = {}
    for finding in findings:
        existing = deduped.get(finding.finding_key)
        if existing is None:
            deduped[finding.finding_key] = finding
        elif finding.source_tool == "crowdstrike_remediation_assets":
            deduped[finding.finding_key] = replace(
                existing,
                record_count=existing.record_count + finding.record_count,
            )
    return deduped


def _asset_label(finding: NormalizedFinding) -> str:
    return finding.dns_name or finding.ip_address or "Unknown Asset"


def _weighted_total(findings: Iterable[NormalizedFinding]) -> int:
    return sum(finding.record_count for finding in findings)


def parse_report_month(value: str) -> date:
    parsed = datetime.strptime(value.strip(), "%B %Y")
    return date(parsed.year, parsed.month, calendar.monthrange(parsed.year, parsed.month)[1])


def _build_crowdstrike_insights(findings: list[NormalizedFinding]) -> dict[str, object] | None:
    if not any(finding.source_tool.startswith("crowdstrike_") for finding in findings):
        return None

    products: Counter[str] = Counter()
    assets: Counter[str] = Counter()
    for finding in findings:
        if finding.product:
            products[finding.product] += finding.record_count
        assets[_asset_label(finding)] += finding.record_count

    return {
        "exploit_available": sum(finding.record_count for finding in findings if finding.exploit_available),
        "cisa_kev": sum(finding.record_count for finding in findings if finding.cisa_kev),
        "internet_exposed": sum(finding.record_count for finding in findings if finding.internet_exposed),
        "critical_assets": len({
            _asset_label(finding)
            for finding in findings
            if "critical" in finding.asset_criticality.lower()
        }),
        "top_products": [
            {"product": product, "vulnerability_count": count}
            for product, count in products.most_common(10)
        ],
        "top_assets": [
            {"asset": asset, "vulnerability_count": count}
            for asset, count in assets.most_common(10)
        ],
    }


_EMPTY_FINDING = NormalizedFinding(
    finding_key="",
    source_tool="tenable_sc",
    source_vulnerability_id="",
    ip_address="",
    dns_name="",
    vulnerability_name="",
    cve="",
    severity="Unknown",
    exploit_available=False,
    exploit_signal="",
    patch_priority="P4",
    asset_exposure=0,
    vulnerability_finding="",
    summary="",
    description="",
    remediation="",
    kb_links="",
    platform_details="",
    first_discovered="",
    last_observed="",
    vulnerability_age_days=None,
    protocol="",
    port="",
    record_count=0,
)
