#!/usr/bin/env python3
"""Generate deterministic OpenShift vulnerability exports for MVA validation."""

from __future__ import annotations

import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUTS = [
    ROOT / "samples" / "openshift_100_row",
    ROOT / "react-ui" / "public" / "sample-data" / "openshift",
]
HEADERS = [
    "Namespace",
    "Deployment",
    "Image",
    "Component",
    "CVE",
    "Fixable",
    "CVE Fixed In",
    "Severity",
    "CVSS",
    "Discovered At",
    "Reference",
]
PERIOD_IDS = {
    "april": range(0, 110),
    "may": range(20, 140),
    "june": range(35, 165),
    "july": range(55, 195),
}
NEW_PERIOD = {
    **{item: "april" for item in range(0, 110)},
    **{item: "may" for item in range(110, 140)},
    **{item: "june" for item in range(140, 165)},
    **{item: "july" for item in range(165, 195)},
}
PERIOD_DATES = {
    "april": "2026-04-18T09:30:00Z",
    "may": "2026-05-17T10:15:00Z",
    "june": "2026-06-16T11:00:00Z",
    "july": "2026-07-15T12:45:00Z",
}
NAMESPACES = ["payments", "identity", "customer-portal", "analytics", "integration", "monitoring", "shared-services", "edge"]
DEPLOYMENTS = ["api", "worker", "web", "scheduler", "gateway"]
REGISTRIES = ["registry.example.internal/core", "registry.example.internal/digital", "registry.example.internal/platform"]
COMPONENTS = ["openssl", "glibc", "curl", "libxml2", "expat", "zlib", "krb5-libs", "python3-libs", "go-toolset", "nginx"]
SEVERITIES = ["Critical", "High", "High", "Medium", "Medium", "Low"]
CVSS = {"Critical": 9.8, "High": 8.1, "Medium": 6.5, "Low": 3.7}


def discovered_at(item: int) -> str:
    if item < 110:
        aged_dates = [
            "2025-10-12T08:00:00Z",
            "2026-01-10T08:00:00Z",
            "2026-02-18T08:00:00Z",
            "2026-03-22T08:00:00Z",
            "2026-04-18T09:30:00Z",
        ]
        return aged_dates[item % len(aged_dates)]
    return PERIOD_DATES[NEW_PERIOD[item]]


def row(item: int) -> list[str]:
    namespace = NAMESPACES[item % len(NAMESPACES)]
    deployment = f"{DEPLOYMENTS[(item // len(NAMESPACES)) % len(DEPLOYMENTS)]}-{(item % 5) + 1}"
    component = COMPONENTS[item % len(COMPONENTS)]
    image_version = 20 + (item % 14)
    image = f"{REGISTRIES[item % len(REGISTRIES)]}/{namespace}-{deployment}:2026.{image_version:02d}"
    cve = f"CVE-2026-{3000 + (item % 45):04d}"
    severity = SEVERITIES[item % len(SEVERITIES)]
    fixable = item % 5 != 0
    fixed_in = f"{component}-{2 + (item % 4)}.{(item % 9) + 1}.{(item % 13) + 2}" if fixable else ""
    return [
        namespace,
        deployment,
        image,
        component,
        cve,
        "Yes" if fixable else "No",
        fixed_in,
        severity,
        f"{CVSS[severity]:.1f}",
        discovered_at(item),
        "https://access.redhat.com/security/security-updates/cve",
    ]


def main() -> None:
    for directory in OUTPUTS:
        directory.mkdir(parents=True, exist_ok=True)
        for period, identifiers in PERIOD_IDS.items():
            target = directory / f"openshift_{period}_2026_100plus.csv"
            with target.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream)
                writer.writerow(HEADERS)
                writer.writerows(row(item) for item in identifiers)

    print("Generated OpenShift samples:")
    for period, identifiers in PERIOD_IDS.items():
        print(f"  {period.title()} 2026: {len(identifiers)} findings")


if __name__ == "__main__":
    main()
