#!/usr/bin/env python3
from __future__ import annotations

import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
QUALYS_SOURCE = ROOT / "samples" / "qualys_100_row"
CUSTOM_QUALYS_SAMPLE = ROOT / "samples" / "custom_qualys_100_row"
PUBLIC_CUSTOM_QUALYS = ROOT / "react-ui" / "public" / "sample-data" / "custom-qualys"
PUBLIC_CUSTOM_CSV = ROOT / "react-ui" / "public" / "sample-data" / "custom-csv"
GENERIC_SAMPLE = ROOT / "samples" / "universal_custom_parser"

MONTHS = ("april", "may", "june", "july")
CUSTOM_RATING_LABELS = {
    "5": "Urgent",
    "4": "Critical",
    "3": "Serious",
    "2": "Medium",
    "1": "Minimal",
}

GENERIC_FIELDS = [
    "Host IP",
    "DNS Name",
    "Finding Name",
    "Finding ID",
    "CVE",
    "Risk Rating",
    "Exploit Evidence",
    "Finding Status",
    "Data Center",
    "Detection Count",
    "Finding Confidence",
    "Threat Summary",
    "Impact",
    "Fix",
    "Vendor Reference",
    "Operating System",
    "First Seen",
    "Last Seen",
    "Finding Evidence",
    "Service Protocol",
    "Service Port",
]


def main() -> None:
    for directory in (CUSTOM_QUALYS_SAMPLE, PUBLIC_CUSTOM_QUALYS, PUBLIC_CUSTOM_CSV, GENERIC_SAMPLE):
        directory.mkdir(parents=True, exist_ok=True)

    for month in MONTHS:
        source = QUALYS_SOURCE / f"qualys_monthly_{month}_2026_100plus.csv"
        rows, fields = read_csv(source)
        custom_rows, custom_fields = custom_qualys_rows(rows, fields)
        custom_name = f"custom_qualys_monthly_{month}_2026.csv"
        write_csv(CUSTOM_QUALYS_SAMPLE / custom_name, custom_fields, custom_rows)
        write_csv(PUBLIC_CUSTOM_QUALYS / custom_name, custom_fields, custom_rows)

        generic_rows = [generic_row(row) for row in custom_rows]
        generic_name = f"generic_scanner_{month}_2026.csv"
        write_csv(GENERIC_SAMPLE / generic_name, GENERIC_FIELDS, generic_rows)
        write_csv(PUBLIC_CUSTOM_CSV / generic_name, GENERIC_FIELDS, generic_rows)

    adhoc_rows, adhoc_fields = read_csv(QUALYS_SOURCE / "qualys_adhoc_july_2026_100plus.csv")
    custom_adhoc_rows, custom_adhoc_fields = custom_qualys_rows(adhoc_rows, adhoc_fields)
    write_csv(
        CUSTOM_QUALYS_SAMPLE / "custom_qualys_adhoc_july_2026.csv",
        custom_adhoc_fields,
        custom_adhoc_rows,
    )
    write_csv(
        PUBLIC_CUSTOM_QUALYS / "custom_qualys_adhoc_july_2026.csv",
        custom_adhoc_fields,
        custom_adhoc_rows,
    )


def custom_qualys_rows(rows: list[dict[str, str]], fields: list[str]) -> tuple[list[dict[str, str]], list[str]]:
    output_fields = ["threat" if field == "Threat" else "impact" if field == "Impact" else field for field in fields]
    output = []
    for row in rows:
        qid = int(row.get("QID") or 0)
        rating = str((qid % 5) + 1)
        transformed = {}
        for field in fields:
            target = "threat" if field == "Threat" else "impact" if field == "Impact" else field
            transformed[target] = row.get(field, "")
        transformed["Severity"] = rating
        transformed["Type"] = "VUL"
        transformed["Vuln Status"] = transformed.get("Vuln Status") or "Active"
        output.append(transformed)
    return output, output_fields


def generic_row(row: dict[str, str]) -> dict[str, str]:
    rating = str(row.get("Severity") or "")
    exploit_reference = row.get("Exploitability", "")
    last_seen = row.get("Last Detected") or "2026-07-31"
    first_seen = row.get("First Detected") or last_seen
    return {
        "Host IP": row.get("IP", ""),
        "DNS Name": row.get("DNS") or row.get("FQDN", ""),
        "Finding Name": row.get("Title", ""),
        "Finding ID": row.get("QID", ""),
        "CVE": row.get("CVE ID", ""),
        "Risk Rating": CUSTOM_RATING_LABELS.get(rating, "Unknown"),
        "Exploit Evidence": f"Exploit available: {exploit_reference}" if exploit_reference else "",
        "Finding Status": row.get("Vuln Status") or "Active",
        "Data Center": row.get("Datacentre", ""),
        "Detection Count": row.get("Times Detected") or "1",
        "Finding Confidence": "Confirmed",
        "Threat Summary": row.get("threat", ""),
        "Impact": row.get("impact", ""),
        "Fix": row.get("Solution", ""),
        "Vendor Reference": row.get("Vendor Reference", ""),
        "Operating System": row.get("OS", ""),
        "First Seen": first_seen,
        "Last Seen": last_seen,
        "Finding Evidence": row.get("Results", ""),
        "Service Protocol": row.get("Protocol", ""),
        "Service Port": row.get("Port", ""),
    }


def read_csv(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader), list(reader.fieldnames or [])


def write_csv(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    main()
