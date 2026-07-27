#!/usr/bin/env python3
"""Independent raw-CSV pivot for the MVA unified four-scanner release."""

from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter
from datetime import date, datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "final" / "Unified" / "Validation"
MONTHS = ["april", "may", "june", "july"]
MONTH_LABELS = {month: f"{month.title()} 2026" for month in MONTHS}
SOURCES = {
    "tenable-sc": ROOT / "samples" / "tenable_100_row" / "tenable_sc_{month}_2026_100plus.csv",
    "tenable-io": ROOT / "samples" / "tenable_100_row" / "tenable_io_{month}_2026_100plus.csv",
    "qualys": ROOT / "samples" / "qualys_100_row" / "qualys_monthly_{month}_2026_100plus.csv",
    "crowdstrike": ROOT / "samples" / "crowdstrike_100_row" / "crowdstrike_vulnerabilities_{month}_2026_100plus.csv",
}
EXPECTED = {
    "April 2026": {"raw": 410, "open": 150, "repeats": 260, "confirmed": 40, "source_only": 110, "exploit": 70, "new": 0, "patched": 0, "priority": {"P1": 42, "P2": 62, "P3": 23, "P4": 23}},
    "May 2026": {"raw": 450, "open": 160, "repeats": 290, "confirmed": 40, "source_only": 120, "exploit": 74, "new": 30, "patched": 20, "priority": {"P1": 44, "P2": 66, "P3": 24, "P4": 26}},
    "June 2026": {"raw": 485, "open": 165, "repeats": 320, "confirmed": 40, "source_only": 125, "exploit": 78, "new": 25, "patched": 20, "priority": {"P1": 44, "P2": 73, "P3": 23, "P4": 25}},
    "July 2026": {"raw": 495, "open": 160, "repeats": 335, "confirmed": 40, "source_only": 120, "exploit": 77, "new": 20, "patched": 25, "priority": {"P1": 44, "P2": 69, "P3": 23, "P4": 24}},
}
SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Unknown": 5}


def text(row: dict[str, str], *keys: str) -> str:
    for key in keys:
        value = str(row.get(key, "") or "").strip()
        if value:
            return value
    return ""


def identity(value: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9.:_-]+", " ", value.lower())).strip()


def severity(value: str, qualys: bool = False) -> str:
    value = value.strip().lower()
    if qualys:
        return {"0": "Info", "1": "Info", "2": "Low", "3": "Medium", "4": "High", "5": "Critical"}.get(value, "Unknown")
    numeric = {"0": "Info", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"}
    if value in numeric:
        return numeric[value]
    for token, label in (("crit", "Critical"), ("high", "High"), ("med", "Medium"), ("low", "Low"), ("info", "Info")):
        if token in value:
            return label
    return "Unknown"


def exploitable(value: str) -> bool:
    value = value.strip().lower()
    if not value or value in {"0", "false", "n", "no", "none", "not available", "unavailable", "unproven", "no known exploits", "no known exploit", "no exploit", "not exploitable"}:
        return False
    if any(token in value for token in ("available", "exploited", "exploitable", "exploit code", "functional", "weaponized", "confirmed", "proof-of-concept", "poc", "true", "yes")):
        return True
    return bool(re.search(r"\b[1-9](?:\.\d+)?\b", value))


def priority(level: str, exploit: bool) -> str:
    if exploit:
        return {"Critical": "P1", "High": "P1", "Medium": "P2", "Low": "P2"}.get(level, "P4")
    return {"Critical": "P2", "High": "P2", "Medium": "P3", "Low": "P4"}.get(level, "P4")


def parsed_date(value: str) -> date | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value[:10]).date()
    except ValueError:
        return None


def normalize(source: str, row: dict[str, str]) -> dict | None:
    if source == "qualys" and text(row, "Vuln Status").lower() in {"fixed", "closed", "resolved", "remediated", "ignored"}:
        return None
    if source == "crowdstrike":
        if text(row, "Is Suppressed").lower() in {"yes", "true", "1"}:
            return None
        if text(row, "Status", "Instance state").lower() in {"closed", "fixed", "resolved", "remediated", "inactive"}:
            return None

    if source == "tenable-sc":
        dns, ip = text(row, "DNS Name", "NetBIOS Name"), text(row, "IP Address")
        name, cve = text(row, "Plugin Name", "Synopsis"), text(row, "CVE")
        level = severity(text(row, "Severity", "Risk Factor"))
        exploit = exploitable(text(row, "Exploit?", "Exploit Ease", "Exploit Frameworks"))
        first, age = text(row, "First Discovered"), None
        protocol, port = text(row, "Protocol"), text(row, "Port")
    elif source == "tenable-io":
        dns, ip = text(row, "asset.display_fqdn", "asset.host_name", "asset.name", "asset.netbios_name"), text(row, "asset.display_ipv4_address", "asset.ipv4_addresses", "scan.target")
        name, cve = text(row, "definition.name"), text(row, "definition.cve")
        level = severity(text(row, "definition.severity", "severity"))
        exploit = exploitable(text(row, "definition.exploitability_ease", "definition.exploited_by_malware", "definition.exploited_by_nessus", "definition.vpr_v2.drivers_exploit_code_maturity"))
        first = text(row, "first_observed")
        raw_age = text(row, "vuln_age", "age_in_days")
        age = int(float(raw_age)) if raw_age else None
        protocol, port = text(row, "protocol"), text(row, "port")
    elif source == "qualys":
        dns, ip = text(row, "FQDN", "DNS", "NetBIOS"), text(row, "IP")
        name, cve = text(row, "Title"), text(row, "CVE ID")
        level = severity(text(row, "Severity"), qualys=True)
        exploit = exploitable(" | ".join(filter(None, (text(row, "Exploitability"), text(row, "Associated Malware")))))
        first, age = text(row, "First Detected"), None
        protocol, port = text(row, "Protocol"), text(row, "Port")
    else:
        dns, ip = text(row, "Hostname"), text(row, "LocalIP")
        name, cve = text(row, "CVE Description", "CVE ID", "Vulnerability ID"), text(row, "CVE ID")
        level = severity(text(row, "Severity", "Third-party Rating"))
        exploit = exploitable(" | ".join(filter(None, (text(row, "Exploit status label"), text(row, "Exploit status value"))))) or text(row, "Is CISA KEV").lower() in {"yes", "true", "1"}
        first, age = text(row, "Created Date"), None
        protocol, port = text(row, "Services Transports", "Services Protocols"), text(row, "Ports", "Services Ports")

    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", f"{cve} {name}", re.I)))
    vuln = f"cve:{','.join(value.upper() for value in cves)}" if cves else f"name:{identity(name)}"
    asset = f"dns:{identity(dns).rstrip('.')}" if dns else f"ip:{identity(ip)}"
    key = f"{asset}|{vuln}|service:{identity(protocol)}|{identity(port)}|"
    return {"key": key, "source": source, "severity": level, "exploit": exploit, "first": parsed_date(first), "age": age}


def consolidate(records: list[dict]) -> dict[str, dict]:
    groups: dict[str, dict] = {}
    for record in records:
        group = groups.setdefault(record["key"], {**record, "sources": set(), "observations": 0})
        group["sources"].add(record["source"])
        group["observations"] += 1
        if SEVERITY_RANK[record["severity"]] < SEVERITY_RANK[group["severity"]]:
            group["severity"] = record["severity"]
        group["exploit"] = group["exploit"] or record["exploit"]
        if record["first"] and (not group["first"] or record["first"] < group["first"]):
            group["first"] = record["first"]
        if record["age"] is not None:
            group["age"] = max(group["age"] or 0, record["age"])
    for group in groups.values():
        group["priority"] = priority(group["severity"], group["exploit"])
    return groups


def main() -> int:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    snapshots: dict[str, dict[str, dict]] = {}
    results: list[dict] = []
    previous: dict[str, dict] | None = None

    for month_index, month in enumerate(MONTHS, start=4):
        records = []
        source_rows = {}
        for source, pattern in SOURCES.items():
            file_path = Path(str(pattern).format(month=month))
            with file_path.open(encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))
            normalized = [finding for row in rows if (finding := normalize(source, row))]
            source_rows[source] = len(normalized)
            records.extend(normalized)
        groups = consolidate(records)
        snapshots[MONTH_LABELS[month]] = groups
        current_keys = set(groups)
        previous_keys = set(previous or {})
        new_count = len(current_keys - previous_keys) if previous is not None else 0
        patched_count = len(previous_keys - current_keys) if previous is not None else 0
        report_date = date(2026, month_index + 1, 1) if month_index < 12 else date(2027, 1, 1)
        report_date = report_date.fromordinal(report_date.toordinal() - 1)
        age_matrix = {item: {bucket: 0 for bucket in (">7 days", ">30 days", ">60 days", ">180 days (6+ months)")} for item in ("P1", "P2", "P3", "P4")}
        for group in groups.values():
            age = group["age"]
            if age is None and group["first"]:
                age = max(0, (report_date - group["first"]).days)
            if age is None:
                continue
            for threshold, bucket in ((7, ">7 days"), (30, ">30 days"), (60, ">60 days"), (180, ">180 days (6+ months)")):
                if age > threshold:
                    age_matrix[group["priority"]][bucket] += 1

        result = {
            "period": MONTH_LABELS[month],
            "rawObservations": len(records),
            "totalOpen": len(groups),
            "newFindings": new_count,
            "patchedFindings": patched_count,
            "carriedFindings": len(current_keys & previous_keys) if previous is not None else 0,
            "repeatsRemoved": len(records) - len(groups),
            "crossToolConfirmed": sum(len(group["sources"]) >= 2 for group in groups.values()),
            "singleSourceOnly": sum(len(group["sources"]) == 1 for group in groups.values()),
            "exploitAvailable": sum(group["exploit"] for group in groups.values()),
            "priority": dict(Counter(group["priority"] for group in groups.values())),
            "severity": dict(Counter(group["severity"] for group in groups.values())),
            "ageByPriority": age_matrix,
            "sourceRows": source_rows,
        }
        expected = EXPECTED[result["period"]]
        checks = {
            "raw": result["rawObservations"], "open": result["totalOpen"], "repeats": result["repeatsRemoved"],
            "confirmed": result["crossToolConfirmed"], "source_only": result["singleSourceOnly"],
            "exploit": result["exploitAvailable"], "new": result["newFindings"], "patched": result["patchedFindings"],
        }
        for key, actual in checks.items():
            assert actual == expected[key], f"{result['period']} {key}: expected {expected[key]}, got {actual}"
        assert result["priority"] == expected["priority"], f"{result['period']} priority mismatch"
        results.append(result)
        previous = groups

    engine_path = OUTPUT / "engine_analysis.json"
    if engine_path.exists():
        engine = json.loads(engine_path.read_text())
        for manual, app in zip(results, engine["periods"], strict=True):
            assert manual["period"] == app["period"]
            for manual_key, app_key in (("totalOpen", "totalOpen"), ("newFindings", "newFindings"), ("patchedFindings", "patchedFindings"), ("repeatsRemoved", "repeatsRemoved"), ("crossToolConfirmed", "crossToolConfirmed"), ("singleSourceOnly", "singleSourceOnly"), ("exploitAvailable", "exploitable")):
                assert manual[manual_key] == app[app_key], f"Engine mismatch: {manual['period']} {manual_key}"
            for item in ("P1", "P2", "P3", "P4"):
                assert manual["priority"][item] == app[item], f"Engine priority mismatch: {manual['period']} {item}"
        assert results[-1]["ageByPriority"] == engine["latest"]["ageByPriority"], "Latest age/priority matrix differs from engine"

    payload = {"status": "PASS", "method": "Independent Python raw-CSV pivot; no React engine imports", "periods": results}
    (OUTPUT / "manual_pivot.json").write_text(json.dumps(payload, indent=2) + "\n")
    with (OUTPUT / "manual_pivot.csv").open("w", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["Period", "Raw", "Open", "New", "Patched", "Carried", "Repeats Removed", "Confirmed", "Source-only", "Exploit Available", "P1", "P2", "P3", "P4"])
        for item in results:
            writer.writerow([item["period"], item["rawObservations"], item["totalOpen"], item["newFindings"], item["patchedFindings"], item["carriedFindings"], item["repeatsRemoved"], item["crossToolConfirmed"], item["singleSourceOnly"], item["exploitAvailable"], *[item["priority"][key] for key in ("P1", "P2", "P3", "P4")]])
    print(json.dumps({"status": "PASS", "periods": [{"period": item["period"], "open": item["totalOpen"], "new": item["newFindings"], "patched": item["patchedFindings"]} for item in results]}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"VALIDATION FAILED: {error}", file=sys.stderr)
        raise SystemExit(1)
