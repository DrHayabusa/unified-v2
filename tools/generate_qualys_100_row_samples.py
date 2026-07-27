#!/usr/bin/env python3
from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "samples" / "qualys_100_row"

QUALYS_MONTHLY_FIELDS = [
    "IP",
    "DNS",
    "NetBIOS",
    "Datacentre",
    "Tracking Method",
    "OS",
    "IP Status",
    "QID",
    "Title",
    "Vuln Status",
    "Type",
    "Severity",
    "Port",
    "Protocol",
    "FQDN",
    "SSL",
    "First Detected",
    "Last Detected",
    "Times Detected",
    "Date Last Fixed",
    "First Reopened",
    "Last Reopened",
    "Times Reopened",
    "CVE ID",
    "Vendor Reference",
    "Bugtraq ID",
    "CVSS",
    "CVSS Base",
    "CVSS Temporal",
    "CVSS Environment",
    "CVSS3.1",
    "CVSS3.1 Base",
    "CVSS3.1 Temporal",
    "Threat",
    "Impact",
    "Solution",
    "Exploitability",
    "Associated Malware",
    "Results",
    "PCI Vuln",
    "Ticket State",
    "Instance",
    "Category",
]

QUALYS_ADHOC_FIELDS = [
    "IP",
    "DNS",
    "NetBIOS",
    "Datacentre",
    "OS",
    "IP Status",
    "QID",
    "Title",
    "Type",
    "Severity",
    "Port",
    "Protocol",
    "FQDN",
    "SSL",
    "CVE ID",
    "Vendor Reference",
    "Bugtraq ID",
    "CVSS Base",
    "CVSS Temporal",
    "CVSS3.1 Base",
    "CVSS3.1 Temporal",
    "CVSS4 Base",
    "Threat",
    "Impact",
    "Solution",
    "Exploitability",
    "Associated Malware",
    "Results",
    "PCI Vuln",
    "Instance",
    "Category",
]

MONTHS = [
    ("April 2026", date(2026, 4, 30), list(range(1, 101))),
    ("May 2026", date(2026, 5, 31), list(range(1, 81)) + list(range(101, 131))),
    ("June 2026", date(2026, 6, 30), list(range(31, 131)) + list(range(131, 151))),
    ("July 2026", date(2026, 7, 31), list(range(56, 151)) + list(range(151, 181))),
]

VULN_TEMPLATES = [
    ("Apache Tomcat AJP Request Injection", "CVE-2020-1938", "Web Application", "tcp", "8009"),
    ("Apache Log4j Remote Code Execution", "CVE-2021-44228", "Web Application", "tcp", "8080"),
    ("Microsoft SQL Server Unsupported Version", "", "Database", "tcp", "1433"),
    ("OpenSSL Security Update Available", "CVE-2023-0286", "SSL", "tcp", "443"),
    ("Remote Desktop Weak Encryption Enabled", "", "Windows", "tcp", "3389"),
    ("Nginx Security Update Available", "CVE-2025-2345", "Web Server", "tcp", "443"),
    ("SMB Signing Not Required", "", "Windows", "tcp", "445"),
    ("Oracle Java Unsupported Version", "CVE-2024-20919", "General", "tcp", "0"),
    ("Linux Kernel Security Update Available", "CVE-2024-1086", "Linux", "tcp", "0"),
    ("TLS 1.0 Protocol Detection", "", "SSL", "tcp", "443"),
]


@dataclass(frozen=True)
class QualysFinding:
    index: int
    qid: str
    ip: str
    dns: str
    netbios: str
    os: str
    title: str
    cve: str
    category: str
    protocol: str
    port: str
    severity: int
    exploit_available: bool
    first_detected: date


def main() -> None:
    findings = build_findings()
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    for month_name, report_date, indexes in MONTHS:
        rows = [build_monthly_row(findings[index], report_date) for index in indexes]
        safe_month = month_name.lower().replace(" ", "_")
        path = OUT_DIR / f"qualys_monthly_{safe_month}_100plus.csv"
        write_csv(path, QUALYS_MONTHLY_FIELDS, rows)
        print(f"{path} ({len(rows)} rows)")

    july_rows = [build_adhoc_row(findings[index]) for index in MONTHS[-1][2]]
    path = OUT_DIR / "qualys_adhoc_july_2026_100plus.csv"
    write_csv(path, QUALYS_ADHOC_FIELDS, july_rows)
    print(f"{path} ({len(july_rows)} rows)")


def build_findings() -> dict[int, QualysFinding]:
    severities = [5, 4, 3, 2]
    findings = {}
    for index in range(1, 181):
        template = VULN_TEMPLATES[(index - 1) % len(VULN_TEMPLATES)]
        severity = severities[(index - 1) % len(severities)]
        exploit_available = severity in {5, 4} and index % 3 != 0
        if severity in {3, 2}:
            exploit_available = index % 7 == 0

        if index <= 100:
            first_seen = date(2026, 4, 1) + timedelta(days=(index - 1) % 25)
        elif index <= 130:
            first_seen = date(2026, 5, 1) + timedelta(days=(index - 101) % 25)
        elif index <= 150:
            first_seen = date(2026, 6, 1) + timedelta(days=(index - 131) % 25)
        else:
            first_seen = date(2026, 7, 1) + timedelta(days=(index - 151) % 25)

        if index % 17 == 0:
            first_seen = date(2025, 11, 1) + timedelta(days=index % 20)
        elif index % 11 == 0:
            first_seen = date(2026, 1, 15) + timedelta(days=index % 15)

        asset_number = ((index - 1) % 40) + 1
        subnet = 10 + (asset_number % 9)
        host = 20 + asset_number
        dns = f"asset-{asset_number:03d}.corp.local"
        findings[index] = QualysFinding(
            index=index,
            qid=str(300000 + index),
            ip=f"10.30.{subnet}.{host}",
            dns=dns,
            netbios=dns.split(".")[0].upper(),
            os=["Windows Server 2019", "Ubuntu 22.04", "RHEL 8", "Network Appliance"][(index - 1) % 4],
            title=template[0],
            cve=template[1],
            category=template[2],
            protocol=template[3],
            port=template[4],
            severity=severity,
            exploit_available=exploit_available,
            first_detected=first_seen,
        )
    return findings


def build_monthly_row(finding: QualysFinding, report_date: date) -> dict[str, str]:
    row = blank_row(QUALYS_MONTHLY_FIELDS)
    times_detected = max(1, ((report_date.year - finding.first_detected.year) * 12 + report_date.month - finding.first_detected.month) + 1)
    reopened = finding.index % 19 == 0 and finding.first_detected.replace(day=1) != report_date.replace(day=1)
    row.update(
        {
            "IP": finding.ip,
            "DNS": finding.dns,
            "NetBIOS": finding.netbios,
            "Datacentre": ("DC1", "DC2", "DR")[finding.index % 3],
            "Tracking Method": "IP",
            "OS": finding.os,
            "IP Status": "Active",
            "QID": finding.qid,
            "Title": finding.title,
            "Vuln Status": "New" if finding.first_detected.replace(day=1) == report_date.replace(day=1) else ("Re-Opened" if reopened else "Active"),
            "Type": "VUL",
            "Severity": str(finding.severity),
            "Port": finding.port,
            "Protocol": finding.protocol,
            "FQDN": finding.dns,
            "SSL": "Yes" if finding.port == "443" else "No",
            "First Detected": finding.first_detected.isoformat(),
            "Last Detected": report_date.isoformat(),
            "Times Detected": str(times_detected),
            "Date Last Fixed": "",
            "First Reopened": (finding.first_detected + timedelta(days=21)).isoformat() if reopened else "",
            "Last Reopened": report_date.isoformat() if reopened else "",
            "Times Reopened": "1" if reopened else "0",
            "CVE ID": finding.cve,
            "Vendor Reference": kb_for(finding),
            "Bugtraq ID": str(95000 + finding.index),
            "CVSS": cvss_vector_for(finding),
            "CVSS Base": cvss2_for(finding),
            "CVSS Temporal": cvss2_for(finding),
            "CVSS Environment": "",
            "CVSS3.1": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS3.1 Base": cvss31_for(finding),
            "CVSS3.1 Temporal": cvss31_for(finding),
            "Threat": f"{finding.title} may expose the affected service to unauthorized access or service disruption.",
            "Impact": impact_for(finding),
            "Solution": remediation_for(finding),
            "Exploitability": kb_for(finding) if finding.exploit_available else "",
            "Associated Malware": "Observed malware association" if finding.exploit_available and finding.index % 5 == 0 else "",
            "Results": f"{finding.title} detected on {finding.ip}:{finding.port}.",
            "PCI Vuln": "Yes" if finding.severity >= 4 else "No",
            "Ticket State": "Open",
            "Instance": f"{finding.protocol}/{finding.port}",
            "Category": finding.category,
        }
    )
    return row


def build_adhoc_row(finding: QualysFinding) -> dict[str, str]:
    row = blank_row(QUALYS_ADHOC_FIELDS)
    row.update(
        {
            "IP": finding.ip,
            "DNS": finding.dns,
            "NetBIOS": finding.netbios,
            "Datacentre": ("DC1", "DC2", "DR")[finding.index % 3],
            "OS": finding.os,
            "IP Status": "Active",
            "QID": finding.qid,
            "Title": finding.title,
            "Type": "VUL",
            "Severity": str(finding.severity),
            "Port": finding.port,
            "Protocol": finding.protocol,
            "FQDN": finding.dns,
            "SSL": "Yes" if finding.port == "443" else "No",
            "CVE ID": finding.cve,
            "Vendor Reference": kb_for(finding),
            "Bugtraq ID": str(95000 + finding.index),
            "CVSS Base": cvss2_for(finding),
            "CVSS Temporal": cvss2_for(finding),
            "CVSS3.1 Base": cvss31_for(finding),
            "CVSS3.1 Temporal": cvss31_for(finding),
            "CVSS4 Base": cvss4_for(finding),
            "Threat": f"{finding.title} may expose the affected service to unauthorized access or service disruption.",
            "Impact": impact_for(finding),
            "Solution": remediation_for(finding),
            "Exploitability": kb_for(finding) if finding.exploit_available else "",
            "Associated Malware": "Observed malware association" if finding.exploit_available and finding.index % 5 == 0 else "",
            "Results": f"{finding.title} detected on {finding.ip}:{finding.port}.",
            "PCI Vuln": "Yes" if finding.severity >= 4 else "No",
            "Instance": f"{finding.protocol}/{finding.port}",
            "Category": finding.category,
        }
    )
    return row


def write_csv(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def blank_row(fields: list[str]) -> dict[str, str]:
    return {field: "" for field in fields}


def cvss_vector_for(finding: QualysFinding) -> str:
    return "AV:N/AC:L/Au:N/C:P/I:P/A:P" if finding.severity >= 4 else "AV:N/AC:M/Au:N/C:P/I:N/A:N"


def cvss2_for(finding: QualysFinding) -> str:
    return {5: "9.0", 4: "7.5", 3: "5.0", 2: "2.6", 1: "0.0"}[finding.severity]


def cvss31_for(finding: QualysFinding) -> str:
    return {5: "9.8", 4: "8.1", 3: "6.5", 2: "3.7", 1: "0.0"}[finding.severity]


def cvss4_for(finding: QualysFinding) -> str:
    return {5: "9.4", 4: "8.0", 3: "6.2", 2: "3.5", 1: "0.0"}[finding.severity]


def kb_for(finding: QualysFinding) -> str:
    if "Tomcat" in finding.title:
        return "https://tomcat.apache.org/security-9.html"
    if "Log4j" in finding.title:
        return "https://logging.apache.org/log4j/2.x/security.html"
    if "SQL Server" in finding.title:
        return "https://learn.microsoft.com/sql/sql-server/end-of-support"
    if "OpenSSL" in finding.title:
        return "https://www.openssl.org/news/vulnerabilities.html"
    if "Nginx" in finding.title:
        return "https://nginx.org/en/security_advisories.html"
    if "SMB" in finding.title:
        return "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always"
    return "https://www.qualys.com/research/security-alerts/"


def impact_for(finding: QualysFinding) -> str:
    if finding.severity >= 4:
        return "Successful exploitation may allow remote compromise, privilege abuse, or exposure of sensitive services."
    if finding.severity == 3:
        return "The finding increases attack surface and should be remediated through planned patching."
    return "The finding represents a hardening issue or lower-risk exposure."


def remediation_for(finding: QualysFinding) -> str:
    if "Unsupported" in finding.title:
        return "Upgrade the affected software to a vendor-supported release and validate with a follow-up scan."
    if "TLS 1.0" in finding.title:
        return "Disable TLS 1.0 and TLS 1.1, enable TLS 1.2 or later, then restart the affected service."
    if "SMB Signing" in finding.title:
        return "Require SMB signing through Group Policy and validate domain controller and member server policy refresh."
    return "Apply the vendor security update, restart the affected service if required, and validate with a follow-up scan."


if __name__ == "__main__":
    main()
