#!/usr/bin/env python3
from __future__ import annotations

import csv
import argparse
import re
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC_PATH = ROOT / "docs" / "TENABLE_FIELD_VALIDATION_AND_DASHBOARDS.md"
OUT_DIR = ROOT / "samples" / "tenable_100_row"


@dataclass(frozen=True)
class SyntheticFinding:
    index: int
    plugin_id: str
    ip: str
    dns: str
    protocol: str
    port: str
    severity: str
    exploit_available: bool
    name: str
    cve: str
    family: str
    first_discovered: date
    os: str


MONTHS = [
    ("April 2026", date(2026, 4, 30), "sc", list(range(1, 101))),
    ("May 2026", date(2026, 5, 31), "sc", list(range(1, 81)) + list(range(101, 131))),
    ("June 2026", date(2026, 6, 30), "io", list(range(31, 131)) + list(range(131, 151))),
    ("July 2026", date(2026, 7, 31), "io", list(range(56, 151)) + list(range(151, 181))),
]

VULN_TEMPLATES = [
    ("Apache Tomcat AJP Request Injection", "CVE-2020-1938", "Web Servers", "tcp", "8009"),
    ("Apache Log4j Remote Code Execution", "CVE-2021-44228", "Web Servers", "tcp", "8080"),
    ("Microsoft SQL Server Unsupported Version", "", "Databases", "tcp", "1433"),
    ("OpenSSL Security Update Available", "CVE-2023-0286", "General", "tcp", "443"),
    ("Remote Desktop Weak Encryption Enabled", "", "Windows", "tcp", "3389"),
    ("Nginx Security Update Available", "CVE-2025-2345", "Web Servers", "tcp", "443"),
    ("SMB Signing Not Required", "", "Windows", "tcp", "445"),
    ("Oracle Java Unsupported Version", "CVE-2024-20919", "General", "tcp", "0"),
    ("Linux Kernel Security Update Available", "CVE-2024-1086", "Linux", "tcp", "0"),
    ("TLS 1.0 Protocol Detection", "", "SSL", "tcp", "443"),
]


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate 100+ row Tenable sample CSVs.")
    parser.add_argument(
        "--format",
        choices=("mixed", "sc", "io"),
        default="mixed",
        help="Generate the original mixed SC/IO timeline, or force every month to one Tenable export format.",
    )
    args = parser.parse_args()

    sc_fields, io_fields = load_raw_fields()
    findings = build_findings()
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    for month_name, report_date, source, indexes in MONTHS:
        if args.format != "mixed":
            source = args.format
        rows = [findings[index] for index in indexes]
        safe_month = month_name.lower().replace(" ", "_")
        if source == "sc":
            path = OUT_DIR / f"tenable_sc_{safe_month}_100plus.csv"
            write_csv(path, sc_fields, [build_sc_row(finding, report_date, sc_fields) for finding in rows])
        else:
            path = OUT_DIR / f"tenable_io_{safe_month}_100plus.csv"
            write_csv(path, io_fields, [build_io_row(finding, report_date, io_fields) for finding in rows])
        print(f"{path} ({len(rows)} rows)")


def load_raw_fields() -> tuple[list[str], list[str]]:
    text = DOC_PATH.read_text(encoding="utf-8")
    blocks = re.findall(r"```text\n(.*?)```", text, flags=re.S)
    if len(blocks) < 2:
        raise RuntimeError("Unable to read Tenable SC/IO field blocks from validation doc")
    return split_fields(blocks[0]), split_fields(blocks[1])


def split_fields(block: str) -> list[str]:
    return [line.strip() for line in block.splitlines() if line.strip()]


def build_findings() -> dict[int, SyntheticFinding]:
    severities = ["Critical", "High", "Medium", "Low"]
    findings = {}
    for index in range(1, 181):
        template = VULN_TEMPLATES[(index - 1) % len(VULN_TEMPLATES)]
        severity = severities[(index - 1) % len(severities)]
        exploit_available = severity in {"Critical", "High"} and index % 3 != 0
        if severity in {"Medium", "Low"}:
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
        plugin_id = str(200000 + index)
        findings[index] = SyntheticFinding(
            index=index,
            plugin_id=plugin_id,
            ip=f"10.20.{subnet}.{host}",
            dns=f"asset-{asset_number:03d}.corp.local",
            protocol=template[3],
            port=template[4],
            severity=severity,
            exploit_available=exploit_available,
            name=template[0],
            cve=template[1],
            family=template[2],
            first_discovered=first_seen,
            os=["Windows Server 2019", "Ubuntu 22.04", "RHEL 8", "Appliance OS"][(index - 1) % 4],
        )
    return findings


def write_csv(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def build_sc_row(finding: SyntheticFinding, report_date: date, fields: list[str]) -> dict[str, str]:
    row = blank_row(fields)
    vpr = vpr_score(finding)
    row.update(
        {
            "Vulnerability Priority Rating": f"{vpr:.1f}",
            "Exploit Prediction Scoring System (EPSS)": f"{min(0.97, vpr / 11):.3f}",
            "IP Address": finding.ip,
            "Protocol": finding.protocol,
            "Port": finding.port,
            "ACR": str(700 + finding.index % 250),
            "AES": str(650 + finding.index % 300),
            "Exploit?": "Yes" if finding.exploit_available else "No",
            "Repository": "MVA Sample Repository",
            "MAC Address": f"00:16:3e:{finding.index % 255:02x}:aa:{(finding.index * 7) % 255:02x}",
            "DNS Name": finding.dns,
            "NetBIOS Name": finding.dns.split(".")[0].upper(),
            "Plugin Output": f"{finding.name} detected on {finding.ip}:{finding.port}.",
            "Synopsis": finding.name,
            "Description": f"{finding.name} was identified during the monthly vulnerability report.",
            "Steps to Remediate": remediation_for(finding),
            "Risk Factor": finding.severity,
            "STIG Severity": finding.severity,
            "CVSS V2 Base Score": cvss2_for(finding),
            "CVSS V3 Base Score": cvss3_for(finding),
            "CVSS V4 Base Score": cvss4_for(finding),
            "CVSS V2 Temporal Score": cvss2_for(finding),
            "CVSS V3 Temporal Score": cvss3_for(finding),
            "CVSS V4 Threat Score": cvss4_for(finding),
            "CVSS V2 Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "CVSS V3 Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS V4 Vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "CVSS V4 Threat Vector": "E:A",
            "CVSS V4 Supplemental": "Automatable",
            "CPE": f"cpe:/a:mva:{finding.family.lower().replace(' ', '_')}",
            "CVE": finding.cve,
            "BID": str(90000 + finding.index),
            "Cross References": kb_for(finding),
            "First Discovered": finding.first_discovered.isoformat(),
            "Last Observed": report_date.isoformat(),
            "Vuln Publication Date": "2025-01-15",
            "Security End of Life Date": "2026-12-31" if "Unsupported" in finding.name else "",
            "Patch Publication Date": "2026-01-20",
            "Plugin Publication Date": "2026-02-01",
            "Plugin Modification Date": report_date.isoformat(),
            "Exploit Ease": "Functional exploit exists" if finding.exploit_available else "No known exploits",
            "Exploit Frameworks": "Metasploit" if finding.exploit_available else "",
            "Check Type": "Remote",
            "Version": "1.0",
            "Agent ID": f"agent-{finding.index:04d}",
            "Host ID": f"host-{finding.index:04d}",
            "Nessus Web Tests": "No",
            "Thorough Tests": "Yes",
            "Scan Accuracy": "High",
            "Plugin Name": finding.name,
            "Family": finding.family,
            "Plugin": finding.plugin_id,
            "Severity": finding.severity,
            "See Also": kb_for(finding),
        }
    )
    return row


def build_io_row(finding: SyntheticFinding, report_date: date, fields: list[str]) -> dict[str, str]:
    row = blank_row(fields)
    vpr = vpr_score(finding)
    age = (report_date - finding.first_discovered).days
    row.update(
        {
            "age_in_days": str(age),
            "asset.display_fqdn": finding.dns,
            "asset.display_ipv4_address": finding.ip,
            "asset.display_ipv6_address": "",
            "asset.display_mac_address": f"00:16:3e:{finding.index % 255:02x}:bb:{(finding.index * 5) % 255:02x}",
            "asset.host_name": finding.dns.split(".")[0],
            "asset.id": f"asset-{finding.index:04d}",
            "asset.ipv4_addresses": finding.ip,
            "asset.ipv6_addresses": "",
            "asset.last_authenticated_scan_time": report_date.isoformat(),
            "asset.last_licensed_scan_time": report_date.isoformat(),
            "asset.name": finding.dns,
            "asset.netbios_name": finding.dns.split(".")[0].upper(),
            "asset.network.id": "default",
            "asset.network.name": "Corporate",
            "asset.operating_system": finding.os,
            "asset.operating_systems": finding.os,
            "asset.system_type": "server",
            "asset.tags": "mva-sample",
            "definition.bugtraq": str(90000 + finding.index),
            "definition.cpe": f"cpe:/a:mva:{finding.family.lower().replace(' ', '_')}",
            "definition.cve": finding.cve,
            "definition.cvss2.base_score": cvss2_for(finding),
            "definition.cvss2.base_vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "definition.cvss2.temporal_score": cvss2_for(finding),
            "definition.cvss2.temporal_vector": "E:F/RL:OF/RC:C",
            "definition.cvss3.base_score": cvss3_for(finding),
            "definition.cvss3.base_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "definition.cvss3.temporal_score": cvss3_for(finding),
            "definition.cvss3.temporal_vector": "E:F/RL:O/RC:C",
            "definition.cvss4.base_score": cvss4_for(finding),
            "definition.cvss4.base_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "definition.cwe": "CWE-20",
            "definition.description": f"{finding.name} was identified during the monthly vulnerability report.",
            "definition.epss.score": f"{min(0.97, vpr / 11):.3f}",
            "definition.exploitability_ease": "Functional" if finding.exploit_available else "No known exploits",
            "definition.exploited_by_malware": "true" if finding.exploit_available and finding.index % 5 == 0 else "false",
            "definition.exploited_by_nessus": "true" if finding.exploit_available else "false",
            "definition.family": finding.family,
            "definition.id": finding.plugin_id,
            "definition.in_the_news": "true" if finding.exploit_available and finding.index % 4 == 0 else "false",
            "definition.malware": "true" if finding.exploit_available and finding.index % 5 == 0 else "false",
            "definition.name": finding.name,
            "definition.patch_published": "2026-01-20",
            "definition.plugin_published": "2026-02-01",
            "definition.plugin_updated": report_date.isoformat(),
            "definition.plugin_version": "1.0",
            "definition.references": kb_for(finding),
            "definition.see_also": kb_for(finding),
            "definition.severity": finding.severity,
            "definition.solution": remediation_for(finding),
            "definition.stig_severity": finding.severity,
            "definition.synopsis": finding.name,
            "definition.type": "remote",
            "definition.unsupported_by_vendor": "true" if "Unsupported" in finding.name else "false",
            "definition.vpr.score": f"{vpr:.1f}",
            "definition.vpr_v2.drivers_cve_id": finding.cve,
            "definition.vpr_v2.drivers_exploit_code_maturity": "Functional" if finding.exploit_available else "Unproven",
            "definition.vpr_v2.drivers_exploit_probability": f"{min(0.95, vpr / 10):.2f}",
            "definition.vpr_v2.drivers_on_cisa_kev": "true" if finding.exploit_available and finding.index % 6 == 0 else "false",
            "definition.vpr_v2.score": f"{vpr:.1f}",
            "definition.vulnerability_published": "2025-01-15",
            "definition.workaround": remediation_for(finding),
            "definition.workaround_published": "2026-01-20",
            "definition.workaround_type": "patch",
            "first_observed": finding.first_discovered.isoformat(),
            "id": f"vuln-{finding.plugin_id}-{finding.ip}",
            "last_fixed": "",
            "last_seen": report_date.isoformat(),
            "output": f"{finding.name} detected on {finding.ip}:{finding.port}.",
            "port": finding.port,
            "protocol": finding.protocol,
            "recast_reason": "",
            "resurfaced_date": "",
            "risk_modified": "false",
            "scan.id": f"scan-{report_date:%Y%m}",
            "scan.target": finding.ip,
            "severity": finding.severity,
            "software_vulns": "true",
            "source": "tenable.io",
            "state": "open",
            "time_to_fix": "",
            "vuln_age": str(age),
            "vuln_sla_date": (finding.first_discovered + timedelta(days=30)).isoformat(),
        }
    )
    return row


def blank_row(fields: list[str]) -> dict[str, str]:
    return {field: "" for field in fields}


def vpr_score(finding: SyntheticFinding) -> float:
    base = {"Critical": 9.4, "High": 7.4, "Medium": 5.4, "Low": 2.4}[finding.severity]
    return min(10.0, base + (0.4 if finding.exploit_available else 0.0))


def cvss2_for(finding: SyntheticFinding) -> str:
    return {"Critical": "9.0", "High": "7.5", "Medium": "5.0", "Low": "2.6"}[finding.severity]


def cvss3_for(finding: SyntheticFinding) -> str:
    return {"Critical": "9.8", "High": "8.1", "Medium": "6.5", "Low": "3.7"}[finding.severity]


def cvss4_for(finding: SyntheticFinding) -> str:
    return {"Critical": "9.4", "High": "8.0", "Medium": "6.2", "Low": "3.5"}[finding.severity]


def kb_for(finding: SyntheticFinding) -> str:
    if "Tomcat" in finding.name:
        return "https://tomcat.apache.org/security-9.html"
    if "Log4j" in finding.name:
        return "https://logging.apache.org/log4j/2.x/security.html"
    if "SQL Server" in finding.name:
        return "https://learn.microsoft.com/sql/sql-server/end-of-support"
    if "OpenSSL" in finding.name:
        return "https://www.openssl.org/news/vulnerabilities.html"
    if "Nginx" in finding.name:
        return "https://nginx.org/en/security_advisories.html"
    if "SMB" in finding.name:
        return "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always"
    return "https://www.tenable.com/plugins"


def remediation_for(finding: SyntheticFinding) -> str:
    if "Unsupported" in finding.name:
        return "Upgrade the affected software to a vendor-supported release and validate with a follow-up scan."
    if "TLS 1.0" in finding.name:
        return "Disable TLS 1.0 and TLS 1.1, enable TLS 1.2 or later, then restart the service."
    if "SMB Signing" in finding.name:
        return "Require SMB signing through Group Policy and validate domain controller and member server policy refresh."
    return "Apply the vendor security update, restart the affected service if required, and validate with a follow-up scan."


if __name__ == "__main__":
    main()
