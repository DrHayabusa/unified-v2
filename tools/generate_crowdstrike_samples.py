#!/usr/bin/env python3
from __future__ import annotations

import csv
from datetime import date, timedelta
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "samples" / "crowdstrike_100_row"

VULNERABILITY_HEADERS = [
    "Hostname", "LocalIP", "HostType", "OSVersion", "MachineDomain", "OU", "SiteName",
    "Product", "CVE ID", "CVE Description", "Status", "Severity", "Created Date", "Closed Date",
    "Closed Dwell Time", "Base Score", "CVSS Version", "Vector", "Vendor Advisory", "References",
    "Recommended Remediations", "Remediation Details", "Remediation Links", "Group Names", "Tags",
    "Host ID", "Exploit status value", "Exploit status label", "Platform", "Vulnerable Product Versions",
    "Closed Product Versions", "RemediationLevel", "ExPRT Rating", "Is Suppressed",
    "AdditionalRemediationAdvisoryUrl", "AdditionalRemediationSteps", "Is CISA KEV", "CISA KEV Due Date",
    "CVE Published Date", "Spotlight Published Date", "Host Last Seen Within", "Cloud Service Instance ID",
    "OS Build", "Evaluation logic", "Asset Criticality", "Asset Roles", "Internet exposure",
    "Vulnerability ID", "Vulnerability Metadata ID", "Managed By", "Vulnerability Data Providers",
    "Third-party Asset IDs", "Third-party Scanner ID", "Ports", "Third-party Rating", "Last Scan Time",
    "Types", "CID", "Customer", "CWEs", "Vulnerability Confidence", "Asset Confidence",
    "Asset Subsidiaries", "Services Ports", "Services Transports", "Services Protocols",
    "Recommended Remediation Patch Publication Date", "Minimum Remediation", "Minimum Remediation Details",
    "Minimum Remediation Links", "Minimum Remediation Advisory URL", "Minimum Remediation Steps",
    "Patch Publication Date", "Scan ID", "Instance state", "Simplified Evaluation Logic",
]

REMEDIATION_ASSET_HEADERS = [
    "Hostname", "LocalIP", "HostType", "OSVersion", "MachineDomain", "OU", "SiteName",
    "RecommendedRemediation", "RemediationDetail", "Products", "Count", "Critical", "High", "Medium",
    "Low", "Unknown", "GroupNames", "Tags", "HostID", "Exploits", "Platform", "ExPRT Critical",
    "ExPRT High", "ExPRT Medium", "ExPRT Low", "ExPRT Unknown", "AdditionalRemediationAdvisoryUrl",
    "AdditionalRemediationSteps", "Asset Criticality", "Asset Roles", "Internet exposure", "Managed By",
    "Data Providers", "Third-party Asset IDs", "CID", "Customer", "Recommendation Type",
    "Patch Publication Date", "Instance state",
]

VULNERABILITIES = [
    {
        "product": "Microsoft Windows Server",
        "cve": "CVE-2024-38077",
        "name": "Windows Remote Desktop Licensing Service remote code execution",
        "remediation": "Install the current Microsoft cumulative security update and restart the affected host.",
        "link": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38077",
        "cwe": "CWE-122",
        "port": "3389",
        "protocol": "TCP",
    },
    {
        "product": "Apache Log4j",
        "cve": "CVE-2021-44228",
        "name": "Apache Log4j remote code execution",
        "remediation": "Upgrade Log4j to a vendor-supported fixed release and restart the application service.",
        "link": "https://logging.apache.org/log4j/2.x/security.html",
        "cwe": "CWE-502",
        "port": "8080",
        "protocol": "TCP",
    },
    {
        "product": "OpenSSL",
        "cve": "CVE-2023-0286",
        "name": "OpenSSL X.400 address type confusion",
        "remediation": "Apply the operating-system vendor OpenSSL package update and restart dependent services.",
        "link": "https://www.openssl.org/news/secadv/20230207.txt",
        "cwe": "CWE-843",
        "port": "443",
        "protocol": "TCP",
    },
    {
        "product": "Apache Tomcat",
        "cve": "CVE-2020-1938",
        "name": "Apache Tomcat AJP file read and inclusion",
        "remediation": "Upgrade Apache Tomcat, disable unused AJP connectors, and require a connector secret.",
        "link": "https://tomcat.apache.org/security-9.html",
        "cwe": "CWE-22",
        "port": "8009",
        "protocol": "TCP",
    },
    {
        "product": "Google Chrome",
        "cve": "CVE-2024-4671",
        "name": "Google Chrome use-after-free vulnerability",
        "remediation": "Update Google Chrome to the latest enterprise stable release and relaunch the browser.",
        "link": "https://chromereleases.googleblog.com/",
        "cwe": "CWE-416",
        "port": "",
        "protocol": "",
    },
    {
        "product": "Cisco IOS XE",
        "cve": "CVE-2023-20198",
        "name": "Cisco IOS XE web UI privilege escalation",
        "remediation": "Install the fixed Cisco IOS XE release and disable the HTTP server when it is not required.",
        "link": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z",
        "cwe": "CWE-420",
        "port": "443",
        "protocol": "TCP",
    },
    {
        "product": "Linux Kernel",
        "cve": "CVE-2024-1086",
        "name": "Linux kernel netfilter use-after-free",
        "remediation": "Install the distribution kernel security update and reboot into the fixed kernel.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-1086",
        "cwe": "CWE-416",
        "port": "",
        "protocol": "",
    },
    {
        "product": "Microsoft Exchange Server",
        "cve": "CVE-2024-21410",
        "name": "Microsoft Exchange privilege escalation",
        "remediation": "Install the supported Exchange Server security update and verify Extended Protection configuration.",
        "link": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21410",
        "cwe": "CWE-287",
        "port": "443",
        "protocol": "TCP",
    },
]

MONTHS = {
    "april_2026": (date(2026, 4, 30), set(range(0, 110)), set()),
    "may_2026": (date(2026, 5, 31), set(range(20, 140)), set(range(0, 10))),
    "june_2026": (date(2026, 6, 30), set(range(40, 165)), set(range(20, 30))),
    "july_2026": (date(2026, 7, 31), set(range(65, 185)), set(range(40, 50))),
}


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for month_slug, (report_date, active_ids, closed_ids) in MONTHS.items():
        rows = [vulnerability_row(index, report_date, False) for index in sorted(active_ids)]
        rows.extend(vulnerability_row(index, report_date, True) for index in sorted(closed_ids))
        write_csv(OUT_DIR / f"crowdstrike_vulnerabilities_{month_slug}_100plus.csv", VULNERABILITY_HEADERS, rows)

    july_report_date, july_active, _ = MONTHS["july_2026"]
    per_asset_rows = [vulnerability_row(index, july_report_date, False) for index in sorted(july_active)]
    write_csv(
        OUT_DIR / "crowdstrike_vulnerability_per_asset_july_2026_100plus.csv",
        VULNERABILITY_HEADERS,
        per_asset_rows,
    )
    write_csv(
        OUT_DIR / "crowdstrike_remediation_per_assets_july_2026_100plus.csv",
        REMEDIATION_ASSET_HEADERS,
        [remediation_asset_row(index, july_report_date) for index in range(100)],
    )

    for path in sorted(OUT_DIR.glob("*.csv")):
        print(path)


def vulnerability_row(index: int, report_date: date, closed: bool) -> dict[str, str]:
    template = VULNERABILITIES[index % len(VULNERABILITIES)]
    host_index = index % 45
    severity = ("Critical", "High", "Medium", "Low")[index % 4]
    first_seen = first_seen_date(index)
    exploitable = index % 3 == 0
    cisa_kev = index % 11 == 0
    internet_exposed = index % 5 == 0
    asset_criticality = ("Critical", "High", "Medium", "Low")[host_index % 4]
    base_score = {"Critical": "9.8", "High": "8.1", "Medium": "6.4", "Low": "3.7"}[severity]
    closed_date = report_date - timedelta(days=index % 10) if closed else None
    platform = "Windows" if "Microsoft" in template["product"] or "Chrome" in template["product"] else "Linux"
    exploit_label = ("Actively used", "Critical", "Medium", "Easily accessible")[index % 4] if exploitable else "Unproven"

    return {
        "Hostname": f"cs-asset-{host_index + 1:03d}.corp.example",
        "LocalIP": f"10.40.{host_index // 20 + 1}.{20 + host_index}",
        "HostType": "Server" if host_index % 3 else "Workstation",
        "OSVersion": "Windows Server 2022" if platform == "Windows" else "Ubuntu 22.04 LTS",
        "MachineDomain": "CORP.EXAMPLE",
        "OU": "OU=Production,DC=corp,DC=example",
        "SiteName": ("Dubai-DC", "Abu-Dhabi-DC", "Cloud-AZ1")[host_index % 3],
        "Product": template["product"],
        "CVE ID": template["cve"],
        "CVE Description": template["name"],
        "Status": "Closed" if closed else "Open",
        "Severity": severity,
        "Created Date": first_seen.isoformat(),
        "Closed Date": closed_date.isoformat() if closed_date else "",
        "Closed Dwell Time": str((closed_date - first_seen).days) if closed_date else "",
        "Base Score": base_score,
        "CVSS Version": "3.1",
        "Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "Vendor Advisory": template["link"],
        "References": f"https://nvd.nist.gov/vuln/detail/{template['cve']}",
        "Recommended Remediations": template["remediation"],
        "Remediation Details": f"Patch {template['product']} during the approved change window and capture validation evidence.",
        "Remediation Links": template["link"],
        "Group Names": ("Production Servers", "Internet Services", "Corporate Endpoints")[host_index % 3],
        "Tags": f"owner:team-{host_index % 6 + 1};environment:production",
        "Host ID": f"host-{host_index + 1:05d}",
        "Exploit status value": "1" if exploitable else "0",
        "Exploit status label": exploit_label,
        "Platform": platform,
        "Vulnerable Product Versions": "Detected vulnerable installed version",
        "Closed Product Versions": "Vendor fixed release or later",
        "RemediationLevel": "Patch",
        "ExPRT Rating": ("Critical", "High", "Medium", "Low")[index % 4],
        "Is Suppressed": "False",
        "AdditionalRemediationAdvisoryUrl": template["link"],
        "AdditionalRemediationSteps": "Test in pre-production, deploy, restart if required, and run a verification scan.",
        "Is CISA KEV": "Yes" if cisa_kev else "No",
        "CISA KEV Due Date": (report_date + timedelta(days=14)).isoformat() if cisa_kev else "",
        "CVE Published Date": (first_seen - timedelta(days=45)).isoformat(),
        "Spotlight Published Date": (first_seen - timedelta(days=7)).isoformat(),
        "Host Last Seen Within": report_date.isoformat(),
        "Cloud Service Instance ID": f"i-{host_index + 100000:08d}" if host_index % 4 == 0 else "",
        "OS Build": "20348.2527" if platform == "Windows" else "5.15.0-113-generic",
        "Evaluation logic": f"{template['product']} version matched the vulnerable range for {template['cve']}.",
        "Asset Criticality": asset_criticality,
        "Asset Roles": "Business Critical" if asset_criticality == "Critical" else "Standard",
        "Internet exposure": "Yes" if internet_exposed else "No",
        "Vulnerability ID": f"CS-VULN-{index + 1:06d}",
        "Vulnerability Metadata ID": f"CS-META-{index % len(VULNERABILITIES) + 1:04d}",
        "Managed By": "CrowdStrike Falcon",
        "Vulnerability Data Providers": "CrowdStrike Spotlight",
        "Third-party Asset IDs": f"asset-ext-{host_index + 1:05d}",
        "Third-party Scanner ID": "",
        "Ports": template["port"],
        "Third-party Rating": base_score,
        "Last Scan Time": report_date.isoformat(),
        "Types": "CVE",
        "CID": "sample-cid-001",
        "Customer": "Sample Organization",
        "CWEs": template["cwe"],
        "Vulnerability Confidence": "Confirmed" if index % 5 else "Potential",
        "Asset Confidence": "High",
        "Asset Subsidiaries": "Primary Company",
        "Services Ports": template["port"],
        "Services Transports": template["protocol"],
        "Services Protocols": "HTTPS" if template["port"] == "443" else template["protocol"],
        "Recommended Remediation Patch Publication Date": (first_seen - timedelta(days=10)).isoformat(),
        "Minimum Remediation": template["remediation"],
        "Minimum Remediation Details": "Apply the minimum vendor-supported fixed release.",
        "Minimum Remediation Links": template["link"],
        "Minimum Remediation Advisory URL": template["link"],
        "Minimum Remediation Steps": "Back up configuration, patch, restart, validate service, and rescan.",
        "Patch Publication Date": (first_seen - timedelta(days=10)).isoformat(),
        "Scan ID": f"scan-{report_date:%Y%m}-{index % 4 + 1}",
        "Instance state": "Closed" if closed else "Open",
        "Simplified Evaluation Logic": f"Vulnerable {template['product']} release detected.",
    }


def remediation_asset_row(index: int, report_date: date) -> dict[str, str]:
    template = VULNERABILITIES[index % len(VULNERABILITIES)]
    count = 2 + index % 8
    severity_index = index % 4
    severity_counts = {"Critical": "0", "High": "0", "Medium": "0", "Low": "0", "Unknown": "0"}
    severity_counts[("Critical", "High", "Medium", "Low")[severity_index]] = str(count)
    exploits = index % 4
    host_index = index % 45

    return {
        "Hostname": f"cs-asset-{host_index + 1:03d}.corp.example",
        "LocalIP": f"10.40.{host_index // 20 + 1}.{20 + host_index}",
        "HostType": "Server" if host_index % 3 else "Workstation",
        "OSVersion": "Windows Server 2022" if index % 2 == 0 else "Ubuntu 22.04 LTS",
        "MachineDomain": "CORP.EXAMPLE",
        "OU": "OU=Production,DC=corp,DC=example",
        "SiteName": ("Dubai-DC", "Abu-Dhabi-DC", "Cloud-AZ1")[host_index % 3],
        "RecommendedRemediation": template["remediation"],
        "RemediationDetail": f"Update {template['product']} to the approved fixed release and validate the service.",
        "Products": template["product"],
        "Count": str(count),
        **severity_counts,
        "GroupNames": ("Production Servers", "Internet Services", "Corporate Endpoints")[host_index % 3],
        "Tags": f"owner:team-{host_index % 6 + 1};environment:production",
        "HostID": f"host-{host_index + 1:05d}",
        "Exploits": str(exploits),
        "Platform": "Windows" if index % 2 == 0 else "Linux",
        "ExPRT Critical": str(count if severity_index == 0 and exploits else 0),
        "ExPRT High": str(count if severity_index == 1 and exploits else 0),
        "ExPRT Medium": str(count if severity_index == 2 and exploits else 0),
        "ExPRT Low": str(count if severity_index == 3 and exploits else 0),
        "ExPRT Unknown": "0",
        "AdditionalRemediationAdvisoryUrl": template["link"],
        "AdditionalRemediationSteps": "Test, deploy, restart if required, verify service health, and rescan.",
        "Asset Criticality": ("Critical", "High", "Medium", "Low")[host_index % 4],
        "Asset Roles": "Business Critical" if host_index % 4 == 0 else "Standard",
        "Internet exposure": "Yes" if host_index % 5 == 0 else "No",
        "Managed By": "CrowdStrike Falcon",
        "Data Providers": "CrowdStrike Spotlight",
        "Third-party Asset IDs": f"asset-ext-{host_index + 1:05d}",
        "CID": "sample-cid-001",
        "Customer": "Sample Organization",
        "Recommendation Type": "Patch",
        "Patch Publication Date": (report_date - timedelta(days=20 + index % 120)).isoformat(),
        "Instance state": "Open",
    }


def first_seen_date(index: int) -> date:
    if index < 80:
        return date(2025, 7, 1) + timedelta(days=(index * 5) % 250)
    if index < 110:
        return date(2026, 4, 1) + timedelta(days=(index - 80) % 29)
    if index < 140:
        return date(2026, 5, 1) + timedelta(days=(index - 110) % 30)
    if index < 165:
        return date(2026, 6, 1) + timedelta(days=(index - 140) % 29)
    return date(2026, 7, 1) + timedelta(days=(index - 165) % 30)


def write_csv(path: Path, headers: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    main()
