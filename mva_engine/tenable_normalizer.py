from __future__ import annotations

import csv
import hashlib
import re
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Iterable, Literal

SourceTool = Literal[
    "tenable_sc",
    "tenable_io",
    "qualys_monthly",
    "qualys_adhoc",
    "crowdstrike_vulnerabilities",
    "crowdstrike_remediation_assets",
]


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info", "Unknown"]
AGE_BUCKETS = [">7 days", ">30 days", ">60 days", ">180 days (6+ months)"]


@dataclass(frozen=True)
class NormalizedFinding:
    finding_key: str
    source_tool: SourceTool
    source_vulnerability_id: str
    ip_address: str
    dns_name: str
    vulnerability_name: str
    cve: str
    severity: str
    exploit_available: bool
    exploit_signal: str
    patch_priority: str
    asset_exposure: int
    vulnerability_finding: str
    summary: str
    description: str
    remediation: str
    kb_links: str
    platform_details: str
    first_discovered: str
    last_observed: str
    vulnerability_age_days: int | None
    protocol: str
    port: str
    record_count: int = 1
    status: str = ""
    product: str = ""
    asset_criticality: str = ""
    internet_exposed: bool = False
    cisa_kev: bool = False
    group_names: str = ""
    tags: str = ""
    exploit_rating: str = ""
    export_type: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def detect_source(fieldnames: Iterable[str]) -> SourceTool:
    normalized = {field.strip() for field in fieldnames if field}
    if {"Hostname", "RecommendedRemediation", "RemediationDetail", "Count"} <= normalized:
        return "crowdstrike_remediation_assets"
    if {"Hostname", "CVE ID", "Vulnerability ID", "Exploit status label"} <= normalized:
        return "crowdstrike_vulnerabilities"
    if {"IP Address", "Plugin", "Plugin Name"} & normalized:
        return "tenable_sc"
    if any(field.startswith("definition.") for field in normalized) or any(field.startswith("asset.") for field in normalized):
        return "tenable_io"
    if {"QID", "Title", "Vuln Status"} <= normalized:
        return "qualys_monthly"
    if {"QID", "Title", "CVSS4 Base"} <= normalized:
        return "qualys_adhoc"
    raise ValueError(
        "Unable to detect source. Expected Tenable.sc, Tenable.io, Qualys, or CrowdStrike CSV headers."
    )


def detect_tenable_source(fieldnames: Iterable[str]) -> SourceTool:
    return detect_source(fieldnames)


def load_findings(csv_path: str | Path, source_tool: SourceTool | None = None) -> list[NormalizedFinding]:
    path = Path(csv_path)
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError(f"{path} has no CSV headers")
        detected = source_tool or detect_source(reader.fieldnames)
        return [
            normalize_row(row, detected)
            for row in reader
            if row_is_open(row, detected)
        ]


def normalize_row(row: dict[str, str], source_tool: SourceTool) -> NormalizedFinding:
    if source_tool == "tenable_sc":
        return _normalize_sc_row(row)
    if source_tool == "tenable_io":
        return _normalize_io_row(row)
    if source_tool in {"qualys_monthly", "qualys_adhoc"}:
        return _normalize_qualys_row(row, source_tool)
    if source_tool == "crowdstrike_vulnerabilities":
        return _normalize_crowdstrike_vulnerability_row(row)
    if source_tool == "crowdstrike_remediation_assets":
        return _normalize_crowdstrike_remediation_row(row)
    raise ValueError(f"Unsupported source tool: {source_tool}")


def _normalize_sc_row(row: dict[str, str]) -> NormalizedFinding:
    severity = normalize_severity(_pick(row, "Severity", "Risk Factor"))
    exploit_signal = _pick(row, "Exploit?", "Exploit Ease", "Exploit Frameworks")
    exploit_available = is_exploit_available(exploit_signal)
    plugin_id = _pick(row, "Plugin", "Plugin ID")
    name = _pick(row, "Plugin Name", "Synopsis")
    ip = _pick(row, "IP Address")
    dns = _pick(row, "DNS Name", "NetBIOS Name")
    cve = clean_multi_value(_pick(row, "CVE"))
    protocol = _pick(row, "Protocol")
    port = _pick(row, "Port")

    return NormalizedFinding(
        finding_key=build_finding_key("tenable_sc", ip, plugin_id or name, cve, protocol, port),
        source_tool="tenable_sc",
        source_vulnerability_id=plugin_id,
        ip_address=ip,
        dns_name=dns,
        vulnerability_name=name,
        cve=cve,
        severity=severity,
        exploit_available=exploit_available,
        exploit_signal=exploit_signal,
        patch_priority=calculate_patch_priority(severity, exploit_available),
        asset_exposure=calculate_asset_exposure(severity, exploit_available, _pick(row, "Vulnerability Priority Rating"), _pick(row, "ACR"), _pick(row, "AES")),
        vulnerability_finding=_pick(row, "Plugin Output"),
        summary=_pick(row, "Synopsis"),
        description=_pick(row, "Description"),
        remediation=_pick(row, "Steps to Remediate"),
        kb_links=_pick(row, "See Also", "Cross References"),
        platform_details=_pick(row, "CPE", "Repository", "Family"),
        first_discovered=normalize_date_string(_pick(row, "First Discovered")),
        last_observed=normalize_date_string(_pick(row, "Last Observed")),
        vulnerability_age_days=None,
        protocol=protocol,
        port=port,
    )


def _normalize_io_row(row: dict[str, str]) -> NormalizedFinding:
    severity = normalize_severity(_pick(row, "definition.severity", "severity"))
    exploit_signal = _pick(
        row,
        "definition.exploitability_ease",
        "definition.exploited_by_malware",
        "definition.exploited_by_nessus",
        "definition.vpr_v2.drivers_exploit_code_maturity",
        "definition.vpr_v2.drivers_exploit_probability",
    )
    exploit_available = is_exploit_available(exploit_signal)
    vulnerability_id = _pick(row, "definition.id", "id")
    name = _pick(row, "definition.name")
    ip = _pick(row, "asset.display_ipv4_address", "asset.ipv4_addresses", "scan.target")
    dns = _pick(row, "asset.display_fqdn", "asset.host_name", "asset.name", "asset.netbios_name")
    cve = clean_multi_value(_pick(row, "definition.cve"))
    protocol = _pick(row, "protocol")
    port = _pick(row, "port")
    os_details = _pick(row, "asset.operating_system", "asset.operating_systems", "asset.system_type")

    return NormalizedFinding(
        finding_key=build_finding_key("tenable_io", ip, vulnerability_id or name, cve, protocol, port),
        source_tool="tenable_io",
        source_vulnerability_id=vulnerability_id,
        ip_address=ip,
        dns_name=dns,
        vulnerability_name=name,
        cve=cve,
        severity=severity,
        exploit_available=exploit_available,
        exploit_signal=exploit_signal,
        patch_priority=calculate_patch_priority(severity, exploit_available),
        asset_exposure=calculate_asset_exposure(severity, exploit_available, _pick(row, "definition.vpr.score", "definition.vpr_v2.score")),
        vulnerability_finding=_pick(row, "output"),
        summary=_pick(row, "definition.synopsis"),
        description=_pick(row, "definition.description"),
        remediation=_pick(row, "definition.solution", "definition.workaround"),
        kb_links=_pick(row, "definition.see_also", "definition.references"),
        platform_details=os_details,
        first_discovered=normalize_date_string(_pick(row, "first_observed")),
        last_observed=normalize_date_string(_pick(row, "last_seen")),
        vulnerability_age_days=parse_int(_pick(row, "vuln_age", "age_in_days")),
        protocol=protocol,
        port=port,
    )


def _normalize_qualys_row(row: dict[str, str], source_tool: SourceTool) -> NormalizedFinding:
    severity = normalize_qualys_severity(_pick(row, "Severity"))
    exploit_signal = join_values(
        _pick(row, "Exploitability"),
        _pick(row, "Associated Malware"),
    )
    exploit_available = is_exploit_available(exploit_signal)
    qid = _pick(row, "QID")
    name = _pick(row, "Title")
    ip = _pick(row, "IP")
    dns = _pick(row, "FQDN", "DNS", "NetBIOS")
    cve = clean_multi_value(_pick(row, "CVE ID"))
    protocol = _pick(row, "Protocol")
    port = _pick(row, "Port")
    first_detected = _pick(row, "First Detected")
    last_detected = _pick(row, "Last Detected")
    platform_details = join_values(
        _pick(row, "OS"),
        _pick(row, "Category"),
        _pick(row, "Instance"),
    )
    kb_links = join_values(
        _pick(row, "Vendor Reference"),
        _pick(row, "Bugtraq ID"),
    )

    return NormalizedFinding(
        finding_key=build_finding_key(source_tool, ip, qid or name, cve, protocol, port),
        source_tool=source_tool,
        source_vulnerability_id=qid,
        ip_address=ip,
        dns_name=dns,
        vulnerability_name=name,
        cve=cve,
        severity=severity,
        exploit_available=exploit_available,
        exploit_signal=exploit_signal,
        patch_priority=calculate_patch_priority(severity, exploit_available),
        asset_exposure=calculate_asset_exposure(
            severity,
            exploit_available,
            _pick(row, "CVSS4 Base"),
            _pick(row, "CVSS3.1 Base"),
            _pick(row, "CVSS Base"),
        ),
        vulnerability_finding=_pick(row, "Results"),
        summary=_pick(row, "Threat", "Title"),
        description=_pick(row, "Impact", "Threat"),
        remediation=_pick(row, "Solution"),
        kb_links=kb_links,
        platform_details=platform_details,
        first_discovered=normalize_date_string(first_detected),
        last_observed=normalize_date_string(last_detected),
        vulnerability_age_days=None,
        protocol=protocol,
        port=port,
    )


def _normalize_crowdstrike_vulnerability_row(row: dict[str, str]) -> NormalizedFinding:
    severity = normalize_severity(_pick(row, "Severity", "Third-party Rating"))
    exploit_status = join_values(
        _pick(row, "Exploit status label"),
        _pick(row, "Exploit status value"),
    )
    cisa_kev = is_truthy(_pick(row, "Is CISA KEV"))
    exploit_available = is_exploit_available(exploit_status) or cisa_kev
    exploit_rating = _pick(row, "ExPRT Rating")
    vulnerability_id = _pick(row, "Vulnerability ID", "Vulnerability Metadata ID", "CVE ID")
    cve = clean_multi_value(_pick(row, "CVE ID"))
    ip = _pick(row, "LocalIP")
    hostname = _pick(row, "Hostname")
    host_id = _pick(row, "Host ID", "Third-party Asset IDs")
    protocol = _pick(row, "Services Transports", "Services Protocols")
    port = _pick(row, "Ports", "Services Ports")
    product = _pick(row, "Product")
    internet_exposed = is_truthy(_pick(row, "Internet exposure"))
    asset_criticality = _pick(row, "Asset Criticality")
    remediation = join_values(
        _pick(row, "Recommended Remediations"),
        _pick(row, "Remediation Details"),
        _pick(row, "Minimum Remediation"),
        _pick(row, "Minimum Remediation Details"),
        _pick(row, "AdditionalRemediationSteps"),
    )
    kb_links = join_values(
        _pick(row, "Remediation Links"),
        _pick(row, "Minimum Remediation Links"),
        _pick(row, "Minimum Remediation Advisory URL"),
        _pick(row, "AdditionalRemediationAdvisoryUrl"),
        _pick(row, "Vendor Advisory"),
        _pick(row, "References"),
    )

    return NormalizedFinding(
        finding_key=build_finding_key(
            "crowdstrike_vulnerabilities",
            ip or host_id or hostname,
            vulnerability_id,
            cve,
            protocol,
            port,
        ),
        source_tool="crowdstrike_vulnerabilities",
        source_vulnerability_id=vulnerability_id,
        ip_address=ip,
        dns_name=hostname,
        vulnerability_name=_pick(row, "CVE Description", "CVE ID", "Vulnerability ID"),
        cve=cve,
        severity=severity,
        exploit_available=exploit_available,
        exploit_signal=exploit_status or ("CISA KEV" if cisa_kev else ""),
        patch_priority=calculate_patch_priority(severity, exploit_available),
        asset_exposure=calculate_crowdstrike_exposure(
            severity=severity,
            exploit_available=exploit_available,
            base_score=_pick(row, "Base Score"),
            asset_criticality=asset_criticality,
            internet_exposed=internet_exposed,
            cisa_kev=cisa_kev,
        ),
        vulnerability_finding=_pick(row, "Simplified Evaluation Logic", "Evaluation logic"),
        summary=_pick(row, "CVE Description"),
        description=join_values(
            _pick(row, "Evaluation logic"),
            _pick(row, "Vulnerable Product Versions"),
        ),
        remediation=remediation,
        kb_links=kb_links,
        platform_details=join_values(
            _pick(row, "Platform"),
            _pick(row, "OSVersion"),
            _pick(row, "OS Build"),
            product,
        ),
        first_discovered=normalize_date_string(_pick(row, "Created Date")),
        last_observed=normalize_date_string(
            _pick(row, "Last Scan Time", "Host Last Seen Within", "Spotlight Published Date")
        ),
        vulnerability_age_days=None,
        protocol=protocol,
        port=port,
        status=_pick(row, "Status", "Instance state"),
        product=product,
        asset_criticality=asset_criticality,
        internet_exposed=internet_exposed,
        cisa_kev=cisa_kev,
        group_names=_pick(row, "Group Names"),
        tags=_pick(row, "Tags"),
        exploit_rating=exploit_rating,
        export_type="Vulnerabilities / Vulnerability per asset",
    )


def _normalize_crowdstrike_remediation_row(row: dict[str, str]) -> NormalizedFinding:
    severity = _crowdstrike_aggregate_severity(row)
    exploit_signal = _pick(row, "Exploits")
    if not exploit_signal:
        exploit_signal = join_values(
            f"ExPRT Critical={_pick(row, 'ExPRT Critical')}",
            f"ExPRT High={_pick(row, 'ExPRT High')}",
        )
    exploit_available = is_exploit_available(_pick(row, "Exploits"))
    ip = _pick(row, "LocalIP")
    hostname = _pick(row, "Hostname")
    host_id = _pick(row, "HostID", "Third-party Asset IDs")
    remediation_name = _pick(row, "RecommendedRemediation", "Recommendation Type")
    product = _pick(row, "Products")
    internet_exposed = is_truthy(_pick(row, "Internet exposure"))
    asset_criticality = _pick(row, "Asset Criticality")
    count = max(1, parse_int(_pick(row, "Count")) or 1)

    return NormalizedFinding(
        finding_key=build_finding_key(
            "crowdstrike_remediation_assets",
            ip or host_id or hostname,
            remediation_name,
            "",
            "",
            product,
        ),
        source_tool="crowdstrike_remediation_assets",
        source_vulnerability_id=remediation_name,
        ip_address=ip,
        dns_name=hostname,
        vulnerability_name=remediation_name,
        cve="",
        severity=severity,
        exploit_available=exploit_available,
        exploit_signal=exploit_signal,
        patch_priority=calculate_patch_priority(severity, exploit_available),
        asset_exposure=calculate_crowdstrike_exposure(
            severity=severity,
            exploit_available=exploit_available,
            base_score="",
            asset_criticality=asset_criticality,
            internet_exposed=internet_exposed,
            cisa_kev=False,
        ),
        vulnerability_finding=_pick(row, "RemediationDetail"),
        summary=remediation_name,
        description=_pick(row, "AdditionalRemediationSteps", "RemediationDetail"),
        remediation=join_values(
            remediation_name,
            _pick(row, "RemediationDetail"),
            _pick(row, "AdditionalRemediationSteps"),
        ),
        kb_links=_pick(row, "AdditionalRemediationAdvisoryUrl"),
        platform_details=join_values(
            _pick(row, "Platform"),
            _pick(row, "OSVersion"),
            product,
        ),
        first_discovered="",
        last_observed=normalize_date_string(_pick(row, "Patch Publication Date")),
        vulnerability_age_days=None,
        protocol="",
        port="",
        record_count=count,
        status=_pick(row, "Instance state"),
        product=product,
        asset_criticality=asset_criticality,
        internet_exposed=internet_exposed,
        cisa_kev=False,
        group_names=_pick(row, "GroupNames"),
        tags=_pick(row, "Tags"),
        exploit_rating=join_values(
            _pick(row, "ExPRT Critical"),
            _pick(row, "ExPRT High"),
            _pick(row, "ExPRT Medium"),
            _pick(row, "ExPRT Low"),
        ),
        export_type="Remediation per assets",
    )


def calculate_patch_priority(severity: str, exploit_available: bool) -> str:
    severity = severity.title()
    if exploit_available:
        return {"Critical": "P1", "High": "P1", "Medium": "P2", "Low": "P2"}.get(severity, "P4")
    return {"Critical": "P2", "High": "P2", "Medium": "P3", "Low": "P4"}.get(severity, "P4")


def is_exploit_available(value: str) -> bool:
    text = clean_text(value).lower()
    if not text:
        return False
    negative_tokens = {
        "0",
        "false",
        "n",
        "no",
        "none",
        "not available",
        "unavailable",
        "unproven",
        "no known exploits",
        "no exploit",
        "not exploitable",
    }
    if text in negative_tokens:
        return False
    if any(
        token in text
        for token in (
            "available",
            "confirmed",
            "weaponized",
            "exploited",
            "exploitable",
            "exploit code",
            "functional",
            "high",
            "proof-of-concept",
            "poc",
            "true",
            "yes",
        )
    ):
        return True
    return bool(re.search(r"\b[1-9](?:\.\d+)?\b", text))


def normalize_severity(value: str) -> str:
    text = clean_text(value)
    if not text:
        return "Unknown"
    numeric_map = {"0": "Info", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"}
    lower = text.lower()
    if lower in numeric_map:
        return numeric_map[lower]
    for severity in SEVERITY_ORDER:
        if lower == severity.lower():
            return severity
    if "crit" in lower:
        return "Critical"
    if "high" in lower:
        return "High"
    if "med" in lower:
        return "Medium"
    if "low" in lower:
        return "Low"
    if "info" in lower:
        return "Info"
    return "Unknown"


def normalize_qualys_severity(value: str) -> str:
    text = clean_text(value)
    if not text:
        return "Unknown"
    lower = text.lower()
    numeric_map = {"0": "Info", "1": "Info", "2": "Low", "3": "Medium", "4": "High", "5": "Critical"}
    if lower in numeric_map:
        return numeric_map[lower]
    return normalize_severity(text)


def row_is_open(row: dict[str, str], source_tool: SourceTool) -> bool:
    if source_tool == "crowdstrike_vulnerabilities":
        status = clean_text(row.get("Status")).lower()
        instance_state = clean_text(row.get("Instance state")).lower()
        suppressed = is_truthy(row.get("Is Suppressed"))
        closed_tokens = {"closed", "fixed", "resolved", "remediated", "inactive"}
        return not suppressed and status not in closed_tokens and instance_state not in closed_tokens

    if source_tool != "qualys_monthly":
        return True
    status = clean_text(row.get("Vuln Status")).lower()
    if not status:
        return True
    closed_tokens = {"fixed", "closed", "resolved", "remediated", "ignored"}
    return status not in closed_tokens


def calculate_asset_exposure(severity: str, exploit_available: bool, *score_candidates: str) -> int:
    for candidate in score_candidates:
        number = parse_float(candidate)
        if number is None:
            continue
        if number <= 10:
            return max(0, min(1000, round(number * 100)))
        return max(0, min(1000, round(number)))

    severity_base = {"Critical": 900, "High": 720, "Medium": 480, "Low": 220, "Info": 80}.get(severity, 120)
    return min(1000, severity_base + (80 if exploit_available else 0))


def calculate_crowdstrike_exposure(
    *,
    severity: str,
    exploit_available: bool,
    base_score: str,
    asset_criticality: str,
    internet_exposed: bool,
    cisa_kev: bool,
) -> int:
    score = parse_float(base_score)
    if score is None:
        exposure = {
            "Critical": 760,
            "High": 610,
            "Medium": 410,
            "Low": 190,
            "Info": 70,
        }.get(severity, 120)
    else:
        exposure = round(score * 75) if score <= 10 else round(score * 0.75)

    criticality = clean_text(asset_criticality).lower()
    criticality_bonus = 110 if "critical" in criticality else 70 if "high" in criticality else 35 if "medium" in criticality else 0
    signal_bonus = (90 if exploit_available else 0) + (80 if cisa_kev else 0) + (65 if internet_exposed else 0)
    return max(0, min(1000, exposure + criticality_bonus + signal_bonus))


def is_truthy(value: object) -> bool:
    text = clean_text(value).lower()
    return text in {"1", "true", "yes", "y", "available", "exposed", "internet exposed"}


def _crowdstrike_aggregate_severity(row: dict[str, str]) -> str:
    for severity in ("Critical", "High", "Medium", "Low", "Unknown"):
        if (parse_int(_pick(row, severity)) or 0) > 0:
            return severity
    return "Unknown"


def build_finding_key(source_tool: SourceTool, ip: str, vulnerability_id: str, cve: str, protocol: str, port: str) -> str:
    del source_tool  # SC and IO exports for the same asset/vulnerability should match month-to-month.
    key_parts = [
        clean_text(ip).lower(),
        clean_text(vulnerability_id).lower(),
        clean_text(cve).lower(),
        clean_text(protocol).lower(),
        clean_text(port).lower(),
    ]
    raw_key = "|".join(key_parts)
    return hashlib.sha1(raw_key.encode("utf-8")).hexdigest()[:16]


def age_in_days(finding: NormalizedFinding, as_of: date | None = None) -> int | None:
    if finding.vulnerability_age_days is not None:
        return max(0, finding.vulnerability_age_days)
    discovered = parse_date(finding.first_discovered)
    if not discovered:
        return None
    anchor = as_of or date.today()
    return max(0, (anchor - discovered.date()).days)


def age_bucket_flags(days: int | None) -> dict[str, bool]:
    if days is None:
        return {bucket: False for bucket in AGE_BUCKETS}
    return {
        ">7 days": days > 7,
        ">30 days": days > 30,
        ">60 days": days > 60,
        ">180 days (6+ months)": days > 180,
    }


def parse_date(value: str) -> datetime | None:
    text = clean_text(value)
    if not text:
        return None
    cleaned = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(cleaned)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        pass

    formats = [
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%m/%d/%Y",
        "%d/%m/%Y",
        "%b %d, %Y",
        "%B %d, %Y",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M",
        "%d/%m/%Y %H:%M",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def normalize_date_string(value: str) -> str:
    parsed = parse_date(value)
    return parsed.date().isoformat() if parsed else clean_text(value)


def clean_multi_value(value: str) -> str:
    text = clean_text(value)
    if not text:
        return ""
    parts = re.split(r"[,;\s]+", text)
    cves = [part.strip() for part in parts if part.strip()]
    return ", ".join(dict.fromkeys(cves))


def join_values(*values: str) -> str:
    return " | ".join(value for value in (clean_text(item) for item in values) if value)


def parse_float(value: str) -> float | None:
    text = clean_text(value)
    if not text:
        return None
    match = re.search(r"-?\d+(?:\.\d+)?", text)
    if not match:
        return None
    return float(match.group(0))


def parse_int(value: str) -> int | None:
    number = parse_float(value)
    return None if number is None else int(number)


def clean_text(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _pick(row: dict[str, str], *keys: str) -> str:
    for key in keys:
        value = clean_text(row.get(key))
        if value:
            return value
    return ""
