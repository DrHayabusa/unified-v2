# Field-to-Dashboard Mapping and Calculation Rules

This document is the authoritative data dictionary for MVA. It describes which source fields feed each normalized field, dashboard, workbook, and PDF.

## 1. Canonical Finding

Every supported scanner is mapped to this common record:

| Canonical field | Purpose |
|---|---|
| `ipAddress` | Primary network identity |
| `dnsName` | DNS/FQDN/host identity |
| `vulnerabilityName` | Human-readable vulnerability title |
| `sourceVulnerabilityId` | Plugin, QID, definition ID, or scanner ID |
| `cve` | One or more CVE identifiers |
| `severity` | Critical, High, Medium, Low, Info, or Unknown |
| `exploitAvailable` | Deterministic scanner-evidence boolean |
| `exploitSignal` | Original exploit evidence retained for audit |
| `patchPriority` | P1-P4 from the approved matrix |
| `assetExposure` | Source score normalized to 0-1000, or deterministic fallback |
| `vulnerabilityFinding` | Scanner/plugin output |
| `summary` | Short source summary or threat text |
| `description` | Technical source description or impact text |
| `remediation` | Source solution/remediation |
| `kbLinks` | Vendor, KB, advisory, and reference links |
| `platformDetails` | OS, product, CPE, category, repository, or family |
| `firstDiscovered` | First known date |
| `lastObserved` | Latest observed date |
| `vulnerabilityAgeDays` | Native source age or calculated age |
| `protocol` / `port` | Service identity |
| `recordCount` | Weighted count for aggregated exports |
| `status` | Source lifecycle state |
| `datacentre` | Customer-supplied Qualys location category |
| `timesDetected` | Qualys historic observation count |
| `vendorSeverityLabel` | Original standard/custom rating label |
| `vulnerabilityConfidence` | CrowdStrike Confirmed/Potential evidence |
| `exploitEvidenceSource` | CrowdStrike field that established exploit availability |
| `threat` / `impact` | Qualys threat and impact text |
| `namespace` / `deployment` | OpenShift workload identity |
| `image` / `component` | OpenShift container and package identity |
| `fixable` / `fixedIn` | OpenShift remediation availability evidence |
| `cvssScore` | OpenShift numeric CVSS evidence |
| `sourceTools` | All scanners contributing to a consolidated finding |

## 2. Tenable.sc Mapping

| Canonical field | Tenable.sc field |
|---|---|
| IP | `IP Address` |
| DNS | `DNS Name`, fallback `NetBIOS Name` |
| Vulnerability name | `Plugin Name`, fallback `Synopsis` |
| Source ID | `Plugin`, fallback `Plugin ID` |
| CVE | `CVE` |
| Severity | `Severity`, fallback `Risk Factor` |
| Exploit evidence | First supplied of `Exploit?`, `Exploit Ease`, `Exploit Frameworks` |
| EPSS | `Exploit Prediction Scoring System (EPSS)` |
| Exposure | `Vulnerability Priority Rating`, `ACR`, `AES`, then deterministic fallback |
| Finding | `Plugin Output` |
| Summary | `Synopsis` |
| Description | `Description` |
| Remediation | `Steps to Remediate` |
| References | `See Also`, fallback `Cross References` |
| Platform | `CPE`, `Repository`, `Family` |
| First discovered | `First Discovered` |
| Last observed | `Last Observed` |
| Service | `Protocol`, `Port` |

## 3. Tenable.io Mapping

| Canonical field | Tenable.io field |
|---|---|
| IP | `asset.display_ipv4_address`, `asset.ipv4_addresses`, `scan.target` |
| DNS | `asset.display_fqdn`, `asset.host_name`, `asset.name`, `asset.netbios_name` |
| Vulnerability name | `definition.name` |
| Source ID | `definition.id`, fallback `id` |
| CVE | `definition.cve` |
| Severity | `definition.severity`, fallback `severity` |
| Exploit evidence | `definition.exploitability_ease`, malware/Nessus exploit evidence, VPR exploit maturity |
| EPSS | `definition.epss.score` |
| Exposure | `definition.vpr.score`, `definition.vpr_v2.score`, then deterministic fallback |
| Finding | `output` |
| Summary | `definition.synopsis` |
| Description | `definition.description` |
| Remediation | `definition.solution`, fallback `definition.workaround` |
| References | `definition.see_also`, `definition.references` |
| Platform | `asset.operating_system`, `asset.operating_systems`, `asset.system_type` |
| First discovered | `first_observed` |
| Last observed | `last_seen` |
| Native age | `vuln_age`, fallback `age_in_days` |
| Service | `protocol`, `port` |

## 4. Qualys VMDR Mapping

MVA treats header case as insignificant, so `Threat`, `threat`, `Impact`, and `impact` map correctly.

| Canonical field | Qualys field/rule |
|---|---|
| IP | `IP` |
| DNS | `FQDN`, `DNS`, `NetBIOS` |
| Vulnerability name | `Title` |
| Source ID | `QID` |
| CVE | `CVE ID` |
| Severity | `Severity` |
| Exploit available | **True only when `Exploitability` contains non-whitespace text** |
| Exploit evidence | Original `Exploitability` text/reference |
| Exposure | `CVSS4 Base`, `CVSS3.1 Base`, `CVSS Base`, then deterministic fallback |
| Finding | `Results` |
| Summary | Case-insensitive `Threat`, fallback `Title` |
| Description | Case-insensitive `Impact`, fallback `Threat` |
| Remediation | `Solution` |
| References | `Vendor Reference`, `Bugtraq ID` |
| Platform | `OS`, `Category`, `Instance` |
| First discovered | `First Detected` |
| Last observed | `Last Detected` |
| Status | `Vuln Status` |
| Datacentre | `Datacentre`, `Data Centre`, `Data Center` |
| Detection history | `Times Detected` |
| Service | `Protocol`, `Port` |

Qualys row inclusion:

- `Type` may be empty or `VUL`/`VULN`/`Vulnerability`.
- `Fixed`, `Closed`, `Resolved`, `Remediated`, `Ignored`, and `Inactive` statuses are excluded from current open posture.
- `New`, `Active`, and `Re-Opened` remain open and are retained for lifecycle analysis.
- A blank `Exploitability` field is **No exploit evidence**.
- Any non-empty `Exploitability` text or reference is **Exploit available**. MVA does not expect `Yes`/`No`.

### Standard Qualys severity

| Source rating | Canonical severity |
|---:|---|
| 5 | Critical |
| 4 | High |
| 3 | Medium |
| 2 | Low |
| 1 | Info / Minimal |

### Custom Qualys severity

| Customer rating | Preserved label | Canonical severity for P1-P4 |
|---:|---|---|
| 5 | Urgent | Critical |
| 4 | Critical | Critical |
| 3 | Serious | High |
| 2 | Medium | Medium |
| 1 | Minimal | Low |

The preserved label is displayed separately so no customer meaning is lost when the common matrix is applied.

## 5. CrowdStrike Mapping

| Canonical field | CrowdStrike field |
|---|---|
| IP | `LocalIP` |
| DNS | `Hostname` |
| Vulnerability name | `CVE Description`, `CVE ID`, `Vulnerability ID` |
| Source ID | `Vulnerability ID`, `Vulnerability Metadata ID`, `CVE ID` |
| CVE | `CVE ID` |
| Severity | `Severity`, fallback `Third-party Rating` |
| Confidence | `Vulnerability Confidence` |
| Product | `Product` |
| Internet exposure | `Internet exposure` only when supplied |
| Asset criticality | `Asset Criticality` |
| Finding | `Simplified Evaluation Logic`, `Evaluation logic` |
| Description | `Evaluation logic`, `Vulnerable Product Versions` |
| Remediation | Recommended, minimum, details, and additional-remediation fields |
| References | Remediation, minimum-remediation, advisory, vendor, and reference URLs |
| Platform | `Platform`, `OSVersion`, `OS Build`, `Product` |
| First discovered | `Created Date` |
| Last observed | `Last Scan Time`, `Host Last Seen Within`, `Spotlight Published Date` |
| Status | `Status`, `Instance state` |
| Service | transport/protocol and port fields |

### CrowdStrike exploit decision

MVA evaluates fields in this order:

1. `Exploit status label`
2. `Exploit status value` only when the label is absent
3. `ExPRT Rating` only when label and value are absent

Positive label evidence includes scanner terms such as:

```text
Actively Used
Actively Exploited
Critical
Medium
Easily Accessible
Weaponized
Functional
Proof-of-Concept
Exploit Available
```

Explicit negative terms include:

```text
Unproven
Not Available
Unavailable
No Known Exploit
No Exploit
None
False
Unknown
```

`Vulnerability Confidence` is not converted into exploit availability. It is retained as a separate Confirmed/Potential finding-quality signal.

For the aggregate `Remediation per assets` format:

- severity is the highest non-zero Critical/High/Medium/Low count;
- `Exploits` provides exploit availability;
- `Count` is the weighted record count;
- the format is valid for ad hoc aggregate analysis, not per-asset monthly lifecycle.

## 6. Red Hat OpenShift Mapping

The supported OpenShift export is detected only from the supplied workload schema:

```text
Namespace, Deployment, Image, Component, CVE, Fixable, CVE Fixed In,
Severity, CVSS, Discovered At, Reference
```

| Canonical field | OpenShift field/rule |
|---|---|
| Workload identity | `Namespace` + `Deployment` |
| Consolidation asset key | `Namespace` + `Deployment` + `Image` |
| Vulnerability name | `Component` + `CVE` |
| Source ID | `CVE`, fallback `Component` |
| CVE | `CVE` |
| Severity | `Severity` |
| Exploit available | Always false for this schema because no exploit field is supplied |
| Exposure | Severity + `CVSS` deterministic 0-1000 calculation |
| Finding | `Image`, `Component`, and `CVE Fixed In` |
| Description/platform | `Namespace`, `Deployment`, `Image`, `Component` |
| Remediation | Generated from `Fixable` and `CVE Fixed In` |
| References | `Reference` |
| First/last observed | `Discovered At` |
| Fix availability | True when `Fixable` is affirmative or `CVE Fixed In` is populated |

Critical OpenShift findings therefore map to P2 and high findings to P2 unless a future, explicitly mapped source field provides positive exploit evidence. A fixable package does not imply a public or functional exploit.

OpenShift dashboards also show fixable findings, fixed-version coverage, no-fixed-version findings, namespace count, deployment count, image count, component count, and top namespace/component/image distributions.

## 7. Universal Custom Parser

The custom parser accepts CSV or XLSX and auto-suggests common aliases for:

```text
IP address
DNS name
Vulnerability name
Source vulnerability ID
CVE
Severity
Exploit evidence
Status
Datacentre
Times detected
Vulnerability confidence
Summary
Description
Remediation
KB links
Platform details
First discovered
Last observed
Vulnerability age
Finding output
Protocol
Port
```

Required logical mappings:

- at least one asset identity: IP or DNS;
- at least one vulnerability identity: CVE, source ID, or vulnerability name;
- severity.

Exploit interpretation options:

- **Boolean labels**: parse explicit positive and negative words.
- **Evidence presence**: any non-empty value means available.

Severity options:

- automatic/common Critical-High-Medium-Low;
- standard Qualys;
- custom Qualys.

The mapper validates required selections before analysis and never guesses a required field after the user rejects the suggestion.

## 8. Finding Identity and Multi-Tool Consolidation

The normalized finding key is:

```text
asset identity
| vulnerability identity
| CVE
| protocol
| port or product
```

Rules:

- Same asset + different vulnerability = two findings.
- Same vulnerability + different asset = two findings.
- Same asset/vulnerability + different port/service = two findings.
- Same asset/vulnerability/service from multiple scanners = one consolidated finding with all source tools retained.
- Highest severity, exploit-positive evidence, earliest first-discovered, latest last-observed, and strongest available remediation/reference evidence are retained.
- The patch priority is recalculated after consolidation.

## 9. Patch Priority Calculation

| Exploit available | Critical | High | Medium | Low |
|---|---:|---:|---:|---:|
| Yes | P1 | P1 | P2 | P2 |
| No | P2 | P2 | P3 | P4 |

`Info` and `Unknown` default to P4.

Immediate Patch Needed is:

```text
P1 count + P2 count
```

## 10. Required Monthly Dashboard Formulas

Let:

- `P` = previous-period finding map;
- `C` = current-period finding map;
- `w(key, period)` = weighted record count for one normalized finding key.

### New vulnerabilities

```text
sum(max(0, w(key, C) - w(key, P)))
```

### Not closed from previous period

```text
sum(min(w(key, P), w(key, C)))
```

### Total open

```text
New + Not closed
```

The engine validates this identity before displaying the dashboard.

### Patched / no longer observed

User-approved arithmetic:

```text
Previous total open + New this period - Current total open
```

The result is also independently reconciled as:

```text
sum(max(0, w(key, P) - w(key, C)))
```

MVA labels the operational evidence carefully: a finding absent from the latest scan requires coverage/change validation before final closure.

### Vulnerabilities discovered in last three periods

For each of the latest three uploaded periods:

```text
sum(recordCount where First Discovered belongs to that reporting period)
```

Displayed as a line chart.

### Vulnerabilities remediated in last three period transitions

For each of the latest three available transitions:

```text
sum(max(0, previous count - current count))
```

Displayed as a separate line chart.

### Total open by patch priority

```text
P1 + P2 + P3 + P4 = Current total open
```

### Age by priority

Each threshold is cumulative:

| Threshold | Test |
|---|---|
| `>7 days` | age > 7 |
| `>30 days` | age > 30 |
| `>60 days` | age > 60 |
| `>180 days (6+ months)` | age > 180 |

Age source order:

1. Native Tenable.io `vuln_age` or `age_in_days`.
2. `report date - First Discovered`.
3. Unknown when neither is supplied.

For each priority, counts must be monotonically non-increasing:

```text
>7 >= >30 >= >60 >= >180
```

## 11. Browser Dashboards

### Tenant dashboard

| Dashboard | Inputs |
|---|---|
| Total open/new/fixed/repeated | Latest and previous ready normalized findings |
| Severity posture | Canonical severity |
| Patch-priority posture | Canonical P1-P4 |
| Open age by priority | Age and P1-P4 |
| Trend | Saved report periods |
| Top affected assets | Distinct asset identity and weighted findings |
| Responsible team posture | Asset-to-team assignment plus active findings |
| Inventory coverage | In-scope assets versus matched scan identities |

### Ad hoc

| Dashboard | Inputs |
|---|---|
| Total, severity, exploit, immediate patch | Current normalized findings |
| P1-P4 distribution | Current matrix result |
| Top 10 affected assets | Current asset counts |
| Remediation queue | Priority, exposure, identity, and evidence |
| Qualys insights | Datacentre, status, Times Detected, rating, exploit evidence |
| CrowdStrike insights | Exploit source, confidence, supplied internet exposure |
| OpenShift insights | Fix availability, fixed version, namespace, deployment, image, and component evidence |
| Data quality | Completeness of canonical evidence |
| Remediation campaigns | CVE/name grouping, assets, actions, references |

### Monthly

The browser contains exactly the five required customer comparison groups:

1. Discovered line chart, latest three periods.
2. Total open = new + not closed.
3. Total open by P1-P4.
4. Cumulative age-by-priority matrix.
5. Patched summary and remediated line chart.

Supporting tables show the source period counts used by those charts.

### Quarterly

Quarterly uses one current scan result that contains up to the latest three months of first-discovered dates. It does not require artificial quarter baselines. A future phase may add true quarter-over-quarter comparison.

### Unified multi-tool

| Dashboard | Meaning |
|---|---|
| Consolidated analysis | Total/new/patched/P1-P4 across selected scanner sources |
| Multi-tool confirmation | Same normalized finding observed by more than one selected scanner |
| Single-source findings | Findings currently supported by one scanner |
| Per-source contribution | Open, affected assets, exploit, immediate patch, exclusive/confirmed |
| Top risk assets | Assets ranked by immediate priority, severity, exploit, exposure, and count |
| Top vulnerabilities | Vulnerabilities ranked by the same evidence across assets |

Confirmation is an evidence-depth indicator, not a correctness score and not a reason to remove a finding.

### Asset validation and discovery

| Dashboard | Inputs |
|---|---|
| In-scope inventory | Approved tenant assets |
| Host-discovered assets | Parsed host discovery IP/DNS for one to five periods |
| Vulnerability-scan assets | Latest saved normalized scan identities |
| Confirmed by both | Inventory asset matched in discovery and vulnerability scan |
| Not discovered | Inventory minus host discovery |
| Discovered, not scanned | Host discovery minus vulnerability scan |
| Scan-only identity | Vulnerability scan minus host discovery |
| Monthly coverage line | Discovered inventory percentage by reporting period |
| Never/consistently discovered | Per-asset history across uploaded periods |

Every listed population can be downloaded as a separate CSV without changing the customer workbook.

## 12. Excel Output

Customer workbooks intentionally remain focused:

| Sheet | Included |
|---|---|
| `Cover Page` | Help AG branded title, source, period, and report contents |
| `Executive Dashboard` | Severity, P1-P4, immediate-patch KPIs, and executive observations |
| `Monthly Report` | Required five monthly dashboards and compact source tables |
| `Adhoc Report` | Current posture, P1-P4, and top affected assets |
| `Quarterly Report` | Current posture and three-month discovery trend |
| `Unified Dashboard` | Added only for selected multi-tool analysis |
| `Briefing` | Priority summary, urgent actions, approved matrix, and calculation notes |
| `Top Vulnerable Assets` | Ranked assets and chart |
| `Top Vulnerabilities` | Ranked vulnerabilities and chart |
| `Report Data` | Normalized customer finding rows |
| `Source Audit` | Source contribution and input reconciliation |

Browser-only decision-intelligence additions are not copied into the customer Excel unless already part of the core required dashboards. The workbook does not contain `Lane`, CISA KEV, SSVC, API keys, or hidden raw input columns.

## 13. PDF Input and Output

The selected report period controls which findings enter the Remediation Guide. The local LLM or deterministic fallback receives normalized fields only. The PDF contains:

- title `Remediation Guide`;
- report type `Remediation`;
- selected tool source;
- selected reporting date/month;
- table of contents;
- prioritized vulnerability actions;
- affected assets;
- clean command blocks;
- validation steps;
- source reference appendix;
- page headers, footers, and page numbers.

The PDF must not claim that a patch was applied. Commands and KB identifiers must be source-supported or clearly marked for manual vendor validation.

MVA also generates a deterministic **Executive Dashboard PDF** for the selected month. It includes the branded cover, executive summary, separate discovered and remediated line charts, total-open reconciliation, P1-P4 distribution, priority matrix, age-by-priority, top assets, top vulnerabilities, and methodology. It is generated locally and does not require an LLM.

## 14. PostgreSQL Dashboard Mapping

| Stored table | Dashboard use |
|---|---|
| `finding_observations` | Current/previous open, new, fixed, repeated, severity, P1-P4, age, source, datacentre, status, confidence, OpenShift workload/fix evidence |
| `scan_runs` | Ready report history, source, period, workflow, reconciliation |
| `customer_assets` | Approved scope, type, platform, team, tool |
| `customer_asset_aliases` | IP/DNS/host/external identity matching |
| `customer_teams` | Responsible-group filters |
| `threat_intel_records` | Tenant CVE/name/QID/plugin search and affected assets |
| `audit_events` | Administrative and AI action audit |

## 15. Accuracy Invariants

Every comparison must satisfy:

```text
total open = new + not closed
total open = P1 + P2 + P3 + P4
patched = previous open + new - current open
age >7 >= age >30 >= age >60 >= age >180 for each priority
received chunks = expected chunks
received normalized rows = expected normalized rows
tenant A data is never returned through a tenant B route
```

If an invariant fails, MVA stops the analysis/finalization instead of displaying an unverified dashboard.
