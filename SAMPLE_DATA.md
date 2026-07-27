# MVA Sample Data

All files in `samples/` are synthetic and safe for demonstrations. They are intentionally cross-checked against tenant-specific asset inventories so scanner coverage and asset matching can be validated without using customer data.

## Scanner Test Sets

| Profile | Monthly files | Ad hoc file | Reference output |
|---|---:|---:|---|
| Tenable.sc | April-July 2026 | July 2026 | `final/Production Evidence/Tenable_SC/` |
| Tenable.io | April-July 2026 | July 2026 | `final/Production Evidence/Tenable_IO/` |
| Qualys VMDR | April-July 2026 | July 2026 | `final/Production Evidence/Qualys/` |
| Custom Qualys | April-July 2026 | July 2026 | `final/Production Evidence/Custom_Qualys/` |
| CrowdStrike | April-July 2026 | July 2026 | `final/Production Evidence/CrowdStrike/` |
| Red Hat OpenShift | April-July 2026 | July 2026 | `final/Production Evidence/OpenShift/` |
| Universal custom parser | April-July 2026 | July file can be used ad hoc | Parsed through the Custom CSV workflow |

## Upload Paths

### Tenable.sc

```text
samples/tenable_100_row/tenable_sc_april_2026_100plus.csv
samples/tenable_100_row/tenable_sc_may_2026_100plus.csv
samples/tenable_100_row/tenable_sc_june_2026_100plus.csv
samples/tenable_100_row/tenable_sc_july_2026_100plus.csv
```

### Tenable.io

```text
samples/tenable_100_row/tenable_io_april_2026_100plus.csv
samples/tenable_100_row/tenable_io_may_2026_100plus.csv
samples/tenable_100_row/tenable_io_june_2026_100plus.csv
samples/tenable_100_row/tenable_io_july_2026_100plus.csv
```

### Qualys VMDR

```text
samples/qualys_100_row/qualys_monthly_april_2026_100plus.csv
samples/qualys_100_row/qualys_monthly_may_2026_100plus.csv
samples/qualys_100_row/qualys_monthly_june_2026_100plus.csv
samples/qualys_100_row/qualys_monthly_july_2026_100plus.csv
samples/qualys_100_row/qualys_adhoc_july_2026_100plus.csv
```

### Custom Qualys

```text
samples/custom_qualys_100_row/custom_qualys_monthly_april_2026.csv
samples/custom_qualys_100_row/custom_qualys_monthly_may_2026.csv
samples/custom_qualys_100_row/custom_qualys_monthly_june_2026.csv
samples/custom_qualys_100_row/custom_qualys_monthly_july_2026.csv
samples/custom_qualys_100_row/custom_qualys_adhoc_july_2026.csv
```

### CrowdStrike

```text
samples/crowdstrike_100_row/crowdstrike_vulnerabilities_april_2026_100plus.csv
samples/crowdstrike_100_row/crowdstrike_vulnerabilities_may_2026_100plus.csv
samples/crowdstrike_100_row/crowdstrike_vulnerabilities_june_2026_100plus.csv
samples/crowdstrike_100_row/crowdstrike_vulnerabilities_july_2026_100plus.csv
samples/crowdstrike_100_row/crowdstrike_vulnerability_per_asset_july_2026_100plus.csv
samples/crowdstrike_100_row/crowdstrike_remediation_per_assets_july_2026_100plus.csv
```

`Remediation per assets` is an aggregated ad hoc export. Its `Count` is used as the finding weight; it is not a monthly asset-level lifecycle source.

### Red Hat OpenShift

```text
samples/openshift_100_row/openshift_april_2026_100plus.csv
samples/openshift_100_row/openshift_may_2026_100plus.csv
samples/openshift_100_row/openshift_june_2026_100plus.csv
samples/openshift_100_row/openshift_july_2026_100plus.csv
```

Every file uses the exact supplied schema:

```text
Namespace,Deployment,Image,Component,CVE,Fixable,CVE Fixed In,Severity,CVSS,Discovered At,Reference
```

The monthly lifecycle is intentionally deterministic: July contains 140 open findings, 30 new findings, 110 carried findings, and 20 findings no longer observed. `Fixable` and `CVE Fixed In` control remediation availability only. The supplied OpenShift schema has no exploit field, so it never creates positive exploit evidence.

### Universal Custom Parser

```text
samples/universal_custom_parser/generic_scanner_april_2026.csv
samples/universal_custom_parser/generic_scanner_may_2026.csv
samples/universal_custom_parser/generic_scanner_june_2026.csv
samples/universal_custom_parser/generic_scanner_july_2026.csv
```

Choose **Custom CSV**, review the auto-suggested mappings, select the severity scale, and choose either boolean-label or non-empty-evidence exploit handling.

## Tenant, Inventory, and Discovery Pack

`samples/sample_data/` is organized by tool and contains:

- approved in-scope asset inventory;
- five host-discovery reporting periods;
- four vulnerability reporting periods;
- one ad hoc scanner result.

`samples/customer_assets/` contains the compact tenant inventories used by the deterministic PostgreSQL seed:

| Tenant | Source |
|---|---|
| `sample_1` | Tenable.sc |
| `sample_2` | Tenable.io |
| `sample_3` | Qualys VMDR |
| `sample_4` | CrowdStrike |

Every scanner IP in the generated samples is present in that tenant's in-scope inventory. The host-discovery files intentionally vary observation coverage so the dashboard can display:

- approved in-scope assets;
- assets present in vulnerability scan results;
- assets present in host-discovery results;
- inventory assets not seen by either source;
- monthly discovery coverage up to five periods.

## Manual Test Sequence

1. Open **Tool selection**.
2. Choose one scanner.
3. Choose **Ad hoc scan** and upload its July file.
4. Confirm total findings, severity, P1-P4, top affected assets, scanner-specific insights, and export buttons.
5. Return to **Dashboards**.
6. Choose **Monthly comparison** and add April, May, June, and July one file at a time.
7. Remove one selected file, add it again, and confirm the other files remain.
8. Analyze and confirm both discovered and remediated line charts.
9. Download Excel, normalized CSV, and a selected-month PDF.
10. Repeat with **Unified multi-tool**, selecting only the tools intended for that test.
11. Import the matching tenant inventory and discovery files.
12. Confirm the three-layer coverage reconciliation.
13. Import a scanner file into **Threat intelligence** and search a CVE from the file.

## Automated Sample Check

```bash
cd "/Users/mohammedshahid/Documents/New project/unified-v2"
node tools/validate_sample_data_pack.mjs
```

The validator checks all six implemented source profiles, 600 inventory rows, 30 discovery files, 24 monthly scanner files, six ad hoc scenarios, universal custom mapping, and scanner-to-inventory identity alignment.
