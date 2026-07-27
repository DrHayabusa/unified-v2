# MVA Tool-Specific Sample Data

This deterministic test pack contains no production or customer data. Each scanner has a completely separate folder with a matching inventory, host-discovery history, scanner exports, expected results, and testing instructions.

| Folder | Scenario |
|---|---|
| `tenable-sc/` | Tenable.sc inventory, discovery, ad hoc, and four-month comparison |
| `tenable-io/` | Tenable.io inventory, discovery, ad hoc, and four-month comparison |
| `qualys/` | Qualys VMDR inventory, discovery, ad hoc, and four-month comparison |
| `crowdstrike/` | CrowdStrike inventory, discovery, per-asset ad hoc, remediation, and four-month comparison |
| `openshift/` | OpenShift workload inventory, discovery, ad hoc, and four-month comparison |

## Standard layout

Every tool folder contains:

```text
asset_inventory/
host_discovery/
scan_results/
expected_results/
README.md
manifest.json
```

Each inventory contains 100 active in-scope assets using the simplified Tool, Asset Type, IP Address, DNS Name, Host Name, Team Name, and OS Name layout. Scanner-observed assets are included in the matching tool inventory.

Each discovery month contains only the `IP Address` and `DNS Name` columns. It intentionally includes three unmanaged hosts and two duplicate rows to validate coverage, deduplication, and exception handling. No out-of-scope rows are included in asset inventory.

Start with the `README.md` inside the tool folder you want to test. Use the expected JSON files for exact reconciliation.
