# Qualys VMDR Test Pack

This folder contains only synthetic or generated test data. It contains no customer data.

## Folder contents

- `asset_inventory/qualys_asset_inventory.csv`: 100-asset inventory. Assets found in the supplied Qualys VMDR scans are included so inventory and scanner analysis can be tested together.
- `host_discovery/`: five monthly host-discovery files from March through July 2026. Every file uses only `IP Address` and `DNS Name`.
- `scan_results/`: Qualys VMDR ad hoc and monthly scanner exports using the supported raw field layout.
- `expected_results/host_discovery_metrics.json`: exact expected host-discovery counts.
- `expected_results/scanner_metrics.json`: exact expected ad hoc and monthly dashboard counts.
- `manifest.json`: machine-readable list of every file used by this scenario.

## Test order

1. Create or select a test tenant.
2. Import `asset_inventory/qualys_asset_inventory.csv` in Asset inventory.
3. Open Discovery coverage and add one to five files from `host_discovery/`.
4. Compare the dashboard with `expected_results/host_discovery_metrics.json`.
5. Select Qualys VMDR in Tool selection.
6. For Monthly comparison, upload the four files listed in `manifest.json > monthlyFiles`.
7. For Ad hoc analysis, upload `scan_results/qualys_adhoc_july_2026_100plus.csv`.
8. Compare dashboard totals with `expected_results/scanner_metrics.json`, then test CSV, Excel, and PDF downloads.
