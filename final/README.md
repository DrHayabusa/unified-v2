# MVA Production Evidence

Generated: 26 July 2026

The `Production Evidence` directory is the customer-facing release pack for the current PostgreSQL-backed MVA platform.

## Included Sources

- Tenable.sc
- Tenable.io
- Qualys VMDR
- Custom Qualys severity profile
- CrowdStrike
- Red Hat OpenShift

## Files Per Source

Each source directory contains:

1. A monthly Excel report.
2. An ad hoc Excel report.
3. A month-selectable Executive Dashboard PDF.
4. A Remediation Guide PDF.
5. A deterministic `validation.json` record containing source inputs, lifecycle reconciliation, priority totals, and output paths.

## Workbook Layout

Monthly workbooks contain:

- Cover Page
- Executive Dashboard
- Monthly Report
- Briefing
- Top Vulnerable Assets
- Top Vulnerabilities
- Report Data
- Source Audit for unified multi-source reports

Ad hoc workbooks contain:

- Cover Page
- Executive Dashboard
- Adhoc Report
- Top Vulnerable Assets
- Top Vulnerabilities
- Report Data

## Validation

The release manifest is [`Production Evidence/release_manifest.json`](Production%20Evidence/release_manifest.json).

The complete command evidence is in [`../docs/VALIDATION_EVIDENCE.md`](../docs/VALIDATION_EVIDENCE.md). Twelve workbook renders reported zero formula errors, and all six source packs passed the approved monthly dashboard reconciliation.

`SHA256SUMS.txt` provides a checksum for every file in `Production Evidence`.

No API key, customer export, password, or production database is included.
