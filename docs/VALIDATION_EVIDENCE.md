# MVA Release Validation Evidence

Validated: 26 July 2026

## Release Decision

**PASS for controlled internal deployment**, subject to the infrastructure hardening actions in [PLATFORM_SECURITY_VALIDATION_REPORT.md](PLATFORM_SECURITY_VALIDATION_REPORT.md).

This evidence describes the exact repository state validated before release. It does not represent an independent penetration test or infrastructure certification.

## Automated Gate

| Gate | Result | Evidence |
|---|---:|---|
| React parsing, dashboard, export, persistence-client, and security tests | **78 / 78 passed** | [Frontend TAP log](../output/validation/frontend-tests-2026-07-26.tap) |
| Fastify route, authentication, authorization, database, and security tests | **18 / 18 passed** | [API TAP log](../output/validation/api-tests-2026-07-26.tap) |
| Combined automated tests | **96 / 96 passed** | Both TAP logs above |
| React production build | **Passed** | [Build log](../output/validation/frontend-build-2026-07-26.log) |
| React production dependency audit | **0 known vulnerabilities** | [Audit JSON](../output/validation/npm-audit-frontend-2026-07-26.json) |
| API production dependency audit | **0 known vulnerabilities** | [Audit JSON](../output/validation/npm-audit-api-2026-07-26.json) |
| Source whitespace and patch hygiene | **Passed** | `git diff --check` returned no output |
| Tracked source secret-pattern scan | **Passed** | No provider-key or private-key pattern found |

## Login 404 Regression

The local frontend is compiled with the API base URL `http://127.0.0.1:8787`. Authentication uses:

```text
POST http://127.0.0.1:8787/api/v1/auth/login
```

The following live contract was reproduced:

| Request | Expected | Observed |
|---|---:|---:|
| `GET /health` | API health response | HTTP `200` |
| `GET /api/v1/auth/setup-status` | Authentication route exists | HTTP `200` |
| Invalid `POST /api/v1/auth/login` | Generic authentication rejection | HTTP `401` |

The launcher now tests both `/health` and `/api/v1/auth/setup-status`. A different or stale process that exposes only `/health` can no longer be mistaken for the current MVA API. The production UI is rebuilt on every launcher execution, including when the Vite preview is already running.

Evidence: [live API route check](../output/validation/live-api-route-check-2026-07-26.txt), [platformApi.js](../react-ui/src/lib/platformApi.js), and [run-postgres-native.sh](../run-postgres-native.sh).

## Scanner and Sample-Pack Validation

The deterministic sample validator passed:

```json
{
  "ok": true,
  "toolsValidated": 6,
  "inventoryRowsValidated": 600,
  "discoveryFilesValidated": 30,
  "monthlyScannerFilesValidated": 24,
  "adhocScenariosValidated": 6,
  "universalCustomParserValidated": true,
  "allScannerAssetsMatchedToInventory": true
}
```

Sources covered:

1. Tenable.sc
2. Tenable.io
3. Qualys VMDR
4. Custom Qualys severity scale
5. CrowdStrike
6. Red Hat OpenShift

Evidence: [sample-pack validation JSON](../output/validation/sample-pack-validation-2026-07-26.json) and [sample-data guide](../SAMPLE_DATA.md).

## Dashboard Reconciliation

Every monthly source report passed all five approved checks:

1. Vulnerabilities discovered in the latest three reporting periods.
2. Total open equals new plus findings not closed from earlier periods.
3. Total open reconciles to P1 + P2 + P3 + P4.
4. Age and patch-priority buckets reconcile for `>7`, `>30`, `>60`, and `>180` days.
5. Patched findings reconcile as previous open + new this period - current open.

| Source | Current open | New | Not closed | Patched | Validation |
|---|---:|---:|---:|---:|---:|
| Tenable.sc | 125 | 30 | 95 | 25 | Pass |
| Tenable.io | 125 | 30 | 95 | 25 | Pass |
| Qualys VMDR | 125 | 30 | 95 | 25 | Pass |
| Custom Qualys | 125 | 30 | 95 | 25 | Pass |
| CrowdStrike | 120 | 20 | 100 | 25 | Pass |
| Red Hat OpenShift | 140 | 30 | 110 | 20 | Pass |

The source-specific JSON evidence and all generated outputs are indexed in [release_manifest.json](../final/Production%20Evidence/release_manifest.json).

## Priority Matrix

The same deterministic matrix is applied to every source:

| Exploit available | Critical | High | Medium | Low |
|---|---:|---:|---:|---:|
| Yes | P1 | P1 | P2 | P2 |
| No | P2 | P2 | P3 | P4 |

OpenShift `Fixable` and `CVE Fixed In` values are remediation evidence and never imply exploit availability. OpenShift data with no explicit exploit evidence therefore cannot be promoted to P1.

## OpenShift Database Round Trip

The exact 11-column OpenShift input schema was parsed, normalized, stored in PostgreSQL, read back, and exported:

```json
{
  "ok": true,
  "findingsStored": 140,
  "fixable": 112,
  "fixedVersionSupplied": 112,
  "namespaces": 8,
  "components": 10,
  "exportedRows": 140,
  "cvssRange": [3.7, 9.8]
}
```

Evidence: [OpenShift PostgreSQL validation](../output/validation/openshift-postgres-validation-2026-07-26.json).

## Excel Evidence

Twelve workbooks were generated and rendered:

| Source | Monthly | Ad hoc |
|---|---:|---:|
| Tenable.sc | Pass | Pass |
| Tenable.io | Pass | Pass |
| Qualys VMDR | Pass | Pass |
| Custom Qualys | Pass | Pass |
| CrowdStrike | Pass | Pass |
| Red Hat OpenShift | Pass | Pass |

All 12 formula scans reported zero formula-error matches. The rendered cover, executive dashboard, workflow report, briefing, top-assets, and top-vulnerabilities sheets are under [`ss/final-evidence/workbooks`](../ss/final-evidence/workbooks/).

Evidence: [workbook render manifest](../ss/final-evidence/workbooks/render_manifest.json).

## Browser Evidence

The authenticated production bundle was hard-reloaded from `http://127.0.0.1:8820/` after the final build. It rendered tenant-scoped metrics, the open-vulnerability trend, severity profile, and the approved exploit-availability priority matrix without an API error.

Evidence: [final MVA dashboard screenshot](../ss/final-evidence/ui/mva-dashboard-viewport-final.png).

## PDF Evidence

Each source has two distinct PDF outputs:

- **Executive Dashboard PDF**: cover, executive summary, discovered and patched line charts, total-open analysis, priority matrix, aging, top assets, top vulnerabilities, and methodology.
- **Remediation Guide PDF**: prioritized technical remediation actions, clean command blocks, validation guidance, references, headers, footers, and contents.

The customer-facing artifacts are under [`final/Production Evidence`](../final/Production%20Evidence/). Rendered PDF pages are under [`ss/final-evidence/pdfs`](../ss/final-evidence/pdfs/).

## Capacity Evidence

The retained browser performance validation processed 80,000 findings:

| Metric | Result |
|---|---:|
| CSV size | 28.851 MiB |
| Parse | 1.275 seconds |
| Normalize | 0.448 seconds |
| Dashboard | 0.641 seconds |
| Total | 2.364 seconds |
| Normalized findings | 80,000 |
| Dashboard findings | 80,000 |
| Distinct assets | 2,000 |

Evidence: [browser_80000_rows.json](../output/validation/browser_80000_rows.json). The current React test gate also includes an 80,000-finding dashboard regression.

## Reproduction

```bash
cd react-ui
npm test
npm run build
npm audit --omit=dev --json

cd ../server
npm test
npm audit --omit=dev --json

cd ..
node tools/validate_sample_data_pack.mjs
node tools/test_openshift_postgres.mjs
node tools/generate_production_evidence.mjs
node tools/render_production_evidence.mjs
git diff --check
```

The PostgreSQL integration commands require the local platform database and valid test-administrator environment variables. No credential is stored in this document or tracked source.

## Evidence Index

- [Full production output set](../final/Production%20Evidence/)
- [Workbook screenshots](../ss/final-evidence/workbooks/)
- [PDF screenshots](../ss/final-evidence/pdfs/)
- [Sample data](../samples/)
- [Tool-specific inventory and discovery packs](../ss/sample%20data/)
- [Architecture](ARCHITECTURE_AND_STACK.md)
- [Field-to-dashboard mapping](FIELD_TO_DASHBOARD_MAPPING.md)
- [Deployment runbook](DEPLOYMENT_RUNBOOK.md)
- [Security validation report](PLATFORM_SECURITY_VALIDATION_REPORT.md)
