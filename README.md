# MVA Unified Vulnerability Management Platform

MVA is a database-backed, multi-tenant vulnerability analysis and remediation platform. Analysts upload scanner exports, normalize them in the browser, apply one approved exploit-aware P1-P4 matrix, compare reporting periods, validate scanner coverage against the approved asset inventory, and generate customer-ready Excel, CSV, and Remediation Guide PDF outputs.

The production design is private by default:

- Raw CSV/XLSX scanner files are parsed in the authenticated browser and are not stored.
- Normalized findings, tenant assets, report history, threat-intelligence evidence, users, teams, sessions, and audit events are stored in PostgreSQL.
- AI enrichment is available only through the authenticated Fastify API to an organization-controlled LiteLLM proxy.
- The LiteLLM virtual key remains server-side; no provider-key form or static GitHub Pages deployment is part of the production platform.

## Supported Inputs

| Source | Ad hoc | Monthly | Quarterly | Important source behavior |
|---|---:|---:|---:|---|
| Tenable.sc | Yes | Yes | Yes | `Exploit?`, `Exploit Ease`, and `Exploit Frameworks` provide exploit evidence |
| Tenable.io | Yes | Yes | Yes | Uses dot-notation fields and native `vuln_age` / `age_in_days` |
| Qualys VMDR | Yes | Yes | Yes | Non-empty `Exploitability` means exploit available; `Datacentre`, `Times Detected`, and `Vuln Status` are retained |
| Custom Qualys | Yes | Yes | Yes | 5 Urgent, 4 Critical, 3 Serious, 2 Medium, 1 Minimal |
| CrowdStrike | Yes | Yes | Yes | Exploit label first, then status value, then ExPRT fallback; confidence remains separate |
| Red Hat OpenShift | Yes | Yes | Yes | Exact workload schema; `Fixable` and `CVE Fixed In` are remediation evidence, never exploit evidence |
| Custom CSV/XLSX | Yes | Yes | Yes | User maps common fields and selects severity/exploit interpretation |
| Unified multi-tool | Yes | Yes | Yes | Selected tools are consolidated without treating different vulnerabilities on one asset as duplicates |

MDVM remains visible as a future source and is not presented as implemented.

## Approved Priority Matrix

| Exploit available | Critical | High | Medium | Low |
|---|---:|---:|---:|---:|
| Yes | P1 | P1 | P2 | P2 |
| No | P2 | P2 | P3 | P4 |

The matrix is deterministic. Threat overlays, EPSS, internet exposure, scanner confidence, and customer context support analyst review but do not silently change patch priority.

## Local Run

### Native macOS launcher

```bash
cd "/Users/mohammedshahid/Documents/New project/unified-v2"
chmod +x run-postgres-native.sh stop-postgres-native.sh
./run-postgres-native.sh
```

Open [http://127.0.0.1:8820/](http://127.0.0.1:8820/).

The launcher starts project-local PostgreSQL on `55432`, Fastify on `8787`, and the React production preview on `8820`. On first use, create the one-time system administrator. Additional users are created only by an administrator.

Stop it with:

```bash
./stop-postgres-native.sh
```

If the sign-in screen reports an API `404`, do not open the API health URL as the application. Run the launcher again and use the UI URL above. The launcher verifies both API health and `/api/v1/auth/setup-status`; it will reject an unrelated or stale process on port `8787` instead of presenting a broken login.

### Docker Desktop

```bash
cd "/Users/mohammedshahid/Documents/New project/unified-v2"
cp .env.example .env
chmod +x run-postgres-local.sh stop-postgres-local.sh
./run-postgres-local.sh
```

Open [http://127.0.0.1:8820/](http://127.0.0.1:8820/).

## First Functional Test

1. Sign in as the system administrator.
2. Select **sample_1**, **sample_2**, **sample_3**, or **sample_4**.
3. Open **Tool selection**.
4. Choose a scanner and an analysis workflow.
5. Use **Load Test Pack** or upload files from `samples/`.
6. Analyze the data.
7. Confirm the on-screen dashboard and download Excel, normalized CSV, and PDF.
8. Open **Asset inventory** and **Discovery coverage** to compare approved inventory, vulnerability-scan assets, and host-discovery assets.
9. Open **Threat intelligence**, import scanner evidence, and search by CVE, QID, plugin, or vulnerability name.

## Sample Data and Final Outputs

- Scanner samples: [`samples/`](samples/)
- Four isolated tenant inventories: [`samples/customer_assets/`](samples/customer_assets/)
- Complete generated evidence: [`final/Production Evidence/`](final/Production%20Evidence/)
- UI and report screenshots: [`ss/final-evidence/`](ss/final-evidence/)
- Sample instructions and expected values: [`SAMPLE_DATA.md`](SAMPLE_DATA.md)

The sample pack includes four monthly exports and one ad hoc export for Tenable.sc, Tenable.io, Qualys, Custom Qualys, CrowdStrike, Red Hat OpenShift, and a universal custom-parser profile. Inventory and host-discovery samples use different asset identities per tenant and scanner.

## Validation

```bash
cd "/Users/mohammedshahid/Documents/New project/unified-v2/react-ui"
npm ci
npm test
npm run build
npm audit --audit-level=moderate

cd ../server
npm ci
npm test
npm audit --audit-level=moderate

cd ..
node tools/validate_sample_data_pack.mjs
MVA_TEST_ADMIN_EMAIL='<admin email>' \
MVA_TEST_ADMIN_PASSWORD='<admin password>' \
node tools/test_multitenant_platform.mjs

MVA_TEST_ADMIN_EMAIL='<admin email>' \
MVA_TEST_ADMIN_PASSWORD='<admin password>' \
node tools/test_asset_inventory_postgres.mjs

MVA_TEST_ADMIN_EMAIL='<admin email>' \
MVA_TEST_ADMIN_PASSWORD='<admin password>' \
MVA_RUN_LARGE_VALIDATION=1 \
node tools/test_postgres_integration.mjs

MVA_TEST_ADMIN_EMAIL='<admin email>' \
MVA_TEST_ADMIN_PASSWORD='<admin password>' \
node tools/test_threat_intel_postgres.mjs
```

The 80,000-observation database validation checks chunking, weighted totals, idempotency, and final reconciliation. The platform tests cover tenant isolation, CSRF, roles, asset scoping, single/bulk asset deletion, saved report history, dashboard reconciliation, and threat-intelligence persistence.

## Production Deployment

Do not deploy this platform as a static site. It requires the Fastify API and PostgreSQL.

Use:

- [`docs/DEPLOYMENT_RUNBOOK.md`](docs/DEPLOYMENT_RUNBOOK.md) for line-by-line internal deployment.
- [`compose.production.yml`](compose.production.yml) for the isolated production container topology.
- [`.env.production.example`](.env.production.example) for non-secret configuration placeholders.

Production traffic should enter only through an organization-managed HTTPS reverse proxy. PostgreSQL, Fastify, and LiteLLM must remain private.

## Authoritative Documentation

- Architecture and stack: [`docs/ARCHITECTURE_AND_STACK.md`](docs/ARCHITECTURE_AND_STACK.md)
- Repository folder and file guide: [`docs/REPOSITORY_STRUCTURE.md`](docs/REPOSITORY_STRUCTURE.md)
- Field-to-dashboard mapping and formulas: [`docs/FIELD_TO_DASHBOARD_MAPPING.md`](docs/FIELD_TO_DASHBOARD_MAPPING.md)
- Complete build and handover: [`docs/COMPLETE_PRODUCTION_HANDOVER.md`](docs/COMPLETE_PRODUCTION_HANDOVER.md)
- Internal deployment runbook: [`docs/DEPLOYMENT_RUNBOOK.md`](docs/DEPLOYMENT_RUNBOOK.md)
- Validation evidence: [`docs/VALIDATION_EVIDENCE.md`](docs/VALIDATION_EVIDENCE.md)
- Security validation report: [`docs/PLATFORM_SECURITY_VALIDATION_REPORT.md`](docs/PLATFORM_SECURITY_VALIDATION_REPORT.md)
- Local AI PDF contract: [`docs/AI_PDF_GENERATION_PROMPT.md`](docs/AI_PDF_GENERATION_PROMPT.md)

## Normalized Finding Schema

```text
IP Address
DNS Name
Vulnerability Name
CVE
Severity
Exploit Available
Patch Priority
Asset Exposure (0-1000)
Vulnerability Finding
Summary
Description
Remediation
KB Links
Platform Details
First Discovered
Last Observed
Source Tools
Record Count
Datacentre
Times Detected
Vulnerability Status
Vendor Severity Rating
Threat
Impact
Vulnerability Confidence
Exploit Evidence Source
Namespace
Deployment
Image
Component
Fixable
CVE Fixed In
CVSS
```
