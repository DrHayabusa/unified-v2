# MVA Unified Vulnerability Management Platform

## Application Security Validation Report

| Document field | Value |
|---|---|
| Assessment date | 26 July 2026 |
| Assessment type | Application security regression and control validation |
| Assessed build | Final release candidate on `main`; commit recorded after validation |
| Frontend | React 18, Vite, Tailwind CSS |
| API | Node.js, Fastify 5 |
| Data store | PostgreSQL |
| Overall result | **PASS with production hardening actions** |
| Evidence summary | [VALIDATION_EVIDENCE.md](VALIDATION_EVIDENCE.md) |

> This report is supporting technical evidence for an internal compliance review. It is not a third-party penetration test, vulnerability scan certificate, SOC 2 report, ISO 27001 certification, or guarantee that the platform has no vulnerabilities.

## 1. Executive Summary

The current MVA application passed all automated tests executed for this review:

| Validation set | Result | Evidence |
|---|---:|---|
| React data, upload, report, persistence-client, and security regression tests | **78 / 78 passed** | [Frontend TAP log](../output/validation/frontend-tests-2026-07-26.tap) |
| Fastify API, authentication, authorization, local-LLM, and security tests | **18 / 18 passed** | [API TAP log](../output/validation/api-tests-2026-07-26.tap) |
| Combined current automated tests | **96 / 96 passed** | Both TAP logs above |
| Production React build | **Passed** | Reproduced with `npm run build` on 26 July 2026 |
| React production dependency audit | **0 known vulnerabilities** | [Frontend npm audit JSON](../output/validation/npm-audit-frontend-2026-07-26.json), 350 total dependencies |
| API production dependency audit | **0 known vulnerabilities** | [API npm audit JSON](../output/validation/npm-audit-api-2026-07-26.json), 66 total dependencies |
| Tracked source secret-pattern scan | **No matches** | Reproduced with the command in Section 10 |
| Tool-specific sample validation | **6 tool packs, 600 inventory assets, and 30 discovery files passed** | [Sample-pack evidence](../output/validation/sample-pack-validation-2026-07-26.json) |
| OpenShift PostgreSQL round trip | **140 / 140 findings preserved** | [OpenShift evidence](../output/validation/openshift-postgres-validation-2026-07-26.json) |
| Workbook formula scan | **12 workbooks, 0 formula errors** | [Render manifest](../ss/final-evidence/workbooks/render_manifest.json) |

No exploitable defect was confirmed by this test pass. One low-risk error-handling issue was corrected during testing: a disallowed CORS origin previously surfaced as a generic server error; it now fails closed with HTTP `403` and no `Access-Control-Allow-Origin` header. The corrected behavior is covered by [security.test.js](../server/test/security.test.js).

The platform is suitable for continued controlled internal testing. Before production deployment, the organization must complete the hardening actions in Section 9, particularly TLS, `COOKIE_SECURE=true`, exact CORS origins, a Content Security Policy, centralized rate limiting for multiple API replicas, and independent penetration testing.

## 2. Scope

### Included

- React browser application and local parsing engine.
- Fastify authentication and tenant API.
- Session, CSRF, password, CORS, and role controls.
- Tenant-scoped dashboard and export request paths.
- CSV/XLSX input handling and scanner normalization.
- Spreadsheet export injection defenses.
- Private Ollama request construction and graceful unavailable-service handling.
- Host-discovery matching and exception classification.
- Production JavaScript dependency advisories.
- Existing report-integrity and 80,000-row performance evidence.

### Excluded

- External network penetration testing and authenticated DAST.
- Source-code scanning by a commercial SAST platform.
- Operating system, container image, PostgreSQL host, reverse proxy, firewall, and cloud-account scanning.
- TLS certificate and load-balancer configuration.
- Database encryption at rest, backup restoration, disaster recovery, and high availability.
- NVIDIA, OpenRouter, Groq, Tenable, Qualys, and CrowdStrike provider infrastructure.
- Social engineering, phishing, physical security, and endpoint security.

## 3. Methodology

The review used deterministic unit and API-injection tests, production builds, package advisory checks, static secret-pattern searches, generated-file validation, and source inspection. Negative tests intentionally supplied missing sessions, missing CSRF tokens, unauthorized roles, untrusted origins, malformed identifiers, conflicting asset aliases, unsupported files, ambiguous host identities, malicious spreadsheet prefixes, and unavailable private-model services.

Results are classified as:

| Status | Meaning |
|---|---|
| Pass | The expected security behavior was reproduced by an automated test. |
| Verified by inspection | The control exists in source, but this pass did not test the complete deployed environment. |
| Conditional | The control is effective only when required production configuration is enabled. |
| Not tested | Additional specialist or infrastructure testing is required. |

## 4. Security Test Results

### 4.1 Authentication and Session Security

| Test | Expected result | Result | Evidence |
|---|---|---:|---|
| Protected write without session | HTTP `401` | Pass | [app.test.js](../server/test/app.test.js) and [API TAP log](../output/validation/api-tests-2026-07-26.tap) |
| Write with session but no CSRF token | HTTP `403` | Pass | [app.test.js](../server/test/app.test.js) |
| CSRF comparison | Constant-time token comparison | Verified by inspection | [auth.js](../server/src/auth.js) and [app.js](../server/src/app.js) |
| Production session cookie | `Secure`, `HttpOnly`, `SameSite=Strict` | Pass | [security.test.js](../server/test/security.test.js) |
| Session token storage | Only SHA-256 token hash stored in PostgreSQL | Verified by inspection | [auth.js](../server/src/auth.js) and [repository.js](../server/src/repository.js) |
| Session expiry | Eight-hour expiry and expired-session rejection | Verified by inspection | [app.js](../server/src/app.js) and [repository.js](../server/src/repository.js) |
| Logout | Server-side session deletion, cookie clearing, `Clear-Site-Data` | Verified by inspection | [app.js](../server/src/app.js) |
| Password storage | Salted scrypt; plaintext absent from stored value | Pass | [app.test.js](../server/test/app.test.js) |
| Password policy | 12–128 characters; rejects email-derived passwords | Pass | [security.test.js](../server/test/security.test.js) |
| Login error disclosure | Generic message for unknown or invalid credentials | Pass | [security.test.js](../server/test/security.test.js) |
| Repeated invalid login | Ninth attempt within the window returns HTTP `429` | Pass | [security.test.js](../server/test/security.test.js) |

### 4.2 Authorization and Tenant Boundaries

| Test | Expected result | Result | Evidence |
|---|---|---:|---|
| Tenant deletion without CSRF | HTTP `403` | Pass | [app.test.js](../server/test/app.test.js) |
| Tenant deletion by non-administrator | HTTP `403` | Pass | [app.test.js](../server/test/app.test.js) |
| Tenant deletion confirmation | Exact tenant name required | Pass | [app.test.js](../server/test/app.test.js) |
| Dashboard/export filters | Same validated team and asset scope sent to both paths | Pass | [app.test.js](../server/test/app.test.js) |
| Invalid asset identifier | HTTP `400` | Pass | [app.test.js](../server/test/app.test.js) |
| Browser writes | Cookie credentials plus CSRF; no trusted tenant header | Pass | [platformApi.test.js](../react-ui/src/lib/platformApi.test.js) |
| Tenant data access | Repository access assertion precedes dashboard, asset, team, run, and export queries | Verified by inspection | [app.js](../server/src/app.js) |

The route and repository design is tenant-scoped, but this pass did not perform a hostile direct-database test or PostgreSQL row-level-security bypass test. PostgreSQL RLS is not currently the enforcement mechanism; the API and parameterized repository queries enforce the boundary.

### 4.3 Browser and API Hardening

| Test | Expected result | Result | Evidence |
|---|---|---:|---|
| Allowed CORS origin | Exact configured origin receives CORS credentials headers | Pass | [security.test.js](../server/test/security.test.js) |
| Untrusted CORS origin | HTTP `403`; no allow-origin header | Pass | [security.test.js](../server/test/security.test.js) |
| API cache protection | `Cache-Control: no-store` | Pass | [security.test.js](../server/test/security.test.js) |
| MIME sniffing protection | `X-Content-Type-Options: nosniff` | Pass | [security.test.js](../server/test/security.test.js) |
| Clickjacking protection | `X-Frame-Options: DENY` | Pass | [security.test.js](../server/test/security.test.js) |
| Referrer restriction | `Referrer-Policy: no-referrer` on API | Pass | [security.test.js](../server/test/security.test.js) |
| Frontend static headers | `nosniff`, `DENY`, strict referrer policy | Verified by inspection | [nginx.local.conf](../react-ui/nginx.local.conf) |
| API request size | Fastify body limit is 32 MiB | Verified by inspection | [app.js](../server/src/app.js) |

### 4.4 Input, Export, and Injection Defenses

| Test | Expected result | Result | Evidence |
|---|---|---:|---|
| CSV formula injection | Prefix `=`, `+`, `-`, and `@` values before export | Pass | [app.test.js](../server/test/app.test.js) |
| Discovery CSV formula injection | Neutralize formulas in coverage and exception exports | Pass | [hostDiscovery.test.js](../react-ui/src/lib/hostDiscovery.test.js) |
| Finding normalization | Bound exposure to 0–1000, validate dates, strip NUL, constrain text | Pass | [app.test.js](../server/test/app.test.js) |
| Asset identity collision | Reject one alias assigned to multiple assets | Pass | [app.test.js](../server/test/app.test.js) |
| Dashboard identifiers | Reject malformed team and asset UUIDs | Pass | [app.test.js](../server/test/app.test.js) |
| Database values | Repository queries use PostgreSQL parameters for user-controlled values | Verified by inspection | [repository.js](../server/src/repository.js) |

No dynamic SQL-injection attack tool was run against a deployed API. Parameterization and validation reduce risk, but independent DAST remains required before production approval.

### 4.5 File Upload and Parsing Safety

| Test | Expected result | Result | Evidence |
|---|---|---:|---|
| Accepted upload types | CSV and XLSX accepted | Pass | [uploadFiles.test.js](../react-ui/src/lib/uploadFiles.test.js) |
| Unsupported upload types | Legacy XLS and PDF rejected | Pass | [uploadFiles.test.js](../react-ui/src/lib/uploadFiles.test.js) |
| Multi-drop behavior | Additional files append instead of replacing earlier files | Pass | [uploadFiles.test.js](../react-ui/src/lib/uploadFiles.test.js) |
| Duplicate filename behavior | Same filename replaces only its earlier copy | Pass | [uploadFiles.test.js](../react-ui/src/lib/uploadFiles.test.js) |
| XLSX cover sheet | Scanner header found after non-data rows | Pass | [vulnerabilityEngine.test.js](../react-ui/src/lib/vulnerabilityEngine.test.js) |
| Unsupported scanner layout | Actionable rejection rather than silent mapping | Pass | [vulnerabilityEngine.test.js](../react-ui/src/lib/vulnerabilityEngine.test.js) |
| Discovery duplicates/offline rows | Removed and counted separately | Pass | [hostDiscovery.test.js](../react-ui/src/lib/hostDiscovery.test.js) |
| Ambiguous host identity | Not counted as scanned | Pass | [hostDiscovery.test.js](../react-ui/src/lib/hostDiscovery.test.js) |

Raw scanner files are parsed in the browser. This reduces server-side raw-file exposure, but it does not replace endpoint malware controls. Production policy should restrict file size, retain parser dependency updates, and consider malware scanning if raw uploads are later stored or processed server-side.

### 4.6 Secrets and Private AI Controls

| Test | Expected result | Result | Evidence |
|---|---|---:|---|
| Browser model access | Browser calls only authenticated MVA API routes with CSRF | Pass | [platformApi.test.js](../react-ui/src/lib/platformApi.test.js) |
| Ollama status | Server reports configured route/model without exposing a secret | Pass | [localLlm.test.js](../server/test/localLlm.test.js) |
| Bounded request | Server sends a non-streaming, timeout-bounded `/api/chat` request | Pass | [localLlm.test.js](../server/test/localLlm.test.js) |
| Missing model/service | Controlled error; deterministic reports remain available | Pass | [localLlm.test.js](../server/test/localLlm.test.js) |
| Cloud provider keys | No browser API-key input or cloud-provider runtime exists | Verified by inspection | [LlmConfiguration.jsx](../react-ui/src/components/LlmConfiguration.jsx) |
| Tracked key patterns | No NVIDIA, OpenAI, Groq, or private-key pattern found in tracked source/config | Pass | Command in Section 10 |

Production model connectivity is configured only through server environment variables. Ollama must remain on a private network path reachable by the MVA API, not by end-user browsers.

### 4.7 Dependency and Supply-Chain Review

| Package set | Production dependencies | Critical | High | Moderate | Low | Result |
|---|---:|---:|---:|---:|---:|---:|
| React application | 350 | 0 | 0 | 0 | 0 | Pass |
| Fastify API | 66 | 0 | 0 | 0 | 0 | Pass |

The results reflect the npm advisory database at the execution time. They are point-in-time results and must be repeated in CI for every release. Container base images and operating-system packages were not scanned in this pass.

## 5. Functional Integrity Supporting Security

Security depends on accurate scope and report output. The following non-security regression evidence supports data integrity:

| Validation | Result | Evidence |
|---|---:|---|
| Current automated release gate | 96 / 96 frontend and API tests passed | [VALIDATION_EVIDENCE.md](VALIDATION_EVIDENCE.md) |
| 80,000-row browser workload | 80,000 normalized; dashboard total 80,000 | [browser_80000_rows.json](../output/validation/browser_80000_rows.json) |
| Scanner, inventory, and discovery pack | 6 tools, 600 inventory assets, 30 discovery files, 24 monthly files | [sample-pack-validation-2026-07-26.json](../output/validation/sample-pack-validation-2026-07-26.json) |
| OpenShift persistence/export | 140 findings, 112 fixable, 8 namespaces, 10 components | [openshift-postgres-validation-2026-07-26.json](../output/validation/openshift-postgres-validation-2026-07-26.json) |
| Executive PDF integrity | Valid `%PDF`, landscape layout, selected-period reconciliation, and 8 rendered monthly pages | [Executive PDF tests](../react-ui/src/lib/executiveReportPdf.test.js) and [rendered pages](../ss/final-evidence/pdfs/openshift-executive/) |
| Excel formula-error inspection | 12 workbooks, zero formula errors | [Render manifest](../ss/final-evidence/workbooks/render_manifest.json) |

Earlier evidence is retained for traceability. The current 26 July pass reran all 96 JavaScript tests, the production build, both dependency audits, secret and diff-hygiene scans, all six sample packs, OpenShift PostgreSQL persistence, workbook rendering/formula inspection, and PDF visual inspection.

## 6. Randomized Test Data

The test pack is available at [`ss/sample data`](../ss/sample%20data/README.md). It contains no customer or production data.

| Dataset | Contents |
|---|---|
| `tenable-sc` | Matching asset inventory, five discovery months, and Tenable.sc scanner exports |
| `tenable-io` | Matching asset inventory, five discovery months, and Tenable.io scanner exports |
| `qualys` | Matching asset inventory, five discovery months, and Qualys VMDR scanner exports |
| `custom-qualys` | Matching asset inventory, five discovery months, and custom-severity Qualys exports |
| `crowdstrike` | Matching asset inventory, five discovery months, and CrowdStrike scanner exports |
| `openshift` | Workload inventory, five discovery periods, and exact-schema OpenShift vulnerability exports |

Each tool-specific pack has 100 active in-scope assets or workloads in the simplified Tool, Asset Type, IP/DNS/Workload, Team, and OS/platform layout. Every scanner-observed identity is present in its matching inventory. Host-discovery files use exactly `IP Address` and `DNS Name`; the files deliberately include unmanaged identities and duplicate rows to exercise coverage, matching, and exception handling. Customer inventories contain no out-of-scope addresses.

## 7. OWASP Risk Traceability

This mapping is indicative evidence, not an OWASP certification.

| OWASP Top 10 theme | MVA evidence |
|---|---|
| A01 Broken Access Control | Authenticated routes, CSRF, administrator deletion, tenant access assertions, scope-filter tests |
| A02 Cryptographic Failures | Salted scrypt, hashed session tokens, secure-cookie test; deployment TLS remains conditional |
| A03 Injection | Parameterized repository queries, input constraints, CSV formula neutralization |
| A04 Insecure Design | Fail-closed ambiguous identity matching and explicit destructive-action confirmation |
| A05 Security Misconfiguration | Exact-origin CORS, cache prevention, clickjacking and MIME headers; CSP remains open |
| A06 Vulnerable and Outdated Components | Current production npm audits report zero known advisories |
| A07 Identification and Authentication Failures | Generic login errors, password policy, session expiry, and throttling |
| A08 Software and Data Integrity Failures | File-type validation, deterministic normalization, workbook and PDF integrity checks |
| A09 Security Logging and Monitoring Failures | Login/finalization/admin audit events exist; retention and alerting were not independently tested |
| A10 Server-Side Request Forgery | The browser cannot supply an arbitrary model URL; the API uses only the server-administered `OLLAMA_BASE_URL`. Deployment must restrict that value to the approved private model endpoint. |

## 8. Findings Closed During This Review

### SEC-2026-001: Disallowed CORS origin returned a generic server error

| Field | Detail |
|---|---|
| Initial severity | Low |
| Risk | Correctly blocked requests could appear as internal server failures, creating noisy monitoring and ambiguous client behavior. |
| Resolution | The CORS callback now returns an explicit HTTP `403` validation error. |
| Regression test | `CORS allows the configured origin and rejects an untrusted origin` |
| Status | **Closed and verified** |

## 9. Production Hardening Actions

| Priority | Action | Rationale / acceptance evidence |
|---|---|---|
| High | Terminate TLS at an approved reverse proxy and set `COOKIE_SECURE=true`. | Production cookie test passes when enabled; deployment evidence must show HTTPS-only access. |
| High | Configure exact production `CORS_ORIGINS`; never use `*` with credentialed production requests. | Capture response headers for allowed and untrusted origins. |
| High | Complete an independent authenticated penetration test and API DAST. | Attach signed report and remediation retest. |
| Medium | Add a restrictive Content Security Policy and `Permissions-Policy` to the frontend proxy. | Browser header scan shows policy present without breaking UI/export functions. |
| Medium | Move login throttling to Redis or an API gateway for multi-replica deployments. | Rate limit persists across restarts and applies consistently across replicas. |
| Medium | Integrate SSO/MFA for enterprise identities and remove locally managed passwords where required. | Identity-provider test evidence and access review. |
| Medium | Restrict the server-administered Ollama endpoint with network policy and authenticated service-to-service access where supported. | Browser network capture contains no model endpoint override or provider credential. |
| Medium | Scan container images and host packages in CI/CD. | Zero unresolved critical/high findings or approved exceptions. |
| Medium | Define audit-log retention, access, alerting, and tamper-protection requirements. | Retention test and sample alert evidence. |
| Low | Add automated dependency, secret, SAST, and report-integrity gates to every pull request. | CI branch protection requires all security jobs. |

## 10. Reproduction Commands

Run from the repository root unless a command changes directory:

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
git diff --check
git grep -I -n -E 'nvapi-[A-Za-z0-9_-]{12,}|sk-[A-Za-z0-9_-]{16,}|gsk_[A-Za-z0-9_-]{16,}|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' -- . ':!output' ':!final' ':!samples' ':!ss'
```

Expected results for this baseline:

- Frontend tests: `78` passed, `0` failed.
- API tests: `18` passed, `0` failed.
- Production build: successful.
- Both production dependency audits: `0` known vulnerabilities.
- Sample validator: `6` source packs, `600` inventory rows, `30` discovery files, `24` monthly files, and `6` ad hoc scenarios validated.
- Secret-pattern command: no output.

## 11. Captured Command Output

The following summaries were captured from the final local validation run. Full individual test names and timings are retained in the linked TAP logs.

### React test suite

```text
$ cd react-ui && npm test
tests 78
suites 0
pass 78
fail 0
cancelled 0
skipped 0
todo 0
exit code 0
```

### Fastify API security suite

```text
$ cd server && npm test
tests 18
suites 0
pass 18
fail 0
cancelled 0
skipped 0
todo 0
exit code 0
```

The API output includes the negative-test responses expected by the suite: unauthenticated write `401`, missing CSRF `403`, non-administrator deletion `403`, untrusted CORS origin `403`, invalid asset identifier `400`, eight generic invalid-login `401` responses, and the ninth invalid-login response `429`.

### Production build

```text
$ cd react-ui && npm run build
2494 modules transformed
production assets rendered
built successfully
exit code 0
```

### Dependency advisory checks

```text
$ cd react-ui && npm audit --omit=dev --json
critical 0 | high 0 | moderate 0 | low 0 | total 0
exit code 0

$ cd server && npm audit --omit=dev --json
critical 0 | high 0 | moderate 0 | low 0 | total 0
exit code 0
```

### Tool-specific sample-data reconciliation

```text
$ node tools/validate_sample_data_pack.mjs
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
exit code 0
```

### Source hygiene

```text
$ git diff --check
(no output)
exit code 0

$ git grep -I -n -E '<provider-key-and-private-key-patterns>' -- tracked-source
(no matches)
exit code 0
```

## 12. Evidence Index

- [Current validation report](VALIDATION_EVIDENCE.md)
- [Frontend TAP evidence](../output/validation/frontend-tests-2026-07-26.tap)
- [API TAP evidence](../output/validation/api-tests-2026-07-26.tap)
- [Frontend npm audit JSON](../output/validation/npm-audit-frontend-2026-07-26.json)
- [API npm audit JSON](../output/validation/npm-audit-api-2026-07-26.json)
- [Sample-pack validation](../output/validation/sample-pack-validation-2026-07-26.json)
- [OpenShift PostgreSQL validation](../output/validation/openshift-postgres-validation-2026-07-26.json)
- [Workbook render and formula manifest](../ss/final-evidence/workbooks/render_manifest.json)
- [Focused API security tests](../server/test/security.test.js)
- [API contract and data-safety tests](../server/test/app.test.js)
- [Executive PDF tests](../react-ui/src/lib/executiveReportPdf.test.js)
- [Host-discovery tests](../react-ui/src/lib/hostDiscovery.test.js)
- [Upload tests](../react-ui/src/lib/uploadFiles.test.js)
- [Scanner and priority tests](../react-ui/src/lib/vulnerabilityEngine.test.js)
- [Randomized sample-data guide](../ss/sample%20data/README.md)

## 13. Approval Record

| Role | Name | Decision | Date |
|---|---|---|---|
| Engineering owner |  |  |  |
| Security reviewer |  |  |  |
| Compliance reviewer |  |  |  |
| Production approver |  |  |  |
