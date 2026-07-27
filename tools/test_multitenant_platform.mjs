import assert from "node:assert/strict";

import pg from "../server/node_modules/pg/lib/index.js";

const API_URL = process.env.MVA_API_URL || "http://127.0.0.1:8787";
const DATABASE_URL = process.env.DATABASE_URL || "postgresql://mva@127.0.0.1:55432/mva";
const ADMIN_EMAIL = process.env.MVA_TEST_ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.MVA_TEST_ADMIN_PASSWORD;

if (!ADMIN_EMAIL || !ADMIN_PASSWORD) throw new Error("Set MVA_TEST_ADMIN_EMAIL and MVA_TEST_ADMIN_PASSWORD for the local validation administrator.");

const runSuffix = `${Date.now()}`;
const slugs = [`mva-lifecycle-${runSuffix}`, `mva-isolation-${runSuffix}`];
const viewerEmail = `viewer-${runSuffix}@mva.local`;
const viewerPassword = "Viewer-Validation!2026";
const analystEmail = `analyst-${runSuffix}@mva.local`;
const analystPassword = "Analyst-Validation!2026";
const keepValidationData = process.env.MVA_KEEP_VALIDATION_DATA === "1";

let adminSession;
let customer;
let isolatedCustomer;

try {
  adminSession = await login(ADMIN_EMAIL, ADMIN_PASSWORD);
  customer = (await adminSession.api("/api/v1/customers", {
    method: "POST",
    body: { name: `Lifecycle Validation ${runSuffix}`, slug: slugs[0], assetScopeMode: "inventory", notes: "Automated multi-tenant integration validation" },
  })).customer;
  isolatedCustomer = (await adminSession.api("/api/v1/customers", {
    method: "POST",
    body: { name: `Isolation Validation ${runSuffix}`, slug: slugs[1], assetScopeMode: "observed", notes: "Cross-customer access validation" },
  })).customer;

  const editedCustomer = (await adminSession.api(`/api/v1/customers/${customer.id}`, {
    method: "PUT",
    body: { name: `Lifecycle Validation Updated ${runSuffix}`, slug: slugs[0], assetScopeMode: "inventory", status: "active", notes: "Updated by automated administration validation" },
  })).customer;
  assert.match(editedCustomer.name, /Updated/);

  const linuxTeam = (await adminSession.api(`/api/v1/customers/${customer.id}/teams`, {
    method: "POST",
    body: { name: "Linux Operations", code: "linux-operations", description: "Owns Linux application servers." },
  })).team;
  const databaseTeam = (await adminSession.api(`/api/v1/customers/${customer.id}/teams`, {
    method: "POST",
    body: { name: "Database Engineering", code: "database-engineering", description: "Owns database infrastructure." },
  })).team;

  const imported = await adminSession.api(`/api/v1/customers/${customer.id}/assets`, {
    method: "POST",
    body: { assets: [
      { assetKey: "10.10.0.1", ipAddress: "10.10.0.1", dnsName: "app01.acme.local", assetType: "Linux Server", teamId: linuxTeam.id, platform: "Linux", businessUnit: "Applications", criticality: "Critical", internetExposed: false, inScope: true },
      { assetKey: "10.10.0.2", ipAddress: "10.10.0.2", dnsName: "db01.acme.local", assetType: "Database", teamId: databaseTeam.id, platform: "PostgreSQL", businessUnit: "Data", criticality: "High", internetExposed: false, inScope: true },
    ] },
  });
  assert.equal(imported.count, 2);
  const importedAssets = (await adminSession.api(`/api/v1/customers/${customer.id}/assets`)).assets;
  const applicationAsset = importedAssets.find((asset) => asset.ipAddress === "10.10.0.1");
  const toggled = (await adminSession.api(`/api/v1/customers/${customer.id}/assets/${applicationAsset.id}`, { method: "PATCH", body: { inScope: false } })).asset;
  assert.equal(toggled.assetType, "Linux Server", "A scope-only edit must preserve the asset category.");
  assert.equal(toggled.teamId, linuxTeam.id, "A scope-only edit must preserve responsible-team ownership.");
  await adminSession.api(`/api/v1/customers/${customer.id}/assets/${applicationAsset.id}`, { method: "PATCH", body: { inScope: true } });

  await adminSession.api("/api/v1/admin/users", {
    method: "POST",
    body: {
      fullName: "Portfolio Validation Viewer",
      email: viewerEmail,
      password: viewerPassword,
      globalRole: "customer_user",
      memberships: [{ customerId: customer.id, role: "viewer" }],
    },
  });
  await adminSession.api("/api/v1/admin/users", {
    method: "POST",
    body: {
      fullName: "Portfolio Validation Analyst",
      email: analystEmail,
      password: analystPassword,
      globalRole: "customer_user",
      memberships: [{ customerId: customer.id, role: "analyst" }],
    },
  });

  const findings = lifecycleFindings();
  const created = await adminSession.api(`/api/v1/customers/${customer.id}/scan-runs`, {
    method: "POST",
    body: {
      ingestionKey: `platform-validation-${runSuffix}`,
      workflow: "monthly",
      sourceTool: "tenable-sc",
      sourceLabel: "Tenable.sc",
      reportPeriod: "June 2026 - July 2026",
      fileNames: ["tenable_sc_june_2026.csv", "tenable_sc_july_2026.csv"],
      sourceIds: ["tenable-sc"],
      expectedFindings: findings.length,
      expectedChunks: 1,
      dashboard: { validation: true },
      inputSummary: { fileCount: 2 },
    },
  });
  await adminSession.api(`/api/v1/customers/${customer.id}/scan-runs/${created.run.id}/chunks`, {
    method: "POST",
    body: { chunkIndex: 0, startIndex: 0, findings },
  });
  const finalized = await adminSession.api(`/api/v1/customers/${customer.id}/scan-runs/${created.run.id}/finalize`, { method: "POST", body: {} });
  assert.equal(finalized.run.status, "ready");
  assert.equal(finalized.run.receivedFindings, 6);

  const dashboard = (await adminSession.api(`/api/v1/customers/${customer.id}/dashboard`)).dashboard;
  assert.equal(dashboard.currentPeriod, "July 2026");
  assert.equal(dashboard.previousPeriod, "June 2026");
  assert.equal(dashboard.comparisonAvailable, true);
  assert.deepEqual(dashboard.metrics, {
    totalOpen: 2,
    affectedAssets: 1,
    immediatePatch: 2,
    exploitable: 2,
    newFindings: 1,
    fixedFindings: 2,
    repeatedFindings: 1,
    excludedByScope: 1,
  });
  assert.deepEqual(dashboard.trend.map((row) => [row.period, row.totalOpen]), [["June 2026", 3], ["July 2026", 2]]);
  assert.equal(dashboard.inventory.totalAssets, 3, "Out-of-scope scanner assets remain visible for review without entering dashboard scope.");
  assert.equal(dashboard.inventory.inScopeAssets, 2);
  assert.equal(dashboard.priority.P1, 1);
  assert.equal(dashboard.priority.P2, 1);
  assert.equal(dashboard.teamBreakdown.find((team) => team.id === linuxTeam.id).totalOpen, 2);
  assert.equal(dashboard.teamBreakdown.find((team) => team.id === databaseTeam.id).totalOpen, 0);
  const linuxDashboard = (await adminSession.api(`/api/v1/customers/${customer.id}/dashboard?teamId=${linuxTeam.id}`)).dashboard;
  assert.equal(linuxDashboard.metrics.totalOpen, 2);
  assert.equal(linuxDashboard.metrics.affectedAssets, 1);
  assert.equal(linuxDashboard.inventory.inScopeAssets, 1);
  const assetDashboard = (await adminSession.api(`/api/v1/customers/${customer.id}/dashboard?teamId=${linuxTeam.id}&assetId=${applicationAsset.id}`)).dashboard;
  assert.equal(assetDashboard.metrics.totalOpen, 2);
  assert.equal(assetDashboard.metrics.affectedAssets, 1);
  assert.equal(await directAssetFindingTotal(created.run.id, "2026-07-01", applicationAsset.ipAddress), assetDashboard.metrics.totalOpen);

  const initialExport = await adminSession.raw(`/api/v1/customers/${customer.id}/findings.csv?teamId=${linuxTeam.id}&assetId=${applicationAsset.id}`);
  assert.equal(initialExport.status, 200);
  assert.match(initialExport.headers.get("content-disposition") || "", /vulnerabilities\.csv/);
  const initialCsv = await initialExport.text();
  assert.match(initialCsv, /^(?:\uFEFF)?"IP Address","DNS Name","Asset Owner","Vulnerability Name","CVE","Severity","Exploit\?","Patch Priority","Asset Exposure \(on 1000\)","Vulnerability Finding","Summary","Description","Remediation","KB Links","Platform Details","First Discovered","Last Observed"/);
  assert.match(initialCsv, /"2026-07-01","2026-07-20"/);
  assert.equal((initialCsv.match(/"10\.10\.0\.1"/g) ?? []).length, 2);
  assert.doesNotMatch(initialCsv, /"10\.10\.0\.2"/);

  const analystSession = await login(analystEmail, analystPassword);
  const analystTeam = (await analystSession.api(`/api/v1/customers/${customer.id}/teams`, {
    method: "POST",
    body: { name: "Application Operations", code: "application-operations", description: "Created by an Analyst during validation." },
  })).team;
  const analystAssignedAsset = (await analystSession.api(`/api/v1/customers/${customer.id}/assets/${applicationAsset.id}`, {
    method: "PATCH",
    body: { teamId: analystTeam.id },
  })).asset;
  assert.equal(analystAssignedAsset.teamId, analystTeam.id);
  const analystInventory = (await analystSession.api(`/api/v1/customers/${customer.id}/assets`)).assets;
  assert.equal(analystInventory.some((asset) => asset.id === applicationAsset.id && asset.teamName === analystTeam.name), true);
  const analystDashboard = (await analystSession.api(`/api/v1/customers/${customer.id}/dashboard?teamId=${analystTeam.id}&assetId=${applicationAsset.id}`)).dashboard;
  assert.equal(analystDashboard.metrics.totalOpen, 2);
  const analystExport = await analystSession.raw(`/api/v1/customers/${customer.id}/findings.csv?teamId=${analystTeam.id}&assetId=${applicationAsset.id}`);
  assert.equal(analystExport.status, 200);
  assert.match(await analystExport.text(), /"Application Operations"/);

  const viewerSession = await login(viewerEmail, viewerPassword);
  const viewerDashboard = await viewerSession.api(`/api/v1/customers/${customer.id}/dashboard`);
  assert.equal(viewerDashboard.dashboard.metrics.totalOpen, 2);
  await assert.rejects(
    viewerSession.api(`/api/v1/customers/${isolatedCustomer.id}/dashboard`),
    (error) => error.status === 403,
  );
  await assert.rejects(
    viewerSession.api(`/api/v1/customers/${customer.id}/assets`, { method: "POST", body: { assets: [{ assetKey: "blocked" }] } }),
    (error) => error.status === 403,
  );

  const julyOnlyFinding = finding("July 2026", "10.10.0.1", "CVE-2026-1001", "Critical", true, "P1", 110);
  const julyOnlyRun = await adminSession.api(`/api/v1/customers/${customer.id}/scan-runs`, {
    method: "POST",
    body: {
      ingestionKey: `platform-validation-july-only-${runSuffix}`,
      workflow: "adhoc",
      sourceTool: "tenable-sc",
      sourceLabel: "Tenable.sc",
      reportPeriod: "July 2026",
      fileNames: ["tenable_sc_july_only_2026.csv"],
      sourceIds: ["tenable-sc"],
      expectedFindings: 1,
      expectedChunks: 1,
      dashboard: { validation: true },
      inputSummary: { fileCount: 1 },
    },
  });
  await adminSession.api(`/api/v1/customers/${customer.id}/scan-runs/${julyOnlyRun.run.id}/chunks`, {
    method: "POST",
    body: { chunkIndex: 0, startIndex: 0, findings: [julyOnlyFinding] },
  });
  await adminSession.api(`/api/v1/customers/${customer.id}/scan-runs/${julyOnlyRun.run.id}/finalize`, { method: "POST", body: {} });
  const fallbackDashboard = (await adminSession.api(`/api/v1/customers/${customer.id}/dashboard`)).dashboard;
  assert.equal(fallbackDashboard.currentPeriod, "July 2026");
  assert.equal(fallbackDashboard.previousPeriod, "June 2026", "A later same-month upload must compare with the prior month, not another July run.");

  process.stdout.write(`${JSON.stringify({
    ok: true,
    validationCustomer: { id: customer.id, name: customer.name, slug: customer.slug },
    customerIsolation: "passed",
    viewerWriteProtection: "passed",
    inventoryScope: "passed",
    customerEdit: "passed",
    teamOwnership: "passed",
    analystAssetOnboarding: "passed",
    assetScopedDashboard: "passed",
    assetScopedCsvExport: "passed",
    directSqlReconciliation: "passed",
    partialAssetUpdate: "passed",
    sameMonthFallback: "passed",
    lifecycle: dashboard.metrics,
    trend: dashboard.trend,
  }, null, 2)}\n`);
} finally {
  if (!keepValidationData) await cleanup();
}

async function login(email, password) {
  const response = await fetch(`${API_URL}/api/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || `Login failed with HTTP ${response.status}`);
  const cookie = response.headers.get("set-cookie")?.split(";")[0];
  assert.ok(cookie, "Authentication must issue an HttpOnly session cookie.");
  return {
    api: (route, options = {}) => api(route, { ...options, cookie, csrfToken: payload.csrfToken }),
    raw: (route, options = {}) => raw(route, { ...options, cookie, csrfToken: payload.csrfToken }),
  };
}

async function api(route, { method = "GET", body, cookie, csrfToken } = {}) {
  const response = await raw(route, { method, body, cookie, csrfToken });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.error || `HTTP ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return payload;
}

async function raw(route, { method = "GET", body, cookie, csrfToken } = {}) {
  const headers = { Accept: "application/json", Cookie: cookie };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && csrfToken) headers["X-MVA-CSRF"] = csrfToken;
  return fetch(`${API_URL}${route}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
}

async function directAssetFindingTotal(scanRunId, reportPeriodDate, ipAddress) {
  const client = new pg.Client({ connectionString: DATABASE_URL });
  await client.connect();
  try {
    const result = await client.query(
      `SELECT COALESCE(sum(record_count), 0)::integer AS count
       FROM finding_observations
       WHERE scan_run_id = $1 AND report_period_date = $2::date AND ip_address = $3`,
      [scanRunId, reportPeriodDate, ipAddress],
    );
    return result.rows[0].count;
  } finally {
    await client.end();
  }
}

function lifecycleFindings() {
  return [
    finding("June 2026", "10.10.0.1", "CVE-2026-1001", "Critical", true, "P1", 80),
    finding("June 2026", "10.10.0.1", "CVE-2026-1002", "High", false, "P2", 45),
    finding("June 2026", "10.10.0.2", "CVE-2026-1003", "Medium", false, "P3", 20),
    finding("July 2026", "10.10.0.1", "CVE-2026-1001", "Critical", true, "P1", 110),
    finding("July 2026", "10.10.0.1", "CVE-2026-1004", "Medium", true, "P2", 12),
    finding("July 2026", "10.10.0.99", "CVE-2026-1005", "Low", false, "P4", 5),
  ];
}

function finding(reportPeriod, ipAddress, cve, severity, exploitAvailable, patchPriority, age) {
  return {
    reportPeriod,
    findingKey: `${ipAddress}|${cve}|tcp|443`,
    sourceTool: "tenable-sc",
    sourceTools: ["tenable-sc"],
    sourceDisplay: "Tenable.sc",
    sourceVulnerabilityId: cve,
    ipAddress,
    dnsName: ipAddress === "10.10.0.1" ? "app01.acme.local" : ipAddress === "10.10.0.2" ? "db01.acme.local" : "outside-scope.acme.local",
    vulnerabilityName: `Validation ${cve}`,
    cve,
    severity,
    exploitAvailable,
    exploitSignal: exploitAvailable ? "Available" : "No",
    patchPriority,
    assetExposure: exploitAvailable ? 800 : 300,
    summary: "Lifecycle validation finding.",
    description: "Synthetic finding used only for local multi-customer validation.",
    remediation: "Apply the supported vendor update and validate the service.",
    kbLinks: "https://example.invalid/mva-validation",
    platformDetails: "Linux",
    firstDiscovered: reportPeriod === "June 2026" ? "2026-04-01" : "2026-07-01",
    lastObserved: reportPeriod === "June 2026" ? "2026-06-30" : "2026-07-20",
    vulnerabilityAgeDays: age,
    protocol: "tcp",
    port: "443",
    recordCount: 1,
  };
}

async function cleanup() {
  const client = new pg.Client({ connectionString: DATABASE_URL });
  await client.connect();
  try {
    await client.query("BEGIN");
    await client.query("DELETE FROM scan_runs WHERE customer_id IN (SELECT id FROM customers WHERE slug = ANY($1::text[]))", [slugs]);
    await client.query("DELETE FROM customers WHERE slug = ANY($1::text[])", [slugs]);
    await client.query("DELETE FROM users WHERE email = $1", [viewerEmail]);
    await client.query("DELETE FROM users WHERE email = $1", [analystEmail]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    await client.end();
  }
}
