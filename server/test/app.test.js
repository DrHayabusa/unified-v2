import assert from "node:assert/strict";
import test from "node:test";

import { buildApp } from "../src/app.js";
import { hashPassword, verifyPassword } from "../src/auth.js";
import { FINDING_EXPORT_COLUMNS, findingCsvLines } from "../src/csv.js";
import { normalizeAssetPayloads, normalizeFinding } from "../src/validation.js";

const CUSTOMER_ID = "11111111-1111-4111-8111-111111111111";
const ASSET_ID = "44444444-4444-4444-8444-444444444444";

function repositoryStub({ globalRole = "system_admin" } = {}) {
  let csrfToken = "";
  const user = {
    id: "22222222-2222-4222-8222-222222222222",
    email: "admin@example.com",
    fullName: "MVA Administrator",
    globalRole,
    status: "active",
  };
  return {
    health: async () => ({ database: "mva_test", checked_at: "2026-07-15T00:00:00Z" }),
    setupStatus: async () => ({ setupRequired: true }),
    bootstrapAdmin: async () => user,
    markLogin: async () => {},
    createSession: async (session) => { csrfToken = session.csrfToken; },
    getSession: async () => ({ sessionId: "session-1", csrfToken, user }),
    deleteSession: async () => {},
    listCustomersForUser: async () => [{ id: CUSTOMER_ID, name: "Demo Customer", assetScopeMode: "observed" }],
    assertCustomerAccess: async () => ({ customer: { id: CUSTOMER_ID, name: "Demo Customer" }, role: "system_admin", assetTypes: [] }),
    getCustomerDashboard: async (_customerId, assetTypes, teamId, assetId) => ({ assetTypes, selectedTeamId: teamId, selectedAssetId: assetId }),
    getCustomerScanAssetCoverage: async () => ({ available: true, reportPeriod: "2026-07-01", matchedInventoryAssets: 2, assetIds: [ASSET_ID] }),
    getCustomerFindingExport: async () => ({
      customer: { id: CUSTOMER_ID, name: "Demo Customer", slug: "demo-customer" },
      reportPeriod: "July 2026",
      rows: [{
        ipAddress: "10.20.1.10",
        dnsName: "server01.example.com",
        assetOwner: "Linux Operations",
        vulnerabilityName: "Example finding",
        cve: "CVE-2026-0001",
        severity: "Critical",
        exploitAvailable: true,
        patchPriority: "P1",
        assetExposure: 740,
        vulnerabilityFinding: "Open",
        summary: "Example summary",
        description: "Example description",
        remediation: "Apply the vendor patch.",
        kbLinks: "https://example.com/kb",
        platformDetails: "Ubuntu 24.04",
        firstDiscovered: "2026-06-01",
        lastObserved: "2026-07-15",
      }],
    }),
    deleteCustomer: async (_actorUserId, customerId, confirmation) => ({ id: customerId, name: confirmation, reports: 2, assets: 20, memberships: 1 }),
    deleteCustomerAssets: async (_actorUserId, _customerId, assetIds) => ({ count: assetIds.length }),
    updateCustomerAsset: async (_actorUserId, _customerId, assetId, changes) => ({ id: assetId, ...changes }),
    createThreatIntelImport: async (_customerId, _createdBy, payload) => ({
      id: "55555555-5555-4555-8555-555555555555",
      status: "uploading",
      expectedRecords: payload.expectedRecords,
      receivedRecords: 0,
      sourceLabel: payload.sourceLabel,
      existing: false,
    }),
    ingestThreatIntelChunk: async (_customerId, _importId, payload) => ({
      inserted: payload.records.length,
      import: {
        id: "55555555-5555-4555-8555-555555555555",
        status: "uploading",
        expectedRecords: 1,
        receivedRecords: payload.records.length,
      },
    }),
    finalizeThreatIntelImport: async () => ({
      id: "55555555-5555-4555-8555-555555555555",
      status: "ready",
      expectedRecords: 1,
      receivedRecords: 1,
      sourceLabel: "Qualys VMDR",
    }),
    searchThreatIntel: async (_customerId, query) => query ? [{
      importId: "55555555-5555-4555-8555-555555555555",
      cve: "CVE-2021-44228",
      vulnerabilityName: "Apache Log4j Remote Code Execution",
      sourceTool: "qualys-monthly",
      sourceVulnerabilityId: "376157",
      ipAddress: "10.20.1.25",
      dnsName: "web-25.example.com",
      severity: "Critical",
      patchPriority: "P1",
      exploitAvailable: true,
      vulnerabilityConfidence: "Confirmed",
      exploitEvidence: "https://example.com/exploit-reference",
      description: "Scanner-confirmed Log4j finding.",
      remediation: "Upgrade to a vendor-supported fixed release.",
      kbLinks: "https://logging.apache.org/log4j/2.x/security.html",
      product: "Apache Log4j",
      platformDetails: "Java",
      firstObserved: "2026-04-01",
      lastObserved: "2026-07-01",
    }] : [],
    saveThreatIntelEnrichment: async () => ({ id: "66666666-6666-4666-8666-666666666666", createdAt: "2026-07-26T00:00:00Z" }),
    createScanRun: async (_customerId, _userId, metadata) => ({ id: "run-1", status: "uploading", existing: false, ...metadata }),
    ingestChunk: async () => ({ duplicate: false, receivedFindings: 1, receivedChunks: 1, status: "uploading" }),
    finalizeScanRun: async () => ({ id: "run-1", status: "ready" }),
    listScanRuns: async () => [{ id: "run-1", status: "ready" }],
    getScanRun: async () => ({ id: "run-1", status: "ready", metrics: [] }),
    audit: async () => {},
  };
}

test("tenant deletion requires administrator role, CSRF, and explicit confirmation payload", async (context) => {
  const adminApp = await buildApp({ repository: repositoryStub(), allowedOrigins: ["*"] });
  context.after(() => adminApp.close());
  const admin = await bootstrap(adminApp);

  const missingCsrf = await adminApp.inject({ method: "DELETE", url: `/api/v1/customers/${CUSTOMER_ID}`, headers: { cookie: admin.cookie }, payload: { confirmation: "Demo Customer" } });
  assert.equal(missingCsrf.statusCode, 403);

  const deleted = await adminApp.inject({ method: "DELETE", url: `/api/v1/customers/${CUSTOMER_ID}`, headers: { cookie: admin.cookie, "x-mva-csrf": admin.csrfToken }, payload: { confirmation: "Demo Customer" } });
  assert.equal(deleted.statusCode, 200);
  assert.equal(deleted.json().deleted.name, "Demo Customer");

  const customerApp = await buildApp({ repository: repositoryStub({ globalRole: "customer_user" }), allowedOrigins: ["*"] });
  context.after(() => customerApp.close());
  const customerSession = await bootstrap(customerApp);
  const forbidden = await customerApp.inject({ method: "DELETE", url: `/api/v1/customers/${CUSTOMER_ID}`, headers: { cookie: customerSession.cookie, "x-mva-csrf": customerSession.csrfToken }, payload: { confirmation: "Demo Customer" } });
  assert.equal(forbidden.statusCode, 403);
});

async function bootstrap(app) {
  const response = await app.inject({
    method: "POST",
    url: "/api/v1/auth/bootstrap",
    payload: { email: "admin@example.com", fullName: "MVA Administrator", password: "Correct horse battery staple 2026" },
  });
  assert.equal(response.statusCode, 201);
  const cookie = response.headers["set-cookie"].split(";")[0];
  return { cookie, csrfToken: response.json().csrfToken };
}

test("health, setup, and first administrator contracts are exposed", async (context) => {
  const app = await buildApp({ repository: repositoryStub(), allowedOrigins: ["http://127.0.0.1:8820"] });
  context.after(() => app.close());

  const health = await app.inject({ method: "GET", url: "/health" });
  assert.equal(health.statusCode, 200);
  assert.equal(health.json().database, "mva_test");

  const setup = await app.inject({ method: "GET", url: "/api/v1/auth/setup-status" });
  assert.equal(setup.statusCode, 200);
  assert.equal(setup.json().setupRequired, true);

  const session = await bootstrap(app);
  assert.match(session.cookie, /^mva_session=/);
  assert.ok(session.csrfToken.length > 20);
});

test("customer scan routes require a session and CSRF token", async (context) => {
  const app = await buildApp({ repository: repositoryStub(), allowedOrigins: ["*"] });
  context.after(() => app.close());

  const unauthenticated = await app.inject({ method: "POST", url: `/api/v1/customers/${CUSTOMER_ID}/scan-runs`, payload: {} });
  assert.equal(unauthenticated.statusCode, 401);

  const session = await bootstrap(app);
  const missingCsrf = await app.inject({
    method: "POST",
    url: `/api/v1/customers/${CUSTOMER_ID}/scan-runs`,
    headers: { cookie: session.cookie },
    payload: {},
  });
  assert.equal(missingCsrf.statusCode, 403);

  const created = await app.inject({
    method: "POST",
    url: `/api/v1/customers/${CUSTOMER_ID}/scan-runs`,
    headers: { cookie: session.cookie, "x-mva-csrf": session.csrfToken },
    payload: {
      ingestionKey: "mva:test:123",
      workflow: "adhoc",
      sourceTool: "tenable-sc",
      sourceLabel: "Tenable.sc",
      reportPeriod: "July 2026",
      expectedFindings: 1,
      expectedChunks: 1,
    },
  });
  assert.equal(created.statusCode, 201);
  assert.equal(created.json().run.customerName, "Demo Customer");
});

test("customer dashboard and CSV export accept the same validated scope filters", async (context) => {
  const app = await buildApp({ repository: repositoryStub(), allowedOrigins: ["*"] });
  context.after(() => app.close());
  const session = await bootstrap(app);
  const teamId = "33333333-3333-4333-8333-333333333333";
  const assetId = "44444444-4444-4444-8444-444444444444";

  const dashboard = await app.inject({ method: "GET", url: `/api/v1/customers/${CUSTOMER_ID}/dashboard?teamId=${teamId}&assetId=${assetId}`, headers: { cookie: session.cookie } });
  assert.equal(dashboard.statusCode, 200);
  assert.equal(dashboard.json().dashboard.selectedTeamId, teamId);
  assert.equal(dashboard.json().dashboard.selectedAssetId, assetId);

  const exported = await app.inject({ method: "GET", url: `/api/v1/customers/${CUSTOMER_ID}/findings.csv?teamId=${teamId}&assetId=${assetId}`, headers: { cookie: session.cookie } });
  assert.equal(exported.statusCode, 200);
  assert.match(exported.headers["content-type"], /^text\/csv/);
  assert.match(exported.headers["content-disposition"], /mva-demo-customer-july-2026-vulnerabilities\.csv/);
  assert.match(exported.body, /"Asset Owner"/);
  assert.match(exported.body, /"Linux Operations"/);

  const invalid = await app.inject({ method: "GET", url: `/api/v1/customers/${CUSTOMER_ID}/dashboard?assetId=not-a-uuid`, headers: { cookie: session.cookie } });
  assert.equal(invalid.statusCode, 400);

  const scanCoverage = await app.inject({ method: "GET", url: `/api/v1/customers/${CUSTOMER_ID}/scan-asset-coverage`, headers: { cookie: session.cookie } });
  assert.equal(scanCoverage.statusCode, 200);
  assert.equal(scanCoverage.json().coverage.matchedInventoryAssets, 2);
});

test("finding CSV exports exact reporting columns and neutralizes spreadsheet formulas", () => {
  const csv = [...findingCsvLines([{ ipAddress: "=1+1", exploitAvailable: false, vulnerabilityName: "+malicious", firstDiscovered: new Date("2026-07-01T00:00:00Z") }])].join("");
  assert.equal(csv.startsWith(`\uFEFF"${FINDING_EXPORT_COLUMNS[0][0]}"`), true);
  assert.match(csv, /"'=1\+1"/);
  assert.match(csv, /"'\+malicious"/);
  assert.match(csv, /"No"/);
  assert.match(csv, /"2026-07-01"/);
});

test("scrypt passwords verify without storing plaintext", async () => {
  const encoded = await hashPassword("A long and memorable local password 2026");
  assert.match(encoded, /^scrypt\$/);
  assert.equal(await verifyPassword("A long and memorable local password 2026", encoded), true);
  assert.equal(await verifyPassword("incorrect password", encoded), false);
  assert.equal(encoded.includes("memorable"), false);
});

test("finding normalization constrains priority, exposure, dates, and text", () => {
  const finding = normalizeFinding({
    sourceTool: "tenable-sc",
    severity: "Critical",
    patchPriority: "P1",
    reportPeriod: "July 2026",
    assetExposure: 5000,
    firstDiscovered: "not-a-date",
    lastObserved: "2026-07-15",
    recordCount: 2,
    vulnerabilityName: "Example\u0000 finding",
  }, 7);
  assert.equal(finding.rowIndex, 7);
  assert.equal(finding.reportPeriodDate, "2026-07-01");
  assert.equal(finding.assetExposure, 1000);
  assert.equal(finding.firstDiscovered, null);
  assert.equal(finding.lastObserved, "2026-07-15");
  assert.equal(finding.vulnerabilityName, "Example finding");
  assert.equal(finding.recordCount, 2);
});

test("backend canonical finding identity ignores mutable service and description fields", () => {
  const base = {
    sourceTool: "tenable-sc",
    sourceVulnerabilityId: "1001",
    ipAddress: "10.20.1.10",
    severity: "High",
    patchPriority: "P2",
    reportPeriod: "May 2026",
  };
  const before = normalizeFinding({
    ...base,
    findingKey: "untrusted-browser-key-a",
    vulnerabilityName: "Original title",
    cve: "CVE-2026-1001",
    protocol: "tcp",
    port: "443",
  }, 0);
  const after = normalizeFinding({
    ...base,
    findingKey: "untrusted-browser-key-b",
    vulnerabilityName: "Renamed title",
    cve: "",
    protocol: "udp",
    port: "8443",
  }, 1);
  assert.equal(before.findingKey, after.findingKey);
  assert.notEqual(before.findingKey, "untrusted-browser-key-a");

  const workload = normalizeFinding({
    sourceTool: "openshift",
    sourceVulnerabilityId: "CVE-2026-2001 | openssl",
    assetKey: "team-a/app-a/image:v1",
    namespace: "team-a",
    deployment: "app-a",
    image: "image:v1",
    severity: "High",
    patchPriority: "P2",
    reportPeriod: "May 2026",
  }, 2);
  assert.equal(workload.assetKey, "team-a/app-a/image:v1");
  assert.match(workload.findingKey, /^[a-f0-9]{8}$/);
});

test("asset inventory accepts repeated aliases for one asset and rejects cross-asset collisions", () => {
  const assets = normalizeAssetPayloads({ assets: [{ assetKey: "10.20.1.10", ipAddress: "10.20.1.10", dnsName: "server01.local", onboardingTool: "Tenable.sc", inScope: false }] });
  assert.equal(assets.length, 1);
  assert.equal(assets[0].assetKey, "10.20.1.10");
  assert.equal(assets[0].onboardingTool, "tenable-sc");
  assert.equal(assets[0].inScope, true);

  assert.throws(() => normalizeAssetPayloads({ assets: [
    { assetKey: "asset-a", ipAddress: "10.20.1.10" },
    { assetKey: "asset-b", ipAddress: "10.20.1.10" },
  ] }), /assigned to more than one inventory record/);
});

test("asset edit and bulk delete routes validate identity, CSRF, and selected IDs", async (context) => {
  const app = await buildApp({ repository: repositoryStub(), allowedOrigins: ["*"] });
  context.after(() => app.close());
  const session = await bootstrap(app);

  const missingCsrf = await app.inject({
    method: "DELETE",
    url: `/api/v1/customers/${CUSTOMER_ID}/assets`,
    headers: { cookie: session.cookie },
    payload: { assetIds: [ASSET_ID] },
  });
  assert.equal(missingCsrf.statusCode, 403);

  const invalidSelection = await app.inject({
    method: "DELETE",
    url: `/api/v1/customers/${CUSTOMER_ID}/assets`,
    headers: { cookie: session.cookie, "x-mva-csrf": session.csrfToken },
    payload: { assetIds: ["not-an-asset-id"] },
  });
  assert.equal(invalidSelection.statusCode, 400);

  const deleted = await app.inject({
    method: "DELETE",
    url: `/api/v1/customers/${CUSTOMER_ID}/assets`,
    headers: { cookie: session.cookie, "x-mva-csrf": session.csrfToken },
    payload: { assetIds: [ASSET_ID] },
  });
  assert.equal(deleted.statusCode, 200);
  assert.equal(deleted.json().count, 1);

  const edited = await app.inject({
    method: "PATCH",
    url: `/api/v1/customers/${CUSTOMER_ID}/assets/${ASSET_ID}`,
    headers: { cookie: session.cookie, "x-mva-csrf": session.csrfToken },
    payload: {
      ipAddress: "10.20.1.25",
      dnsName: "web-25.example.com",
      hostName: "web-25",
      onboardingTool: "Qualys VMDR",
      platform: "RHEL 9",
      teamId: null,
    },
  });
  assert.equal(edited.statusCode, 200);
  assert.equal(edited.json().asset.dnsName, "web-25.example.com");
  assert.equal(edited.json().asset.onboardingTool, "qualys");
});

test("tenant threat-intelligence import, search, local enrichment, and remediation routes are protected and complete", async (context) => {
  const llmCalls = [];
  const llmClient = {
    status: () => ({ configured: true, provider: "Local Ollama", model: "gemma3:12b", baseUrl: "http://127.0.0.1:11434" }),
    test: async () => ({ configured: true, reachable: true, modelInstalled: true, model: "gemma3:12b", installedModels: ["gemma3:12b"] }),
    chat: async (request) => {
      llmCalls.push(request);
      return request.json
        ? { model: "gemma3:12b", content: JSON.stringify({ summary: "Evidence-backed result", references: ["https://logging.apache.org/log4j/2.x/security.html"] }) }
        : { model: "gemma3:12b", content: "# Remediation Guide\n\nValidated remediation content." };
    },
  };
  const app = await buildApp({ repository: repositoryStub(), llmClient, allowedOrigins: ["*"] });
  context.after(() => app.close());
  const session = await bootstrap(app);
  const headers = { cookie: session.cookie, "x-mva-csrf": session.csrfToken };

  const status = await app.inject({ method: "GET", url: "/api/v1/llm/status", headers: { cookie: session.cookie } });
  assert.equal(status.statusCode, 200);
  assert.equal(status.json().llm.model, "gemma3:12b");

  const tested = await app.inject({ method: "POST", url: `/api/v1/customers/${CUSTOMER_ID}/llm/test`, headers, payload: {} });
  assert.equal(tested.statusCode, 200);
  assert.equal(tested.json().llm.modelInstalled, true);

  const created = await app.inject({
    method: "POST",
    url: `/api/v1/customers/${CUSTOMER_ID}/threat-intel/imports`,
    headers,
    payload: {
      ingestionKey: "mva:threat-intel:test",
      sourceLabel: "Qualys VMDR",
      fileNames: ["qualys.csv"],
      expectedRecords: 1,
    },
  });
  assert.equal(created.statusCode, 201);
  const importId = created.json().import.id;

  const chunked = await app.inject({
    method: "POST",
    url: `/api/v1/customers/${CUSTOMER_ID}/threat-intel/imports/${importId}/chunks`,
    headers,
    payload: {
      startIndex: 0,
      records: [{
        cve: "CVE-2021-44228",
        vulnerabilityName: "Apache Log4j Remote Code Execution",
        sourceTool: "qualys-monthly",
        ipAddress: "10.20.1.25",
        dnsName: "web-25.example.com",
        severity: "Critical",
        patchPriority: "P1",
        exploitAvailable: true,
        vulnerabilityConfidence: "Confirmed",
      }],
    },
  });
  assert.equal(chunked.statusCode, 200);
  assert.equal(chunked.json().inserted, 1);

  const finalized = await app.inject({
    method: "POST",
    url: `/api/v1/customers/${CUSTOMER_ID}/threat-intel/imports/${importId}/finalize`,
    headers,
    payload: {},
  });
  assert.equal(finalized.statusCode, 200);
  assert.equal(finalized.json().import.status, "ready");

  const searched = await app.inject({
    method: "GET",
    url: `/api/v1/customers/${CUSTOMER_ID}/threat-intel?q=CVE-2021-44228`,
    headers: { cookie: session.cookie },
  });
  assert.equal(searched.statusCode, 200);
  assert.equal(searched.json().records[0].cve, "CVE-2021-44228");
  assert.equal(searched.json().records[0].ipAddress, "10.20.1.25");
  assert.equal(searched.json().records[0].dnsName, "web-25.example.com");

  const enriched = await app.inject({
    method: "POST",
    url: `/api/v1/customers/${CUSTOMER_ID}/threat-intel/enrich`,
    headers,
    payload: { query: "CVE-2021-44228" },
  });
  assert.equal(enriched.statusCode, 200);
  assert.equal(enriched.json().evidenceCount, 1);
  assert.match(llmCalls[0].messages[1].content, /Scanner-confirmed Log4j finding/);

  const remediation = await app.inject({
    method: "POST",
    url: `/api/v1/customers/${CUSTOMER_ID}/ai/remediation`,
    headers,
    payload: {
      prompt: "Create a customer-ready remediation guide from this normalized scanner evidence.",
      targetPeriod: "July 2026",
      sourceLabel: "Qualys VMDR",
    },
  });
  assert.equal(remediation.statusCode, 200);
  assert.match(remediation.json().markdown, /Remediation Guide/);
  assert.equal(llmCalls[1].json, undefined);

  const withoutCsrf = await app.inject({
    method: "POST",
    url: `/api/v1/customers/${CUSTOMER_ID}/threat-intel/enrich`,
    headers: { cookie: session.cookie },
    payload: { query: "CVE-2021-44228" },
  });
  assert.equal(withoutCsrf.statusCode, 403);
});
