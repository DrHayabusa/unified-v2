import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import pg from "../server/node_modules/pg/lib/index.js";
import { persistAnalysis } from "../react-ui/src/lib/databaseClient.js";
import { analyzeMonthlyFiles } from "../react-ui/src/lib/vulnerabilityEngine.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const API_URL = process.env.MVA_API_URL || "http://127.0.0.1:8787";
const DATABASE_URL = process.env.DATABASE_URL || "postgresql://mva@127.0.0.1:55432/mva";
const ADMIN_EMAIL = process.env.MVA_TEST_ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.MVA_TEST_ADMIN_PASSWORD;
const slug = `mva-persistence-${Date.now()}`;

if (!ADMIN_EMAIL || !ADMIN_PASSWORD) throw new Error("Set MVA_TEST_ADMIN_EMAIL and MVA_TEST_ADMIN_PASSWORD before running PostgreSQL integration validation.");

const session = await login();
const customer = (await session.api("/api/v1/customers", {
  method: "POST",
  body: { name: "MVA Persistence Validation", slug, assetScopeMode: "observed", notes: "Temporary automated validation portfolio" },
})).customer;

try {
  const samplePaths = ["april", "may", "june", "july"].map((month) => path.join(ROOT, "samples/tenable_100_row", `tenable_sc_${month}_2026_100plus.csv`));
  const sampleFiles = await Promise.all(samplePaths.map(readFileLike));
  const monthly = await analyzeMonthlyFiles(sampleFiles, "tenable-sc");
  const expectedRows = monthly.snapshots.reduce((sum, snapshot) => sum + snapshot.findings.length, 0);
  const expectedWeighted = monthly.snapshots.flatMap((snapshot) => snapshot.findings).reduce((sum, finding) => sum + (Number(finding.recordCount) || 1), 0);
  const persistenceOptions = { customerId: customer.id, customerName: customer.name, csrfToken: session.csrfToken, fetchImpl: session.fetch };

  const first = await persistAnalysis(monthly, persistenceOptions);
  assert.equal(first.status, "ready");
  assert.equal(first.receivedFindings, expectedRows);
  assert.equal(first.weightedFindings, expectedWeighted);

  const repeated = await persistAnalysis(monthly, persistenceOptions);
  assert.equal(repeated.id, first.id, "Repeated persistence must return the original idempotent scan run.");

  const stored = await session.api(`/api/v1/customers/${customer.id}/scan-runs/${first.id}`);
  const metricTotal = stored.run.metrics.reduce((sum, row) => sum + row.finding_count, 0);
  assert.equal(metricTotal, expectedWeighted);
  assert.equal(stored.run.status, "ready");
  assert.equal(stored.run.sourceLabel, "Tenable.sc");

  const result = { monthly: { id: first.id, periods: monthly.snapshots.length, observationRows: expectedRows, weightedFindings: expectedWeighted, duplicateRunId: repeated.id, metricTotal } };

  if (process.env.MVA_RUN_LARGE_VALIDATION === "1") {
    const large = syntheticAnalysis(80_000);
    const savedLarge = await persistAnalysis(large, persistenceOptions);
    assert.equal(savedLarge.status, "ready");
    assert.equal(savedLarge.receivedFindings, 80_000);
    assert.equal(savedLarge.weightedFindings, 80_000);
    const storedLarge = await session.api(`/api/v1/customers/${customer.id}/scan-runs/${savedLarge.id}`);
    assert.equal(storedLarge.run.metrics.reduce((sum, row) => sum + row.finding_count, 0), 80_000);
    result.large = { id: savedLarge.id, observationRows: savedLarge.receivedFindings, weightedFindings: savedLarge.weightedFindings, chunks: savedLarge.receivedChunks };
  }

  process.stdout.write(`${JSON.stringify({ ok: true, ...result }, null, 2)}\n`);
} finally {
  await cleanup();
}

async function login() {
  const response = await fetch(`${API_URL}/api/v1/auth/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD }) });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || `Login failed with HTTP ${response.status}`);
  const cookie = response.headers.get("set-cookie")?.split(";")[0];
  assert.ok(cookie);
  const authenticatedFetch = (url, options = {}) => fetch(url, { ...options, headers: { ...(options.headers ?? {}), Cookie: cookie } });
  return {
    csrfToken: payload.csrfToken,
    fetch: authenticatedFetch,
    api: async (route, { method = "GET", body } = {}) => {
      const headers = { Accept: "application/json", Cookie: cookie };
      if (body !== undefined) headers["Content-Type"] = "application/json";
      if (method !== "GET") headers["X-MVA-CSRF"] = payload.csrfToken;
      const apiResponse = await fetch(`${API_URL}${route}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
      const apiPayload = await apiResponse.json().catch(() => ({}));
      if (!apiResponse.ok) throw new Error(apiPayload.error || `HTTP ${apiResponse.status}`);
      return apiPayload;
    },
  };
}

async function readFileLike(filePath) {
  const bytes = await fs.readFile(filePath);
  return { name: path.basename(filePath), size: bytes.length, text: async () => bytes.toString("utf8"), arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) };
}

async function cleanup() {
  const client = new pg.Client({ connectionString: DATABASE_URL });
  await client.connect();
  try {
    await client.query("BEGIN");
    await client.query("DELETE FROM scan_runs WHERE customer_id IN (SELECT id FROM customers WHERE slug = $1)", [slug]);
    await client.query("DELETE FROM customers WHERE slug = $1", [slug]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    await client.end();
  }
}

function syntheticAnalysis(count) {
  const findings = Array.from({ length: count }, (_, index) => ({
    sourceTool: "tenable-sc",
    sourceTools: ["tenable-sc"],
    sourceDisplay: "Tenable.sc",
    sourceVulnerabilityId: String(100_000 + index % 250),
    ipAddress: `10.${Math.floor(index / 65_536) % 255}.${Math.floor(index / 256) % 255}.${index % 255}`,
    dnsName: `asset-${String(index).padStart(5, "0")}.validation.local`,
    vulnerabilityName: `Validation finding ${index % 250}`,
    cve: `CVE-2026-${String(10_000 + index % 250)}`,
    severity: ["Critical", "High", "Medium", "Low"][index % 4],
    exploitAvailable: index % 3 === 0,
    exploitSignal: index % 3 === 0 ? "Available" : "No",
    patchPriority: ["P1", "P2", "P3", "P4"][index % 4],
    assetExposure: index % 1001,
    summary: "Synthetic local persistence validation record.",
    description: "Generated only to validate 80,000-row chunking and database reconciliation.",
    remediation: "Apply the vendor update and verify the affected service.",
    kbLinks: "https://example.invalid/validation",
    platformDetails: "Validation platform",
    firstDiscovered: "2026-07-01",
    lastObserved: "2026-07-15",
    protocol: "tcp",
    port: String(1 + index % 65_535),
    recordCount: 1,
    findingKey: `validation|asset-${index}|finding-${index % 250}|tcp|${1 + index % 65_535}`,
  }));
  return { workflow: "adhoc", sourceTool: "tenable-sc", sourceLabel: "Tenable.sc", reportMonth: "July 2026 - 80K Validation", fileName: "synthetic_80k_validation.csv", fileNames: ["synthetic_80k_validation.csv"], sourceIds: ["tenable-sc"], findings, dashboard: { totalVulnerabilities: count }, inputSummary: { fileCount: 1, normalizedObservations: count } };
}
