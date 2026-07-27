import assert from "node:assert/strict";
import test from "node:test";

import {
  deleteCustomerAssets,
  downloadCustomerFindingsCsv,
  fetchCustomerScanAssetCoverage,
  generateRemediationWithLocalLlm,
  importThreatIntelRecords,
  request,
  testLocalLlm,
} from "./platformApi.js";

test("platform writes send cookie credentials and CSRF without legacy tenant headers", async () => {
  let captured;
  const fetchImpl = async (url, options) => {
    captured = { url, options };
    return { ok: true, json: async () => ({ ok: true }) };
  };
  await request("/api/v1/customers", { method: "POST", body: { name: "Acme" }, csrfToken: "csrf-test", fetchImpl });
  assert.equal(captured.options.credentials, "include");
  assert.equal(captured.options.headers["X-MVA-CSRF"], "csrf-test");
  assert.equal(captured.options.headers["X-MVA-Tenant"], undefined);
});

test("platform API surfaces server validation messages", async () => {
  const fetchImpl = async () => ({ ok: false, status: 403, json: async () => ({ error: "Customer access denied." }) });
  await assert.rejects(request("/api/v1/customers/blocked/dashboard", { fetchImpl }), /Customer access denied/);
});

test("finding CSV download sends the selected owner and asset filters", async () => {
  let captured;
  const fetchImpl = async (url, options) => {
    captured = { url, options };
    return {
      ok: true,
      headers: { get: (name) => name === "Content-Disposition" ? 'attachment; filename="mva-acme-july.csv"' : null },
      blob: async () => new Blob(["IP Address\r\n10.20.1.10\r\n"], { type: "text/csv" }),
    };
  };
  const result = await downloadCustomerFindingsCsv("customer-one", { teamId: "team-one", assetId: "asset-one", fetchImpl });
  assert.match(captured.url, /teamId=team-one&assetId=asset-one$/);
  assert.equal(captured.options.credentials, "include");
  assert.equal(result.filename, "mva-acme-july.csv");
  assert.equal(await result.blob.text(), "IP Address\r\n10.20.1.10\r\n");
});

test("bulk asset deletion sends selected IDs with CSRF protection", async () => {
  let captured;
  const fetchImpl = async (url, options) => {
    captured = { url, options };
    return { ok: true, json: async () => ({ ok: true, count: 2 }) };
  };
  const assetIds = ["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"];
  const result = await deleteCustomerAssets("tenant-one", assetIds, "csrf-delete", { fetchImpl });
  assert.match(captured.url, /\/api\/v1\/customers\/tenant-one\/assets$/);
  assert.equal(captured.options.method, "DELETE");
  assert.equal(captured.options.headers["X-MVA-CSRF"], "csrf-delete");
  assert.deepEqual(JSON.parse(captured.options.body), { assetIds });
  assert.equal(result.count, 2);
});

test("scan asset coverage reads the authenticated tenant endpoint", async () => {
  let captured;
  const fetchImpl = async (url, options) => {
    captured = { url, options };
    return { ok: true, json: async () => ({ ok: true, coverage: { available: true, matchedInventoryAssets: 12 } }) };
  };
  const result = await fetchCustomerScanAssetCoverage("tenant-one", { fetchImpl });
  assert.match(captured.url, /\/api\/v1\/customers\/tenant-one\/scan-asset-coverage$/);
  assert.equal(captured.options.credentials, "include");
  assert.equal(result.coverage.matchedInventoryAssets, 12);
});

test("local LLM requests are routed through the authenticated MVA API with CSRF", async () => {
  const requests = [];
  const fetchImpl = async (url, options) => {
    requests.push({ url, options });
    return { ok: true, json: async () => ({ ok: true, llm: { model: "gemma3:12b" }, markdown: "# Remediation Guide" }) };
  };

  await testLocalLlm("tenant-one", "csrf-local", { fetchImpl });
  await generateRemediationWithLocalLlm("tenant-one", {
    prompt: "Create a remediation guide from normalized evidence.",
    targetPeriod: "July 2026",
    sourceLabel: "Qualys VMDR",
  }, "csrf-local", { fetchImpl });

  assert.equal(requests.length, 2);
  assert.match(requests[0].url, /\/customers\/tenant-one\/llm\/test$/);
  assert.match(requests[1].url, /\/customers\/tenant-one\/ai\/remediation$/);
  assert.equal(requests[0].options.headers["X-MVA-CSRF"], "csrf-local");
  assert.equal(requests[1].options.headers["X-MVA-CSRF"], "csrf-local");
  assert.equal(JSON.parse(requests[1].options.body).targetPeriod, "July 2026");
});

test("threat-intelligence import accumulates every chunk and finalizes once", async () => {
  const requests = [];
  const records = Array.from({ length: 1_205 }, (_, index) => ({
    cve: `CVE-2026-${String(index).padStart(4, "0")}`,
    vulnerabilityName: `Finding ${index}`,
    ipAddress: `10.20.${Math.floor(index / 250)}.${index % 250 + 1}`,
    dnsName: `asset-${index}.example.internal`,
    severity: "High",
    patchPriority: "P2",
  }));
  const fetchImpl = async (url, options) => {
    requests.push({ url, body: options.body ? JSON.parse(options.body) : null });
    if (url.endsWith("/threat-intel/imports")) {
      return { ok: true, json: async () => ({ ok: true, import: { id: "import-one", status: "uploading" } }) };
    }
    if (url.endsWith("/finalize")) {
      return { ok: true, json: async () => ({ ok: true, import: { id: "import-one", status: "ready", expectedRecords: records.length, receivedRecords: records.length } }) };
    }
    return { ok: true, json: async () => ({ ok: true, inserted: options.body ? JSON.parse(options.body).records.length : 0 }) };
  };
  const progress = [];

  const imported = await importThreatIntelRecords("tenant-one", {
    ingestionKey: "mva:threat-intel:test",
    sourceLabel: "Multi-Tool",
    fileNames: ["one.csv", "two.xlsx"],
    records,
    csrfToken: "csrf-import",
    fetchImpl,
    onProgress: (value) => progress.push(value),
  });

  const chunks = requests.filter((entry) => entry.url.includes("/chunks"));
  assert.deepEqual(chunks.map((entry) => entry.body.startIndex), [0, 500, 1000]);
  assert.deepEqual(chunks.map((entry) => entry.body.records.length), [500, 500, 205]);
  assert.equal(chunks[0].body.records[0].ipAddress, "10.20.0.1");
  assert.equal(chunks[0].body.records[0].dnsName, "asset-0.example.internal");
  assert.equal(requests.at(-1).url.endsWith("/finalize"), true);
  assert.deepEqual(progress.at(-1), { completed: 1205, total: 1205 });
  assert.equal(imported.status, "ready");
});
