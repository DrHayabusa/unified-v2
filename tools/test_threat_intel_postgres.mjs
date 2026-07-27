import assert from "node:assert/strict";

import pg from "../server/node_modules/pg/lib/index.js";

const API_URL = process.env.MVA_API_URL || "http://127.0.0.1:8787";
const DATABASE_URL = process.env.DATABASE_URL || "postgresql://mva@127.0.0.1:55432/mva";
const ADMIN_EMAIL = process.env.MVA_TEST_ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.MVA_TEST_ADMIN_PASSWORD;
const suffix = Date.now();
const slug = `mva-threat-intel-${suffix}`;

if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
  throw new Error("Set MVA_TEST_ADMIN_EMAIL and MVA_TEST_ADMIN_PASSWORD for the validation administrator.");
}

const session = await login();
const customer = (await session.api("/api/v1/customers", {
  method: "POST",
  body: {
    name: `Threat Intelligence Validation ${suffix}`,
    slug,
    assetScopeMode: "inventory",
    notes: "Temporary end-to-end threat-intelligence validation.",
  },
})).customer;

try {
  const created = await session.api(`/api/v1/customers/${customer.id}/threat-intel/imports`, {
    method: "POST",
    body: {
      ingestionKey: `mva:threat-intel:validation-${suffix}`,
      sourceLabel: "Tenable.sc",
      fileNames: ["tenable_sc_threat_intel_validation.csv"],
      expectedRecords: 2,
    },
  });

  const records = [
    threatRecord(0, "10.44.10.21", "log4j-app01.validation.local", "CVE-2021-44228", "Critical", "P1", true),
    threatRecord(1, "10.44.10.22", "log4j-app02.validation.local", "CVE-2021-44228", "High", "P1", true),
  ];
  const chunk = await session.api(
    `/api/v1/customers/${customer.id}/threat-intel/imports/${created.import.id}/chunks`,
    { method: "POST", body: { startIndex: 0, records } },
  );
  assert.equal(chunk.import.receivedRecords, 2);

  const finalized = await session.api(
    `/api/v1/customers/${customer.id}/threat-intel/imports/${created.import.id}/finalize`,
    { method: "POST", body: {} },
  );
  assert.equal(finalized.import.status, "ready");

  const searched = await session.api(`/api/v1/customers/${customer.id}/threat-intel?q=CVE-2021-44228`);
  assert.equal(searched.records.length, 2);
  assert.deepEqual(
    new Set(searched.records.map((record) => record.ipAddress)),
    new Set(["10.44.10.21", "10.44.10.22"]),
  );
  assert.deepEqual(
    new Set(searched.records.map((record) => record.dnsName)),
    new Set(["log4j-app01.validation.local", "log4j-app02.validation.local"]),
  );

  const database = new pg.Client({ connectionString: DATABASE_URL });
  await database.connect();
  let persisted;
  try {
    persisted = await database.query(
      `SELECT count(*)::integer AS records,
              count(DISTINCT NULLIF(ip_address, ''))::integer AS assets_by_ip,
              count(DISTINCT NULLIF(dns_name, ''))::integer AS assets_by_dns
       FROM threat_intel_records
       WHERE customer_id = $1`,
      [customer.id],
    );
  } finally {
    await database.end();
  }
  assert.deepEqual(persisted.rows[0], { records: 2, assets_by_ip: 2, assets_by_dns: 2 });

  const llmStatus = await session.api("/api/v1/llm/status");
  const llmTest = await session.raw(`/api/v1/customers/${customer.id}/llm/test`, {
    method: "POST",
    body: {},
  });
  const llmPayload = await llmTest.json().catch(() => ({}));
  assert.ok([200, 503].includes(llmTest.status), `Expected local Ollama success or controlled unavailability, received ${llmTest.status}.`);
  if (llmTest.status === 503) {
    assert.match(llmPayload.error || "", /Ollama|model/i);
  }

  process.stdout.write(`${JSON.stringify({
    ok: true,
    importedRecords: 2,
    searchedRecords: searched.records.length,
    uniqueAffectedAssetsByIp: persisted.rows[0].assets_by_ip,
    uniqueAffectedAssetsByDns: persisted.rows[0].assets_by_dns,
    tenantBoundary: customer.id,
    localLlm: {
      provider: llmStatus.llm.provider,
      model: llmStatus.llm.model,
      connectivityStatus: llmTest.status,
      controlledUnavailable: llmTest.status === 503,
    },
  }, null, 2)}\n`);
} finally {
  const database = new pg.Client({ connectionString: DATABASE_URL });
  await database.connect();
  try {
    await database.query("DELETE FROM customers WHERE id = $1", [customer.id]);
  } finally {
    await database.end();
  }
}

function threatRecord(rowIndex, ipAddress, dnsName, cve, severity, patchPriority, exploitAvailable) {
  return {
    rowIndex,
    cve,
    vulnerabilityName: "Apache Log4j remote code execution",
    sourceTool: "tenable-sc",
    sourceVulnerabilityId: `validation-${rowIndex + 1}`,
    ipAddress,
    dnsName,
    severity,
    patchPriority,
    exploitAvailable,
    vulnerabilityConfidence: "Confirmed",
    exploitEvidence: "Exploit reference supplied by scanner",
    description: "Synthetic private scanner evidence for end-to-end validation.",
    remediation: "Upgrade Log4j to a supported, non-vulnerable release and validate the application.",
    kbLinks: "https://logging.apache.org/log4j/2.x/security.html",
    product: "Apache Log4j",
    platformDetails: "Linux",
    firstObserved: "2026-05-01",
    lastObserved: "2026-07-25",
  };
}

async function login() {
  const response = await fetch(`${API_URL}/api/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD }),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `Login failed with HTTP ${response.status}.`);
  const cookie = response.headers.get("set-cookie")?.split(";")[0];
  assert.ok(cookie, "Authentication must issue an HttpOnly session cookie.");

  const raw = async (route, { method = "GET", body } = {}) => {
    const headers = { Accept: "application/json", Cookie: cookie };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (method !== "GET") headers["X-MVA-CSRF"] = payload.csrfToken;
    return fetch(`${API_URL}${route}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  };

  return {
    raw,
    api: async (route, options) => {
      const apiResponse = await raw(route, options);
      const apiPayload = await apiResponse.json().catch(() => ({}));
      if (!apiResponse.ok) throw new Error(apiPayload.error || `HTTP ${apiResponse.status}.`);
      return apiPayload;
    },
  };
}
