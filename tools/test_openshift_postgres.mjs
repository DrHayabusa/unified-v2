import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import pg from "../server/node_modules/pg/lib/index.js";

import { PostgresRepository } from "../server/src/repository.js";
import { analyzeAdhocFiles } from "../react-ui/src/lib/vulnerabilityEngine.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DATABASE_URL = process.env.DATABASE_URL || "postgresql://mva@127.0.0.1:55432/mva";
const suffix = `${Date.now()}-${randomUUID().slice(0, 8)}`;
const repository = new PostgresRepository({ connectionString: DATABASE_URL, maxConnections: 4 });
const client = new pg.Client({ connectionString: DATABASE_URL });
let actorId;
let customerId;
let connected = false;

try {
  await repository.migrate();
  await client.connect();
  connected = true;
  actorId = (await client.query(
    `INSERT INTO users (email, full_name, password_hash, global_role)
     VALUES ($1, 'OpenShift Validation', 'not-a-login-credential', 'system_admin')
     RETURNING id`,
    [`openshift-validation-${suffix}@example.invalid`],
  )).rows[0].id;
  customerId = (await client.query(
    `INSERT INTO customers (name, slug, asset_scope_mode, notes)
     VALUES ('OpenShift Validation', $1, 'observed', 'Temporary automated validation')
     RETURNING id`,
    [`openshift-validation-${suffix}`],
  )).rows[0].id;

  const filePath = path.join(ROOT, "samples", "openshift_100_row", "openshift_july_2026_100plus.csv");
  const bytes = await fs.readFile(filePath);
  const file = {
    name: path.basename(filePath),
    size: bytes.length,
    text: async () => bytes.toString("utf8"),
    arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
  };
  const analysis = await analyzeAdhocFiles([file], "openshift");
  const findings = analysis.findings.map((finding) => ({ ...finding, reportPeriod: analysis.reportMonth }));
  const run = await repository.createScanRun(customerId, actorId, {
    customerName: "OpenShift Validation",
    ingestionKey: `mva:openshift-validation-${suffix}`,
    workflow: "adhoc",
    sourceTool: "openshift",
    sourceLabel: "OpenShift",
    reportPeriod: analysis.reportMonth,
    fileNames: [file.name],
    sourceIds: ["openshift"],
    expectedFindings: findings.length,
    expectedChunks: 1,
    dashboard: analysis.dashboard,
    inputSummary: analysis.inputSummary,
  });
  const chunk = await repository.ingestChunk(customerId, run.id, { chunkIndex: 0, startIndex: 0, findings });
  assert.equal(chunk.receivedFindings, 140);
  const finalized = await repository.finalizeScanRun(customerId, run.id);
  assert.equal(finalized.status, "ready");
  assert.equal(finalized.metrics.reduce((sum, row) => sum + row.finding_count, 0), 140);

  const stored = (await client.query(
    `SELECT count(*)::integer AS total,
            count(*) FILTER (WHERE fixable)::integer AS fixable,
            count(*) FILTER (WHERE fixed_in <> '')::integer AS fixed_version,
            count(DISTINCT namespace)::integer AS namespaces,
            count(DISTINCT component)::integer AS components,
            min(cvss_score)::double precision AS min_cvss,
            max(cvss_score)::double precision AS max_cvss
     FROM finding_observations
     WHERE scan_run_id = $1`,
    [run.id],
  )).rows[0];
  assert.deepEqual(
    { total: stored.total, fixable: stored.fixable, fixedVersion: stored.fixed_version, namespaces: stored.namespaces, components: stored.components },
    { total: 140, fixable: 112, fixedVersion: 112, namespaces: 8, components: 10 },
  );
  assert.ok(stored.min_cvss >= 0 && stored.max_cvss <= 10);

  const exported = await repository.getCustomerFindingExport(customerId);
  assert.equal(exported.rows.length, 140);
  assert.ok(exported.rows.every((row) => row.namespace && row.deployment && row.image && row.component));
  assert.equal(exported.rows.filter((row) => row.fixable).length, 112);
  assert.ok(exported.rows.every((row) => row.cvssScore >= 0 && row.cvssScore <= 10));

  process.stdout.write(`${JSON.stringify({
    ok: true,
    findingsStored: stored.total,
    fixable: stored.fixable,
    fixedVersionSupplied: stored.fixed_version,
    namespaces: stored.namespaces,
    components: stored.components,
    exportedRows: exported.rows.length,
    cvssRange: [stored.min_cvss, stored.max_cvss],
  }, null, 2)}\n`);
} finally {
  if (connected) {
    if (customerId) {
      await client.query("DELETE FROM scan_runs WHERE customer_id = $1", [customerId]);
      await client.query("DELETE FROM customers WHERE id = $1", [customerId]);
    }
    if (actorId) await client.query("DELETE FROM users WHERE id = $1", [actorId]);
    await client.end();
  }
  await repository.close();
}
