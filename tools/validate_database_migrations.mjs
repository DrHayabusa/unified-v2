import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import pg from "../server/node_modules/pg/lib/index.js";
import { PostgresRepository } from "../server/src/repository.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DATABASE_URL = process.env.DATABASE_URL;
const EXPECTED_TABLES = [
  "audit_events",
  "auth_sessions",
  "customer_asset_aliases",
  "customer_assets",
  "customer_memberships",
  "customer_teams",
  "customers",
  "finding_observations",
  "ingestion_chunks",
  "scan_runs",
  "schema_migrations",
  "threat_intel_enrichments",
  "threat_intel_imports",
  "threat_intel_records",
  "users",
];

if (!DATABASE_URL) throw new Error("Set DATABASE_URL to a disposable PostgreSQL validation database.");

const migrationFiles = (await fs.readdir(path.join(ROOT, "server/migrations")))
  .filter((name) => name.endsWith(".sql"))
  .sort();
const repository = new PostgresRepository({ connectionString: DATABASE_URL });
await repository.migrate();
await repository.migrate();
await repository.close();

const client = new pg.Client({ connectionString: DATABASE_URL });
await client.connect();
try {
  const recorded = await client.query("SELECT name, checksum FROM schema_migrations ORDER BY name");
  assert.deepEqual(recorded.rows.map((row) => row.name), migrationFiles);
  assert.ok(recorded.rows.every((row) => /^[a-f0-9]{64}$/.test(row.checksum)));

  const tables = await client.query(
    "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename",
  );
  assert.deepEqual(tables.rows.map((row) => row.tablename), EXPECTED_TABLES);

  const indexes = await client.query(
    "SELECT count(*)::integer AS count FROM pg_indexes WHERE schemaname = 'public'",
  );
  const constraints = await client.query(
    `SELECT contype, count(*)::integer AS count
       FROM pg_constraint constraint_record
       JOIN pg_namespace namespace_record ON namespace_record.oid = constraint_record.connamespace
      WHERE namespace_record.nspname = 'public'
      GROUP BY contype
      ORDER BY contype`,
  );

  await client.query("BEGIN");
  try {
    const customer = await client.query(
      `INSERT INTO customers (name, slug)
       VALUES ('Migration Validation', $1)
       RETURNING id`,
      [`migration-validation-${Date.now()}`],
    );
    const scanRunId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    await client.query(
      `INSERT INTO scan_runs (
         id, tenant_key, customer_id, customer_name, ingestion_key, workflow,
         source_tool, source_label, report_period, expected_findings, expected_chunks
       ) VALUES ($1, 'migration-validation', $2, 'Migration Validation', $3, 'monthly',
                 'tenable-sc', 'Tenable.sc', 'July 2026', 1, 1)`,
      [scanRunId, customer.rows[0].id, `migration-validation-${Date.now()}`],
    );
    await client.query(
      `INSERT INTO finding_observations (
         scan_run_id, row_index, report_period, report_period_date, finding_key,
         source_tool, severity, patch_priority, normalized_payload
       ) VALUES ($1, 0, 'July 2026', DATE '0001-07-01 BC', 'migration-validation',
                 'tenable-sc', 'Critical', 'P1', '{}'::jsonb)`,
      [scanRunId],
    );
    const repairSql = await fs.readFile(
      path.join(ROOT, "server/migrations/012_repair_report_period_date_capture.sql"),
      "utf8",
    );
    await client.query(repairSql);
    const repaired = await client.query(
      "SELECT report_period_date::text AS report_period_date FROM finding_observations WHERE scan_run_id = $1",
      [scanRunId],
    );
    assert.equal(repaired.rows[0].report_period_date, "2026-07-01");
  } finally {
    await client.query("ROLLBACK");
  }

  process.stdout.write(`${JSON.stringify({
    ok: true,
    postgresVersion: (await client.query("SHOW server_version")).rows[0].server_version,
    migrations: recorded.rowCount,
    tables: tables.rowCount,
    indexes: indexes.rows[0].count,
    constraints: Object.fromEntries(constraints.rows.map((row) => [row.contype, row.count])),
    idempotentSecondRun: true,
    periodDateRepair: "2026-07-01",
  }, null, 2)}\n`);
} finally {
  await client.end();
}
