import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { PostgresRepository } from "../server/src/repository.js";
import { normalizeAssetPayloads } from "../server/src/validation.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const connectionString = process.env.DATABASE_URL || "postgresql://mva@127.0.0.1:55432/mva";
const resetSampleData = process.env.MVA_RESET_SAMPLE_DATA === "1";
const PERIODS = [
  { label: "May 2026", date: "2026-05-01", lastObserved: "2026-05-31", indices: range(0, 12) },
  { label: "June 2026", date: "2026-06-01", lastObserved: "2026-06-30", indices: range(4, 16) },
  { label: "July 2026", date: "2026-07-01", lastObserved: "2026-07-21", indices: range(8, 21) },
];
const CUSTOMERS = [
  { name: "sample_1", slug: "sample-1", sourceTool: "tenable-sc", sourceLabel: "Tenable.sc", file: "sample_1_inventory.csv" },
  { name: "sample_2", slug: "sample-2", sourceTool: "tenable-io", sourceLabel: "Tenable.io", file: "sample_2_inventory.csv" },
  { name: "sample_3", slug: "sample-3", sourceTool: "qualys", sourceLabel: "Qualys VMDR", file: "sample_3_inventory.csv" },
  { name: "sample_4", slug: "sample-4", sourceTool: "crowdstrike", sourceLabel: "CrowdStrike Spotlight", file: "sample_4_inventory.csv" },
];

const repository = new PostgresRepository({ connectionString });
try {
  await repository.migrate();
  const admin = await repository.pool.query(
    "SELECT id FROM users WHERE global_role = 'system_admin' AND status = 'active' ORDER BY created_at LIMIT 1",
  );
  if (!admin.rowCount) throw new Error("Create the first MVA administrator before seeding sample customers.");
  const actorUserId = admin.rows[0].id;

  for (const definition of CUSTOMERS) {
    const customerResult = await repository.pool.query(
      `INSERT INTO customers (name, slug, asset_scope_mode, notes)
       VALUES ($1, $2, 'inventory', $3)
       ON CONFLICT (slug) DO UPDATE SET
         name = EXCLUDED.name, asset_scope_mode = 'inventory', status = 'active', notes = EXCLUDED.notes, updated_at = now()
       RETURNING *`,
      [definition.name, definition.slug, `Validated sample customer for ${definition.sourceLabel}.`],
    );
    const customer = customerResult.rows[0];
    if (resetSampleData) {
      const resetClient = await repository.pool.connect();
      try {
        await resetClient.query("BEGIN");
        await resetClient.query("DELETE FROM scan_runs WHERE customer_id = $1", [customer.id]);
        await resetClient.query("DELETE FROM threat_intel_imports WHERE customer_id = $1", [customer.id]);
        await resetClient.query("DELETE FROM threat_intel_enrichments WHERE customer_id = $1", [customer.id]);
        await resetClient.query("DELETE FROM customer_assets WHERE customer_id = $1", [customer.id]);
        await resetClient.query("DELETE FROM customer_teams WHERE customer_id = $1", [customer.id]);
        await resetClient.query("COMMIT");
      } catch (error) {
        await resetClient.query("ROLLBACK");
        throw error;
      } finally {
        resetClient.release();
      }
    }
    const rows = parseCsv(await fs.readFile(path.join(ROOT, "samples/customer_assets", definition.file), "utf8"));
    const teamNames = [...new Set(rows.map((row) => row["Responsible Team"]).filter(Boolean))];
    const teamByName = new Map();
    for (const name of teamNames) {
      const teamResult = await repository.pool.query(
        `INSERT INTO customer_teams (customer_id, name, code, description)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (customer_id, code) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, updated_at = now()
         RETURNING *`,
        [customer.id, name, slugify(name), `${name} owns the assigned customer assets and associated remediation.`],
      );
      teamByName.set(name.toLowerCase(), teamResult.rows[0]);
    }

    const assets = normalizeAssetPayloads({
      assets: rows.map((row) => ({
        assetKey: row["IP Address"],
        ipAddress: row["IP Address"],
        dnsName: row["DNS Name"],
        hostName: row["Host Name"],
        externalId: row["Asset ID"],
        assetType: row["Asset Type"],
        platform: row.Platform,
        businessUnit: row["Business Unit"],
        criticality: row.Criticality,
        teamId: teamByName.get(row["Responsible Team"].toLowerCase())?.id,
        internetExposed: row["Internet Exposed"],
        inScope: row["In Scope"].toLowerCase() !== "no",
      })),
    });
    await repository.upsertCustomerAssets(actorUserId, customer.id, assets, "sample-seed");

    for (const period of PERIODS) {
      const findings = buildFindings(definition, assets, period);
      const run = await repository.createScanRun(customer.id, actorUserId, {
        customerName: definition.name,
        ingestionKey: `mva:sample-seed:v1:${definition.slug}:${period.date.slice(0, 7)}`,
        workflow: "monthly",
        sourceTool: definition.sourceTool,
        sourceLabel: definition.sourceLabel,
        reportPeriod: period.label,
        fileNames: [`${definition.slug}_${period.date.slice(0, 7)}.csv`],
        sourceIds: [definition.sourceTool],
        expectedFindings: findings.length,
        expectedChunks: 1,
        dashboard: {},
        inputSummary: { seeded: true, source: definition.sourceLabel },
      });
      if (run.status !== "ready") {
        await repository.ingestChunk(customer.id, run.id, { chunkIndex: 0, startIndex: 0, findings });
        await repository.finalizeScanRun(customer.id, run.id);
      }
    }

    const dashboard = await repository.getCustomerDashboard(customer.id);
    if (dashboard.metrics.totalOpen !== 13 || dashboard.metrics.newFindings !== 5 || dashboard.metrics.fixedFindings !== 4) {
      throw new Error(`${definition.name} dashboard reconciliation failed: ${JSON.stringify(dashboard.metrics)}`);
    }
    process.stdout.write(`${definition.name}: ${assets.length} assets, ${teamNames.length} teams, ${dashboard.metrics.totalOpen} open, ${dashboard.metrics.newFindings} new, ${dashboard.metrics.fixedFindings} fixed\n`);
  }
} finally {
  await repository.close();
}

function buildFindings(definition, assets, period) {
  const severities = ["Critical", "High", "Medium", "Low"];
  return period.indices.map((index) => {
    const asset = assets[index % assets.length];
    const severity = severities[index % severities.length];
    const exploitAvailable = index % 3 !== 1;
    const firstDiscovered = `2025-${String(index % 12 + 1).padStart(2, "0")}-01`;
    return {
      reportPeriod: period.label,
      findingKey: `${asset.assetKey}|CVE-2026-${String(4100 + index).padStart(4, "0")}|tcp|443`,
      sourceTool: definition.sourceTool,
      sourceTools: [definition.sourceTool],
      sourceDisplay: definition.sourceLabel,
      sourceVulnerabilityId: `${definition.sourceTool.toUpperCase()}-${9000 + index}`,
      ipAddress: asset.ipAddress,
      dnsName: asset.dnsName,
      vulnerabilityName: `Sample ${severity} vulnerability ${index + 1}`,
      cve: `CVE-2026-${String(4100 + index).padStart(4, "0")}`,
      severity,
      exploitAvailable,
      exploitSignal: exploitAvailable ? "Exploit available" : "No known exploit",
      epssScore: exploitAvailable ? 0.82 : 0.08,
      patchPriority: priorityFor(severity, exploitAvailable),
      assetExposure: exploitAvailable ? 820 : 360,
      vulnerabilityFinding: `Validated sample finding on ${asset.dnsName}.`,
      summary: `Sample vulnerability lifecycle record for ${definition.sourceLabel}.`,
      description: "Synthetic validation data used to verify customer-isolated PostgreSQL dashboard aggregation.",
      remediation: "Apply the vendor update and verify the affected service after the maintenance window.",
      kbLinks: "https://nvd.nist.gov/",
      platformDetails: asset.platform,
      firstDiscovered,
      lastObserved: period.lastObserved,
      vulnerabilityAgeDays: daysBetween(firstDiscovered, period.lastObserved),
      protocol: "tcp",
      port: "443",
      recordCount: 1,
      product: asset.platform,
      assetCriticality: asset.criticality,
      internetExposed: Boolean(asset.internetExposed),
      internetExposureKnown: asset.internetExposed !== null,
      cisaKev: false,
    };
  });
}

function priorityFor(severity, exploitable) {
  if (exploitable) return severity === "Critical" || severity === "High" ? "P1" : "P2";
  return severity === "Critical" || severity === "High" ? "P2" : severity === "Medium" ? "P3" : "P4";
}

function parseCsv(text) {
  const records = [];
  let row = [];
  let value = "";
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (char === '"' && quoted && text[index + 1] === '"') { value += '"'; index += 1; continue; }
    if (char === '"') { quoted = !quoted; continue; }
    if (char === "," && !quoted) { row.push(value); value = ""; continue; }
    if ((char === "\n" || char === "\r") && !quoted) {
      if (char === "\r" && text[index + 1] === "\n") index += 1;
      row.push(value);
      if (row.some((cell) => cell.trim())) records.push(row.map((cell) => cell.trim()));
      row = [];
      value = "";
      continue;
    }
    value += char;
  }
  if (value || row.length) { row.push(value); records.push(row.map((cell) => cell.trim())); }
  const [headers, ...data] = records;
  return data.map((values) => Object.fromEntries(headers.map((header, index) => [header, values[index] ?? ""])));
}

function daysBetween(from, to) {
  return Math.max(0, Math.round((Date.parse(`${to}T00:00:00Z`) - Date.parse(`${from}T00:00:00Z`)) / 86_400_000));
}

function range(start, end) {
  return Array.from({ length: end - start }, (_, index) => start + index);
}

function slugify(value) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60);
}
