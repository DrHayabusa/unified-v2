import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";

import pg from "../server/node_modules/pg/lib/index.js";

import { PostgresRepository } from "../server/src/repository.js";
import { normalizeAssetPayloads } from "../server/src/validation.js";

const DATABASE_URL = process.env.DATABASE_URL || "postgresql://mva:mva_local_only@127.0.0.1:55432/mva";
const suffix = `${Date.now()}-${randomUUID().slice(0, 8)}`;
const repository = new PostgresRepository({ connectionString: DATABASE_URL, maxConnections: 4 });
const client = new pg.Client({ connectionString: DATABASE_URL });
let actorId;
let customerA;
let customerB;

try {
  await repository.migrate();
  await client.connect();

  actorId = (await client.query(
    `INSERT INTO users (email, full_name, password_hash, global_role)
     VALUES ($1, 'Asset Validation', 'not-a-login-credential', 'system_admin')
     RETURNING id`,
    [`asset-validation-${suffix}@example.invalid`],
  )).rows[0].id;
  customerA = (await client.query(
    `INSERT INTO customers (name, slug, asset_scope_mode, notes)
     VALUES ('Asset Validation A', $1, 'inventory', 'Temporary automated validation')
     RETURNING id`,
    [`asset-validation-a-${suffix}`],
  )).rows[0].id;
  customerB = (await client.query(
    `INSERT INTO customers (name, slug, asset_scope_mode, notes)
     VALUES ('Asset Validation B', $1, 'inventory', 'Temporary automated validation')
     RETURNING id`,
    [`asset-validation-b-${suffix}`],
  )).rows[0].id;
  const teamId = (await client.query(
    `INSERT INTO customer_teams (customer_id, name, code, description)
     VALUES ($1, 'Linux Operations', 'LINUX-OPS', 'Temporary validation team')
     RETURNING id`,
    [customerA],
  )).rows[0].id;

  const assets = normalizeAssetPayloads({ assets: [
    {
      ipAddress: "10.250.10.10",
      dnsName: "validation-a-01.example.internal",
      hostName: "validation-a-01",
      onboardingTool: "Tenable.sc",
      assetType: "Linux Server",
      teamId,
      platform: "Ubuntu 24.04 LTS",
      inScope: false,
    },
    {
      ipAddress: "10.250.10.11",
      dnsName: "validation-a-02.example.internal",
      hostName: "validation-a-02",
      onboardingTool: "Qualys VMDR",
      assetType: "Network Device",
      teamId,
      platform: "Cisco IOS XE 17",
      inScope: false,
    },
    {
      ipAddress: "10.250.10.12",
      dnsName: "validation-a-03.example.internal",
      hostName: "validation-a-03",
      onboardingTool: "Tenable.io",
      assetType: "Windows Server",
      teamId,
      platform: "Windows Server 2022",
      inScope: false,
    },
  ] });
  assert.equal(assets.every((asset) => asset.inScope), true, "Imported tenant assets must always be in scope.");
  assert.equal((await repository.upsertCustomerAssets(actorId, customerA, assets, "127.0.0.1")).count, 3);

  const initial = await repository.listCustomerAssets(customerA, 100, []);
  assert.equal(initial.length, 3);
  assert.deepEqual(new Set(initial.map((asset) => asset.onboardingTool)), new Set(["tenable-sc", "tenable-io", "qualys"]));
  assert.equal(initial.every((asset) => asset.teamName === "Linux Operations"), true);

  const edited = await repository.updateCustomerAsset(actorId, customerA, initial[0].id, {
    ipAddress: "10.250.10.20",
    hasIpAddress: true,
    dnsName: "validation-a-20.example.internal",
    hasDnsName: true,
    hostName: "validation-a-20",
    hasHostName: true,
    onboardingTool: "crowdstrike",
    hasOnboardingTool: true,
    assetType: "Endpoint",
    teamId,
    hasTeamId: true,
    platform: "Windows 11 Enterprise",
    hasPlatform: true,
  }, "127.0.0.1");
  assert.equal(edited.ipAddress, "10.250.10.20");
  assert.equal(edited.dnsName, "validation-a-20.example.internal");
  assert.equal(edited.onboardingTool, "crowdstrike");
  assert.equal(edited.assetType, "Endpoint");
  assert.equal(edited.platform, "Windows 11 Enterprise");

  const currentAssets = await repository.listCustomerAssets(customerA, 100, []);
  const run = await repository.createScanRun(customerA, actorId, {
    customerName: "Asset Validation A",
    ingestionKey: `mva:asset-delete-${suffix}`,
    workflow: "adhoc",
    sourceTool: "tenable-sc",
    sourceLabel: "Tenable.sc",
    reportPeriod: "July 2026",
    fileNames: ["asset-delete-validation.csv"],
    sourceIds: ["tenable-sc"],
    expectedFindings: 3,
    expectedChunks: 1,
    dashboard: {},
    inputSummary: {},
  });
  await repository.ingestChunk(customerA, run.id, {
    chunkIndex: 0,
    startIndex: 0,
    findings: currentAssets.map((asset, index) => ({
      reportPeriod: "July 2026",
      findingKey: `${asset.assetKey}|CVE-2026-${1000 + index}|tcp|443`,
      sourceTool: "tenable-sc",
      sourceTools: ["tenable-sc"],
      sourceDisplay: "Tenable.sc",
      sourceVulnerabilityId: String(90_000 + index),
      ipAddress: asset.ipAddress,
      dnsName: asset.dnsName,
      vulnerabilityName: `Asset deletion validation ${index + 1}`,
      cve: `CVE-2026-${1000 + index}`,
      severity: index === 0 ? "Critical" : "High",
      exploitAvailable: index === 0,
      exploitSignal: index === 0 ? "Available" : "No",
      patchPriority: index === 0 ? "P1" : "P2",
      assetExposure: 500,
      firstDiscovered: "2026-07-01",
      lastObserved: "2026-07-15",
      recordCount: 1,
    })),
  });
  await repository.finalizeScanRun(customerA, run.id);
  assert.equal((await repository.getCustomerDashboard(customerA, [])).metrics.totalOpen, 3);
  assert.equal((await repository.getCustomerScanAssetCoverage(customerA, [])).matchedInventoryAssets, 3);

  const foreignAssets = normalizeAssetPayloads({ assets: [{
    ipAddress: "10.251.10.10",
    hostName: "validation-b-01",
    onboardingTool: "tenable-io",
    assetType: "Windows Server",
    platform: "Windows Server 2022",
  }] });
  await repository.upsertCustomerAssets(actorId, customerB, foreignAssets, "127.0.0.1");
  const foreign = (await repository.listCustomerAssets(customerB, 10, []))[0];

  await assert.rejects(
    repository.deleteCustomerAssets(actorId, customerA, [initial[0].id, foreign.id], "127.0.0.1"),
    /not found in this tenant/,
  );
  assert.equal((await repository.listCustomerAssets(customerA, 100, [])).length, 3, "Cross-tenant selection must roll back completely.");

  const ids = (await repository.listCustomerAssets(customerA, 100, [])).map((asset) => asset.id);
  assert.equal((await repository.deleteCustomerAssets(actorId, customerA, [ids[0]], "127.0.0.1")).count, 1);
  assert.equal((await repository.getCustomerDashboard(customerA, [])).metrics.totalOpen, 2, "Single deletion must remove that asset's findings from active posture.");
  assert.equal((await repository.deleteCustomerAssets(actorId, customerA, ids.slice(1), "127.0.0.1")).count, 2);
  assert.equal((await repository.listCustomerAssets(customerA, 100, [])).length, 0);
  assert.equal((await repository.getCustomerDashboard(customerA, [])).metrics.totalOpen, 0, "Deleting all inventory must clear active vulnerability posture.");
  assert.equal((await repository.getCustomerFindingExport(customerA, [])).rows.length, 0, "Deleted assets must not remain in active CSV exports.");
  assert.equal((await repository.getCustomerScanAssetCoverage(customerA, [])).matchedInventoryAssets, 0);
  assert.equal(Number((await client.query("SELECT count(*) FROM finding_observations WHERE scan_run_id = $1", [run.id])).rows[0].count), 3, "Historical scan evidence must remain available for audit.");
  assert.equal(Number((await client.query("SELECT count(*) FROM customer_asset_aliases WHERE customer_id = $1", [customerA])).rows[0].count), 0);
  assert.equal(Number((await client.query("SELECT count(*) FROM audit_events WHERE customer_id = $1 AND event_type = 'assets.deleted'", [customerA])).rows[0].count), 2);

  const migration = await client.query(
    "SELECT data_type FROM information_schema.columns WHERE table_name = 'customer_assets' AND column_name = 'onboarding_tool'",
  );
  assert.equal(migration.rowCount, 1);

  process.stdout.write(`${JSON.stringify({
    ok: true,
    importedAssets: 3,
    editedFields: ["IP Address", "DNS Name", "Host Name", "Platform / Tool", "Asset Type", "Team", "OS"],
    crossTenantDeleteRolledBack: true,
    singleDeletedAssets: 1,
    bulkDeletedAssets: 2,
    activeVulnerabilitiesAfterSingleDelete: 2,
    activeVulnerabilitiesAfterAllDeletes: 0,
    activeCsvRowsAfterAllDeletes: 0,
    historicalObservationsRetainedForAudit: 3,
    scanCoverageAssetsAfterAllDeletes: 0,
    aliasesRemovedByCascade: true,
    deletionAuditRecorded: true,
    migrationApplied: "008_asset_onboarding_tool.sql",
  }, null, 2)}\n`);
} finally {
  if (client._connected) {
    if (customerA || customerB) {
      const customerIds = [customerA, customerB].filter(Boolean);
      await client.query("DELETE FROM audit_events WHERE customer_id = ANY($1::uuid[])", [customerIds]);
      await client.query("DELETE FROM scan_runs WHERE customer_id = ANY($1::uuid[])", [customerIds]);
      await client.query("DELETE FROM customers WHERE id = ANY($1::uuid[])", [customerIds]);
    }
    if (actorId) await client.query("DELETE FROM users WHERE id = $1", [actorId]);
    await client.end();
  }
  await repository.close();
}
