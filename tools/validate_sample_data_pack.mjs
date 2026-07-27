import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { parseAssetInventory } from "../react-ui/src/lib/assetInventory.js";
import { analyzeHostDiscoveryCoverage } from "../react-ui/src/lib/hostDiscovery.js";
import { analyzeAdhocFiles, analyzeMonthlyFiles, autoMapCustomHeaders, parseExportFile } from "../react-ui/src/lib/vulnerabilityEngine.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PACK = path.join(ROOT, "ss", "sample data");
const TOOL_IDS = ["tenable-sc", "tenable-io", "qualys", "custom-qualys", "crowdstrike", "openshift"];
const evidence = [];

for (const toolId of TOOL_IDS) {
  const directory = path.join(PACK, toolId);
  const manifest = JSON.parse(await fs.readFile(path.join(directory, "manifest.json"), "utf8"));
  const discoveryExpected = JSON.parse(await fs.readFile(path.join(directory, manifest.expectedDiscovery), "utf8"));
  const scannerExpected = JSON.parse(await fs.readFile(path.join(directory, manifest.expectedScanner), "utf8"));
  const inventory = await parseAssetInventory(await localFile(path.join(directory, manifest.inventory)));
  assert.equal(inventory.length, discoveryExpected.totalInventoryRows, `${toolId} inventory rows`);
  assert.equal(inventory.filter((asset) => asset.inScope).length, discoveryExpected.inScopeAssets, `${toolId} in-scope rows`);

  const uploads = await Promise.all(discoveryExpected.periods.map(async (period) => {
    const file = await localFile(path.join(directory, "host_discovery", period.filename));
    const header = (await file.text()).replace(/^\uFEFF/, "").split(/\r?\n/, 1)[0];
    assert.equal(header, '"IP Address","DNS Name"', `${toolId} ${period.period} discovery header`);
    return { period: period.period, file };
  }));
  const backendShape = inventory.map((asset, index) => ({ ...asset, id: `${toolId}-${index + 1}`, teamName: asset.responsibleTeam }));
  const discovery = await analyzeHostDiscoveryCoverage({ inventory: backendShape, uploads });
  assert.equal(discovery.periods.length, 5, `${toolId} discovery period count`);
  for (const expectedPeriod of discoveryExpected.periods) {
    const actual = discovery.periods.find((period) => period.period === expectedPeriod.period);
    for (const key of ["inventoryAssets", "sourceRows", "discoveredHosts", "rowsWithIpAddress", "rowsWithDnsName", "rowsWithIpAndDns", "scannedAssets", "notScannedAssets", "coveragePercentage", "excludedOfflineRows", "duplicateRowsRemoved", "matchedByIpAndDns", "matchedByIpOnly", "matchedByDnsOnly"]) {
      assert.equal(actual[key], expectedPeriod[key], `${toolId} ${expectedPeriod.period} ${key}`);
    }
    assert.equal(actual.unmatchedHosts.length, expectedPeriod.unmatchedHosts, `${toolId} ${expectedPeriod.period} unmatchedHosts`);
    assert.equal(actual.outOfScopeHosts.length, expectedPeriod.outOfScopeHosts, `${toolId} ${expectedPeriod.period} outOfScopeHosts`);
  }

  const monthlyFiles = await Promise.all(manifest.monthlyFiles.map((name) => localFile(path.join(directory, name))));
  const monthly = await analyzeMonthlyFiles(monthlyFiles, toolId);
  assert.deepEqual(monthly.dashboard.uploadedPeriods, scannerExpected.monthly.uploadedPeriods, `${toolId} monthly periods`);
  assert.deepEqual(monthly.dashboard.totalOpenVulnerabilities, scannerExpected.monthly.totalOpenVulnerabilities, `${toolId} monthly total open`);
  assert.deepEqual(monthly.dashboard.totalOpenByPatchPriority, scannerExpected.monthly.totalOpenByPatchPriority, `${toolId} monthly priority`);
  assert.deepEqual(monthly.dashboard.trendDiscoveredLast3Months, scannerExpected.monthly.trendDiscoveredLast3Months, `${toolId} discovered trend`);
  assert.deepEqual(monthly.dashboard.trendRemediatedLast3Months, scannerExpected.monthly.trendRemediatedLast3Months, `${toolId} remediated trend`);

  const adhoc = await analyzeAdhocFiles([await localFile(path.join(directory, manifest.adhocFile))], toolId);
  assert.equal(adhoc.dashboard.totalVulnerabilities, scannerExpected.adhoc.totalVulnerabilities, `${toolId} ad hoc total`);
  assert.equal(adhoc.dashboard.distinctAssets, scannerExpected.adhoc.distinctAssets, `${toolId} ad hoc assets`);
  assert.deepEqual(adhoc.dashboard.patchPriorityCounts, scannerExpected.adhoc.patchPriorityCounts, `${toolId} ad hoc priority`);

  const inventoryIdentities = new Set(inventory.flatMap((asset) => [asset.ipAddress, asset.dnsName].filter(Boolean).map((value) => value.toLowerCase())));
  const scannerAssets = new Set(monthly.snapshots.flatMap((snapshot) => snapshot.findings).map((finding) => finding.ipAddress || finding.dnsName).filter(Boolean).map((value) => value.toLowerCase()));
  assert.equal([...scannerAssets].every((identity) => inventoryIdentities.has(identity)), true, `${toolId} scanner assets must exist in its inventory`);

  evidence.push({
    tool: toolId,
    inventoryRows: inventory.length,
    scannerAssetsMatchedToInventory: scannerAssets.size,
    monthlyScannerFiles: monthlyFiles.length,
    adhocFile: path.basename(manifest.adhocFile),
    monthlyTotalOpen: monthly.dashboard.totalOpenVulnerabilities,
    adhocTotal: adhoc.dashboard.totalVulnerabilities,
    periods: discovery.periods.map((period) => ({
      period: period.period,
      scanned: period.scannedAssets,
      notScanned: period.notScannedAssets,
      coveragePercentage: period.coveragePercentage,
      sourceRows: period.sourceRows,
      uniqueDiscoveredHosts: period.discoveredHosts,
      matchedByIpAndDns: period.matchedByIpAndDns,
      exceptions: period.unmatchedHosts.length + period.outOfScopeHosts.length + period.ambiguousHosts.length,
    })),
  });
}

const customParserDirectory = path.join(ROOT, "samples", "universal_custom_parser");
const customParserFiles = await Promise.all(["april", "may", "june", "july"].map((month) => (
  localFile(path.join(customParserDirectory, `generic_scanner_${month}_2026.csv`))
)));
const customParserHeader = await parseExportFile(customParserFiles[0], { allowUnknown: true });
const customParserMapping = autoMapCustomHeaders(customParserHeader.fields);
const customParserAnalysis = await analyzeMonthlyFiles(customParserFiles, "custom-csv", {
  customMapping: customParserMapping,
  customExploitMode: "boolean",
});
assert.equal(customParserAnalysis.dashboard.uploadedPeriods.length, 4, "universal custom parser monthly periods");
assert.ok(customParserAnalysis.dashboard.totalOpenVulnerabilities.totalOpen > 0, "universal custom parser total open");
assert.ok(customParserAnalysis.snapshots.flatMap((snapshot) => snapshot.findings).every((finding) => finding.sourceTool === "custom-csv"), "universal custom parser source");

await fs.mkdir(path.join(ROOT, "output", "validation"), { recursive: true });
await fs.writeFile(path.join(ROOT, "output", "validation", "host_discovery_sample_validation.json"), `${JSON.stringify({
  validatedAt: new Date().toISOString(),
  tools: evidence,
  universalCustomParser: {
    files: customParserFiles.map((file) => file.name),
    mappings: customParserMapping,
    totalOpen: customParserAnalysis.dashboard.totalOpenVulnerabilities.totalOpen,
  },
}, null, 2)}\n`);
console.log(JSON.stringify({
  ok: true,
  toolsValidated: evidence.length,
  inventoryRowsValidated: evidence.reduce((total, item) => total + item.inventoryRows, 0),
  discoveryFilesValidated: evidence.length * 5,
  monthlyScannerFilesValidated: evidence.reduce((total, item) => total + item.monthlyScannerFiles, 0),
  adhocScenariosValidated: evidence.length,
  universalCustomParserValidated: true,
  allScannerAssetsMatchedToInventory: true,
}, null, 2));

async function localFile(filePath) {
  const buffer = await fs.readFile(filePath);
  return {
    name: path.basename(filePath),
    size: buffer.length,
    lastModified: (await fs.stat(filePath)).mtimeMs,
    text: async () => buffer.toString("utf8"),
    arrayBuffer: async () => buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength),
  };
}
