import assert from "node:assert/strict";
import test from "node:test";

import {
  analyzeHostDiscoveryCoverage,
  buildThreeLayerCoverage,
  extractDiscoveryPeriod,
  hostDiscoveryAssetListCsv,
  hostDiscoveryCoverageCsv,
  hostDiscoveryExceptionsCsv,
  hostDiscoveryTemplateCsv,
  parseHostDiscoveryFile,
  threeLayerCoverageCsv,
} from "./hostDiscovery.js";

const inventory = [
  asset("a-1", "10.20.1.10", "web01.example.com", "web01", "Linux Server", "Linux Operations"),
  asset("a-2", "10.20.1.11", "db01.example.com", "db01", "Database", "Database Operations"),
  asset("a-3", "10.20.1.12", "app01.example.com", "app01", "Windows Server", "Windows Operations"),
  { ...asset("a-4", "10.20.1.13", "excluded.example.com", "excluded", "Linux Server", "Linux Operations"), inScope: false },
];

test("host discovery parser reads common identities, removes duplicate rows, and excludes offline hosts", async () => {
  const parsed = await parseHostDiscoveryFile(csvFile("discovery_2026-07.csv", [
    "Host IP,FQDN,Host Status",
    "10.20.1.10,web01.example.com,Alive",
    "10.20.1.10,web01.example.com,Alive",
    "10.20.1.11,db01.example.com,Offline",
  ].join("\n")));
  assert.equal(parsed.hosts.length, 1);
  assert.equal(parsed.duplicateRowsRemoved, 1);
  assert.equal(parsed.excludedOfflineRows, 1);
});

test("two-column IP and DNS discovery produces exact input and matching statistics", async () => {
  const analysis = await analyzeHostDiscoveryCoverage({
    inventory,
    uploads: [{ period: "2026-07", file: csvFile("host_discovery_2026-07.csv", [
      "IP Address,DNS Name",
      "10.20.1.10,web01.example.com",
      "10.20.1.11,db01.example.com",
      "10.20.1.10,web01.example.com",
      "198.51.100.20,unmanaged.example.net",
    ].join("\n")) }],
  });
  assert.equal(analysis.latest.sourceRows, 4);
  assert.equal(analysis.latest.discoveredHosts, 3);
  assert.equal(analysis.latest.rowsWithIpAddress, 4);
  assert.equal(analysis.latest.rowsWithDnsName, 4);
  assert.equal(analysis.latest.rowsWithIpAndDns, 4);
  assert.equal(analysis.latest.scannedAssets, 2);
  assert.equal(analysis.latest.matchedByIpAndDns, 2);
  assert.equal(analysis.latest.duplicateRowsRemoved, 1);
  assert.equal(analysis.latest.unmatchedHosts.length, 1);
  assert.equal(hostDiscoveryTemplateCsv().split("\r\n")[0], '"IP Address","DNS Name"');
});

test("three-layer coverage separates inventory, discovery, and vulnerability-result gaps", () => {
  const discoveryPeriod = { period: "2026-07", scannedAssetIds: new Set(["a-1", "a-2"]) };
  const scanCoverage = { available: true, reportPeriod: "2026-07-01", observedScanIdentities: 3, unmatchedScanIdentities: 1, ambiguousScanIdentities: 0, assetIds: ["a-2", "a-3"] };
  const result = buildThreeLayerCoverage({ inventory, discoveryPeriod, scanCoverage });
  assert.deepEqual({
    inventory: result.inventoryAssets,
    discovered: result.hostDiscoveredAssets,
    vulnerabilityResult: result.vulnerabilityScanAssets,
    confirmed: result.confirmedByBoth,
    notDiscovered: result.inventoryNotDiscovered,
    absentFromResult: result.discoveredNotInVulnerabilityScan,
    resultOnly: result.vulnerabilityScanNotInDiscovery,
  }, { inventory: 3, discovered: 2, vulnerabilityResult: 2, confirmed: 1, notDiscovered: 1, absentFromResult: 1, resultOnly: 1 });
  assert.equal(result.discoveryCoveragePercentage, 66.67);
  assert.equal(result.vulnerabilityScanCoveragePercentage, 66.67);
  assert.equal(result.discoveredAssetScanPercentage, 50);
  assert.equal(result.periodsAligned, true);
  assert.deepEqual(result.assetIds.confirmedByBoth, ["a-2"]);
  assert.deepEqual(result.assetIds.inventoryNotDiscovered, ["a-3"]);
  assert.deepEqual(result.assetIds.discoveredNotInVulnerabilityScan, ["a-1"]);
  assert.deepEqual(result.assetIds.vulnerabilityScanNotInDiscovery, ["a-3"]);

  const confirmed = threeLayerCoverageCsv({ inventory, data: result, category: "confirmedByBoth" });
  const missing = threeLayerCoverageCsv({ inventory, data: result, category: "discoveredNotInVulnerabilityScan" });
  assert.match(confirmed, /db01\.example\.com/);
  assert.doesNotMatch(confirmed, /web01\.example\.com/);
  assert.match(missing, /web01\.example\.com/);
  assert.doesNotMatch(missing, /db01\.example\.com/);
});

test("one-month coverage uses only in-scope inventory and separates unmanaged and out-of-scope hosts", async () => {
  const analysis = await analyzeHostDiscoveryCoverage({
    inventory,
    uploads: [{ period: "2026-07", file: csvFile("july.csv", [
      "IP Address,DNS Name,Status",
      "10.20.1.10,web01.example.com,Alive",
      "10.20.1.13,excluded.example.com,Alive",
      "198.51.100.10,unmanaged.example.net,Alive",
    ].join("\n")) }],
  });
  assert.equal(analysis.inventoryAssetCount, 3);
  assert.equal(analysis.latest.scannedAssets, 1);
  assert.equal(analysis.latest.notScannedAssets, 2);
  assert.equal(analysis.latest.coveragePercentage, 33.33);
  assert.equal(analysis.latest.outOfScopeHosts.length, 1);
  assert.equal(analysis.latest.unmatchedHosts.length, 1);
});

test("five-month analysis calculates coverage movement and exact per-asset history", async () => {
  const periods = [
    ["2026-03", ["10.20.1.10"]],
    ["2026-04", ["10.20.1.10", "10.20.1.11"]],
    ["2026-05", ["10.20.1.11"]],
    ["2026-06", ["10.20.1.11", "10.20.1.12"]],
    ["2026-07", ["10.20.1.12"]],
  ];
  const analysis = await analyzeHostDiscoveryCoverage({
    inventory,
    uploads: periods.map(([period, ips]) => ({ period, file: csvFile(`discovery_${period}.csv`, `IP Address\n${ips.join("\n")}`) })),
  });
  assert.equal(analysis.periods.length, 5);
  assert.deepEqual(analysis.periods.map(({ scannedAssets, newCoverage, lostCoverage }) => ({ scannedAssets, newCoverage, lostCoverage })), [
    { scannedAssets: 1, newCoverage: 1, lostCoverage: 0 },
    { scannedAssets: 2, newCoverage: 1, lostCoverage: 0 },
    { scannedAssets: 1, newCoverage: 0, lostCoverage: 1 },
    { scannedAssets: 2, newCoverage: 1, lostCoverage: 0 },
    { scannedAssets: 1, newCoverage: 0, lostCoverage: 1 },
  ]);
  assert.equal(analysis.assetCoverage.find((item) => item.id === "a-1").consecutiveMissed, 3);
  assert.equal(analysis.assetCoverage.find((item) => item.id === "a-3").lastScannedPeriod, "2026-07");
});

test("duplicate months and more than five files are rejected", async () => {
  const file = csvFile("discovery.csv", "IP Address\n10.20.1.10");
  await assert.rejects(() => analyzeHostDiscoveryCoverage({ inventory, uploads: [{ period: "2026-07", file }, { period: "2026-07", file }] }), /more than one/);
  await assert.rejects(() => analyzeHostDiscoveryCoverage({ inventory, uploads: Array.from({ length: 6 }, (_, index) => ({ period: `2026-0${index + 1}`, file })) }), /one and five/);
});

test("ambiguous identities are not counted as scanned", async () => {
  const ambiguousInventory = [
    asset("a-1", "10.20.1.10", "shared.example.com", "web01"),
    asset("a-2", "10.20.1.11", "shared.example.com", "db01"),
  ];
  const analysis = await analyzeHostDiscoveryCoverage({
    inventory: ambiguousInventory,
    uploads: [{ period: "2026-07", file: csvFile("july.csv", "DNS Name\nshared.example.com") }],
  });
  assert.equal(analysis.latest.scannedAssets, 0);
  assert.equal(analysis.latest.ambiguousHosts.length, 1);
});

test("coverage and exception exports retain monthly evidence and neutralize formulas", async () => {
  const formulaInventory = [{ ...inventory[0], criticality: "=HYPERLINK(\"bad\")" }];
  const analysis = await analyzeHostDiscoveryCoverage({
    inventory: formulaInventory,
    uploads: [{ period: "2026-07", file: csvFile("july.csv", "IP Address\n198.51.100.20") }],
  });
  const coverage = hostDiscoveryCoverageCsv(analysis);
  const exceptions = hostDiscoveryExceptionsCsv(analysis);
  const notDiscovered = hostDiscoveryAssetListCsv(analysis, { period: "2026-07", category: "not-discovered" });
  const discovered = hostDiscoveryAssetListCsv(analysis, { period: "2026-07", category: "discovered" });
  assert.match(coverage, /July 2026/);
  assert.match(coverage, /Not Discovered/);
  assert.match(coverage, /'=HYPERLINK/);
  assert.match(exceptions, /Not in inventory/);
  assert.match(notDiscovered, /web01\.example\.com/);
  assert.doesNotMatch(discovered, /web01\.example\.com/);
});

test("month is inferred from named and ISO-style discovery filenames", () => {
  assert.equal(extractDiscoveryPeriod("host_discovery_July_2026.csv"), "2026-07");
  assert.equal(extractDiscoveryPeriod("alive_hosts_2026-05.xlsx"), "2026-05");
});

function asset(id, ipAddress, dnsName, hostName, assetType = "Other", teamName = "Unassigned") {
  return { id, assetKey: ipAddress, ipAddress, dnsName, hostName, externalId: "", assetType, teamName, criticality: "High", inScope: true };
}

function csvFile(name, content) {
  return { name, size: content.length, text: async () => content };
}
