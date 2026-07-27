import assert from "node:assert/strict";
import test from "node:test";

import { assetInventoryTemplateCsv, normalizeAssetRow, normalizeOnboardingTool, parseAssetInventory, parsePastedAssetInventory } from "./assetInventory.js";

test("asset inventory maps common customer headers and scope flags", () => {
  assert.deepEqual(normalizeAssetRow({
    "Host IP": "10.20.1.10",
    FQDN: "server01.example.com",
    OS: "Windows Server 2022",
    ACR: "High",
    "Internet Exposed": "No",
    Scope: "Included",
  }), {
    assetKey: "10.20.1.10",
    ipAddress: "10.20.1.10",
    dnsName: "server01.example.com",
    hostName: "",
    externalId: "",
    assetType: "Windows Server",
    platform: "Windows Server 2022",
    businessUnit: "",
    criticality: "High",
    responsibleTeam: "",
    onboardingTool: "manual",
    internetExposed: false,
    inScope: true,
  });
});

test("CSV asset import removes repeated asset identities", async () => {
  const csv = `${assetInventoryTemplateCsv()}Tenable.sc,Windows Server,10.20.1.10,server01.example.com,SERVER01,Windows Operations,Windows Server 2022\n`;
  const assets = await parseAssetInventory({ name: "assets.csv", text: async () => csv });
  assert.equal(assets.length, 1);
  assert.equal(assets[0].assetKey, "10.20.1.10");
});

test("inventory import applies a selected default asset type while preserving row categories", async () => {
  const csv = "IP Address,DNS Name,Asset Type,Platform\n10.20.2.10,linux01.example.com,,Ubuntu 24.04\n10.20.2.11,db01.example.com,Database,PostgreSQL 17\n";
  const assets = await parseAssetInventory({ name: "assets.csv", text: async () => csv }, { defaultAssetType: "Linux Server" });
  assert.deepEqual(assets.map((asset) => asset.assetType), ["Linux Server", "Database"]);
});

test("inventory import preserves the responsible team for ownership mapping", async () => {
  const csv = "IP Address,Asset Type,Responsible Team\n10.20.3.10,Linux Server,Linux Operations\n";
  const assets = await parseAssetInventory({ name: "assets.csv", text: async () => csv });
  assert.equal(assets[0].responsibleTeam, "Linux Operations");
});

test("simple onboarding template maps tool, type, IP, host, team, and OS", async () => {
  const assets = await parseAssetInventory({ name: "assets.csv", text: async () => assetInventoryTemplateCsv() });
  assert.deepEqual(assets.map(({ onboardingTool, assetType, ipAddress, hostName, responsibleTeam, platform, inScope }) => ({ onboardingTool, assetType, ipAddress, hostName, responsibleTeam, platform, inScope })), [{
    onboardingTool: "tenable-sc",
    assetType: "Windows Server",
    ipAddress: "10.20.1.10",
    hostName: "server01",
    responsibleTeam: "Windows Operations",
    platform: "Windows Server 2022",
    inScope: true,
  }]);
});

test("selected onboarding tool and OS fill minimal IP and host rows", async () => {
  const csv = "IP Address,Host Name\n10.20.8.10,linux-prod-01\n";
  const [asset] = await parseAssetInventory({ name: "assets.csv", text: async () => csv }, { defaultOnboardingTool: "Qualys VMDR", defaultPlatform: "Ubuntu 24.04" });
  assert.equal(asset.onboardingTool, "qualys");
  assert.equal(asset.platform, "Ubuntu 24.04");
  assert.equal(asset.assetType, "Linux Server");
  assert.equal(asset.inScope, true);
});

test("tool names normalize to stable inventory identifiers", () => {
  assert.equal(normalizeOnboardingTool("Tenable.io"), "tenable-io");
  assert.equal(normalizeOnboardingTool("Microsoft Defender Vulnerability Management"), "mdvm");
  assert.equal(normalizeOnboardingTool("Red Hat OpenShift"), "openshift");
  assert.equal(normalizeOnboardingTool("OpenShift Container Platform"), "openshift");
  assert.equal(normalizeOnboardingTool("Multiple tools"), "multi-tool");
});

test("pasted IP inventory maps a two-column row to the responsible owner", () => {
  const assets = parsePastedAssetInventory("10.20.4.10, Linux Operations\n10.20.4.11, Network Operations", { defaultAssetType: "Linux Server" });
  assert.deepEqual(assets.map(({ ipAddress, responsibleTeam, assetType }) => ({ ipAddress, responsibleTeam, assetType })), [
    { ipAddress: "10.20.4.10", responsibleTeam: "Linux Operations", assetType: "Linux Server" },
    { ipAddress: "10.20.4.11", responsibleTeam: "Network Operations", assetType: "Linux Server" },
  ]);
});

test("pasted three-column inventory preserves the asset name and owner", () => {
  const [asset] = parsePastedAssetInventory("10.20.5.10 | web-prod-01 | Application Operations");
  assert.equal(asset.ipAddress, "10.20.5.10");
  assert.equal(asset.hostName, "web-prod-01");
  assert.equal(asset.responsibleTeam, "Application Operations");
});

test("pasted four-column inventory preserves OS and selected tool", () => {
  const [asset] = parsePastedAssetInventory("10.20.5.20 | api-prod-01 | Application Operations | RHEL 9", { defaultOnboardingTool: "tenable-io" });
  assert.equal(asset.onboardingTool, "tenable-io");
  assert.equal(asset.platform, "RHEL 9");
  assert.equal(asset.assetType, "Linux Server");
});

test("pasted inventory accepts a labeled owner column", () => {
  const [asset] = parsePastedAssetInventory("IP Address,Asset Name,Asset Owner\n10.20.6.10,db-prod-01,Database Operations");
  assert.equal(asset.hostName, "db-prod-01");
  assert.equal(asset.responsibleTeam, "Database Operations");
});
