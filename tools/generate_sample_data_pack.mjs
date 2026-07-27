import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { analyzeAdhocFiles, analyzeMonthlyFiles } from "../react-ui/src/lib/vulnerabilityEngine.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUTPUT = path.join(ROOT, "ss", "sample data");
const SOURCE = path.join(ROOT, "react-ui", "public", "sample-data");
const PERIODS = ["2026-03", "2026-04", "2026-05", "2026-06", "2026-07"];
const TYPES = ["Linux Server", "Windows Server", "Network Device", "Database", "Endpoint", "Security Appliance", "Cloud Asset", "Virtualization Host"];
const TEAMS = ["Linux Operations", "Windows Operations", "Network Engineering", "Database Operations", "Endpoint Engineering", "Security Operations", "Cloud Platform", "Infrastructure Operations"];
const PLATFORMS = ["Ubuntu 24.04 LTS", "Windows Server 2022", "Cisco IOS XE 17", "PostgreSQL 16", "Windows 11 Enterprise", "Palo Alto PAN-OS 11", "AWS EC2", "VMware ESXi 8"];
const TOOLS = [
  {
    id: "tenable-sc",
    label: "Tenable.sc",
    prefix: "TSC",
    monthlyPrefix: "tenable_sc_",
    adhocFile: "tenable_sc_july_2026_100plus.csv",
    coverage: [55, 64, 72, 84, 91],
  },
  {
    id: "tenable-io",
    label: "Tenable.io",
    prefix: "TIO",
    monthlyPrefix: "tenable_io_",
    adhocFile: "tenable_io_july_2026_100plus.csv",
    coverage: [88, 82, 76, 86, 94],
  },
  {
    id: "qualys",
    label: "Qualys VMDR",
    prefix: "QLY",
    monthlyPrefix: "qualys_monthly_",
    adhocFile: "qualys_adhoc_july_2026_100plus.csv",
    coverage: [42, 57, 69, 63, 80],
  },
  {
    id: "custom-qualys",
    label: "Custom Qualys",
    prefix: "CQL",
    monthlyPrefix: "custom_qualys_monthly_",
    adhocFile: "custom_qualys_adhoc_july_2026.csv",
    coverage: [48, 61, 73, 82, 93],
  },
  {
    id: "crowdstrike",
    label: "CrowdStrike Exposure Management",
    prefix: "CS",
    monthlyPrefix: "crowdstrike_vulnerabilities_",
    adhocFile: "crowdstrike_vulnerability_per_asset_july_2026_100plus.csv",
    coverage: [70, 70, 78, 89, 96],
  },
  {
    id: "openshift",
    label: "Red Hat OpenShift",
    prefix: "OCP",
    monthlyPrefix: "openshift_",
    adhocFile: "openshift_july_2026_100plus.csv",
    coverage: [52, 61, 73, 87, 95],
  },
];

await fs.rm(OUTPUT, { recursive: true, force: true });
await fs.mkdir(OUTPUT, { recursive: true });

const manifests = [];
for (let toolIndex = 0; toolIndex < TOOLS.length; toolIndex += 1) {
  const tool = TOOLS[toolIndex];
  const sourceDirectory = path.join(SOURCE, tool.id);
  const toolDirectory = path.join(OUTPUT, tool.id);
  const inventoryDirectory = path.join(toolDirectory, "asset_inventory");
  const discoveryDirectory = path.join(toolDirectory, "host_discovery");
  const scanDirectory = path.join(toolDirectory, "scan_results");
  const expectedDirectory = path.join(toolDirectory, "expected_results");
  await Promise.all([
    fs.mkdir(inventoryDirectory, { recursive: true }),
    fs.mkdir(discoveryDirectory, { recursive: true }),
    fs.mkdir(expectedDirectory, { recursive: true }),
    fs.cp(sourceDirectory, scanDirectory, { recursive: true }),
  ]);

  const scanNames = (await fs.readdir(sourceDirectory)).sort();
  const monthlyNames = scanNames.filter((name) => name.startsWith(tool.monthlyPrefix) && /(april|may|june|july)_2026/i.test(name));
  const monthlyFiles = await Promise.all(monthlyNames.map((name) => localFile(path.join(sourceDirectory, name))));
  const monthlyAnalysis = await analyzeMonthlyFiles(monthlyFiles, tool.id);
  const adhocAnalysis = await analyzeAdhocFiles([await localFile(path.join(sourceDirectory, tool.adhocFile))], tool.id);
  const scannerFindings = monthlyAnalysis.snapshots.flatMap((snapshot) => snapshot.findings);
  const assets = buildAssets(tool, toolIndex, scannerFindings);

  const inventoryName = `${tool.id}_asset_inventory.csv`;
  await fs.writeFile(path.join(inventoryDirectory, inventoryName), csv([
    ["Tool", "Asset Type", "IP Address", "DNS Name", "Host Name", "Team Name", "OS Name"],
    ...assets.map((asset) => [tool.label, asset.type, asset.ip, asset.dns, asset.host, asset.team, asset.platform]),
  ]));

  const discoveryExpectations = [];
  for (let periodIndex = 0; periodIndex < PERIODS.length; periodIndex += 1) {
    const period = PERIODS[periodIndex];
    const target = tool.coverage[periodIndex];
    const selected = shuffled(assets, 3100 + toolIndex * 100 + periodIndex).slice(0, target);
    const rows = [
      ["IP Address", "DNS Name"],
      ...selected.map(discoveryRow),
      [`198.51.${toolIndex + 20}.${periodIndex + 20}`, `unmanaged-${tool.id}-${periodIndex + 1}.example.net`],
      [`203.0.113.${toolIndex * 10 + periodIndex + 20}`, `contractor-${tool.id}-${periodIndex + 1}.example.net`],
      [`192.0.2.${toolIndex * 10 + periodIndex + 20}`, `lab-${tool.id}-${periodIndex + 1}.external.example`],
      discoveryRow(selected[0]),
      discoveryRow(selected[1]),
    ];
    const filename = `${tool.id}_host_discovery_${period}.csv`;
    await fs.writeFile(path.join(discoveryDirectory, filename), csv(rows));
    discoveryExpectations.push({
      period,
      filename,
      inventoryAssets: 100,
      sourceRows: target + 5,
      discoveredHosts: target + 3,
      rowsWithIpAddress: target + 5,
      rowsWithDnsName: target + 5,
      rowsWithIpAndDns: target + 5,
      scannedAssets: target,
      notScannedAssets: 100 - target,
      coveragePercentage: target,
      unmatchedHosts: 3,
      outOfScopeHosts: 0,
      excludedOfflineRows: 0,
      duplicateRowsRemoved: 2,
      matchedByIpAndDns: target,
      matchedByIpOnly: 0,
      matchedByDnsOnly: 0,
    });
  }

  const discoveryManifest = {
    tool: tool.id,
    toolLabel: tool.label,
    totalInventoryRows: 100,
    scannerMatchedInventoryAssets: new Set(scannerFindings.map((finding) => assetIdentity(finding)).filter(Boolean)).size,
    inScopeAssets: 100,
    outOfScopeAssets: 0,
    periods: discoveryExpectations,
  };
  const scannerMetrics = expectedScannerMetrics(tool, monthlyNames, monthlyAnalysis, adhocAnalysis);
  const manifest = {
    tool: tool.id,
    label: tool.label,
    inventory: `asset_inventory/${inventoryName}`,
    hostDiscoveryFiles: discoveryExpectations.map((period) => `host_discovery/${period.filename}`),
    scanResultFiles: scanNames.map((name) => `scan_results/${name}`),
    monthlyFiles: monthlyNames.map((name) => `scan_results/${name}`),
    adhocFile: `scan_results/${tool.adhocFile}`,
    expectedDiscovery: "expected_results/host_discovery_metrics.json",
    expectedScanner: "expected_results/scanner_metrics.json",
  };
  manifests.push(manifest);

  await Promise.all([
    fs.writeFile(path.join(expectedDirectory, "host_discovery_metrics.json"), `${JSON.stringify(discoveryManifest, null, 2)}\n`),
    fs.writeFile(path.join(expectedDirectory, "scanner_metrics.json"), `${JSON.stringify(scannerMetrics, null, 2)}\n`),
    fs.writeFile(path.join(toolDirectory, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`),
    fs.writeFile(path.join(toolDirectory, "README.md"), toolReadme(tool, manifest)),
  ]);
}

await fs.writeFile(path.join(OUTPUT, "manifest.json"), `${JSON.stringify({ tools: manifests }, null, 2)}\n`);
await fs.writeFile(path.join(OUTPUT, "README.md"), rootReadme());

function buildAssets(tool, toolIndex, findings) {
  const openshift = tool.id === "openshift";
  const sourceAssets = new Map();
  for (const finding of findings) {
    const identity = assetIdentity(finding);
    if (!identity || sourceAssets.has(identity)) continue;
    const item = sourceAssets.size;
    const typeIndex = inferTypeIndex(finding.platformDetails, item + toolIndex);
    const dns = clean(finding.dnsName) || `${tool.id}-scanner-${String(item + 1).padStart(3, "0")}.example.internal`;
    const ip = clean(finding.ipAddress) || `10.${70 + toolIndex}.1.${item + 10}`;
    sourceAssets.set(identity, {
      ip,
      dns,
      host: dns.split(".")[0],
      externalId: `${tool.prefix}-SCANNER-${String(item + 1).padStart(4, "0")}`,
      type: openshift ? "Container Platform" : TYPES[typeIndex],
      team: openshift ? "Container Platform Operations" : TEAMS[typeIndex],
      platform: openshift ? "Red Hat OpenShift Container Platform" : operatingSystem(finding.platformDetails, typeIndex),
      inScope: true,
    });
  }

  const assets = [...sourceAssets.values()].slice(0, 100);
  const random = mulberry32(8100 + toolIndex);
  while (assets.length < 100) {
    const item = assets.length;
    const typeIndex = Math.floor(random() * TYPES.length);
    const host = `${hostPrefix(typeIndex)}-${tool.id}-${String(item + 1).padStart(3, "0")}`;
    assets.push({
      ip: `10.${80 + toolIndex}.${Math.floor((item - sourceAssets.size) / 200) + 1}.${(item - sourceAssets.size) % 200 + 20}`,
      dns: `${host}.example.internal`,
      host,
      externalId: `${tool.prefix}-INVENTORY-${String(item + 1).padStart(4, "0")}`,
      type: openshift ? "Container Platform" : TYPES[typeIndex],
      team: openshift ? "Container Platform Operations" : TEAMS[typeIndex],
      platform: openshift ? "Red Hat OpenShift Container Platform" : PLATFORMS[typeIndex],
      inScope: true,
    });
  }
  return assets.map((asset) => ({ ...asset, inScope: true }));
}

function expectedScannerMetrics(tool, monthlyNames, monthlyAnalysis, adhocAnalysis) {
  const monthly = monthlyAnalysis.dashboard;
  const adhoc = adhocAnalysis.dashboard;
  return {
    tool: tool.id,
    toolLabel: tool.label,
    monthly: {
      files: monthlyNames,
      uploadedPeriods: monthly.uploadedPeriods,
      reportRange: monthly.reportRange,
      totalOpenVulnerabilities: monthly.totalOpenVulnerabilities,
      totalOpenByPatchPriority: monthly.totalOpenByPatchPriority,
      totalOpenByAgeAndPatchPriority: monthly.totalOpenByAgeAndPatchPriority,
      totalVulnerabilitiesPatchedLastMonth: monthly.totalVulnerabilitiesPatchedLastMonth,
      trendDiscoveredLast3Months: monthly.trendDiscoveredLast3Months,
      trendRemediatedLast3Months: monthly.trendRemediatedLast3Months,
      snapshotRows: monthlyAnalysis.snapshots.map((snapshot) => ({ period: snapshot.periodLabel, findings: snapshot.findings.length })),
    },
    adhoc: {
      file: tool.adhocFile,
      reportPeriod: adhocAnalysis.reportMonth,
      totalVulnerabilities: adhoc.totalVulnerabilities,
      distinctAssets: adhoc.distinctAssets,
      exploitAvailable: adhoc.exploitAvailable,
      severityCounts: adhoc.severityCounts,
      patchPriorityCounts: adhoc.patchPriorityCounts,
    },
  };
}

function assetIdentity(finding) {
  return clean(finding?.ipAddress || finding?.dnsName).toLowerCase();
}

function inferTypeIndex(platform, fallback) {
  const value = clean(platform).toLowerCase();
  if (/linux|ubuntu|rhel|red hat|debian|centos/.test(value)) return 0;
  if (/windows server/.test(value)) return 1;
  if (/cisco|router|switch|network/.test(value)) return 2;
  if (/postgres|mysql|oracle|sql server|database/.test(value)) return 3;
  if (/windows 1[01]|macos|endpoint|workstation/.test(value)) return 4;
  if (/palo alto|firewall|security appliance/.test(value)) return 5;
  if (/aws|azure|gcp|cloud/.test(value)) return 6;
  if (/vmware|esxi|hyper-v|virtual/.test(value)) return 7;
  return fallback % TYPES.length;
}

function operatingSystem(platformDetails, fallbackTypeIndex) {
  const candidates = clean(platformDetails).split("|").map((value) => value.trim()).filter(Boolean);
  const operatingSystemPattern = /\b(windows server(?:\s+\d{4})?|windows 1[01](?: enterprise)?|ubuntu(?:\s+\d+(?:\.\d+)?)?|rhel(?:\s+\d+)?|red hat(?: enterprise linux)?(?:\s+\d+)?|debian(?:\s+\d+)?|centos(?:\s+\d+)?|suse(?:\s+linux)?|macos(?:\s+[\w.]+)?|cisco ios(?:\s+xe)?(?:\s+[\w.]+)?|pan-os(?:\s+[\w.]+)?|vmware esxi(?:\s+[\w.]+)?|postgresql(?:\s+\d+)?|aws ec2)\b/i;
  const match = candidates.find((candidate) => operatingSystemPattern.test(candidate));
  return (match || PLATFORMS[fallbackTypeIndex]).slice(0, 120);
}

function hostPrefix(typeIndex) {
  return ["lnx", "win", "net", "db", "ep", "sec", "cld", "virt"][typeIndex];
}

function discoveryRow(asset) {
  return [asset.ip, asset.dns];
}

function shuffled(values, seed) {
  const output = [...values];
  const random = mulberry32(seed);
  for (let index = output.length - 1; index > 0; index -= 1) {
    const selected = Math.floor(random() * (index + 1));
    [output[index], output[selected]] = [output[selected], output[index]];
  }
  return output;
}

function mulberry32(seed) {
  return () => {
    let value = seed += 0x6D2B79F5;
    value = Math.imul(value ^ value >>> 15, value | 1);
    value ^= value + Math.imul(value ^ value >>> 7, value | 61);
    return ((value ^ value >>> 14) >>> 0) / 4294967296;
  };
}

function csv(rows) {
  return `\uFEFF${rows.map((row) => row.map(csvCell).join(",")).join("\r\n")}\r\n`;
}

function csvCell(value) {
  let text = String(value ?? "");
  if (/^[=+\-@]/.test(text)) text = `'${text}`;
  return `"${text.replaceAll('"', '""')}"`;
}

function clean(value) {
  return String(value ?? "").replace(/\u0000/g, "").trim();
}

async function localFile(filePath) {
  const buffer = await fs.readFile(filePath);
  return {
    name: path.basename(filePath),
    size: buffer.length,
    text: async () => buffer.toString("utf8"),
    arrayBuffer: async () => buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength),
  };
}

function toolReadme(tool, manifest) {
  return [
    `# ${tool.label} Test Pack`,
    "",
    "This folder contains only synthetic or generated test data. It contains no customer data.",
    "",
    "## Folder contents",
    "",
    "- `" + manifest.inventory + "`: 100-asset inventory. Assets found in the supplied " + tool.label + " scans are included so inventory and scanner analysis can be tested together.",
    "- `host_discovery/`: five monthly host-discovery files from March through July 2026. Every file uses only `IP Address` and `DNS Name`.",
    "- `scan_results/`: " + tool.label + " ad hoc and monthly scanner exports using the supported raw field layout.",
    "- `" + manifest.expectedDiscovery + "`: exact expected host-discovery counts.",
    "- `" + manifest.expectedScanner + "`: exact expected ad hoc and monthly dashboard counts.",
    "- `manifest.json`: machine-readable list of every file used by this scenario.",
    "",
    "## Test order",
    "",
    "1. Create or select a test tenant.",
    "2. Import `" + manifest.inventory + "` in Asset inventory.",
    "3. Open Discovery coverage and add one to five files from `host_discovery/`.",
    "4. Compare the dashboard with `" + manifest.expectedDiscovery + "`.",
    "5. Select " + tool.label + " in Tool selection.",
    "6. For Monthly comparison, upload the four files listed in `manifest.json > monthlyFiles`.",
    "7. For Ad hoc analysis, upload `" + manifest.adhocFile + "`.",
    "8. Compare dashboard totals with `" + manifest.expectedScanner + "`, then test CSV, Excel, and PDF downloads.",
    "",
  ].join("\n");
}

function rootReadme() {
  return [
    "# MVA Tool-Specific Sample Data",
    "",
    "This deterministic test pack contains no production or customer data. Each scanner has a completely separate folder with a matching inventory, host-discovery history, scanner exports, expected results, and testing instructions.",
    "",
    "| Folder | Scenario |",
    "|---|---|",
    "| `tenable-sc/` | Tenable.sc inventory, discovery, ad hoc, and four-month comparison |",
    "| `tenable-io/` | Tenable.io inventory, discovery, ad hoc, and four-month comparison |",
    "| `qualys/` | Qualys VMDR inventory, discovery, ad hoc, and four-month comparison |",
    "| `crowdstrike/` | CrowdStrike inventory, discovery, per-asset ad hoc, remediation, and four-month comparison |",
    "| `openshift/` | OpenShift workload inventory, discovery, ad hoc, and four-month comparison |",
    "",
    "## Standard layout",
    "",
    "Every tool folder contains:",
    "",
    "```text",
    "asset_inventory/",
    "host_discovery/",
    "scan_results/",
    "expected_results/",
    "README.md",
    "manifest.json",
    "```",
    "",
    "Each inventory contains 100 active in-scope assets using the simplified Tool, Asset Type, IP Address, DNS Name, Host Name, Team Name, and OS Name layout. Scanner-observed assets are included in the matching tool inventory.",
    "",
    "Each discovery month contains only the `IP Address` and `DNS Name` columns. It intentionally includes three unmanaged hosts and two duplicate rows to validate coverage, deduplication, and exception handling. No out-of-scope rows are included in asset inventory.",
    "",
    "Start with the `README.md` inside the tool folder you want to test. Use the expected JSON files for exact reconciliation.",
    "",
  ].join("\n");
}
