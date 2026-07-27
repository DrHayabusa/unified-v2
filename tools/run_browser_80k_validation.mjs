#!/usr/bin/env node
import fs from "node:fs/promises";
import { performance } from "node:perf_hooks";

import { buildAdhocDashboard, normalizeRows, parseCsvText } from "../react-ui/src/lib/vulnerabilityEngine.js";


const rowCount = 80_000;
const samplePath = new URL("../samples/crowdstrike_100_row/crowdstrike_vulnerabilities_july_2026_100plus.csv", import.meta.url);
const sampleText = await fs.readFile(samplePath, "utf8");
const headers = sampleText.slice(0, sampleText.indexOf("\n")).replace(/\r$/, "").split(",");
const index = Object.fromEntries(headers.map((header, position) => [header, position]));
const rows = new Array(rowCount + 1);
rows[0] = headers.join(",");

for (let rowIndex = 0; rowIndex < rowCount; rowIndex += 1) {
  const hostIndex = rowIndex % 2_000;
  const severity = ["Critical", "High", "Medium", "Low"][rowIndex % 4];
  const row = new Array(headers.length).fill("");
  set(row, index, "Hostname", `browser-load-${String(hostIndex).padStart(4, "0")}.corp.example`);
  set(row, index, "LocalIP", `10.${40 + Math.floor(hostIndex / 256)}.${hostIndex % 256}.${20 + rowIndex % 200}`);
  set(row, index, "HostType", "Server");
  set(row, index, "OSVersion", "Windows Server 2022");
  set(row, index, "Product", "Enterprise Application");
  set(row, index, "CVE ID", `CVE-2026-${10000 + rowIndex}`);
  set(row, index, "CVE Description", "Synthetic browser performance vulnerability");
  set(row, index, "Status", "Open");
  set(row, index, "Severity", severity);
  set(row, index, "Created Date", "2026-01-15");
  set(row, index, "Base Score", { Critical: "9.8", High: "8.1", Medium: "6.4", Low: "3.7" }[severity]);
  set(row, index, "CVSS Version", "3.1");
  set(row, index, "Recommended Remediations", "Apply the approved vendor security update.");
  set(row, index, "Remediation Links", "https://nvd.nist.gov/");
  set(row, index, "Host ID", `BROWSER-HOST-${String(hostIndex).padStart(4, "0")}`);
  set(row, index, "Exploit status label", rowIndex % 3 === 0 ? "Exploit available" : "No known exploit");
  set(row, index, "Platform", "Windows");
  set(row, index, "Is Suppressed", "No");
  set(row, index, "Is CISA KEV", rowIndex % 17 === 0 ? "Yes" : "No");
  set(row, index, "Internet exposure", rowIndex % 7 === 0 ? "Yes" : "No");
  set(row, index, "Vulnerability ID", `CS-BROWSER-${String(rowIndex).padStart(8, "0")}`);
  set(row, index, "Last Scan Time", "2026-07-31T02:00:00Z");
  set(row, index, "Asset Criticality", hostIndex % 10 === 0 ? "Critical" : "Medium");
  set(row, index, "Instance state", "Active");
  rows[rowIndex + 1] = row.map(csvCell).join(",");
}

const csvText = rows.join("\n");
const parseStarted = performance.now();
const parsed = parseCsvText(csvText, "crowdstrike_browser_80000_july_2026.csv");
const parseSeconds = (performance.now() - parseStarted) / 1000;
const normalizeStarted = performance.now();
const findings = normalizeRows(parsed.rows, parsed.sourceTool, new Date("2026-07-31T23:59:59Z"));
const normalizeSeconds = (performance.now() - normalizeStarted) / 1000;
const dashboardStarted = performance.now();
const dashboard = buildAdhocDashboard(findings);
const dashboardSeconds = (performance.now() - dashboardStarted) / 1000;

const result = {
  status: parsed.rows.length === rowCount && findings.length === rowCount && dashboard.totalVulnerabilities === rowCount ? "PASS" : "FAIL",
  rows: rowCount,
  csvSizeMb: round(Buffer.byteLength(csvText) / 1024 / 1024),
  parseSeconds: round(parseSeconds),
  normalizeSeconds: round(normalizeSeconds),
  dashboardSeconds: round(dashboardSeconds),
  totalSeconds: round(parseSeconds + normalizeSeconds + dashboardSeconds),
  normalizedRows: findings.length,
  dashboardTotal: dashboard.totalVulnerabilities,
  distinctAssets: dashboard.distinctAssets,
};

await fs.mkdir(new URL("../output/validation/", import.meta.url), { recursive: true });
await fs.writeFile(new URL("../output/validation/browser_80000_rows.json", import.meta.url), JSON.stringify(result, null, 2), "utf8");
console.log(JSON.stringify(result, null, 2));
if (result.status !== "PASS") process.exitCode = 1;


function set(row, positions, field, value) {
  if (positions[field] != null) row[positions[field]] = value;
}

function csvCell(value) {
  const text = String(value ?? "");
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function round(value) {
  return Math.round(value * 1000) / 1000;
}
