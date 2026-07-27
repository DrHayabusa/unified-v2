import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { buildTemplateMarkdown, createRemediationPdfDocument } from "../react-ui/src/lib/pdfReport.js";
import { buildAnalysisWorkbook } from "../react-ui/src/lib/reportExport.js";
import { analyzeMonthlyFiles } from "../react-ui/src/lib/vulnerabilityEngine.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const months = ["april", "may", "june", "july"];
const sourcePaths = [
  ["tenable-sc", (month) => path.join(root, "samples", "tenable_100_row", `tenable_sc_${month}_2026_100plus.csv`)],
  ["tenable-io", (month) => path.join(root, "samples", "tenable_100_row", `tenable_io_${month}_2026_100plus.csv`)],
  ["qualys", (month) => path.join(root, "samples", "qualys_100_row", `qualys_monthly_${month}_2026_100plus.csv`)],
  ["crowdstrike", (month) => path.join(root, "samples", "crowdstrike_100_row", `crowdstrike_vulnerabilities_${month}_2026_100plus.csv`)],
];

const outputRoot = path.join(root, "final", "Unified");
const tempRoot = path.join(root, "tmp", "unified-release");
await Promise.all([
  fs.mkdir(path.join(outputRoot, "Excel"), { recursive: true }),
  fs.mkdir(path.join(outputRoot, "PDF"), { recursive: true }),
  fs.mkdir(path.join(outputRoot, "Validation"), { recursive: true }),
  fs.mkdir(tempRoot, { recursive: true }),
]);

const filePaths = months.flatMap((month) => sourcePaths.map(([, resolvePath]) => resolvePath(month)));
const files = await Promise.all(filePaths.map(async (filePath) => {
  const blob = new Blob([await fs.readFile(filePath)], { type: "text/csv" });
  Object.defineProperty(blob, "name", { value: path.basename(filePath) });
  return blob;
}));
const sourceIds = sourcePaths.map(([sourceId]) => sourceId);
const analysis = await analyzeMonthlyFiles(files, { mode: "multi", sourceIds });

const workbook = await buildAnalysisWorkbook(analysis);
const workbookBuffer = await workbook.xlsx.writeBuffer();
const baseWorkbook = path.join(tempRoot, "MVA_Unified_Combined_Monthly_Report_base.xlsx");
await fs.writeFile(baseWorkbook, Buffer.from(workbookBuffer));

const targetMonth = "July 2026";
const markdown = buildTemplateMarkdown({ analysis, targetMonth });
const pdf = await createRemediationPdfDocument({
  markdown,
  sourceLabel: analysis.sourceLabel,
  targetMonth,
  workflow: "monthly",
});
const pdfPath = path.join(outputRoot, "PDF", "MVA_Unified_July_2026_Remediation_Guide.pdf");
await fs.writeFile(pdfPath, Buffer.from(pdf.output("arraybuffer")));

const engineEvidence = {
  generatedAt: new Date().toISOString(),
  sourceIds,
  inputFiles: filePaths.map((filePath) => path.relative(root, filePath)),
  reportRange: analysis.dashboard.reportRange,
  inputSummary: analysis.inputSummary,
  periods: analysis.dashboard.unifiedTrend,
  latest: {
    totalOpen: analysis.dashboard.unifiedInsights.totalOpen,
    distinctAssets: analysis.dashboard.unifiedInsights.distinctAssets,
    immediatePatch: analysis.dashboard.unifiedInsights.immediatePatch,
    exploitAvailable: analysis.dashboard.unifiedInsights.exploitAvailable,
    crossToolConfirmed: analysis.dashboard.unifiedInsights.crossToolConfirmed,
    singleSourceOnly: analysis.dashboard.unifiedInsights.singleSourceOnly,
    confirmationRate: analysis.dashboard.unifiedInsights.confirmationRate,
    severity: analysis.dashboard.currentSeverityCounts,
    priority: analysis.dashboard.totalOpenByPatchPriority,
    ageByPriority: analysis.dashboard.totalOpenByAgeAndPatchPriority,
    discoveredLast3Months: analysis.dashboard.trendDiscoveredLast3Months,
    patchedLast3Months: analysis.dashboard.trendRemediatedLast3Months,
  },
  validation: analysis.dashboard.validation,
};
await fs.writeFile(
  path.join(outputRoot, "Validation", "engine_analysis.json"),
  `${JSON.stringify(engineEvidence, null, 2)}\n`,
);

const normalizedHeaders = [
  ["IP Address", "ipAddress"], ["DNS Name", "dnsName"], ["Vulnerability Name", "vulnerabilityName"],
  ["CVE", "cve"], ["Severity", "severity"], ["Exploit Available", "exploitAvailable"],
  ["Patch Priority", "patchPriority"], ["Asset Exposure (on 1000)", "assetExposure"],
  ["Vulnerability Finding", "vulnerabilityFinding"], ["Summary", "summary"], ["Description", "description"],
  ["Remediation", "remediation"], ["KB Links", "kbLinks"], ["Platform Details", "platformDetails"],
  ["First Discovered", "firstDiscovered"], ["Last Observed", "lastObserved"],
  ["Source Tools", "sourceDisplay"], ["Record Count", "recordCount"],
];
const csvRows = [normalizedHeaders.map(([header]) => header)];
analysis.currentFindings.forEach((finding) => {
  csvRows.push(normalizedHeaders.map(([, key]) => key === "exploitAvailable" ? (finding[key] ? "Yes" : "No") : finding[key] ?? ""));
});
const normalizedCsv = csvRows.map((row) => row.map(csvCell).join(",")).join("\n");
await fs.writeFile(path.join(outputRoot, "MVA_Unified_July_2026_Normalized_Findings.csv"), `\ufeff${normalizedCsv}`);

console.log(JSON.stringify({
  baseWorkbook,
  pdfPath,
  periods: analysis.dashboard.unifiedTrend.map((row) => ({ period: row.period, open: row.totalOpen, new: row.newFindings, patched: row.patchedFindings })),
  latest: engineEvidence.latest,
}, null, 2));

function csvCell(value) {
  const text = String(value ?? "");
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}
