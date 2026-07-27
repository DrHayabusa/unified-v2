import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { buildTemplateMarkdown, createRemediationPdfDocument } from "../react-ui/src/lib/pdfReport.js";
import { createExecutiveDashboardPdfDocument } from "../react-ui/src/lib/executiveReportPdf.js";
import { buildAnalysisWorkbook } from "../react-ui/src/lib/reportExport.js";
import { analyzeAdhocFiles, analyzeMonthlyFiles } from "../react-ui/src/lib/vulnerabilityEngine.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const months = ["april", "may", "june", "july"];
const outputRoot = path.join(root, "final", "Production Evidence");

const sources = [
  {
    id: "tenable-sc",
    slug: "Tenable_SC",
    label: "Tenable.sc",
    monthly: (month) => path.join(root, "samples", "tenable_100_row", `tenable_sc_${month}_2026_100plus.csv`),
    adhoc: path.join(root, "samples", "tenable_100_row", "tenable_sc_july_2026_100plus.csv"),
  },
  {
    id: "tenable-io",
    slug: "Tenable_IO",
    label: "Tenable.io",
    monthly: (month) => path.join(root, "samples", "tenable_100_row", `tenable_io_${month}_2026_100plus.csv`),
    adhoc: path.join(root, "samples", "tenable_100_row", "tenable_io_july_2026_100plus.csv"),
  },
  {
    id: "qualys",
    slug: "Qualys",
    label: "Qualys",
    monthly: (month) => path.join(root, "samples", "qualys_100_row", `qualys_monthly_${month}_2026_100plus.csv`),
    adhoc: path.join(root, "samples", "qualys_100_row", "qualys_adhoc_july_2026_100plus.csv"),
  },
  {
    id: "custom-qualys",
    slug: "Custom_Qualys",
    label: "Custom Qualys",
    monthly: (month) => path.join(root, "samples", "custom_qualys_100_row", `custom_qualys_monthly_${month}_2026.csv`),
    adhoc: path.join(root, "samples", "custom_qualys_100_row", "custom_qualys_adhoc_july_2026.csv"),
  },
  {
    id: "crowdstrike",
    slug: "CrowdStrike",
    label: "CrowdStrike",
    monthly: (month) => path.join(root, "samples", "crowdstrike_100_row", `crowdstrike_vulnerabilities_${month}_2026_100plus.csv`),
    adhoc: path.join(root, "samples", "crowdstrike_100_row", "crowdstrike_vulnerability_per_asset_july_2026_100plus.csv"),
  },
  {
    id: "openshift",
    slug: "OpenShift",
    label: "Red Hat OpenShift",
    monthly: (month) => path.join(root, "samples", "openshift_100_row", `openshift_${month}_2026_100plus.csv`),
    adhoc: path.join(root, "samples", "openshift_100_row", "openshift_july_2026_100plus.csv"),
  },
];

await fs.mkdir(outputRoot, { recursive: true });
const release = {
  generatedAt: new Date().toISOString(),
  priorityMatrix: {
    exploitAvailable: { Critical: "P1", High: "P1", Medium: "P2", Low: "P2" },
    exploitUnavailable: { Critical: "P2", High: "P2", Medium: "P3", Low: "P4" },
  },
  sources: [],
};

for (const source of sources) {
  const sourceDir = path.join(outputRoot, source.slug);
  await fs.mkdir(sourceDir, { recursive: true });
  const monthlyPaths = months.map(source.monthly);
  const monthlyFiles = await Promise.all(monthlyPaths.map(fileBlob));
  const monthly = await analyzeMonthlyFiles(monthlyFiles, source.id);
  const adhoc = await analyzeAdhocFiles([await fileBlob(source.adhoc)], source.id);

  const monthlyWorkbookPath = path.join(sourceDir, `MVA_${source.slug}_Monthly_Report.xlsx`);
  const adhocWorkbookPath = path.join(sourceDir, `MVA_${source.slug}_Adhoc_Report.xlsx`);
  await writeWorkbook(monthlyWorkbookPath, monthly);
  await writeWorkbook(adhocWorkbookPath, adhoc);

  const targetMonth = monthly.dashboard.uploadedPeriods.at(-1);
  const markdown = buildTemplateMarkdown({ analysis: monthly, targetMonth });
  const pdf = await createRemediationPdfDocument({
    markdown,
    sourceLabel: monthly.sourceLabel,
    targetMonth,
    workflow: "monthly",
  });
  const pdfPath = path.join(sourceDir, `MVA_${source.slug}_July_2026_Remediation_Guide.pdf`);
  await fs.writeFile(pdfPath, Buffer.from(pdf.output("arraybuffer")));
  const executivePdf = await createExecutiveDashboardPdfDocument({
    analysis: monthly,
    targetPeriod: targetMonth,
  });
  const executivePdfPath = path.join(sourceDir, `MVA_${source.slug}_July_2026_Executive_Dashboard.pdf`);
  await fs.writeFile(executivePdfPath, Buffer.from(executivePdf.output("arraybuffer")));

  const evidence = {
    source: source.label,
    inputs: {
      monthly: monthlyPaths.map((filePath) => path.relative(root, filePath)),
      adhoc: path.relative(root, source.adhoc),
    },
    monthly: comparisonEvidence(monthly),
    adhoc: adhocEvidence(adhoc),
    outputs: {
      monthlyWorkbook: path.relative(root, monthlyWorkbookPath),
      adhocWorkbook: path.relative(root, adhocWorkbookPath),
      remediationGuide: path.relative(root, pdfPath),
      executiveDashboard: path.relative(root, executivePdfPath),
    },
  };
  await fs.writeFile(path.join(sourceDir, "validation.json"), `${JSON.stringify(evidence, null, 2)}\n`);
  release.sources.push(evidence);
}

await fs.writeFile(path.join(outputRoot, "release_manifest.json"), `${JSON.stringify(release, null, 2)}\n`);
process.stdout.write(`${JSON.stringify({
  status: "PASS",
  outputRoot,
  sources: release.sources.map((source) => ({
    source: source.source,
    monthlyOpen: source.monthly.totalOpen,
    monthlyNew: source.monthly.newFindings,
    monthlyPatched: source.monthly.patchedFindings,
    adhocOpen: source.adhoc.totalOpen,
  })),
}, null, 2)}\n`);

async function fileBlob(filePath) {
  const blob = new Blob([await fs.readFile(filePath)], { type: "text/csv" });
  Object.defineProperty(blob, "name", { value: path.basename(filePath) });
  return blob;
}

async function writeWorkbook(filePath, analysis) {
  const workbook = await buildAnalysisWorkbook(analysis);
  const buffer = await workbook.xlsx.writeBuffer();
  await fs.writeFile(filePath, Buffer.from(buffer));
}

function comparisonEvidence(analysis) {
  const dashboard = analysis.dashboard;
  const open = dashboard.totalOpenVulnerabilities;
  const patched = dashboard.totalVulnerabilitiesPatchedLastPeriod;
  return {
    reportRange: dashboard.reportRange,
    periods: dashboard.uploadedPeriods,
    totalOpen: open.totalOpen,
    newFindings: open.newVulnerabilities,
    notClosed: open.notClosedFromPreviousMonths,
    patchedFindings: patched.patchedCount,
    patchedFormula: {
      previousOpen: patched.previousPeriodOpen,
      plusNew: patched.newVulnerabilitiesIdentifiedThisPeriod,
      minusCurrentOpen: patched.currentPeriodOpen,
      result: patched.patchedCount,
    },
    patchPriority: dashboard.totalOpenByPatchPriority,
    ageByPatchPriority: dashboard.totalOpenByAgeAndPatchPriority,
    discoveredLast3Periods: dashboard.trendDiscoveredLast3Periods,
    patchedLast3Periods: dashboard.trendRemediatedLast3Periods,
    validation: dashboard.validation,
    qualys: dashboard.qualysInsights,
    crowdstrike: dashboard.crowdstrikeInsights,
    openshift: dashboard.openshiftInsights,
  };
}

function adhocEvidence(analysis) {
  const dashboard = analysis.dashboard;
  return {
    totalOpen: dashboard.totalVulnerabilities,
    distinctAssets: dashboard.distinctAssets,
    exploitAvailable: dashboard.exploitAvailable,
    severity: dashboard.severityCounts,
    patchPriority: dashboard.patchPriorityCounts,
    qualys: dashboard.qualysInsights,
    crowdstrike: dashboard.crowdstrikeInsights,
    openshift: dashboard.openshiftInsights,
  };
}
