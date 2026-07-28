import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { buildAnalysisWorkbook } from "./reportExport.js";
import { buildRemediationPrompt, buildTemplateMarkdown, createRemediationPdfDocument } from "./pdfReport.js";
import { analyzeAdhocFiles, analyzeMonthlyFiles } from "./vulnerabilityEngine.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

const CASES = [
  ["tenable-sc", "samples/tenable_100_row/tenable_sc_july_2026_100plus.csv"],
  ["tenable-io", "samples/tenable_100_row/tenable_io_july_2026_100plus.csv"],
  ["qualys", "samples/qualys_100_row/qualys_adhoc_july_2026_100plus.csv"],
  ["crowdstrike", "samples/crowdstrike_100_row/crowdstrike_vulnerabilities_july_2026_100plus.csv"],
];

test("every scanner produces a populated source-neutral Adhoc workbook", async () => {
  for (const [sourceId, relativePath] of CASES) {
    const filePath = path.join(root, relativePath);
    const analysis = await analyzeAdhocFiles([await fakeFile(filePath)], sourceId);
    const workbook = await buildAnalysisWorkbook(analysis);
    const dashboard = workbook.getWorksheet("Adhoc Report");
    const data = workbook.getWorksheet("Report Data");

    assert.ok(dashboard, `${sourceId}: Adhoc Report sheet`);
    assert.ok(data, `${sourceId}: Report Data sheet`);
    assert.equal(workbook.getWorksheet("Decision Intelligence"), undefined, `${sourceId}: browser-only decision intelligence`);
    assert.equal(workbook.getWorksheet("Remediation Campaigns"), undefined, `${sourceId}: browser-only remediation campaigns`);
    assert.equal(workbook.getWorksheet("Remediation Verification"), undefined, `${sourceId}: browser-only remediation verification`);
    assert.equal(data.actualRowCount, analysis.findings.length + 1, `${sourceId}: complete normalized rows`);
    assert.match(String(dashboard.getCell("A1").value), /Adhoc Vulnerability Report$/, sourceId);
    assert.doesNotMatch(String(dashboard.getCell("A1").value), /Adhoc Adhoc/, sourceId);

    const dashboardText = dashboard.getSheetValues().flat(3).filter(Boolean).join(" | ");
    assert.match(dashboardText, /Top 10 Affected Assets/, sourceId);
    assert.match(dashboardText, /Affected Asset Concentration/, sourceId);
    assert.match(dashboardText, /Vulnerabilities Discovered - Last 3 Months|Current Open Findings by Severity/, sourceId);
    assert.doesNotMatch(dashboardText, /Top Products/, sourceId);
    assert.ok(dashboard.getImages().length >= 1, `${sourceId}: universal line chart`);
    assert.equal(dashboard.getCell("A21").value, analysis.dashboard.top10AffectedAssets[0].asset, `${sourceId}: full asset label`);
    assert.equal(dashboard.getCell("F21").value, analysis.dashboard.top10AffectedAssets[0].vulnerabilityCount, `${sourceId}: asset count`);
    assert.equal(dashboard.getCell("G21").value, analysis.dashboard.top10AffectedAssets[0].asset, `${sourceId}: concentration label`);

    for (let row = 2; row <= data.actualRowCount; row += 1) {
      assert.ok(data.getCell(row, 1).value || data.getCell(row, 2).value, `${sourceId}: asset identity at row ${row}`);
      assert.notEqual(data.getCell(row, 3).value, "N/A", `${sourceId}: vulnerability name at row ${row}`);
      assert.match(String(data.getCell(row, 7).value), /^P[1-4]$/, `${sourceId}: patch priority at row ${row}`);
      assert.equal(typeof data.getCell(row, 8).value, "number", `${sourceId}: numeric exposure at row ${row}`);
      assert.notEqual(data.getCell(row, 12).value, "N/A", `${sourceId}: remediation at row ${row}`);
    }
  }
});

test("Qualys Adhoc workbook explains dates absent from the source export", async () => {
  const filePath = path.join(root, "samples/qualys_100_row/qualys_adhoc_july_2026_100plus.csv");
  const analysis = await analyzeAdhocFiles([await fakeFile(filePath)], "qualys");
  const workbook = await buildAnalysisWorkbook(analysis);
  const data = workbook.getWorksheet("Report Data");

  assert.equal(data.actualRowCount, 126);
  const firstDiscoveredColumn = columnByHeader(data, "First Discovered");
  const lastObservedColumn = columnByHeader(data, "Last Observed");
  for (let row = 2; row <= data.actualRowCount; row += 1) {
    assert.equal(data.getCell(row, firstDiscoveredColumn).value, "Not provided by source export");
    assert.equal(data.getCell(row, lastObservedColumn).value, "Not provided by source export");
  }
});

test("Custom Qualys reports display all five source ratings and Datacentre categorization", async () => {
  const filePath = path.join(root, "samples/custom_qualys_100_row/custom_qualys_adhoc_july_2026.csv");
  const analysis = await analyzeAdhocFiles([await fakeFile(filePath)], "custom-qualys");
  const workbook = await buildAnalysisWorkbook(analysis);
  const qualys = workbook.getWorksheet("Qualys Analysis");
  const reportData = workbook.getWorksheet("Report Data");
  const sheetText = qualys.getSheetValues().flat(3).filter(Boolean).join(" | ");
  const markdown = buildTemplateMarkdown({ analysis, targetMonth: analysis.reportMonth });
  const prompt = buildRemediationPrompt({ analysis, targetMonth: analysis.reportMonth });

  assert.ok(qualys);
  assert.match(sheetText, /Custom Qualys Operational Analysis/);
  assert.match(sheetText, /Datacentre Distribution/);
  for (const label of ["5 - Urgent", "4 - Critical", "3 - Serious", "2 - Medium", "1 - Minimal"]) {
    assert.match(sheetText, new RegExp(label));
    assert.match(markdown, new RegExp(label));
  }
  for (const datacentre of analysis.dashboard.qualysInsights.datacentres.map((row) => row.datacentre)) {
    assert.match(sheetText, new RegExp(datacentre));
    assert.match(markdown, new RegExp(datacentre));
  }
  assert.equal(qualys.getImages().length, 2);
  assert.equal(qualys.pageSetup.printArea, "A1:L40");
  assert.match(workbook.getWorksheet("Cover Page").getSheetValues().flat(3).filter(Boolean).join(" | "), /Qualys Operational Analysis/);
  assert.ok(columnByHeader(reportData, "Datacentre") > 0);
  assert.ok(columnByHeader(reportData, "Vendor Severity Rating") > 0);
  assert.match(prompt, /complete source-rating distribution and Datacentre distribution/);
  assert.match(prompt, /"rating": "5 - Urgent"/);
  assert.equal(workbook.getWorksheet("Adhoc Report").getImages().length, 1);
});

test("OpenShift workbook preserves every supplied workload and fix field", async () => {
  const filePath = path.join(root, "samples/openshift_100_row/openshift_july_2026_100plus.csv");
  const analysis = await analyzeAdhocFiles([await fakeFile(filePath)], "openshift");
  const workbook = await buildAnalysisWorkbook(analysis);
  const data = workbook.getWorksheet("Report Data");

  assert.equal(data.actualRowCount, 141);
  for (const header of ["Namespace", "Deployment", "Image", "Component", "Fixable", "CVE Fixed In", "CVSS"]) {
    assert.ok(columnByHeader(data, header) > 0);
  }
  assert.ok(data.getColumn(columnByHeader(data, "Namespace")).values.slice(2).every(Boolean));
  assert.ok(data.getColumn(columnByHeader(data, "Image")).values.slice(2).every(Boolean));
  assert.ok(data.getColumn(columnByHeader(data, "Component")).values.slice(2).every(Boolean));
  assert.ok(data.getColumn(columnByHeader(data, "Fixable")).values.slice(2).every((value) => ["Yes", "No"].includes(value)));
});

test("CrowdStrike monthly workbook keeps threat-intelligence additions browser-only", async () => {
  const files = await Promise.all(["april", "may", "june", "july"].map((month) => fakeFile(
    path.join(root, "samples", "crowdstrike_100_row", `crowdstrike_vulnerabilities_${month}_2026_100plus.csv`),
  )));
  const analysis = await analyzeMonthlyFiles(files, "crowdstrike");
  const workbook = await buildAnalysisWorkbook(analysis);
  const report = workbook.getWorksheet("Monthly Report");
  const reportText = report.getSheetValues().flat(3).filter(Boolean).join(" | ");

  assert.match(reportText, /Vulnerability Trend - Last 3 Months/);
  assert.equal(report.getImages().length, 2);
  assert.ok(workbook.media.length >= 7);
  assert.ok(workbook.media.every((image) => image.extension === "png" && image.base64.startsWith("data:image/png;base64,iVBOR")));
  assert.equal(report.pageSetup.orientation, "landscape");
  assert.equal(report.pageSetup.fitToWidth, 1);
  assert.equal(report.pageSetup.printArea, "A1:L41");
  assert.match(reportText, /Total Open by Patch Priority/);
  assert.match(reportText, /Total Open by Age and Patch Priority/);
  assert.match(reportText, /Vulnerabilities Patched in Last Month/);
  assert.doesNotMatch(reportText, /CISA KEV|SSVC|EPSS|Threat Review|CrowdStrike Exposure Signals/);
});

test("Unified workbook preserves scanner provenance and consolidation audit", async () => {
  const files = await Promise.all(CASES.map(([, relativePath]) => fakeFile(path.join(root, relativePath.replace("qualys_adhoc", "qualys_monthly")))));
  const analysis = await analyzeAdhocFiles(files, { mode: "multi", sourceIds: CASES.map(([sourceId]) => sourceId) });
  const workbook = await buildAnalysisWorkbook(analysis);
  const data = workbook.getWorksheet("Report Data");
  const audit = workbook.getWorksheet("Source Audit");
  const unified = workbook.getWorksheet("Unified Dashboard");

  assert.equal(workbook.worksheets[0].name, "Cover Page");
  assert.equal(workbook.getWorksheet("Cover Page").getCell("A6").value, "Vulnerability Analysis Report");
  assert.ok(workbook.getWorksheet("Executive Dashboard"));
  assert.ok(workbook.getWorksheet("Briefing"));
  assert.ok(workbook.getWorksheet("Top Vulnerable Assets"));
  assert.ok(workbook.getWorksheet("Top Vulnerabilities"));
  assert.ok(unified);
  assert.ok(audit);
  assert.equal(unified.getCell("A1").value, "Unified Multi-Tool Consolidated Analysis");
  assert.equal(unified.getCell("A5").value, 160);
  assert.equal(unified.getCell("I5").value, 110);
  assert.equal(unified.getCell("A10").value, 40);
  assert.equal(unified.getCell("E10").value, 120);
  assert.equal(unified.getCell("I10").value, "25%");
  assert.equal(data.getCell("F1").value, "Exploit Available");
  const sourceToolsColumn = columnByHeader(data, "Source Tools");
  const recordCountColumn = columnByHeader(data, "Record Count");
  assert.equal(data.getCell(1, sourceToolsColumn).value, "Source Tools");
  assert.equal(data.getCell(1, recordCountColumn).value, "Record Count");
  assert.ok(data.getColumn(sourceToolsColumn).values.slice(2).every((value) => String(value).length > 0));
  assert.equal(audit.getCell("A1").value, "Unified Multi-Tool Source Audit");
  assert.equal(audit.getCell("A5").value, 4);
  assert.equal(audit.getCell("C5").value, 4);
  assert.equal(audit.getCell("E5").value, analysis.dashboard.totalVulnerabilities);
  assert.equal(audit.getCell("H5").value, analysis.inputSummary.duplicatesRemoved);
});

test("Unified monthly Excel and PDF contain combined analysis plus remediations", async () => {
  const files = await Promise.all(["april", "may", "june", "july"].flatMap((month) => [
    path.join(root, "samples", "tenable_100_row", `tenable_sc_${month}_2026_100plus.csv`),
    path.join(root, "samples", "tenable_100_row", `tenable_io_${month}_2026_100plus.csv`),
  ]).map(fakeFile));
  const analysis = await analyzeMonthlyFiles(files, { mode: "multi", sourceIds: ["tenable-sc", "tenable-io"] });
  const workbook = await buildAnalysisWorkbook(analysis);
  const unified = workbook.getWorksheet("Unified Dashboard");
  const dashboardText = unified.getSheetValues().flat(3).filter(Boolean).join(" | ");

  assert.equal(workbook.worksheets[0].name, "Cover Page");
  assert.match(dashboardText, /Consolidated Analysis Trend/);
  assert.match(dashboardText, /Highest-Risk Assets/);
  assert.match(dashboardText, /Highest-Impact Vulnerabilities/);
  assert.match(dashboardText, /Tool Contribution/);
  assert.equal(unified.getCell("A15").value, "Period");
  assert.equal(unified.getCell("A16").value, "April 2026");
  assert.equal(unified.getCell("B19").value, 40);
  assert.equal(workbook.getWorksheet("Decision Intelligence"), undefined);
  assert.equal(workbook.getWorksheet("Remediation Campaigns"), undefined);
  assert.equal(workbook.getWorksheet("Remediation Verification"), undefined);
  assert.equal(
    analysis.dashboard.customerValueInsights.remediationCampaigns.campaigns.reduce((sum, campaign) => sum + campaign.findingCount, 0),
    analysis.dashboard.totalOpenVulnerabilities.totalOpen,
  );
  assert.equal(analysis.dashboard.customerValueInsights.verification.reconciled, true);

  const markdown = buildTemplateMarkdown({ analysis, targetMonth: "July 2026" });
  const prompt = buildRemediationPrompt({ analysis, targetMonth: "July 2026" });
  assert.match(markdown, /## Table of Contents/);
  assert.match(markdown, /## 1\. Portfolio Risk Overview/);
  assert.match(markdown, /## 2\. Trend Analysis/);
  assert.match(markdown, /Confirmed by Multiple Tools/);
  assert.match(markdown, /Tool Contribution/);
  assert.match(markdown, /## 3\. Remediation Actions/);
  assert.match(markdown, /## 5\. References/);
  assert.match(prompt, /Consolidated analytics for the selected reporting period/);
  assert.match(prompt, /"crossToolConfirmed": 40/);

  const pdf = await createRemediationPdfDocument({ markdown, sourceLabel: analysis.sourceLabel, targetMonth: "July 2026", workflow: "monthly" });
  const bytes = Buffer.from(pdf.output("arraybuffer"));
  assert.equal(bytes.subarray(0, 4).toString(), "%PDF");
  assert.ok(pdf.getNumberOfPages() >= 3);
});

async function fakeFile(filePath) {
  const blob = new Blob([await readFile(filePath)], { type: "text/csv" });
  Object.defineProperty(blob, "name", { value: path.basename(filePath) });
  return blob;
}

function columnByHeader(sheet, header) {
  const cell = sheet.getRow(1).values.findIndex((value) => value === header);
  assert.ok(cell > 0, `Expected "${header}" column`);
  return cell;
}
