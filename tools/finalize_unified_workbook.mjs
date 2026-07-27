import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { FileBlob, SpreadsheetFile } from "@oai/artifact-tool";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const inputPath = path.join(root, "tmp", "unified-release", "MVA_Unified_Combined_Monthly_Report_base.xlsx");
const outputPath = path.join(root, "final", "Unified", "Excel", "MVA_Unified_Combined_Monthly_Report.xlsx");
const evidenceDir = path.join(root, "final", "Unified", "Evidence", "Excel");
await fs.mkdir(path.dirname(outputPath), { recursive: true });
await fs.mkdir(evidenceDir, { recursive: true });

const workbook = await SpreadsheetFile.importXlsx(await FileBlob.load(inputPath));
const dashboard = workbook.worksheets.getItem("Unified Dashboard");
dashboard.charts.deleteAll();

const movement = dashboard.charts.add("line", dashboard.getRange("A15:D19"));
movement.title = "Combined Open, New, and Patched Trend";
movement.hasLegend = true;
movement.xAxis = { axisType: "textAxis", textStyle: { fontSize: 9 } };
movement.yAxis = { numberFormatCode: "#,##0", min: 0 };
movement.setPosition("A22", "H34");

const priority = dashboard.charts.add("line", { chartType: "line", title: "Patch Priority Trend", hasLegend: true });
for (const [name, column] of [["P1", "E"], ["P2", "F"], ["P3", "G"], ["P4", "H"]]) {
  const series = priority.series.add(name);
  series.categoryFormula = "'Unified Dashboard'!$A$16:$A$19";
  series.formula = `'Unified Dashboard'!$${column}$16:$${column}$19`;
  series.fill = { P1: "#DC2626", P2: "#EA580C", P3: "#CA8A04", P4: "#16A34A" }[name];
}
priority.title = "P1-P4 Patch Priority Trend";
priority.hasLegend = true;
priority.xAxis = { axisType: "textAxis", textStyle: { fontSize: 9 } };
priority.yAxis = { numberFormatCode: "#,##0", min: 0 };
priority.setPosition("I22", "P34");

const monthly = workbook.worksheets.getItem("Monthly Report");
monthly.charts.deleteAll();
for (const [title, column, startCell, endCell] of [
  ["Vulnerabilities Discovered", "B", "D9", "G19"],
  ["Vulnerabilities Remediated", "C", "H9", "L19"],
]) {
  const chart = monthly.charts.add("line", { chartType: "line", title, hasLegend: false });
  const series = chart.series.add(title);
  series.categoryFormula = "'Monthly Report'!$A$11:$A$13";
  series.formula = `'Monthly Report'!$${column}$11:$${column}$13`;
  series.fill = column === "B" ? "#2563EB" : "#16A34A";
  chart.title = title;
  chart.hasLegend = false;
  chart.xAxis = { axisType: "textAxis", textStyle: { fontSize: 9 } };
  chart.yAxis = { numberFormatCode: "#,##0", min: 0 };
  chart.setPosition(startCell, endCell);
}

const keyInspection = await workbook.inspect({
  kind: "table",
  sheetId: "Unified Dashboard",
  range: "A1:P19",
  include: "values,formulas",
  tableMaxRows: 20,
  tableMaxCols: 16,
  maxChars: 8000,
});
const formulaErrors = await workbook.inspect({
  kind: "match",
  searchTerm: "#REF!|#DIV/0!|#VALUE!|#NAME\\?|#N/A",
  options: { useRegex: true, maxResults: 300 },
  summary: "final formula error scan",
});
await fs.writeFile(path.join(root, "final", "Unified", "Validation", "workbook_inspection.ndjson"), `${keyInspection.ndjson}\n${formulaErrors.ndjson}\n`);

for (const [sheetName, range, fileName] of [
  ["Unified Dashboard", "A1:P52", "MVA_Unified_Excel_Dashboard.png"],
  ["Monthly Report", "A1:L42", "MVA_Unified_Excel_Monthly_Report.png"],
  ["Report Data", "A1:R18", "MVA_Unified_Excel_Report_Data.png"],
  ["Source Audit", "A1:I27", "MVA_Unified_Excel_Source_Audit.png"],
]) {
  const preview = await workbook.render({ sheetName, range, scale: 1.25, format: "png" });
  await fs.writeFile(path.join(evidenceDir, fileName), new Uint8Array(await preview.arrayBuffer()));
}

const output = await SpreadsheetFile.exportXlsx(workbook);
await output.save(outputPath);
console.log(JSON.stringify({ outputPath, sheets: ["Unified Dashboard", "Monthly Report", "Report Data", "Source Audit"] }, null, 2));
