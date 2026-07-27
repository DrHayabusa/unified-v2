#!/usr/bin/env node
import fs from "node:fs/promises";
import path from "node:path";
import { SpreadsheetFile, Workbook } from "@oai/artifact-tool";

const args = parseArgs(process.argv.slice(2));
const monthlyJsonPath = args.monthly ?? "output/dashboard_json/monthly_may_july_dashboard.json";
const adhocJsonPath = args.adhoc ?? "output/dashboard_json/adhoc_july_dashboard.json";
const outputPath = args.output ?? "output/excel/tenable_dashboard_sample.xlsx";
const previewPath = args.preview ?? "output/previews/tenable_dashboard_workbook_preview.png";
const sourceLabel = args["source-label"] ?? "Tenable";

const monthly = JSON.parse(await fs.readFile(monthlyJsonPath, "utf8"));
const adhoc = JSON.parse(await fs.readFile(adhocJsonPath, "utf8"));
const DASHBOARD_FONT = "Calibri";
const DARK_HEADER = "#1F2933";
const REPORT_SURFACE = "#F8FAF7";
const STRUCTURE_BORDER = "#4B5563";
const HEADER_BORDER = "#111827";
const TREND_BLUE = "#1F4E79";
const PRIORITY_COLORS = {
  P1: "#C00000",
  P2: "#FF6600",
  P3: "#FFC000",
  P4: "#70AD47",
};
const SEVERITY_COLORS = {
  Critical: "#C00000",
  High: "#FF6600",
  Medium: "#FFC000",
  Low: "#70AD47",
  Info: "#A6A6A6",
  Unknown: "#D9EAD3",
};

const workbook = Workbook.create();
const executiveSheet = workbook.worksheets.add("Executive Dashboard");
const monthlySheet = workbook.worksheets.add("Monthly Dashboard");
const adhocSheet = workbook.worksheets.add("Adhoc Dashboard");

buildExecutiveSheet(executiveSheet, monthly, adhoc, sourceLabel);
buildMonthlySheet(monthlySheet, monthly, sourceLabel);
buildAdhocSheet(adhocSheet, adhoc, sourceLabel);

await fs.mkdir(path.dirname(outputPath), { recursive: true });
await fs.mkdir(path.dirname(previewPath), { recursive: true });

const preview = await workbook.render({
  sheetName: "Executive Dashboard",
  range: "A1:L52",
  scale: 1,
  format: "png",
});
await fs.writeFile(previewPath, new Uint8Array(await preview.arrayBuffer()));

const xlsx = await SpreadsheetFile.exportXlsx(workbook);
await xlsx.save(outputPath);

console.log(outputPath);
console.log(previewPath);

function buildExecutiveSheet(sheet, monthlyDashboard, _adhocDashboard, sourceLabel) {
  sheet.showGridLines = false;
  setBaseWidths(sheet, "A:L", 12);
  sheet.getRange("A:L").format = {
    font: { name: DASHBOARD_FONT, color: "#1F2937", size: 10 },
    verticalAlignment: "middle",
  };

  const open = monthlyDashboard.total_open_vulnerabilities;
  const patched = monthlyDashboard.total_vulnerabilities_patched_last_month;
  const priorityCounts = monthlyDashboard.total_open_by_patch_priority;
  const immediatePatchCount = (priorityCounts.P1 ?? 0) + (priorityCounts.P2 ?? 0);
  const ageMatrix = monthlyDashboard.total_open_by_age_and_patch_priority;
  const discoveredTrend = monthlyDashboard.trend_discovered_last_3_months;
  const remediatedTrend = monthlyDashboard.trend_remediated_last_3_months ?? [];
  const remediatedByMonth = Object.fromEntries(remediatedTrend.map((row) => [row.month, row.remediated_count]));

  const executiveSourceLabel = sourceLabel.toLowerCase().startsWith("mva ") ? sourceLabel : `MVA ${sourceLabel}`;
  executiveTitle(sheet, "A2:L3", `${executiveSourceLabel} Monthly Vulnerability Dashboard`);
  executiveKpiRow(sheet, [
    ["Total Open", open.total_open],
    ["New This Month", open.new_vulnerabilities],
    ["Not Closed", open.not_closed_from_previous_months],
    ["Patched Last Month", patched.patched_count],
    ["Immediate Patch Needed", immediatePatchCount],
  ]);
  const totalOpenNote = sheet.getRange("A10:L10");
  totalOpenNote.merge();
  totalOpenNote.values = [["2. Total Open Vulnerabilities = New Vulnerabilities + Vulnerabilities Not Closed from Previous Reports"]];
  totalOpenNote.format = {
    fill: REPORT_SURFACE,
    font: { name: DASHBOARD_FONT, bold: true, italic: true, color: "#1F2933", size: 10 },
    borders: { preset: "outside", style: "thin", color: "#A6A6A6" },
  };

  executiveSectionHeader(sheet, "A12:C12", "1. Vulnerability Trend - Last 3 Months");
  executiveTable(sheet, "A13:C16", [
    ["Month", "Discovered", "Remediated"],
    ...discoveredTrend.map((row) => [
      row.month,
      row.discovered_count,
      remediatedByMonth[row.month] ?? 0,
    ]),
  ]);

  const executiveTrendChart = sheet.charts.add("line", sheet.getRange("A13:B16"));
  const maxDiscovered = Math.max(...discoveredTrend.map((row) => Number(row.discovered_count) || 0), 1);
  executiveTrendChart.title = "Vulnerabilities Discovered";
  executiveTrendChart.hasLegend = false;
  executiveTrendChart.xAxis = { axisType: "textAxis" };
  executiveTrendChart.yAxis = { min: 0, max: Math.ceil(maxDiscovered * 1.2), numberFormatCode: "#,##0" };
  if (executiveTrendChart.series.items[0]) {
    executiveTrendChart.series.items[0].fill = TREND_BLUE;
  }
  executiveTrendChart.setPosition("D12", "H21");

  const remediatedChartData = sheet.getRange("J13:K16");
  remediatedChartData.values = [
    ["Month", "Remediated"],
    ...discoveredTrend.map((row) => [row.month, remediatedByMonth[row.month] ?? 0]),
  ];
  const remediatedTrendChart = sheet.charts.add("line", remediatedChartData);
  const maxRemediated = Math.max(...discoveredTrend.map((row) => Number(remediatedByMonth[row.month]) || 0), 1);
  remediatedTrendChart.title = "Vulnerabilities Remediated";
  remediatedTrendChart.hasLegend = false;
  remediatedTrendChart.xAxis = { axisType: "textAxis" };
  remediatedTrendChart.yAxis = { min: 0, max: Math.ceil(maxRemediated * 1.2), numberFormatCode: "#,##0" };
  if (remediatedTrendChart.series.items[0]) {
    remediatedTrendChart.series.items[0].fill = "#70AD47";
  }
  remediatedTrendChart.setPosition("I12", "L21");

  executiveSectionHeader(sheet, "A24:B24", "3. Total Open by Patch Priority");
  executiveTable(sheet, "A25:B29", [
    ["Patch Priority", "Count"],
    ["P1", priorityCounts.P1 ?? 0],
    ["P2", priorityCounts.P2 ?? 0],
    ["P3", priorityCounts.P3 ?? 0],
    ["P4", priorityCounts.P4 ?? 0],
  ]);
  colorPriorityRows(sheet, 26, 29, 1);

  const priorityChartData = sheet.getRange("E25:I26");
  priorityChartData.values = [
    ["Metric", "P1", "P2", "P3", "P4"],
    ["Open", priorityCounts.P1 ?? 0, priorityCounts.P2 ?? 0, priorityCounts.P3 ?? 0, priorityCounts.P4 ?? 0],
  ];

  const priorityBarChart = sheet.charts.add("bar", priorityChartData);
  priorityBarChart.title = "Patch Priority Distribution";
  priorityBarChart.hasLegend = true;
  Object.values(PRIORITY_COLORS).forEach((color, index) => {
    if (priorityBarChart.series.items[index]) {
      priorityBarChart.series.items[index].fill = color;
    }
  });
  priorityBarChart.setPosition("E24", "I33");

  executiveSectionHeader(sheet, "A36:E36", "4. Total Open by Age and Patch Priority");
  executiveTable(sheet, "A37:E41", [
    ["Patch Priority", ">7 days", ">30 days", ">60 days", ">180 days"],
    ["P1", ageMatrix.P1?.[">7 days"] ?? 0, ageMatrix.P1?.[">30 days"] ?? 0, ageMatrix.P1?.[">60 days"] ?? 0, ageMatrix.P1?.[">180 days (6+ months)"] ?? 0],
    ["P2", ageMatrix.P2?.[">7 days"] ?? 0, ageMatrix.P2?.[">30 days"] ?? 0, ageMatrix.P2?.[">60 days"] ?? 0, ageMatrix.P2?.[">180 days (6+ months)"] ?? 0],
    ["P3", ageMatrix.P3?.[">7 days"] ?? 0, ageMatrix.P3?.[">30 days"] ?? 0, ageMatrix.P3?.[">60 days"] ?? 0, ageMatrix.P3?.[">180 days (6+ months)"] ?? 0],
    ["P4", ageMatrix.P4?.[">7 days"] ?? 0, ageMatrix.P4?.[">30 days"] ?? 0, ageMatrix.P4?.[">60 days"] ?? 0, ageMatrix.P4?.[">180 days (6+ months)"] ?? 0],
  ]);
  colorPriorityRows(sheet, 38, 41, 1);

  executiveSectionHeader(sheet, "A44:F44", "5. Total Vulnerabilities Patched in Last Month");
  executiveTable(sheet, "A45:F49", [
    ["Metric", "Count", "Month", "Meaning", "", "Calculation"],
    ["Previous Month Open", patched.previous_month_open, patched.previous_month, "Open in previous report", "", ""],
    ["New This Month", patched.new_vulnerabilities_identified_this_month, patched.current_month, "Newly identified", "", ""],
    ["Current Month Open", patched.current_month_open, patched.current_month, "Still open now", "", ""],
    ["Patched Last Month", patched.patched_count, patched.current_month, "Closed since previous report", "", "Prev + New - Current"],
  ]);
  sheet.getRange("A49:F49").format = {
    fill: "#E2F0D9",
    font: { name: DASHBOARD_FONT, bold: true, color: "#375623", size: 10 },
    borders: { preset: "all", style: "thin", color: "#70AD47" },
  };

  executivePolish(sheet);
}

function buildMonthlySheet(sheet, dashboard, sourceLabel) {
  sheet.showGridLines = false;
  setBaseWidths(sheet, "A:L", 15);

  titleBand(sheet, "A1:L2", `${sourceLabel} Monthly Vulnerability Dashboard`, "Monthly comparison summary");

  const open = dashboard.total_open_vulnerabilities;
  const patched = dashboard.total_vulnerabilities_patched_last_month;
  kpiCard(sheet, "A4:C7", "TOTAL OPEN", open.total_open, "New + still open from earlier reports", TREND_BLUE);
  kpiCard(sheet, "D4:F7", "NEW THIS MONTH", open.new_vulnerabilities, "Identified in current report", PRIORITY_COLORS.P4);
  kpiCard(sheet, "G4:I7", "NOT CLOSED", open.not_closed_from_previous_months, "Still open from previous report", PRIORITY_COLORS.P2);
  kpiCard(sheet, "J4:L7", "PATCHED LAST MONTH", patched.patched_count, "Closed since previous report", PRIORITY_COLORS.P4);

  const discoveredTrend = dashboard.trend_discovered_last_3_months;
  const remediatedTrend = dashboard.trend_remediated_last_3_months ?? [];
  const remediatedByMonth = Object.fromEntries(remediatedTrend.map((row) => [row.month, row.remediated_count]));

  sectionTitle(sheet, "A9:C9", "Vulnerability Trend - Last 3 Months");
  table(sheet, "A10:C13", [
    ["Month", "Discovered", "Remediated"],
    ...discoveredTrend.map((row) => [
      row.month,
      row.discovered_count,
      remediatedByMonth[row.month] ?? 0,
    ]),
  ]);

  const discoveredChart = sheet.charts.add("line", sheet.getRange("A10:B13"));
  const maxDiscovered = Math.max(...discoveredTrend.map((row) => Number(row.discovered_count) || 0), 1);
  discoveredChart.title = "Vulnerabilities Discovered";
  discoveredChart.hasLegend = false;
  discoveredChart.xAxis = { axisType: "textAxis" };
  discoveredChart.yAxis = { min: 0, max: Math.ceil(maxDiscovered * 1.2), numberFormatCode: "#,##0" };
  if (discoveredChart.series.items[0]) {
    discoveredChart.series.items[0].fill = TREND_BLUE;
  }
  discoveredChart.setPosition("D9", "H19");

  const remediatedChart = sheet.charts.add("line", {
    chartType: "line",
    title: "Vulnerabilities Remediated",
    hasLegend: false,
  });
  const remediatedSeries = remediatedChart.series.add("Remediated");
  remediatedSeries.categoryFormula = "'Monthly Dashboard'!$A$11:$A$13";
  remediatedSeries.formula = "'Monthly Dashboard'!$C$11:$C$13";
  remediatedSeries.fill = PRIORITY_COLORS.P4;
  const maxRemediated = Math.max(...discoveredTrend.map((row) => Number(remediatedByMonth[row.month]) || 0), 1);
  remediatedChart.xAxis = { axisType: "textAxis" };
  remediatedChart.yAxis = { min: 0, max: Math.ceil(maxRemediated * 1.2), numberFormatCode: "#,##0" };
  remediatedChart.setPosition("I9", "L19");

  sectionTitle(sheet, "A21:L21", "Total Open Vulnerabilities by Patch Priority");
  const priorityEntries = Object.entries(dashboard.total_open_by_patch_priority);
  priorityCard(sheet, "A22:C25", "P1", priorityEntries.find(([key]) => key === "P1")?.[1] ?? 0);
  priorityCard(sheet, "D22:F25", "P2", priorityEntries.find(([key]) => key === "P2")?.[1] ?? 0);
  priorityCard(sheet, "G22:I25", "P3", priorityEntries.find(([key]) => key === "P3")?.[1] ?? 0);
  priorityCard(sheet, "J22:L25", "P4", priorityEntries.find(([key]) => key === "P4")?.[1] ?? 0);

  sectionTitle(sheet, "A27:F27", "Total Open by Age and Patch Priority");
  const ageRows = Object.entries(dashboard.total_open_by_age_and_patch_priority).map(([priority, buckets]) => [
    priority,
    buckets[">7 days"],
    buckets[">30 days"],
    buckets[">60 days"],
    buckets[">180 days (6+ months)"],
  ]);
  table(sheet, "A28:E32", [
    ["Patch Priority", ">7 days", ">30 days", ">60 days", ">180 days (6+ months)"],
    ...ageRows,
  ]);
  colorPriorityRows(sheet, 29, 32, 1);

  sectionTitle(sheet, "H27:L27", "Patched Last Month");
  table(sheet, "H28:L32", [
    ["Metric", "Count", "Month", "Meaning", ""],
    ["Previous Month Open", patched.previous_month_open, patched.previous_month, "Open in previous report", ""],
    ["New This Month", patched.new_vulnerabilities_identified_this_month, patched.current_month, "Newly identified", ""],
    ["Current Month Open", patched.current_month_open, patched.current_month, "Still open now", ""],
    ["Patched Last Month", patched.patched_count, patched.current_month, "Closed since previous report", ""],
  ]);
  highlightPatchedRow(sheet);

  monthlyPolish(sheet);
}

function buildAdhocSheet(sheet, dashboard, sourceLabel) {
  sheet.showGridLines = false;
  setBaseWidths(sheet, "A:H", 16);
  titleBand(sheet, "A1:H2", `${sourceLabel} Adhoc Vulnerability Dashboard`, "Adhoc scan summary");

  kpiCard(sheet, "A4:C7", "TOTAL VULNERABILITIES", dashboard.total_vulnerabilities, "Current upload", TREND_BLUE);

  sectionTitle(sheet, "A10:C10", "Severity Counts");
  table(sheet, "A11:B17", [
    ["Severity", "Count"],
    ...Object.entries(dashboard.severity_counts).map(([severity, count]) => [severity, count]),
  ]);
  colorSeverityRows(sheet, 12, 17);

  sectionTitle(sheet, "E10:H10", "Patch Priority Counts");
  table(sheet, "E11:F15", [
    ["Patch Priority", "Count"],
    ...Object.entries(dashboard.patch_priority_counts).map(([priority, count]) => [priority, count]),
  ]);
  colorPriorityRows(sheet, 12, 15, 5);

  sectionTitle(sheet, "A20:H20", "Top 10 Affected Assets");
  table(sheet, "A21:H31", [
    ["Asset", "Vulnerability Count", "", "", "", "", "", ""],
    ...dashboard.top_10_affected_assets.map((row) => [row.asset, row.vulnerability_count, "", "", "", "", "", ""]),
  ]);

  const assetChartData = sheet.getRange("D21:E31");
  assetChartData.values = [
    ["Asset", "Vulnerability Count"],
    ...dashboard.top_10_affected_assets.map((row) => [shortAssetLabel(row.asset), row.vulnerability_count]),
  ];
  const assetChart = sheet.charts.add("bar", assetChartData);
  assetChart.title = "Top 10 Affected Assets";
  assetChart.hasLegend = false;
  if (assetChart.series.items[0]) {
    assetChart.series.items[0].fill = TREND_BLUE;
  }
  assetChart.setPosition("D21", "H36");

  sheet.getRange("A:A").format.columnWidth = 34;
  sheet.getRange("B:B").format.columnWidth = 20;
  sheet.getRange("C:C").format.columnWidth = 6;
  sheet.getRange("D:H").format.columnWidth = 16;
  sheet.getRange("A:H").format.wrapText = true;
  sheet.freezePanes.freezeRows(2);
}

function titleBand(sheet, rangeAddress, title, subtitle) {
  const [start, end] = rangeAddress.split(":");
  const startCell = parseA1(start);
  const endCell = parseA1(end);
  const colCount = endCell.col - startCell.col + 1;

  const titleRange = sheet.getRangeByIndexes(startCell.row, startCell.col, 1, colCount);
  titleRange.merge();
  titleRange.values = [[title, ...Array(colCount - 1).fill("")]];
  titleRange.format = {
    fill: DARK_HEADER,
    font: { name: DASHBOARD_FONT, bold: true, color: "#FFFFFF", size: 18 },
    borders: { preset: "outside", style: "thin", color: HEADER_BORDER },
  };
  titleRange.format.rowHeight = 28;

  const subtitleRange = sheet.getRangeByIndexes(startCell.row + 1, startCell.col, 1, colCount);
  subtitleRange.merge();
  subtitleRange.values = [[subtitle, ...Array(colCount - 1).fill("")]];
  subtitleRange.format = {
    fill: REPORT_SURFACE,
    font: { name: DASHBOARD_FONT, color: "#1F2933", size: 10 },
    borders: { preset: "outside", style: "thin", color: STRUCTURE_BORDER },
  };
  subtitleRange.format.rowHeight = 20;
}

function kpiCard(sheet, rangeAddress, label, value, helper, color) {
  const [start, end] = rangeAddress.split(":");
  const startCell = parseA1(start);
  const endCell = parseA1(end);
  const rowCount = endCell.row - startCell.row + 1;
  const colCount = endCell.col - startCell.col + 1;
  const card = sheet.getRangeByIndexes(startCell.row, startCell.col, rowCount, colCount);
  card.format = {
    fill: softFill(color),
    font: { color: "#0F172A" },
    borders: { preset: "outside", style: "thin", color },
  };

  sheet.getRangeByIndexes(startCell.row, startCell.col, 1, colCount).merge();
  sheet.getRangeByIndexes(startCell.row, startCell.col, 1, colCount).values = [[label, ...Array(colCount - 1).fill("")]];
  sheet.getRangeByIndexes(startCell.row, startCell.col, 1, colCount).format = {
    fill: DARK_HEADER,
    font: { name: DASHBOARD_FONT, bold: true, color: "#FFFFFF", size: 9 },
    borders: { preset: "all", style: "thin", color: HEADER_BORDER },
  };

  sheet.getRangeByIndexes(startCell.row + 1, startCell.col, 2, colCount).merge();
  const valueRange = sheet.getRangeByIndexes(startCell.row + 1, startCell.col, 2, colCount);
  valueRange.values = [[value, ...Array(colCount - 1).fill("")], Array(colCount).fill("")];
  valueRange.format = {
    fill: softFill(color),
    font: { name: DASHBOARD_FONT, bold: true, color, size: 20 },
  };

  sheet.getRangeByIndexes(startCell.row + 3, startCell.col, 1, colCount).merge();
  sheet.getRangeByIndexes(startCell.row + 3, startCell.col, 1, colCount).values = [[helper, ...Array(colCount - 1).fill("")]];
  sheet.getRangeByIndexes(startCell.row + 3, startCell.col, 1, colCount).format = {
    fill: softFill(color),
    font: { name: DASHBOARD_FONT, color: "#1F2933", size: 9 },
  };
}

function priorityCard(sheet, rangeAddress, priority, count) {
  const color = priorityColor(priority);
  kpiCard(sheet, rangeAddress, `${priority} - ${priorityLabel(priority).toUpperCase()}`, count, "Total open findings", color);
}

function sectionTitle(sheet, rangeAddress, title, fill = DARK_HEADER, fontColor = "#FFFFFF") {
  const range = sheet.getRange(rangeAddress);
  range.merge();
  range.values = [[title]];
  range.format = {
    fill,
    font: { name: DASHBOARD_FONT, bold: true, color: fontColor, size: 11 },
    borders: { preset: "outside", style: "thin", color: HEADER_BORDER },
  };
  range.format.rowHeight = 21;
}

function table(sheet, rangeAddress, rows) {
  const range = sheet.getRange(rangeAddress);
  range.values = rows;
  range.format = {
    fill: REPORT_SURFACE,
    font: { name: DASHBOARD_FONT, color: "#1F2937", size: 10 },
    borders: { preset: "all", style: "thin", color: STRUCTURE_BORDER },
  };
  range.getRow(0).format = {
    fill: DARK_HEADER,
    font: { name: DASHBOARD_FONT, bold: true, color: "#FFFFFF", size: 9 },
    borders: { preset: "all", style: "thin", color: HEADER_BORDER },
  };
}

function colorPriorityRows(sheet, startRowOneBased, endRowOneBased, priorityColOneBased) {
  for (let row = startRowOneBased; row <= endRowOneBased; row += 1) {
    const priority = String(sheet.getCell(row - 1, priorityColOneBased - 1).values?.[0]?.[0] ?? "");
    const fill = priorityFill(priority);
    const font = priority === "P3" || priority === "P4" ? "#0F172A" : "#FFFFFF";
    sheet.getRangeByIndexes(row - 1, priorityColOneBased - 1, 1, 1).format = {
      fill,
      font: { name: DASHBOARD_FONT, bold: true, color: font },
      borders: { preset: "all", style: "thin", color: STRUCTURE_BORDER },
    };
  }
}

function highlightPatchedRow(sheet) {
  sheet.getRange("H32:L32").format = {
    fill: "#DCFCE7",
    font: { name: DASHBOARD_FONT, bold: true, color: "#14532D" },
    borders: { preset: "all", style: "thin", color: PRIORITY_COLORS.P4 },
  };
}

function monthlyPolish(sheet) {
  sheet.getRange("A:L").format.wrapText = true;
  sheet.getRange("A:L").format.verticalAlignment = "middle";
  sheet.getRange("A:L").format.autofitRows();
  sheet.getRange("A:A").format.columnWidth = 23;
  sheet.getRange("B:C").format.columnWidth = 15;
  sheet.getRange("D:D").format.columnWidth = 15;
  sheet.getRange("E:L").format.columnWidth = 16;
  sheet.freezePanes.freezeRows(2);
}

function setBaseWidths(sheet, columns, width) {
  sheet.getRange(columns).format.columnWidth = width;
}

function executiveTitle(sheet, rangeAddress, title) {
  const range = sheet.getRange(rangeAddress);
  range.merge();
  range.values = [[title]];
  range.format = {
    fill: DARK_HEADER,
    font: { name: DASHBOARD_FONT, bold: true, color: "#FFFFFF", size: 14 },
    horizontalAlignment: "center",
    verticalAlignment: "middle",
    borders: { preset: "outside", style: "thin", color: "#111827" },
  };
  range.format.rowHeight = 24;
}

function executiveKpiRow(sheet, cards) {
  const cardWidth = 2;
  cards.forEach(([label, value], index) => {
    const startCol = index * cardWidth;
    const labelRange = sheet.getRangeByIndexes(5, startCol, 1, cardWidth);
    labelRange.merge();
    labelRange.values = [[label, ""]];
    labelRange.format = {
      fill: DARK_HEADER,
      font: { name: DASHBOARD_FONT, bold: true, color: "#FFFFFF", size: 10 },
      horizontalAlignment: "left",
      borders: { preset: "all", style: "thin", color: "#111827" },
    };

    const valueRange = sheet.getRangeByIndexes(6, startCol, 3, cardWidth);
    valueRange.merge();
    valueRange.values = [[value, ""], ["", ""], ["", ""]];
    valueRange.format = {
      fill: "#F8FAF7",
      font: { name: DASHBOARD_FONT, bold: true, color: "#333333", size: 18 },
      horizontalAlignment: "center",
      verticalAlignment: "middle",
      borders: { preset: "all", style: "thin", color: "#4B5563" },
    };
  });
}

function executiveSectionHeader(sheet, rangeAddress, title) {
  const range = sheet.getRange(rangeAddress);
  range.merge();
  range.values = [[title]];
  range.format = {
    fill: DARK_HEADER,
    font: { name: DASHBOARD_FONT, bold: true, color: "#FFFFFF", size: 10 },
    horizontalAlignment: "left",
    verticalAlignment: "middle",
    borders: { preset: "outside", style: "thin", color: "#111827" },
  };
  range.format.rowHeight = 20;
}

function executiveTable(sheet, rangeAddress, rows) {
  const range = sheet.getRange(rangeAddress);
  range.values = rows;
  range.format = {
    fill: "#F8FAF7",
    font: { name: DASHBOARD_FONT, color: "#1F2937", size: 10 },
    borders: { preset: "all", style: "thin", color: "#4B5563" },
  };
  range.getRow(0).format = {
    fill: DARK_HEADER,
    font: { name: DASHBOARD_FONT, bold: true, color: "#FFFFFF", size: 10 },
    borders: { preset: "all", style: "thin", color: "#111827" },
  };
}

function colorSeverityRows(sheet, startRowOneBased, endRowOneBased) {
  for (let row = startRowOneBased; row <= endRowOneBased; row += 1) {
    const severity = String(sheet.getCell(row - 1, 0).values?.[0]?.[0] ?? "");
    const fill = SEVERITY_COLORS[severity] ?? SEVERITY_COLORS.Unknown;
    const font = ["Medium", "Low", "Info", "Unknown"].includes(severity) ? "#1F2937" : "#FFFFFF";
    sheet.getRangeByIndexes(row - 1, 0, 1, 1).format = {
      fill,
      font: { name: DASHBOARD_FONT, bold: true, color: font },
      borders: { preset: "all", style: "thin", color: STRUCTURE_BORDER },
    };
  }
}

function executivePolish(sheet) {
  sheet.getRange("A:A").format.columnWidth = 18;
  sheet.getRange("B:C").format.columnWidth = 12;
  sheet.getRange("D:D").format.columnWidth = 18;
  sheet.getRange("E:E").format.columnWidth = 18;
  sheet.getRange("F:F").format.columnWidth = 28;
  sheet.getRange("G:G").format.columnWidth = 20;
  sheet.getRange("H:H").format.columnWidth = 8;
  sheet.getRange("I:I").format.columnWidth = 12;
  sheet.getRange("J:J").format.columnWidth = 20;
  sheet.getRange("K:K").format.columnWidth = 18;
  sheet.getRange("L:L").format.columnWidth = 8;
  sheet.getRange("A:K").format.wrapText = true;
  sheet.freezePanes.freezeRows(3);
}

function priorityColor(priority) {
  return PRIORITY_COLORS[priority] ?? "#64748B";
}

function priorityFill(priority) {
  return PRIORITY_COLORS[priority] ?? "#CBD5E1";
}

function softFill(color) {
  return {
    [TREND_BLUE]: REPORT_SURFACE,
    [PRIORITY_COLORS.P1]: "#F4CCCC",
    [PRIORITY_COLORS.P2]: "#FCE4D6",
    [PRIORITY_COLORS.P3]: "#FFF2CC",
    [PRIORITY_COLORS.P4]: "#E2F0D9",
  }[color] ?? REPORT_SURFACE;
}

function priorityLabel(priority) {
  return {
    P1: "Immediate",
    P2: "Priority",
    P3: "Planned",
    P4: "Deferred",
  }[priority] ?? "Review";
}

function shortAssetLabel(asset) {
  const text = String(asset ?? "");
  if (!text.includes(".")) {
    return text;
  }
  return text.split(".")[0];
}

function parseA1(cell) {
  const match = /^([A-Z]+)(\d+)$/i.exec(cell);
  if (!match) {
    throw new Error(`Invalid A1 cell: ${cell}`);
  }
  const colLetters = match[1].toUpperCase();
  let col = 0;
  for (const char of colLetters) {
    col = col * 26 + char.charCodeAt(0) - 64;
  }
  return { row: Number(match[2]) - 1, col: col - 1 };
}

function parseArgs(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) continue;
    parsed[token.slice(2)] = argv[index + 1];
    index += 1;
  }
  return parsed;
}
