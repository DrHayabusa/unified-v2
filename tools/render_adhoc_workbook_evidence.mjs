import fs from "node:fs/promises";
import path from "node:path";

import { FileBlob, SpreadsheetFile } from "@oai/artifact-tool";

const root = path.resolve(import.meta.dirname, "..");
const inputDir = path.join(root, "final", "Excel", "Adhoc");
const outputDir = path.join(root, "output", "validation", "adhoc-workbooks");
const requestedSource = process.argv[2];
const sources = requestedSource ? [requestedSource] : ["Tenable_SC", "Tenable_IO", "Qualys", "CrowdStrike"];

await fs.mkdir(outputDir, { recursive: true });

for (const source of sources) {
  const inputPath = path.join(inputDir, `MVA_${source}_Adhoc_Report.xlsx`);
  const workbook = await SpreadsheetFile.importXlsx(await FileBlob.load(inputPath));
  const dashboard = await workbook.inspect({
    kind: "table",
    sheetId: "Adhoc Report",
    range: "A1:L31",
    include: "values,formulas",
    tableMaxRows: 31,
    tableMaxCols: 12,
    maxChars: 12000,
  });
  const errors = await workbook.inspect({
    kind: "match",
    searchTerm: "#REF!|#DIV/0!|#VALUE!|#NAME\\?|#N/A",
    options: { useRegex: true, maxResults: 100 },
    summary: `${source} Adhoc formula error scan`,
  });
  const preview = await workbook.render({
    sheetName: "Adhoc Report",
    range: "A1:L31",
    scale: 1.5,
    format: "png",
  });
  const dataPreview = await workbook.render({
    sheetName: "Report Data",
    range: "A1:Q12",
    scale: 1,
    format: "png",
  });
  await fs.writeFile(path.join(outputDir, `${source.toLowerCase()}-adhoc-dashboard.png`), new Uint8Array(await preview.arrayBuffer()));
  await fs.writeFile(path.join(outputDir, `${source.toLowerCase()}-report-data.png`), new Uint8Array(await dataPreview.arrayBuffer()));
  await fs.writeFile(path.join(outputDir, `${source.toLowerCase()}-dashboard.inspect.ndjson`), dashboard.ndjson);
  await fs.writeFile(path.join(outputDir, `${source.toLowerCase()}-formula-errors.inspect.ndjson`), errors.ndjson);
}

console.log(outputDir);
