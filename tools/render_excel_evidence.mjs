import fs from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { FileBlob, SpreadsheetFile } from "@oai/artifact-tool";

const root = path.resolve(import.meta.dirname, "..");
const outputDir = path.join(root, "output", "validation", "excel-evidence");

const workbooks = [
  {
    id: "tenable-sc",
    source: path.join(root, "output", "excel", "mva_tenable_sc_final_team_sample.xlsx"),
    sheets: [
      ["Executive Dashboard", "tenable-sc-executive-dashboard.png", "A1:L52"],
      ["Monthly Dashboard", "tenable-sc-monthly-dashboard.png", "A1:L32"],
      ["Adhoc Dashboard", "tenable-sc-adhoc-dashboard.png", "A1:H36"],
    ],
  },
  {
    id: "tenable-io",
    source: path.join(root, "output", "excel", "mva_tenable_io_final_team_sample.xlsx"),
    sheets: [
      ["Executive Dashboard", "tenable-io-executive-dashboard.png", "A1:L52"],
      ["Monthly Dashboard", "tenable-io-monthly-dashboard.png", "A1:L32"],
      ["Adhoc Dashboard", "tenable-io-adhoc-dashboard.png", "A1:H36"],
    ],
  },
  {
    id: "qualys",
    source: path.join(root, "output", "excel", "mva_qualys_final_team_sample.xlsx"),
    sheets: [
      ["Executive Dashboard", "qualys-executive-dashboard.png", "A1:L52"],
      ["Monthly Dashboard", "qualys-monthly-dashboard.png", "A1:L32"],
      ["Adhoc Dashboard", "qualys-adhoc-dashboard.png", "A1:H36"],
    ],
  },
  {
    id: "crowdstrike",
    source: path.join(root, "output", "excel", "mva_crowdstrike_final_team_sample.xlsx"),
    sheets: [
      ["Executive Dashboard", "crowdstrike-executive-dashboard.png", "A1:L52"],
      ["Monthly Dashboard", "crowdstrike-monthly-dashboard.png", "A1:L32"],
      ["Adhoc Dashboard", "crowdstrike-adhoc-dashboard.png", "A1:H36"],
    ],
  },
];

const requestedId = process.argv[2];
const requestedSheetName = process.argv[3];

// Artifact rendering can leak canvas state between sheets, so the default run
// isolates every sheet in its own process for deterministic evidence images.
if (!requestedId) {
  for (const workbook of workbooks) {
    for (const [sheetName] of workbook.sheets) {
      const result = spawnSync(
        process.execPath,
        [fileURLToPath(import.meta.url), workbook.id, sheetName],
        { stdio: "inherit" },
      );
      if (result.status !== 0) {
        throw new Error(`Rendering failed for ${workbook.id}: ${sheetName}`);
      }
    }
  }
  console.log(outputDir);
  process.exit(0);
}

const selectedWorkbooks = requestedId
  ? workbooks.filter((workbook) => workbook.id === requestedId)
  : workbooks;

if (requestedId && selectedWorkbooks.length === 0) {
  throw new Error(`Unknown workbook id: ${requestedId}`);
}

await fs.mkdir(outputDir, { recursive: true });

for (const item of selectedWorkbooks) {
  const input = await FileBlob.load(item.source);
  const workbook = await SpreadsheetFile.importXlsx(input);

  const selectedSheets = requestedSheetName
    ? item.sheets.filter(([sheetName]) => sheetName === requestedSheetName)
    : item.sheets;
  if (requestedSheetName && selectedSheets.length === 0) {
    throw new Error(`Unknown sheet for ${item.id}: ${requestedSheetName}`);
  }

  for (const [sheetName, filename, range] of selectedSheets) {
    const preview = await workbook.render({
      sheetName,
      range,
      scale: 1.25,
      format: "png",
    });
    await fs.writeFile(
      path.join(outputDir, filename),
      new Uint8Array(await preview.arrayBuffer()),
    );
  }
}

console.log(outputDir);
