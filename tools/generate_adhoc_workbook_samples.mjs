import fs from "node:fs/promises";
import path from "node:path";

import { buildAnalysisWorkbook } from "../react-ui/src/lib/reportExport.js";
import { analyzeAdhocFiles } from "../react-ui/src/lib/vulnerabilityEngine.js";

const root = path.resolve(import.meta.dirname, "..");
const outputDir = path.join(root, "final", "Excel", "Adhoc");
const cases = [
  ["tenable-sc", "Tenable_SC", "samples/tenable_100_row/tenable_sc_july_2026_100plus.csv"],
  ["tenable-io", "Tenable_IO", "samples/tenable_100_row/tenable_io_july_2026_100plus.csv"],
  ["qualys", "Qualys", "samples/qualys_100_row/qualys_adhoc_july_2026_100plus.csv"],
  ["crowdstrike", "CrowdStrike", "samples/crowdstrike_100_row/crowdstrike_vulnerabilities_july_2026_100plus.csv"],
];

await fs.mkdir(outputDir, { recursive: true });

for (const [sourceId, outputName, relativePath] of cases) {
  const filePath = path.join(root, relativePath);
  const file = new Blob([await fs.readFile(filePath)], { type: "text/csv" });
  Object.defineProperty(file, "name", { value: path.basename(filePath) });
  const analysis = await analyzeAdhocFiles([file], sourceId);
  const workbook = await buildAnalysisWorkbook(analysis);
  const outputPath = path.join(outputDir, `MVA_${outputName}_Adhoc_Report.xlsx`);
  await workbook.xlsx.writeFile(outputPath);
  console.log(`${outputPath}\t${analysis.findings.length} findings`);
}
