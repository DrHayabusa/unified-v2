import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { FileBlob, SpreadsheetFile } from "@oai/artifact-tool";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const inputRoot = path.join(root, "final", "Production Evidence");
const outputRoot = path.join(root, "ss", "final-evidence", "workbooks");
const sources = ["Tenable_SC", "Tenable_IO", "Qualys", "Custom_Qualys", "CrowdStrike", "OpenShift"];
const results = [];
const previewSheets = {
  Monthly: [
    ["Cover Page", "A1:L32", "cover"],
    ["Executive Dashboard", "A1:L40", "executive-dashboard"],
    ["Monthly Report", "A1:L41", "monthly-report"],
    ["Briefing", "A1:L35", "briefing"],
    ["Top Vulnerable Assets", "A1:L22", "top-assets"],
    ["Top Vulnerabilities", "A1:L22", "top-vulnerabilities"],
  ],
  Adhoc: [
    ["Cover Page", "A1:L32", "cover"],
    ["Executive Dashboard", "A1:L40", "executive-dashboard"],
    ["Adhoc Report", "A1:L31", "adhoc-report"],
    ["Top Vulnerable Assets", "A1:L22", "top-assets"],
    ["Top Vulnerabilities", "A1:L22", "top-vulnerabilities"],
  ],
};

await fs.mkdir(outputRoot, { recursive: true });

for (const source of sources) {
  for (const workflow of ["Monthly", "Adhoc"]) {
    const filePath = path.join(inputRoot, source, `MVA_${source}_${workflow}_Report.xlsx`);
    const workbook = await SpreadsheetFile.importXlsx(await FileBlob.load(filePath));
    const errors = await workbook.inspect({
      kind: "match",
      searchTerm: "#REF!|#DIV/0!|#VALUE!|#NAME\\?|#N/A",
      options: { useRegex: true, maxResults: 100 },
      summary: `${source} ${workflow} formula error scan`,
    });
    const fileStem = `${source.toLowerCase()}-${workflow.toLowerCase()}`;
    await fs.writeFile(path.join(outputRoot, `${fileStem}-formula-errors.inspect.ndjson`), errors.ndjson);
    const previews = [];
    for (const [sheetName, range, slug] of previewSheets[workflow]) {
      const inspect = await workbook.inspect({
        kind: "table",
        sheetId: sheetName,
        range,
        include: "values,formulas",
        tableMaxRows: Number(range.match(/\d+$/)?.[0] || 40),
        tableMaxCols: 12,
        maxChars: 16000,
      });
      const preview = await workbook.render({
        sheetName,
        range,
        scale: 1.35,
        format: "png",
      });
      const previewPath = path.join(outputRoot, `${fileStem}-${slug}.png`);
      await fs.writeFile(previewPath, new Uint8Array(await preview.arrayBuffer()));
      await fs.writeFile(path.join(outputRoot, `${fileStem}-${slug}.inspect.ndjson`), inspect.ndjson);
      previews.push(path.relative(root, previewPath));
    }
    results.push({
      source,
      workflow,
      previews,
      formulaErrorMatches: countInspectRecords(errors.ndjson),
    });
  }
}

await fs.writeFile(
  path.join(outputRoot, "render_manifest.json"),
  `${JSON.stringify({ status: results.every((result) => result.formulaErrorMatches === 0) ? "PASS" : "FAIL", results }, null, 2)}\n`,
);
process.stdout.write(`${JSON.stringify({ outputRoot, results }, null, 2)}\n`);

function countInspectRecords(ndjson) {
  const lines = String(ndjson || "").split(/\r?\n/).filter((line) => line.trim());
  if (lines.some((line) => line.includes("matched 0 entries"))) return 0;
  return lines.filter((line) => line.includes('"kind":"match"')).length;
}
