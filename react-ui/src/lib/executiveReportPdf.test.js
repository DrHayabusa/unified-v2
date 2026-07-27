import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { buildExecutiveReportModel, createExecutiveDashboardPdfDocument } from "./executiveReportPdf.js";
import { analyzeAdhocFiles, analyzeMonthlyFiles } from "./vulnerabilityEngine.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

test("monthly executive report model reconciles the selected period and required dashboard measures", async () => {
  const files = await Promise.all(["april", "may", "june", "july"].map((month) => localFile(
    path.join(root, "samples", "openshift_100_row", `openshift_${month}_2026_100plus.csv`),
  )));
  const analysis = await analyzeMonthlyFiles(files, "openshift");
  const model = buildExecutiveReportModel(analysis, "July 2026");

  assert.equal(model.totalOpen, 140);
  assert.equal(model.movement.previousOpen, 130);
  assert.equal(model.movement.newFindings, 30);
  assert.equal(model.movement.carried, 110);
  assert.equal(model.movement.patched, 20);
  assert.deepEqual(model.priorityCounts, { P1: 0, P2: 71, P3: 46, P4: 23 });
  assert.deepEqual(model.trend.map((row) => row.remediated), [20, 15, 20]);
  assert.ok(model.ageMatrix.P2[">180 days"] > 0);
  assert.equal(model.openshift.fixable, 112);

  const pdf = await createExecutiveDashboardPdfDocument({ analysis, targetPeriod: "July 2026" });
  const bytes = Buffer.from(pdf.output("arraybuffer"));
  assert.equal(bytes.subarray(0, 4).toString(), "%PDF");
  assert.ok(pdf.internal.pageSize.getWidth() > pdf.internal.pageSize.getHeight());
  assert.ok(pdf.getNumberOfPages() >= 7);
});

test("ad hoc executive report remains valid without invented historical movement", async () => {
  const file = await localFile(path.join(root, "samples", "qualys_100_row", "qualys_adhoc_july_2026_100plus.csv"));
  const analysis = await analyzeAdhocFiles([file], "qualys");
  const model = buildExecutiveReportModel(analysis, analysis.reportMonth);

  assert.equal(model.movement.comparable, false);
  assert.equal(model.movement.newFindings, 0);
  assert.equal(model.movement.patched, 0);
  assert.equal(model.movement.carried, model.totalOpen);

  const pdf = await createExecutiveDashboardPdfDocument({ analysis, targetPeriod: analysis.reportMonth });
  assert.ok(pdf.getNumberOfPages() >= 6);
});

async function localFile(filePath) {
  const content = await readFile(filePath);
  return {
    name: path.basename(filePath),
    size: content.length,
    text: async () => content.toString("utf8"),
    arrayBuffer: async () => content.buffer.slice(content.byteOffset, content.byteOffset + content.byteLength),
  };
}
