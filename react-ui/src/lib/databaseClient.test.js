import assert from "node:assert/strict";
import test from "node:test";

import { analysisIngestionKey, fetchScanHistory, persistenceFindings } from "./databaseClient.js";

test("monthly persistence retains every uploaded period", () => {
  const analysis = {
    workflow: "monthly",
    snapshots: [
      { month: "June 2026", findings: [{ findingKey: "a", severity: "High", patchPriority: "P2" }] },
      { month: "July 2026", findings: [{ findingKey: "b", severity: "Critical", patchPriority: "P1" }] },
    ],
  };
  assert.deepEqual(persistenceFindings(analysis).map((finding) => finding.reportPeriod), ["June 2026", "July 2026"]);
});

test("ingestion key is stable and changes with finding identity", async () => {
  const analysis = { workflow: "adhoc", sourceTool: "tenable-sc", reportMonth: "July 2026", fileNames: ["scan.csv"] };
  const first = [{ findingKey: "asset|cve|tcp|443", recordCount: 1, severity: "High", patchPriority: "P2", reportPeriod: "July 2026" }];
  const same = await analysisIngestionKey(analysis, first);
  assert.equal(await analysisIngestionKey(analysis, first), same);
  assert.notEqual(await analysisIngestionKey(analysis, [{ ...first[0], findingKey: "asset|other|tcp|443" }]), same);
});

test("scan history is fetched from the selected customer boundary", async () => {
  let captured;
  const fetchImpl = async (url, options) => {
    captured = { url, options };
    return { ok: true, json: async () => ({ runs: [] }) };
  };
  await fetchScanHistory({ customerId: "11111111-1111-4111-8111-111111111111", fetchImpl });
  assert.match(captured.url, /customers\/11111111-1111-4111-8111-111111111111\/scan-runs/);
  assert.equal(captured.options.credentials, "include");
  assert.equal(captured.options.headers["X-MVA-Tenant"], undefined);
});
