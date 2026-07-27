import assert from "node:assert/strict";
import test from "node:test";

import { buildLocalThreatIntel, buildThreatIntelPrompt, parseThreatIntelResponse } from "./threatIntel.js";

const findings = [
  { vulnerabilityName: "Apache Log4j Remote Code Execution", cve: "CVE-2021-44228", severity: "Critical", patchPriority: "P1", exploitAvailable: true, dnsName: "app-01", product: "Apache Log4j", remediation: "Upgrade to a vendor-supported fixed release.", kbLinks: "https://logging.apache.org/log4j/2.x/security.html", firstDiscovered: "2026-01-05", lastObserved: "2026-07-01", recordCount: 1 },
  { vulnerabilityName: "Apache Log4j Remote Code Execution", cve: "CVE-2021-44228", severity: "Critical", patchPriority: "P1", exploitAvailable: true, dnsName: "app-02", product: "Apache Log4j", remediation: "Upgrade to a vendor-supported fixed release.", kbLinks: "https://logging.apache.org/log4j/2.x/security.html", firstDiscovered: "2026-02-05", lastObserved: "2026-07-02", recordCount: 2 },
];

test("local threat intelligence aggregates matching normalized findings", () => {
  const intel = buildLocalThreatIntel({ workflow: "adhoc", sourceLabel: "Tenable.sc", findings }, "CVE-2021-44228");
  assert.equal(intel.matchedFindings, 3);
  assert.equal(intel.affectedAssetCount, 2);
  assert.equal(intel.exploitAvailable, true);
  assert.deepEqual(intel.patchPriorities, { P1: 3 });
  assert.deepEqual(intel.references, ["https://logging.apache.org/log4j/2.x/security.html"]);
});

test("threat intelligence prompt requires evidence and structured output", () => {
  const prompt = buildThreatIntelPrompt("Log4Shell", { highestSeverity: "Critical" });
  assert.match(prompt, /valid JSON object only/);
  assert.match(prompt, /Never invent/);
  assert.match(prompt, /Local scanner context/);
});

test("AI threat intelligence JSON is normalized safely", () => {
  const intel = parseThreatIntelResponse('```json\n{"summary":"Known issue","severity":"High","references":["https://example.com/advisory"]}\n```', "AI");
  assert.equal(intel.summary, "Known issue");
  assert.equal(intel.highestSeverity, "High");
  assert.deepEqual(intel.references, ["https://example.com/advisory"]);
});

test("structured NVIDIA patch and reference objects remain readable", () => {
  const intel = parseThreatIntelResponse(JSON.stringify({
    summary: "Known issue",
    patches: [{ name: "Apache Log4j", version: "2.17.1", url: "https://logging.apache.org/log4j/2.x/security.html" }],
    references: [{ title: "Apache advisory", url: "https://logging.apache.org/log4j/2.x/security.html" }],
  }), "NVIDIA");
  assert.deepEqual(intel.patches, ["Apache Log4j - 2.17.1 - https://logging.apache.org/log4j/2.x/security.html"]);
  assert.deepEqual(intel.references, ["https://logging.apache.org/log4j/2.x/security.html"]);
  assert.doesNotMatch(intel.patches[0], /\[object Object\]/);
});
