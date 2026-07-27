import assert from "node:assert/strict";
import test from "node:test";

import { buildCustomerValueInsights } from "./customerInsights.js";

test("customer insights calculate report dates without overflowing on 80,000 findings", () => {
  const findings = Array.from({ length: 80_000 }, (_, index) => ({
    findingKey: `finding-${index}`,
    ipAddress: `10.20.${Math.floor(index / 250) % 250}.${index % 250}`,
    vulnerabilityName: `Synthetic vulnerability ${index}`,
    severity: "Low",
    patchPriority: "P4",
    firstDiscovered: "2026-01-01T00:00:00Z",
    lastObserved: index === 79_999 ? "2026-07-31T23:59:59Z" : "2026-07-01T00:00:00Z",
  }));

  const insights = buildCustomerValueInsights(findings);

  assert.equal(insights.dataQuality.totalFindings, 80_000);
  assert.equal(insights.dataQuality.staleObservations, 79_999);
});
