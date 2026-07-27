import Papa from "papaparse";

const monthlySamples = {
  "tenable-sc": ["april", "may", "june", "july"].map((month) => `sample-data/tenable-sc/tenable_sc_${month}_2026_100plus.csv`),
  "tenable-io": ["april", "may", "june", "july"].map((month) => `sample-data/tenable-io/tenable_io_${month}_2026_100plus.csv`),
  qualys: ["april", "may", "june", "july"].map((month) => `sample-data/qualys/qualys_monthly_${month}_2026_100plus.csv`),
  "custom-qualys": ["april", "may", "june", "july"].map((month) => `sample-data/custom-qualys/custom_qualys_monthly_${month}_2026.csv`),
  "custom-csv": ["april", "may", "june", "july"].map((month) => `sample-data/custom-csv/generic_scanner_${month}_2026.csv`),
  openshift: ["april", "may", "june", "july"].map((month) => `sample-data/openshift/openshift_${month}_2026_100plus.csv`),
};

const crowdStrikeMonthlySamples = {
  vulnerabilities: ["april", "may", "june", "july"].map((month) => `sample-data/crowdstrike/crowdstrike_vulnerabilities_${month}_2026_100plus.csv`),
  // Both detailed exports share the supported per-finding schema in this test pack.
  "vulnerability-per-asset": ["april", "may", "june", "july"].map((month) => `sample-data/crowdstrike/crowdstrike_vulnerabilities_${month}_2026_100plus.csv`),
};

const adhocSamples = {
  "tenable-sc": "sample-data/tenable-sc/tenable_sc_july_2026_100plus.csv",
  "tenable-io": "sample-data/tenable-io/tenable_io_july_2026_100plus.csv",
  qualys: "sample-data/qualys/qualys_adhoc_july_2026_100plus.csv",
  "custom-qualys": "sample-data/custom-qualys/custom_qualys_adhoc_july_2026.csv",
  "custom-csv": "sample-data/custom-csv/generic_scanner_july_2026.csv",
  crowdstrike: "sample-data/crowdstrike/crowdstrike_vulnerability_per_asset_july_2026_100plus.csv",
  openshift: "sample-data/openshift/openshift_july_2026_100plus.csv",
};

export async function loadBundledSamples(sourceId, workflow, crowdStrikeVariant = "vulnerability-per-asset") {
  const comparisonWorkflow = workflow === "monthly" || workflow === "quarterly";
  let paths = comparisonWorkflow ? monthlySamples[sourceId] : [adhocSamples[sourceId]];
  if (comparisonWorkflow && sourceId === "crowdstrike") {
    paths = crowdStrikeMonthlySamples[crowdStrikeVariant] ?? crowdStrikeMonthlySamples["vulnerability-per-asset"];
  }
  if (workflow === "adhoc" && sourceId === "crowdstrike") {
    const variants = {
      vulnerabilities: "sample-data/crowdstrike/crowdstrike_vulnerabilities_july_2026_100plus.csv",
      "vulnerability-per-asset": "sample-data/crowdstrike/crowdstrike_vulnerability_per_asset_july_2026_100plus.csv",
      "remediation-per-assets": "sample-data/crowdstrike/crowdstrike_remediation_per_assets_july_2026_100plus.csv",
    };
    paths = [variants[crowdStrikeVariant] ?? variants["vulnerability-per-asset"]];
  }
  if (!paths?.every(Boolean)) throw new Error(`No bundled sample is available for ${sourceId}.`);

  return Promise.all(paths.map(async (path) => {
    const url = `${import.meta.env.BASE_URL}${path}`;
    const response = await fetch(url);
    if (!response.ok) throw new Error(`Sample download failed with HTTP ${response.status}: ${path}`);
    const blob = await response.blob();
    const sourceName = path.split("/").at(-1);
    let fileName = comparisonWorkflow && sourceId === "crowdstrike" && crowdStrikeVariant === "vulnerability-per-asset"
      ? sourceName.replace("crowdstrike_vulnerabilities_", "crowdstrike_vulnerability_per_asset_")
      : sourceName;
    if (workflow !== "quarterly") return new File([blob], fileName, { type: "text/csv" });

    const index = paths.indexOf(path);
    const quarter = index + 1;
    const text = shiftSampleDatesToQuarter(await blob.text());
    fileName = fileName.replace(/(?:april|may|june|july)_2026/i, `q${quarter}_2026`);
    return new File([text], fileName, { type: "text/csv" });
  }));
}

export async function loadUnifiedBundledSamples(sourceIds, workflow) {
  const normalizedWorkflow = workflow === "quarterly-scan" ? "adhoc" : workflow;
  const sampleGroups = await Promise.all(
    Array.from(sourceIds ?? []).map(async (sourceId) => {
      const files = await loadBundledSamples(sourceId, normalizedWorkflow, "vulnerability-per-asset");
      return Promise.all(files.map(async (file) => new File(
        [diversifyUnifiedSampleText(await file.text(), sourceId)],
        file.name,
        { type: file.type || "text/csv" },
      )));
    }),
  );
  return sampleGroups.flat();
}

// Unified demos retain shared detections while adding stable scanner-only findings.
// This affects bundled samples only; uploaded customer exports are never modified.
export function diversifyUnifiedSampleText(text, sourceId) {
  if (!text || !["tenable-io", "qualys"].includes(sourceId)) return text;

  const parsed = Papa.parse(text, { header: true, skipEmptyLines: true });
  if (!parsed.meta.fields?.length || parsed.errors.some((error) => error.type === "Quotes")) {
    throw new Error(`The bundled ${sourceId} sample could not be prepared for unified analysis.`);
  }

  const rows = parsed.data.map((row) => {
    const identity = sampleFindingIdentity(row, sourceId);
    const scannerBucket = stableHash(identity) % 4;
    const shouldDiversify = (sourceId === "tenable-io" && scannerBucket === 0)
      || (sourceId === "qualys" && scannerBucket === 1);
    if (!shouldDiversify) return row;

    const diversified = { ...row };
    if (sourceId === "tenable-io") {
      for (const field of ["asset.display_fqdn", "asset.host_name", "asset.name", "asset.netbios_name"]) {
        diversified[field] = prefixSampleIdentity(diversified[field], "io-only");
      }
      for (const field of ["asset.display_ipv4_address", "asset.ipv4_addresses", "scan.target"]) {
        diversified[field] = replaceSubnet(diversified[field], "10.20.", "10.21.");
      }
    } else {
      for (const field of ["DNS", "FQDN", "NetBIOS"]) {
        diversified[field] = prefixSampleIdentity(diversified[field], "qualys-only");
      }
      diversified.IP = replaceSubnet(diversified.IP, "10.30.", "10.31.");
    }
    return diversified;
  });

  return Papa.unparse(rows, { columns: parsed.meta.fields, newline: "\r\n" });
}

function sampleFindingIdentity(row, sourceId) {
  const fields = sourceId === "tenable-io"
    ? [row["asset.display_fqdn"], row["definition.cve"] || row["definition.name"], row.protocol, row.port]
    : [row.FQDN || row.DNS, row["CVE ID"] || row.Title, row.Protocol, row.Port];
  return fields.map((value) => String(value ?? "").trim().toLowerCase()).join("|");
}

function stableHash(value) {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function prefixSampleIdentity(value, prefix) {
  const normalized = String(value ?? "").trim();
  if (!normalized || normalized.toLowerCase().startsWith(`${prefix}-`)) return normalized;
  return `${prefix}-${normalized}`;
}

function replaceSubnet(value, originalSubnet, sampleSubnet) {
  return String(value ?? "").split(originalSubnet).join(sampleSubnet);
}

function shiftSampleDatesToQuarter(text) {
  const targetMonths = { "04": 3, "05": 6, "06": 9, "07": 12 };
  return text.replace(/2026-(04|05|06|07)-(\d{2})/g, (_match, sourceMonth, dayText) => {
    const month = targetMonths[sourceMonth];
    const maxDay = new Date(Date.UTC(2026, month, 0)).getUTCDate();
    const day = Math.min(Number(dayText), maxDay);
    return `2026-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
  });
}
