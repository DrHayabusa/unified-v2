export const FINDING_EXPORT_COLUMNS = [
  ["IP Address", "ipAddress"],
  ["DNS Name", "dnsName"],
  ["Asset Owner", "assetOwner"],
  ["Vulnerability Name", "vulnerabilityName"],
  ["CVE", "cve"],
  ["Severity", "severity"],
  ["Exploit?", (row) => row.exploitAvailable ? "Yes" : "No"],
  ["Patch Priority", "patchPriority"],
  ["Asset Exposure (on 1000)", "assetExposure"],
  ["Vulnerability Finding", "vulnerabilityFinding"],
  ["Summary", "summary"],
  ["Description", "description"],
  ["Remediation", "remediation"],
  ["KB Links", "kbLinks"],
  ["Platform Details", "platformDetails"],
  ["Namespace", "namespace"],
  ["Deployment", "deployment"],
  ["Image", "image"],
  ["Component", "component"],
  ["Fixable", (row) => row.fixable ? "Yes" : "No"],
  ["CVE Fixed In", "fixedIn"],
  ["CVSS", "cvssScore"],
  ["First Discovered", "firstDiscovered"],
  ["Last Observed", "lastObserved"],
];

export function* findingCsvLines(rows = []) {
  yield `\uFEFF${FINDING_EXPORT_COLUMNS.map(([header]) => csvCell(header)).join(",")}\r\n`;
  for (const row of rows) {
    yield `${FINDING_EXPORT_COLUMNS.map(([, accessor]) => csvCell(
      typeof accessor === "function" ? accessor(row) : row?.[accessor],
    )).join(",")}\r\n`;
  }
}

export function findingCsvFilename(customerSlug, reportPeriod) {
  const safe = (value, fallback) => String(value || fallback)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || fallback;
  return `mva-${safe(customerSlug, "customer")}-${safe(reportPeriod, "current")}-vulnerabilities.csv`;
}

function csvCell(value) {
  let text = value == null ? "" : value instanceof Date ? localDate(value) : String(value);
  if (/^[=+\-@]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

function localDate(value) {
  const pad = (part) => String(part).padStart(2, "0");
  return `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())}`;
}
