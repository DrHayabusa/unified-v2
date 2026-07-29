const WORKFLOWS = new Set(["adhoc", "monthly", "quarterly", "quarterly-scan"]);
const SEVERITIES = new Set(["Critical", "High", "Medium", "Low", "Info", "Unknown"]);
const PRIORITIES = new Set(["P1", "P2", "P3", "P4"]);
export const ASSET_TYPES = ["Network Device", "Linux Server", "Windows Server", "Endpoint", "Database", "Cloud Asset", "Security Appliance", "Virtualization Host", "Container Platform", "OT Device", "Other"];

export function tenantFromRequest(request) {
  return cleanText(request.headers["x-mva-tenant"] || "local", 120) || "local";
}

export function normalizeCreatePayload(payload = {}) {
  const expectedFindings = positiveInteger(payload.expectedFindings);
  const expectedChunks = positiveInteger(payload.expectedChunks);
  const workflow = cleanText(payload.workflow, 40).toLowerCase();
  const ingestionKey = cleanText(payload.ingestionKey, 128);
  if (!WORKFLOWS.has(workflow)) throw badRequest("Unsupported workflow.");
  if (!ingestionKey || !/^[a-zA-Z0-9:_-]+$/.test(ingestionKey)) throw badRequest("A valid ingestion key is required.");
  if (!expectedFindings || !expectedChunks) throw badRequest("Expected findings and chunks must be positive integers.");
  return {
    customerName: cleanText(payload.customerName, 180) || "Local Organization",
    ingestionKey,
    workflow,
    sourceTool: cleanText(payload.sourceTool, 80) || "unknown",
    sourceLabel: cleanText(payload.sourceLabel, 180) || "Unknown source",
    reportPeriod: cleanText(payload.reportPeriod, 120) || "Unspecified period",
    fileNames: cleanStringArray(payload.fileNames, 120, 500),
    sourceIds: cleanStringArray(payload.sourceIds, 20, 80),
    expectedFindings,
    expectedChunks,
    dashboard: plainObject(payload.dashboard),
    inputSummary: plainObject(payload.inputSummary),
  };
}

export function normalizeChunkPayload(payload = {}, expectedFindings) {
  const chunkIndex = nonNegativeInteger(payload.chunkIndex);
  const startIndex = nonNegativeInteger(payload.startIndex);
  if (chunkIndex == null || startIndex == null) throw badRequest("Chunk index and start index must be non-negative integers.");
  if (!Array.isArray(payload.findings) || payload.findings.length < 1 || payload.findings.length > 1000) {
    throw badRequest("Each chunk must contain between 1 and 1,000 findings.");
  }
  if (startIndex + payload.findings.length > expectedFindings) throw badRequest("Chunk exceeds the declared finding count.");
  return {
    chunkIndex,
    startIndex,
    findings: payload.findings.map((finding, offset) => normalizeFinding(finding, startIndex + offset)),
  };
}

export function normalizeFinding(finding = {}, rowIndex = 0) {
  const severity = SEVERITIES.has(finding.severity) ? finding.severity : "Unknown";
  const patchPriority = PRIORITIES.has(finding.patchPriority) ? finding.patchPriority : "P4";
  const recordCount = positiveInteger(finding.recordCount) || 1;
  const sourceTools = cleanStringArray(finding.sourceTools, 20, 80);
  const assetKey = cleanText(finding.assetKey, 4000);
  const findingKey = canonicalFindingKey(finding, assetKey);
  return {
    rowIndex,
    reportPeriod: cleanText(finding.reportPeriod, 120) || "Unspecified period",
    reportPeriodDate: reportPeriodDate(finding.reportPeriod),
    findingKey: findingKey || `row-${rowIndex}`,
    sourceTool: cleanText(finding.sourceTool, 80) || "unknown",
    sourceTools: sourceTools.length ? sourceTools : [cleanText(finding.sourceTool, 80) || "unknown"],
    sourceDisplay: cleanText(finding.sourceDisplay, 500),
    sourceVulnerabilityId: cleanText(finding.sourceVulnerabilityId, 500),
    assetKey,
    ipAddress: cleanText(finding.ipAddress, 500),
    dnsName: cleanText(finding.dnsName, 1000),
    vulnerabilityName: cleanText(finding.vulnerabilityName, 4000),
    cve: cleanText(finding.cve, 2000),
    severity,
    exploitAvailable: Boolean(finding.exploitAvailable),
    exploitSignal: cleanText(finding.exploitSignal, 4000),
    epssScore: probability(finding.epssScore),
    patchPriority,
    assetExposure: boundedInteger(finding.assetExposure, 0, 1000, 0),
    vulnerabilityFinding: cleanText(finding.vulnerabilityFinding, 100_000),
    summary: cleanText(finding.summary, 20_000),
    description: cleanText(finding.description, 200_000),
    remediation: cleanText(finding.remediation, 200_000),
    kbLinks: cleanText(finding.kbLinks, 20_000),
    platformDetails: cleanText(finding.platformDetails, 20_000),
    firstDiscovered: isoDate(finding.firstDiscovered),
    lastObserved: isoDate(finding.lastObserved),
    vulnerabilityAgeDays: nullableNonNegativeInteger(finding.vulnerabilityAgeDays),
    protocol: cleanText(finding.protocol, 100),
    port: cleanText(finding.port, 100),
    recordCount,
    datacentre: cleanText(finding.datacentre, 1000),
    timesDetected: positiveInteger(finding.timesDetected) || 1,
    vendorSeverityLabel: cleanText(finding.vendorSeverityLabel, 1000),
    vulnerabilityStatus: cleanText(finding.status || finding.vulnerabilityStatus, 1000),
    vulnerabilityConfidence: cleanText(finding.vulnerabilityConfidence, 1000),
    exploitEvidenceSource: cleanText(finding.exploitEvidenceSource, 1000),
    threat: cleanText(finding.threat, 20_000),
    impact: cleanText(finding.impact, 20_000),
    product: cleanText(finding.product, 4000),
    assetCriticality: cleanText(finding.assetCriticality, 1000),
    internetExposed: Boolean(finding.internetExposed),
    internetExposureKnown: Boolean(finding.internetExposureKnown),
    cisaKev: Boolean(finding.cisaKev),
    namespace: cleanText(finding.namespace, 1000),
    deployment: cleanText(finding.deployment, 1000),
    image: cleanText(finding.image, 4000),
    component: cleanText(finding.component, 4000),
    fixable: Boolean(finding.fixable),
    fixableSignal: cleanText(finding.fixableSignal, 1000),
    fixedIn: cleanText(finding.fixedIn, 4000),
    cvssScore: nullableBoundedNumber(finding.cvssScore, 0, 10),
    payload: jsonSafe(finding),
  };
}

function canonicalFindingKey(finding, assetKey = "") {
  const ipAddress = normalizeIdentity(finding.ipAddress);
  const dnsName = normalizeDns(finding.dnsName);
  const workload = normalizeIdentity(
    assetKey
      || [finding.namespace, finding.deployment, finding.image].map((value) => cleanText(value, 4000)).filter(Boolean).join("/"),
  );
  const assetIdentity = ipAddress
    ? `ip:${ipAddress}`
    : dnsName
      ? `dns:${dnsName}`
      : workload
        ? `asset:${workload}`
        : "unknown-asset";
  const sourceId = normalizeIdentity(finding.sourceVulnerabilityId);
  const cve = cleanText(finding.cve, 2000).match(/CVE-\d{4}-\d{4,}/i)?.[0]?.toLowerCase();
  const vulnerabilityIdentity = sourceId
    ? `source:${sourceId}`
    : cve
      ? `cve:${cve}`
      : `name:${normalizeIdentity(finding.vulnerabilityName || finding.summary) || "unknown-vulnerability"}`;
  return buildFindingKey(assetIdentity, vulnerabilityIdentity);
}

function buildFindingKey(...parts) {
  const text = parts.map((part) => cleanText(part, 4000).toLowerCase()).join("|");
  let hash = 2166136261;
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}

function normalizeIdentity(value) {
  return cleanText(value, 4000)
    .toLowerCase()
    .replace(/[^a-z0-9.:_-]+/g, " ")
    .trim()
    .replace(/\s+/g, " ");
}

function normalizeDns(value) {
  return normalizeIdentity(value).replace(/\.+$/, "");
}

export function normalizeCustomerPayload(payload = {}) {
  const name = cleanText(payload.name, 180);
  const requestedSlug = cleanText(payload.slug, 120).toLowerCase();
  const slug = (requestedSlug || name)
    .normalize("NFKD")
    .replace(/[^a-zA-Z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .toLowerCase()
    .slice(0, 80);
  const assetScopeMode = payload.assetScopeMode === "inventory" ? "inventory" : "observed";
  const status = payload.status === "inactive" ? "inactive" : "active";
  if (name.length < 2) throw badRequest("Customer name must contain at least two characters.");
  if (!slug) throw badRequest("A valid customer identifier is required.");
  return { name, slug, assetScopeMode, status, notes: cleanText(payload.notes, 4000) };
}

export function normalizeTeamPayload(payload = {}) {
  const name = cleanText(payload.name, 180);
  const requestedCode = cleanText(payload.code, 80).toLowerCase();
  const code = (requestedCode || name).normalize("NFKD").replace(/[^a-zA-Z0-9]+/g, "-").replace(/^-+|-+$/g, "").toLowerCase().slice(0, 60);
  if (name.length < 2) throw badRequest("Team name must contain at least two characters.");
  if (!code) throw badRequest("A valid team code is required.");
  return { name, code, description: cleanText(payload.description, 2000) };
}

export function normalizeAssetPayloads(payload = {}) {
  const rows = Array.isArray(payload.assets) ? payload.assets : [];
  if (!rows.length || rows.length > 10_000) throw badRequest("Upload between 1 and 10,000 assets per request.");
  const normalized = rows.map((asset, index) => {
    const ipAddress = cleanText(asset.ipAddress, 500);
    const dnsName = cleanText(asset.dnsName, 1000).toLowerCase();
    const hostName = cleanText(asset.hostName, 1000).toLowerCase();
    const externalId = cleanText(asset.externalId, 500);
    const assetKey = cleanText(asset.assetKey, 1000).toLowerCase() || [ipAddress, dnsName, hostName, externalId].find(Boolean)?.toLowerCase();
    if (!assetKey) throw badRequest(`Asset row ${index + 1} has no IP address, DNS name, host name, or external ID.`);
    return {
      assetKey,
      ipAddress,
      dnsName,
      hostName,
      externalId,
      assetType: normalizeAssetType(asset.assetType, asset.platform),
      onboardingTool: normalizeAssetOnboardingTool(asset.onboardingTool),
      teamId: /^[0-9a-f-]{36}$/i.test(String(asset.teamId ?? "")) ? String(asset.teamId) : null,
      platform: cleanText(asset.platform, 2000),
      businessUnit: cleanText(asset.businessUnit, 1000),
      criticality: cleanText(asset.criticality, 1000),
      internetExposed: nullableBoolean(asset.internetExposed),
      inScope: true,
    };
  });
  const uniqueAssets = [...new Map(normalized.map((asset) => [asset.assetKey, asset])).values()];
  const aliasOwners = new Map();
  for (const asset of uniqueAssets) {
    for (const alias of [asset.assetKey, asset.ipAddress, asset.dnsName, asset.hostName, asset.externalId].map((value) => value.toLowerCase()).filter(Boolean)) {
      const owner = aliasOwners.get(alias);
      if (owner && owner !== asset.assetKey) throw badRequest(`Asset identity '${alias}' is assigned to more than one inventory record.`);
      aliasOwners.set(alias, asset.assetKey);
    }
  }
  return uniqueAssets;
}

export function normalizeAssetOnboardingTool(value) {
  const normalized = cleanText(value, 120).toLowerCase().replace(/[._-]+/g, " ").replace(/\s+/g, " ");
  const aliases = new Map([
    ["", "manual"],
    ["manual", "manual"],
    ["manual inventory", "manual"],
    ["tenable sc", "tenable-sc"],
    ["tenable security center", "tenable-sc"],
    ["tenable io", "tenable-io"],
    ["tenable vulnerability management", "tenable-io"],
    ["qualys", "qualys"],
    ["qualys vmdr", "qualys"],
    ["crowdstrike", "crowdstrike"],
    ["crowdstrike exposure management", "crowdstrike"],
    ["openshift", "openshift"],
    ["red hat openshift", "openshift"],
    ["openshift container platform", "openshift"],
    ["mdvm", "mdvm"],
    ["microsoft defender vm", "mdvm"],
    ["microsoft defender vulnerability management", "mdvm"],
    ["multi tool", "multi-tool"],
    ["multiple tools", "multi-tool"],
    ["other", "other"],
    ["other tool", "other"],
  ]);
  const tool = aliases.get(normalized);
  if (!tool) throw badRequest("Select a valid onboarding tool.");
  return tool;
}

export function normalizeAssetIds(payload = {}) {
  const ids = [...new Set((Array.isArray(payload.assetIds) ? payload.assetIds : []).map((value) => String(value ?? "").trim()))];
  if (!ids.length || ids.length > 10_000) throw badRequest("Select between 1 and 10,000 assets.");
  if (ids.some((id) => !/^[0-9a-f-]{36}$/i.test(id))) throw badRequest("One or more selected assets are invalid.");
  return ids;
}

export function normalizeThreatIntelImportPayload(payload = {}) {
  const ingestionKey = cleanText(payload.ingestionKey, 128);
  const expectedRecords = positiveInteger(payload.expectedRecords);
  if (!ingestionKey || !/^[a-zA-Z0-9:_-]+$/.test(ingestionKey)) throw badRequest("A valid threat-intelligence ingestion key is required.");
  if (!expectedRecords || expectedRecords > 200_000) throw badRequest("Threat-intelligence imports must contain between 1 and 200,000 records.");
  return {
    ingestionKey,
    sourceLabel: cleanText(payload.sourceLabel, 180) || "Uploaded scanner data",
    fileNames: cleanStringArray(payload.fileNames, 100, 500),
    expectedRecords,
  };
}

export function normalizeThreatIntelChunkPayload(payload = {}, expectedRecords) {
  const startIndex = nonNegativeInteger(payload.startIndex);
  if (startIndex == null) throw badRequest("Threat-intelligence chunk start index must be a non-negative integer.");
  if (!Array.isArray(payload.records) || payload.records.length < 1 || payload.records.length > 1000) {
    throw badRequest("Each threat-intelligence chunk must contain between 1 and 1,000 records.");
  }
  if (startIndex + payload.records.length > expectedRecords) throw badRequest("Threat-intelligence chunk exceeds the declared record count.");
  return {
    startIndex,
    records: payload.records.map((record, offset) => normalizeThreatIntelRecord(record, startIndex + offset)),
  };
}

export function normalizeThreatIntelQuery(value) {
  const query = cleanText(value, 500);
  if (query.length < 2) throw badRequest("Enter at least two characters to search threat intelligence.");
  return query;
}

export function normalizeAiRemediationPayload(payload = {}) {
  const prompt = cleanText(payload.prompt, 2_000_000);
  if (prompt.length < 20) throw badRequest("Generate a normalized remediation prompt before requesting local AI.");
  return {
    prompt,
    targetPeriod: cleanText(payload.targetPeriod, 120) || "Current period",
    sourceLabel: cleanText(payload.sourceLabel, 180) || "Uploaded scanner data",
  };
}

function normalizeThreatIntelRecord(record = {}, rowIndex) {
  const severity = SEVERITIES.has(record.severity) ? record.severity : "Unknown";
  const patchPriority = PRIORITIES.has(record.patchPriority) ? record.patchPriority : "P4";
  return {
    rowIndex,
    cve: cleanText(record.cve, 2000),
    vulnerabilityName: cleanText(record.vulnerabilityName, 4000),
    sourceTool: cleanText(record.sourceTool, 80),
    sourceVulnerabilityId: cleanText(record.sourceVulnerabilityId, 500),
    ipAddress: cleanText(record.ipAddress, 500),
    dnsName: cleanText(record.dnsName, 1000).toLowerCase(),
    severity,
    patchPriority,
    exploitAvailable: Boolean(record.exploitAvailable),
    vulnerabilityConfidence: cleanText(record.vulnerabilityConfidence, 1000),
    exploitEvidence: cleanText(record.exploitEvidence || record.exploitSignal, 4000),
    description: cleanText(record.description || record.summary, 100_000),
    remediation: cleanText(record.remediation, 100_000),
    kbLinks: cleanText(record.kbLinks, 20_000),
    product: cleanText(record.product, 4000),
    platformDetails: cleanText(record.platformDetails, 20_000),
    namespace: cleanText(record.namespace, 1000),
    deployment: cleanText(record.deployment, 1000),
    image: cleanText(record.image, 4000),
    component: cleanText(record.component, 4000),
    fixable: Boolean(record.fixable),
    fixedIn: cleanText(record.fixedIn, 4000),
    cvssScore: nullableBoundedNumber(record.cvssScore, 0, 10),
    firstObserved: isoDate(record.firstObserved || record.firstDiscovered),
    lastObserved: isoDate(record.lastObserved),
    payload: jsonSafe(record),
  };
}

function normalizeAssetType(value, platform = "") {
  const requested = cleanText(value, 200).toLowerCase();
  const exact = ASSET_TYPES.find((assetType) => assetType.toLowerCase() === requested);
  if (exact) return exact;
  const evidence = `${requested} ${cleanText(platform, 2000).toLowerCase()}`;
  if (/\b(router|switch|wireless|network|load balancer)\b/.test(evidence)) return "Network Device";
  if (/\b(firewall|waf|ids|ips|security appliance)\b/.test(evidence)) return "Security Appliance";
  if (/\b(linux|ubuntu|debian|red hat|rhel|centos|suse|unix)\b/.test(evidence)) return "Linux Server";
  if (/\bwindows server\b/.test(evidence)) return "Windows Server";
  if (/\b(windows 10|windows 11|macos|desktop|laptop|workstation|endpoint)\b/.test(evidence)) return "Endpoint";
  if (/\b(postgres|postgresql|mysql|oracle database|sql server|database|db)\b/.test(evidence)) return "Database";
  if (/\b(aws|azure|gcp|cloud)\b/.test(evidence)) return "Cloud Asset";
  if (/\b(vmware|esxi|hyper-v|virtualization|hypervisor)\b/.test(evidence)) return "Virtualization Host";
  if (/\b(kubernetes|openshift|container|k8s)\b/.test(evidence)) return "Container Platform";
  if (/\b(scada|plc|industrial|ot device|operational technology)\b/.test(evidence)) return "OT Device";
  return "Other";
}

export function reportPeriodDate(value) {
  const text = cleanText(value, 120);
  const monthMatch = text.match(/\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+(20\d{2})\b/i);
  if (monthMatch) {
    const monthIndex = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"].indexOf(monthMatch[1].toLowerCase());
    return `${monthMatch[2]}-${String(monthIndex + 1).padStart(2, "0")}-01`;
  }
  const quarterMatch = text.match(/\bQ([1-4])\s+(20\d{2})\b/i);
  if (quarterMatch) return `${quarterMatch[2]}-${String((Number(quarterMatch[1]) - 1) * 3 + 1).padStart(2, "0")}-01`;
  return null;
}

export function badRequest(message, statusCode = 400) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function cleanText(value, maxLength) {
  if (value == null) return "";
  return String(value).replace(/\u0000/g, "").trim().slice(0, maxLength);
}

function cleanStringArray(value, maxItems, maxLength) {
  return [...new Set((Array.isArray(value) ? value : []).map((item) => cleanText(item, maxLength)).filter(Boolean))].slice(0, maxItems);
}

function plainObject(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? jsonSafe(value) : {};
}

function jsonSafe(value) {
  return JSON.parse(JSON.stringify(value ?? {}));
}

function positiveInteger(value) {
  const number = Number(value);
  return Number.isSafeInteger(number) && number > 0 ? number : null;
}

function nonNegativeInteger(value) {
  const number = Number(value);
  return Number.isSafeInteger(number) && number >= 0 ? number : null;
}

function nullableNonNegativeInteger(value) {
  if (value == null || value === "") return null;
  return nonNegativeInteger(value);
}

function boundedInteger(value, minimum, maximum, fallback) {
  const number = Math.round(Number(value));
  return Number.isFinite(number) ? Math.min(maximum, Math.max(minimum, number)) : fallback;
}

function nullableBoundedNumber(value, minimum, maximum) {
  if (value == null || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) ? Math.min(maximum, Math.max(minimum, number)) : null;
}

function probability(value) {
  if (value == null || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 && number <= 1 ? number : null;
}

function nullableBoolean(value) {
  if (value == null || value === "") return null;
  if (typeof value === "boolean") return value;
  const normalized = String(value).trim().toLowerCase();
  if (["yes", "true", "1", "y"].includes(normalized)) return true;
  if (["no", "false", "0", "n"].includes(normalized)) return false;
  return null;
}

function isoDate(value) {
  if (!value) return null;
  const text = String(value).trim();
  const match = text.match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (!match) return null;
  const date = new Date(`${match[1]}-${match[2]}-${match[3]}T00:00:00Z`);
  return Number.isNaN(date.getTime()) || date.toISOString().slice(0, 10) !== `${match[1]}-${match[2]}-${match[3]}`
    ? null
    : `${match[1]}-${match[2]}-${match[3]}`;
}
