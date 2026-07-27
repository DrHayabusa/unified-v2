export const sourceTools = [
  {
    id: "tenable-sc",
    name: "Tenable.sc",
    shortName: "SC",
    accent: "emerald",
    description: "Security Center export",
    mapped: "12 of 12 key fields mapped",
    implemented: true,
  },
  {
    id: "tenable-io",
    name: "Tenable.io",
    shortName: "IO",
    accent: "sky",
    description: "Dot notation VM export",
    mapped: "12 of 12 key fields mapped",
    implemented: true,
  },
  {
    id: "mdvm",
    name: "MDVM",
    shortName: "M",
    accent: "violet",
    description: "Microsoft Defender VM",
    mapped: "10 of 12 key fields mapped",
    implemented: false,
  },
  {
    id: "crowdstrike",
    name: "CrowdStrike",
    shortName: "CS",
    accent: "red",
    description: "Exposure Management",
    mapped: "All supplied export fields supported",
    implemented: true,
  },
  {
    id: "qualys",
    name: "Qualys",
    shortName: "Q",
    accent: "red",
    description: "VMDR findings export",
    mapped: "12 of 12 key fields mapped",
    implemented: true,
  },
  {
    id: "custom-qualys",
    name: "Custom Qualys",
    shortName: "CQ",
    accent: "amber",
    description: "Urgent-to-minimal rating profile",
    mapped: "Qualys fields with customer severity mapping",
    implemented: true,
  },
  {
    id: "custom-csv",
    name: "Custom CSV",
    shortName: "CSV",
    accent: "slate",
    description: "Manual field mapping",
    mapped: "Auto-suggested manual mapping",
    implemented: true,
  },
  {
    id: "openshift",
    name: "OpenShift",
    shortName: "OCP",
    accent: "red",
    description: "Container workload findings",
    mapped: "11 of 11 supplied fields mapped",
    implemented: true,
  },
];

export const implementedSourceTools = sourceTools.filter((source) => source.implemented);

export const unifiedSourceTool = {
  id: "unified",
  name: "Unified Multi-Tool",
  shortName: "ALL",
  accent: "red",
  description: "Consolidated analysis with multi-tool confirmation",
  mapped: "Source-aware canonical mapping",
  implemented: true,
};

export const metricCards = [
  {
    label: "Total Open",
    value: 125,
    helper: "July sample report",
    color: "#14b8a6",
    data: [100, 110, 120, 125, 122, 126, 125, 128, 124, 125, 123, 125],
  },
  {
    label: "Critical",
    value: 31,
    helper: "24.8% of total",
    color: "#ef4444",
    data: [25, 28, 30, 31, 30, 32, 31, 31, 30, 31, 32, 31],
  },
  {
    label: "High",
    value: 31,
    helper: "24.8% of total",
    color: "#f97316",
    data: [25, 28, 30, 31, 29, 31, 32, 30, 31, 31, 30, 31],
  },
  {
    label: "Medium",
    value: 31,
    helper: "24.8% of total",
    color: "#facc15",
    data: [25, 27, 30, 31, 30, 31, 31, 32, 30, 31, 30, 31],
  },
  {
    label: "Low",
    value: 32,
    helper: "25.6% of total",
    color: "#22c55e",
    data: [25, 27, 30, 32, 31, 32, 32, 31, 32, 31, 33, 32],
  },
  {
    label: "Immediate Patch Needed",
    value: 72,
    helper: "P1 + P2",
    color: "#22d3ee",
    data: [57, 63, 69, 72, 70, 73, 72, 74, 71, 72, 73, 72],
  },
];

export const trendRows = [
  { label: "New", value: 30, change: "since June report", tone: "red" },
  { label: "Not Closed", value: 95, change: "carried forward", tone: "green" },
  { label: "Patched", value: 25, change: "closed since previous report", tone: "green" },
];

export const mappedFields = [
  ["IP Address", "SC: IP Address / IO: asset.display_ipv4_address"],
  ["DNS Name", "SC: DNS Name / IO: asset.display_fqdn"],
  ["Vulnerability ID", "SC: Plugin / IO: definition.id"],
  ["CVE", "SC: CVE / IO: definition.cve"],
  ["Severity", "SC: Severity / IO: definition.severity"],
  ["Exploit Availability", "SC: Exploit? / IO: definition.exploitability_ease"],
  ["First Discovered", "SC: First Discovered / IO: first_observed"],
  ["Remediation", "SC: Steps to Remediate / IO: definition.solution"],
];

export const monthOptions = ["April 2026", "May 2026", "June 2026", "July 2026"];

export const monthlyDashboardMetrics = [
  { label: "Total Open", value: 125, helper: "July report", color: "#10b981" },
  { label: "Critical", value: 31, helper: "24.8% of total", color: "#ef4444" },
  { label: "High", value: 31, helper: "24.8% of total", color: "#fb923c" },
  { label: "New This Month", value: 30, helper: "vs June report", color: "#38bdf8" },
  { label: "Patched", value: 25, helper: "since previous report", color: "#22c55e" },
  { label: "Immediate Patch", value: 72, helper: "P1 + P2", color: "#f43f5e" },
  { label: "Exploitable", value: 51, helper: "known exploit available", color: "#f97316" },
  { label: "Avg Age", value: "93d", helper: "open findings", color: "#94a3b8" },
];

export const monthlySeverityTrend = [
  { month: "April 2026", Critical: 25, High: 25, Medium: 25, Low: 25 },
  { month: "May 2026", Critical: 28, High: 28, Medium: 27, Low: 27 },
  { month: "June 2026", Critical: 30, High: 30, Medium: 30, Low: 30 },
  { month: "July 2026", Critical: 31, High: 31, Medium: 31, Low: 32 },
];

export const monthlyOpenTrend = [
  { month: "April 2026", totalOpen: 100, newThisMonth: 0, patchedSinceLastMonth: 0 },
  { month: "May 2026", totalOpen: 110, newThisMonth: 30, patchedSinceLastMonth: 20 },
  { month: "June 2026", totalOpen: 120, newThisMonth: 20, patchedSinceLastMonth: 10 },
  { month: "July 2026", totalOpen: 125, newThisMonth: 30, patchedSinceLastMonth: 25 },
];

export const monthlyDashboardRows = [
  { month: "April 2026", critical: 25, high: 25, medium: 25, low: 25, totalOpen: 100, period: "Earlier Report" },
  { month: "May 2026", critical: 28, high: 28, medium: 27, low: 27, totalOpen: 110, period: "Earlier Report" },
  { month: "June 2026", critical: 30, high: 30, medium: 30, low: 30, totalOpen: 120, period: "Previous Report" },
  { month: "July 2026", critical: 31, high: 31, medium: 31, low: 32, totalOpen: 125, period: "Current Report" },
];

export const remediationRows = [
  {
    ip: "10.20.12.76",
    dns: "asset-056.corp.local",
    name: "Apache Tomcat AJP Request Injection",
    cve: "CVE-2020-1938",
    severity: "Critical",
    priority: "P1",
    exposure: 980,
  },
  {
    ip: "10.20.13.77",
    dns: "asset-057.corp.local",
    name: "Apache Log4j Remote Code Execution",
    cve: "CVE-2021-44228",
    severity: "High",
    priority: "P1",
    exposure: 780,
  },
  {
    ip: "10.20.14.78",
    dns: "asset-058.corp.local",
    name: "Microsoft SQL Server Unsupported Version",
    cve: "N/A",
    severity: "Medium",
    priority: "P3",
    exposure: 540,
  },
  {
    ip: "10.20.15.79",
    dns: "asset-059.corp.local",
    name: "OpenSSL Security Update Available",
    cve: "CVE-2023-0286",
    severity: "Low",
    priority: "P4",
    exposure: 240,
  },
  {
    ip: "10.20.16.80",
    dns: "asset-060.corp.local",
    name: "Remote Desktop Weak Encryption Enabled",
    cve: "N/A",
    severity: "Critical",
    priority: "P2",
    exposure: 940,
  },
];
