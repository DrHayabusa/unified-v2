from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from textwrap import wrap

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    Flowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "output" / "pdf"


MVA = {
    "bg": colors.HexColor("#07100d"),
    "panel": colors.HexColor("#101c18"),
    "panel_2": colors.HexColor("#142821"),
    "line": colors.HexColor("#28483d"),
    "ink": colors.HexColor("#f4f7f2"),
    "muted": colors.HexColor("#a7b8af"),
    "green": colors.HexColor("#2dd4bf"),
    "green_dark": colors.HexColor("#145a4b"),
    "critical": colors.HexColor("#ef4444"),
    "high": colors.HexColor("#f97316"),
    "medium": colors.HexColor("#facc15"),
    "low": colors.HexColor("#22c55e"),
    "info": colors.HexColor("#94a3b8"),
}


@dataclass(frozen=True)
class Finding:
    ip: str
    dns: str
    name: str
    cve: str
    severity: str
    exploit: str
    priority: str
    exposure: int
    first_seen: str
    last_seen: str
    summary: str
    remediation: str
    kb_links: tuple[str, ...]
    platform: str


FINDINGS = [
    Finding(
        ip="10.20.1.234",
        dns="web-prod-01",
        name="Apache Tomcat AJP Connector Request Injection",
        cve="CVE-2020-1938",
        severity="Critical",
        exploit="Yes",
        priority="P1",
        exposure=920,
        first_seen="2026-04-05",
        last_seen="2026-07-03",
        summary="Internet-adjacent application service with public exploit paths and repeated monthly observation.",
        remediation="Upgrade Tomcat to a fixed version, disable AJP where not required, and restrict connector access to trusted networks.",
        kb_links=("https://nvd.nist.gov/vuln/detail/CVE-2020-1938", "https://tomcat.apache.org/security-9.html"),
        platform="Linux / Apache Tomcat",
    ),
    Finding(
        ip="10.20.1.235",
        dns="vpn-gw-02",
        name="SSL Certificate Cannot Be Trusted",
        cve="",
        severity="High",
        exploit="No",
        priority="P2",
        exposure=780,
        first_seen="2026-05-12",
        last_seen="2026-07-03",
        summary="Externally reachable service presents an untrusted certificate, increasing phishing and interception risk.",
        remediation="Replace the certificate with one issued by an approved CA and validate the full certificate chain.",
        kb_links=("https://docs.tenable.com/nessus/Content/SSLPlugins.htm",),
        platform="Network Appliance / TLS",
    ),
    Finding(
        ip="10.20.2.118",
        dns="sql-prod-03",
        name="Microsoft SQL Server Unsupported Version Detection",
        cve="",
        severity="Critical",
        exploit="Yes",
        priority="P1",
        exposure=860,
        first_seen="2026-04-01",
        last_seen="2026-07-03",
        summary="Unsupported database platform with high-value data exposure and no vendor security fixes.",
        remediation="Migrate to a supported SQL Server release, validate application compatibility, and retire unsupported instances.",
        kb_links=("https://learn.microsoft.com/lifecycle/products/",),
        platform="Windows / Microsoft SQL Server",
    ),
    Finding(
        ip="10.30.5.44",
        dns="jira-app-01",
        name="Remote Code Execution in Web Application Component",
        cve="CVE-2024-21683",
        severity="High",
        exploit="Yes",
        priority="P1",
        exposure=835,
        first_seen="2026-06-15",
        last_seen="2026-07-03",
        summary="Application component has exploit availability and should be patched before the next internet-facing release window.",
        remediation="Apply vendor security updates, restart the service, and confirm the plugin version after remediation.",
        kb_links=("https://nvd.nist.gov/", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
        platform="Linux / Web Application",
    ),
    Finding(
        ip="10.40.8.21",
        dns="win-file-07",
        name="SMB Signing Not Required",
        cve="",
        severity="Medium",
        exploit="No",
        priority="P3",
        exposure=430,
        first_seen="2026-07-01",
        last_seen="2026-07-03",
        summary="Internal host allows unsigned SMB traffic and may be exposed to relay attacks in compromised network segments.",
        remediation="Enable SMB signing through Group Policy and validate compatibility for legacy clients.",
        kb_links=("https://learn.microsoft.com/windows/security/",),
        platform="Windows Server / SMB",
    ),
]


styles = getSampleStyleSheet()
styles.add(
    ParagraphStyle(
        name="MVA_Title",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=25,
        leading=28,
        textColor=MVA["ink"],
        spaceAfter=10,
    )
)
styles.add(
    ParagraphStyle(
        name="MVA_H1",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=17,
        leading=21,
        textColor=MVA["ink"],
        spaceBefore=10,
        spaceAfter=8,
    )
)
styles.add(
    ParagraphStyle(
        name="MVA_H2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=15,
        textColor=MVA["green"],
        spaceBefore=8,
        spaceAfter=6,
    )
)
styles.add(
    ParagraphStyle(
        name="MVA_Body",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13,
        textColor=MVA["ink"],
        spaceAfter=6,
    )
)
styles.add(
    ParagraphStyle(
        name="MVA_Muted",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=8.2,
        leading=11,
        textColor=MVA["muted"],
    )
)
styles.add(
    ParagraphStyle(
        name="MVA_Cell",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=7.2,
        leading=8.8,
        textColor=MVA["ink"],
    )
)
styles.add(
    ParagraphStyle(
        name="MVA_Cell_Muted",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=7.0,
        leading=8.4,
        textColor=MVA["muted"],
    )
)
styles.add(
    ParagraphStyle(
        name="MVA_KPI",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=22,
        textColor=MVA["ink"],
        alignment=TA_CENTER,
    )
)


class DarkBackground(Flowable):
    def __init__(self, width: float, height: float, variant: str = "grid") -> None:
        super().__init__()
        self.width = width
        self.height = height
        self.variant = variant

    def draw(self) -> None:
        c = self.canv
        c.saveState()
        c.setFillColor(MVA["panel"])
        c.roundRect(0, 0, self.width, self.height, 14, fill=1, stroke=0)
        c.setStrokeColor(colors.Color(0.1, 0.8, 0.65, alpha=0.17))
        c.setLineWidth(0.35)
        step = 19
        for x in range(10, int(self.width), step):
            c.line(x, 6, x, self.height - 6)
        for y in range(12, int(self.height), step):
            c.line(6, y, self.width - 6, y)
        c.setStrokeColor(colors.Color(0.95, 0.25, 0.25, alpha=0.22))
        for idx in range(5):
            x = 22 + idx * 41
            y = self.height - 24 - idx * 12
            c.circle(x, y, 4 + idx, stroke=1, fill=0)
            if idx:
                c.line(x - 37, y + 12, x, y)
        c.restoreState()


def p(text: str, style: str = "MVA_Body") -> Paragraph:
    return Paragraph(escape_keep_breaks(text), styles[style])


def escape_keep_breaks(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", "<br/>")
    )


def chip(text: str, color: colors.Color) -> Paragraph:
    return Paragraph(
        f'<font color="#07100d"><b>{escape_keep_breaks(text)}</b></font>',
        ParagraphStyle(
            name=f"chip_{text}",
            fontName="Helvetica-Bold",
            fontSize=7.4,
            leading=9,
            alignment=TA_CENTER,
            backColor=color,
            borderPadding=4,
            borderRadius=6,
        ),
    )


def severity_color(severity: str) -> colors.Color:
    return {
        "Critical": MVA["critical"],
        "High": MVA["high"],
        "Medium": MVA["medium"],
        "Low": MVA["low"],
    }.get(severity, MVA["info"])


def priority_color(priority: str) -> colors.Color:
    return {
        "P1": MVA["critical"],
        "P2": MVA["high"],
        "P3": MVA["medium"],
        "P4": MVA["low"],
    }.get(priority, MVA["info"])


def doc_template(path: Path, title: str) -> SimpleDocTemplate:
    return SimpleDocTemplate(
        str(path),
        pagesize=A4,
        rightMargin=13 * mm,
        leftMargin=13 * mm,
        topMargin=20 * mm,
        bottomMargin=17 * mm,
        title=title,
        author="MVA",
    )


def page_decorator(canvas, doc, report_title: str, summary_date: str) -> None:
    width, height = A4
    canvas.saveState()
    canvas.setFillColor(MVA["bg"])
    canvas.rect(0, 0, width, height, fill=1, stroke=0)
    canvas.setStrokeColor(colors.Color(0.17, 0.82, 0.72, alpha=0.16))
    canvas.setLineWidth(0.4)
    for x in range(0, int(width), 28):
        canvas.line(x, 0, x + 180, height)
    canvas.setFillColor(colors.Color(0.05, 0.95, 0.78, alpha=0.08))
    canvas.circle(width - 70, height - 80, 96, fill=1, stroke=0)
    canvas.setFillColor(MVA["panel"])
    canvas.roundRect(12 * mm, height - 17 * mm, width - 24 * mm, 9 * mm, 4, fill=1, stroke=0)
    canvas.setFillColor(MVA["green"])
    canvas.setFont("Helvetica-Bold", 9)
    canvas.drawString(16 * mm, height - 13.5 * mm, "MVA")
    canvas.setFillColor(MVA["ink"])
    canvas.setFont("Helvetica", 8)
    canvas.drawString(31 * mm, height - 13.5 * mm, report_title)
    canvas.setFillColor(MVA["muted"])
    canvas.drawRightString(width - 16 * mm, height - 13.5 * mm, f"Summary Date: {summary_date}")
    canvas.setStrokeColor(MVA["line"])
    canvas.line(13 * mm, 13 * mm, width - 13 * mm, 13 * mm)
    canvas.setFillColor(MVA["muted"])
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(16 * mm, 8.8 * mm, "Generated by MVA Unified Agent - Local analysis, source-aware mapping, AI-assisted narrative optional")
    canvas.drawRightString(width - 16 * mm, 8.8 * mm, f"Page {doc.page}")
    canvas.restoreState()


def kpi_table(items: list[tuple[str, str, colors.Color]]) -> Table:
    values = []
    labels = []
    for label, value, color in items:
        values.append(p(value, "MVA_KPI"))
        labels.append(chip(label, color))
    table = Table([values, labels], colWidths=[31 * mm] * len(items), rowHeights=[14 * mm, 9 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), MVA["panel"]),
                ("BOX", (0, 0), (-1, -1), 0.7, MVA["line"]),
                ("INNERGRID", (0, 0), (-1, -1), 0.4, MVA["line"]),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    return table


def paragraph_box(title: str, body: str, accent: colors.Color = MVA["green"]) -> Table:
    data = [[p(title, "MVA_H2")], [p(body, "MVA_Body")]]
    table = Table(data, colWidths=[178 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), MVA["panel"]),
                ("BOX", (0, 0), (-1, -1), 0.7, MVA["line"]),
                ("LINEBEFORE", (0, 0), (0, -1), 3, accent),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return table


def queue_table(findings: list[Finding], compact: bool = False) -> Table:
    headers = ["IP Address", "DNS Name", "Vulnerability Name", "CVE", "Severity", "Exploit", "Priority", "Exposure", "Last Observed"]
    rows = [[p(h, "MVA_Cell") for h in headers]]
    for finding in findings:
        rows.append(
            [
                p(finding.ip, "MVA_Cell"),
                p(finding.dns, "MVA_Cell"),
                p(finding.name, "MVA_Cell"),
                p(finding.cve or "N/A", "MVA_Cell"),
                p(finding.severity, "MVA_Cell"),
                p(finding.exploit, "MVA_Cell"),
                p(finding.priority, "MVA_Cell"),
                p(str(finding.exposure), "MVA_Cell"),
                p(finding.last_seen, "MVA_Cell"),
            ]
        )
    widths = [18, 26, 42, 22, 16, 16, 14, 15, 21]
    table = Table(rows, colWidths=[w * mm for w in widths], repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), MVA["green_dark"]),
        ("TEXTCOLOR", (0, 0), (-1, 0), MVA["ink"]),
        ("BOX", (0, 0), (-1, -1), 0.6, MVA["line"]),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, MVA["line"]),
        ("BACKGROUND", (0, 1), (-1, -1), MVA["panel"]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    for row_idx, finding in enumerate(findings, start=1):
        style.append(("BACKGROUND", (4, row_idx), (4, row_idx), severity_color(finding.severity)))
        style.append(("BACKGROUND", (6, row_idx), (6, row_idx), priority_color(finding.priority)))
        style.append(("TEXTCOLOR", (4, row_idx), (4, row_idx), colors.white if finding.severity != "Medium" else colors.black))
        style.append(("TEXTCOLOR", (6, row_idx), (6, row_idx), colors.white if finding.priority in {"P1", "P2"} else colors.black))
    table.setStyle(TableStyle(style))
    return table


def mapping_table() -> Table:
    data = [
        ["MVA Field", "Tenable.sc Source", "Tenable.io Source"],
        ["IP Address", "IP Address", "asset.display_ipv4_address / asset.ipv4_addresses"],
        ["DNS Name", "DNS Name / NetBIOS Name", "asset.display_fqdn / asset.host_name"],
        ["Vulnerability Name", "Plugin Name", "definition.name"],
        ["CVE", "CVE", "definition.cve"],
        ["Severity", "Severity / Risk Factor", "definition.severity / severity"],
        ["Exploit Availability", "Exploit?", "Exploit Ease / definition.exploitability_ease"],
        ["Remediation", "Steps to Remediate", "definition.solution / definition.workaround"],
        ["KB Links", "See Also / Cross References", "definition.see_also / definition.references"],
        ["First / Last Observed", "First Discovered / Last Observed", "first_observed / last_seen"],
    ]
    rows = [[p(cell, "MVA_Cell") for cell in row] for row in data]
    table = Table(rows, colWidths=[42 * mm, 67 * mm, 78 * mm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), MVA["green_dark"]),
                ("BACKGROUND", (0, 1), (-1, -1), MVA["panel"]),
                ("TEXTCOLOR", (0, 0), (-1, -1), MVA["ink"]),
                ("BOX", (0, 0), (-1, -1), 0.6, MVA["line"]),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, MVA["line"]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def priority_matrix_table() -> Table:
    data = [
        ["Exploit Availability", "Critical", "High", "Medium", "Low"],
        ["Yes / Available", "P1", "P1", "P2", "P2"],
        ["No / Unavailable", "P2", "P2", "P3", "P4"],
    ]
    rows = [[p(cell, "MVA_Cell") for cell in row] for row in data]
    table = Table(rows, colWidths=[42 * mm, 30 * mm, 30 * mm, 30 * mm, 30 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), MVA["green_dark"]),
                ("BACKGROUND", (0, 1), (-1, -1), MVA["panel"]),
                ("BACKGROUND", (1, 1), (1, 1), MVA["critical"]),
                ("BACKGROUND", (2, 1), (2, 1), MVA["critical"]),
                ("BACKGROUND", (3, 1), (3, 1), MVA["high"]),
                ("BACKGROUND", (4, 1), (4, 1), MVA["high"]),
                ("BACKGROUND", (1, 2), (1, 2), MVA["high"]),
                ("BACKGROUND", (2, 2), (2, 2), MVA["high"]),
                ("BACKGROUND", (3, 2), (3, 2), MVA["medium"]),
                ("BACKGROUND", (4, 2), (4, 2), MVA["low"]),
                ("BOX", (0, 0), (-1, -1), 0.6, MVA["line"]),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, MVA["line"]),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (1, 1), (-1, -1), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    return table


def kb_table(findings: list[Finding]) -> Table:
    data = [["Finding", "KB / Evidence Links", "How MVA Uses It"]]
    for finding in findings[:4]:
        links = "\n".join(finding.kb_links)
        data.append([finding.name, links, "Referenced in remediation narrative, appendix, and analyst validation checklist."])
    rows = [[p(cell, "MVA_Cell" if idx == 0 else "MVA_Cell_Muted") for cell in row] for idx, row in enumerate(data)]
    table = Table(rows, colWidths=[52 * mm, 82 * mm, 50 * mm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), MVA["green_dark"]),
                ("BACKGROUND", (0, 1), (-1, -1), MVA["panel"]),
                ("BOX", (0, 0), (-1, -1), 0.6, MVA["line"]),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, MVA["line"]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def ai_steps_table() -> Table:
    steps = [
        ("1", "Read only normalized MVA fields", "Use IP, DNS, vulnerability name, CVE, severity, exploit availability, priority, exposure, finding evidence, remediation, KB links, platform, first and last observed dates."),
        ("2", "Respect the selected summary date", "Filter and describe findings according to the date/month selected by the analyst before the PDF is generated."),
        ("3", "Use the priority matrix exactly", "Exploit available plus Critical/High becomes P1; no exploit on Critical/High becomes P2; Medium maps to P2/P3; Low maps to P2/P4."),
        ("4", "Write customer-safe language", "Avoid unsupported claims. Separate confirmed evidence from recommendation. Do not expose raw secrets or unrelated CSV columns."),
        ("5", "Use KB links as evidence", "Summarize vendor/NVD/KB references and place links in a human-readable appendix."),
        ("6", "Return structured sections", "Executive summary, critical actions, technical queue, remediation plan, validation checklist, appendix."),
    ]
    data = [["Step", "Instruction", "Expected Behavior"], *steps]
    rows = [[p(cell, "MVA_Cell") for cell in row] for row in data]
    table = Table(rows, colWidths=[14 * mm, 50 * mm, 116 * mm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), MVA["green_dark"]),
                ("BACKGROUND", (0, 1), (-1, -1), MVA["panel"]),
                ("BOX", (0, 0), (-1, -1), 0.6, MVA["line"]),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, MVA["line"]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def build_executive_pdf() -> Path:
    path = OUT_DIR / "mva_sample_01_executive_summary.pdf"
    doc = doc_template(path, "MVA Executive Summary Sample")
    story = [
        p("MVA Vulnerability Agent", "MVA_Title"),
        p("Executive remediation summary generated from Tenable.sc and Tenable.io CSV exports.", "MVA_Body"),
        Spacer(1, 6),
        kpi_table(
            [
                ("TOTAL OPEN", "8", MVA["green"]),
                ("CRITICAL", "3", MVA["critical"]),
                ("HIGH", "4", MVA["high"]),
                ("MEDIUM", "1", MVA["medium"]),
                ("IMMEDIATE PATCH", "4", MVA["critical"]),
            ]
        ),
        Spacer(1, 10),
        paragraph_box(
            "Executive Decision",
            "MVA recommends immediate remediation for four P1 findings in the July 2026 summary window. The highest-risk items combine Critical or High severity with exploit availability, repeated observation, and high asset exposure.",
            MVA["critical"],
        ),
        Spacer(1, 8),
        p("Priority Matrix", "MVA_H1"),
        priority_matrix_table(),
        Spacer(1, 8),
        p("Top Remediation Queue", "MVA_H1"),
        queue_table(FINDINGS[:4]),
        PageBreak(),
        p("Source Field Mapping", "MVA_H1"),
        p("The PDF narrative is driven by normalized MVA fields. Tenable.sc and Tenable.io can use different raw headers, but the output remains consistent.", "MVA_Body"),
        mapping_table(),
        Spacer(1, 10),
        p("KB Evidence Handling", "MVA_H1"),
        kb_table(FINDINGS),
    ]
    doc.build(
        story,
        onFirstPage=lambda c, d: page_decorator(c, d, "Executive Summary", "July 2026"),
        onLaterPages=lambda c, d: page_decorator(c, d, "Executive Summary", "July 2026"),
    )
    return path


def build_technical_pdf() -> Path:
    path = OUT_DIR / "mva_sample_02_technical_remediation_plan.pdf"
    doc = doc_template(path, "MVA Technical Remediation Plan Sample")
    story = [
        p("MVA Technical Remediation Plan", "MVA_Title"),
        p("Analyst-focused remediation pack with evidence, ownership hints, KB links, platform context, and validation steps.", "MVA_Body"),
        Spacer(1, 6),
        paragraph_box(
            "Selected Summary Date",
            "In the final app, after CSV upload the analyst chooses the reporting month/date window before generating the PDF. MVA filters first observed, last observed, aging, repeated, and remediated metrics against that selection.",
            MVA["green"],
        ),
        Spacer(1, 8),
        p("Action Queue", "MVA_H1"),
        queue_table(FINDINGS),
        PageBreak(),
    ]
    for finding in FINDINGS:
        story.extend(
            [
                KeepTogether(
                    [
                        p(f"{finding.priority} - {finding.name}", "MVA_H1"),
                        paragraph_box(
                            "Finding Summary",
                            f"{finding.summary}\n\nAsset: {finding.ip} / {finding.dns}\nPlatform: {finding.platform}\nSeverity: {finding.severity}\nExploit Availability: {finding.exploit}\nAsset Exposure: {finding.exposure}/1000\nFirst Discovered: {finding.first_seen}\nLast Observed: {finding.last_seen}",
                            severity_color(finding.severity),
                        ),
                        Spacer(1, 6),
                        paragraph_box("Remediation", finding.remediation, priority_color(finding.priority)),
                        Spacer(1, 6),
                        paragraph_box("KB Links", "\n".join(finding.kb_links), MVA["green"]),
                        Spacer(1, 8),
                    ]
                )
            ]
        )
    doc.build(
        story,
        onFirstPage=lambda c, d: page_decorator(c, d, "Technical Remediation Plan", "July 2026"),
        onLaterPages=lambda c, d: page_decorator(c, d, "Technical Remediation Plan", "July 2026"),
    )
    return path


def build_ai_blueprint_pdf() -> Path:
    path = OUT_DIR / "mva_sample_03_ai_pdf_blueprint.pdf"
    doc = doc_template(path, "MVA AI PDF Blueprint Sample")
    story = [
        p("MVA AI PDF Blueprint", "MVA_Title"),
        p("This sample shows the structure MVA should send to the selected AI server so the generated PDF remains consistent, explainable, and customer-safe.", "MVA_Body"),
        Spacer(1, 8),
        p("AI Server Instructions", "MVA_H1"),
        ai_steps_table(),
        Spacer(1, 10),
        paragraph_box(
            "Recommended AI Prompt Contract",
            "You are the MVA remediation report writer. Produce concise, evidence-based vulnerability remediation language from normalized rows only. Use the selected summary date. Preserve severity, exploit availability, patch priority, KB links, first discovered, and last observed values. Never invent CVEs, asset names, exploit status, remediation completion, or business impact.",
            MVA["green"],
        ),
        Spacer(1, 8),
        p("Data Package Sent to AI", "MVA_H1"),
        queue_table(FINDINGS[:3]),
        PageBreak(),
        p("PDF Output Contract", "MVA_H1"),
        paragraph_box(
            "Required Sections",
            "1. Executive Summary\n2. Immediate Patch Needed\n3. Priority Matrix Explanation\n4. Source Tool and Field Mapping\n5. Remediation Queue\n6. Finding Details with KB Links\n7. Validation Checklist\n8. Appendix",
            MVA["green"],
        ),
        Spacer(1, 8),
        kb_table(FINDINGS),
    ]
    doc.build(
        story,
        onFirstPage=lambda c, d: page_decorator(c, d, "AI PDF Blueprint", "July 2026"),
        onLaterPages=lambda c, d: page_decorator(c, d, "AI PDF Blueprint", "July 2026"),
    )
    return path


def build_ai_generated_report_pdf() -> Path:
    path = OUT_DIR / "mva_sample_04_ai_generated_remediation_report.pdf"
    doc = doc_template(path, "MVA AI-Generated Remediation Report Sample")
    story = [
        p("MVA AI-Generated Remediation Report", "MVA_Title"),
        p(
            "Sample final report written from normalized Tenable.sc and Tenable.io rows for the selected July 2026 reporting window.",
            "MVA_Body",
        ),
        Spacer(1, 6),
        kpi_table(
            [
                ("TOTAL OPEN", "8", MVA["green"]),
                ("P1", "4", MVA["critical"]),
                ("P2", "2", MVA["high"]),
                ("P3", "1", MVA["medium"]),
                ("PATCH NOW", "4", MVA["critical"]),
            ]
        ),
        Spacer(1, 10),
        paragraph_box(
            "Executive Summary",
            "MVA identified four findings requiring immediate remediation in the July 2026 summary window. "
            "The primary risk driver is exploit availability on critical or high severity services, combined with repeated observation across multiple uploads and high asset exposure scores. "
            "The remediation team should prioritize externally reachable application and database services first, then validate certificate and SMB hardening items.",
            MVA["critical"],
        ),
        Spacer(1, 8),
        p("Immediate Patch Needed", "MVA_H1"),
        queue_table(FINDINGS[:4]),
        Spacer(1, 8),
        paragraph_box(
            "Recommended Remediation Order",
            "1. Patch or isolate Tomcat AJP exposure on web-prod-01.\n"
            "2. Migrate or upgrade unsupported SQL Server on sql-prod-03.\n"
            "3. Patch the web application component on jira-app-01.\n"
            "4. Replace untrusted VPN gateway certificates on vpn-gw-02.\n"
            "5. Schedule SMB signing enforcement for win-file-07 after compatibility validation.",
            MVA["green"],
        ),
        PageBreak(),
        p("AI-Written Finding Details", "MVA_Title"),
    ]
    for finding in FINDINGS:
        story.extend(
            [
                KeepTogether(
                    [
                        p(f"{finding.priority} - {finding.name}", "MVA_H1"),
                        paragraph_box(
                            "Why This Matters",
                            f"{finding.summary} MVA assigned {finding.priority} because the finding is {finding.severity}, "
                            f"exploit availability is marked as {finding.exploit}, and asset exposure is {finding.exposure}/1000.",
                            severity_color(finding.severity),
                        ),
                        Spacer(1, 6),
                        paragraph_box(
                            "Remediation Guidance",
                            f"{finding.remediation} After applying the fix, run a validation scan and confirm the finding is absent from the next selected reporting window.",
                            priority_color(finding.priority),
                        ),
                        Spacer(1, 6),
                        paragraph_box(
                            "Evidence and KB References",
                            f"Asset: {finding.ip} / {finding.dns}\n"
                            f"Platform: {finding.platform}\n"
                            f"CVE: {finding.cve or 'Not provided'}\n"
                            f"First Discovered: {finding.first_seen}\n"
                            f"Last Observed: {finding.last_seen}\n"
                            f"KB Links:\n" + "\n".join(finding.kb_links),
                            MVA["green"],
                        ),
                        Spacer(1, 10),
                    ]
                )
            ]
        )
    story.extend(
        [
            PageBreak(),
            p("Validation Checklist", "MVA_Title"),
            paragraph_box(
                "Post-Remediation Validation",
                "Confirm patch installation evidence, restart affected services where required, rerun authenticated scans, verify the finding no longer appears in the selected source export, and retain KB/vendor evidence with the change record.",
                MVA["green"],
            ),
            Spacer(1, 8),
            p("KB Evidence Appendix", "MVA_H1"),
            kb_table(FINDINGS),
        ]
    )
    doc.build(
        story,
        onFirstPage=lambda c, d: page_decorator(c, d, "AI-Generated Remediation Report", "July 2026"),
        onLaterPages=lambda c, d: page_decorator(c, d, "AI-Generated Remediation Report", "July 2026"),
    )
    return path


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    paths = [build_executive_pdf(), build_technical_pdf(), build_ai_blueprint_pdf(), build_ai_generated_report_pdf()]
    for path in paths:
        print(path)


if __name__ == "__main__":
    main()
