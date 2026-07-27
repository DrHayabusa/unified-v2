#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import reportlab
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from mva_engine.tenable_normalizer import load_findings


OUT_PATH = ROOT / "output" / "pdf" / "mva_100plus_remediation_guide.pdf"
CSV_PATH = ROOT / "samples" / "tenable_100_row" / "tenable_io_july_2026_100plus.csv"

PRIORITY_ORDER = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
FONT_REGULAR = "MVA-Vera"
FONT_BOLD = "MVA-Vera-Bold"


def register_fonts() -> None:
    """Embed deterministic fonts so the report renders identically everywhere."""
    font_dir = Path(reportlab.__file__).resolve().parent / "fonts"
    pdfmetrics.registerFont(TTFont(FONT_REGULAR, str(font_dir / "Vera.ttf")))
    pdfmetrics.registerFont(TTFont(FONT_BOLD, str(font_dir / "VeraBd.ttf")))
    pdfmetrics.registerFontFamily(
        FONT_REGULAR,
        normal=FONT_REGULAR,
        bold=FONT_BOLD,
        italic=FONT_REGULAR,
        boldItalic=FONT_BOLD,
    )


def main() -> None:
    register_fonts()
    parser = argparse.ArgumentParser(description="Generate a customer-ready MVA Remediation Guide PDF.")
    parser.add_argument("--csv", default=str(CSV_PATH), help="Supported source CSV path")
    parser.add_argument("--output", default=str(OUT_PATH), help="Output PDF path")
    parser.add_argument("--source-label", default="", help="Customer-facing tool source")
    parser.add_argument("--report-month", default="July 2026", help="Customer-facing report month")
    parser.add_argument("--max-actions", type=int, default=12, help="Maximum remediation action sections")
    args = parser.parse_args()

    findings = load_findings(args.csv)
    findings = sorted(
        findings,
        key=lambda finding: (
            PRIORITY_ORDER.get(finding.patch_priority, 9),
            SEVERITY_ORDER.get(finding.severity, 9),
            -finding.asset_exposure,
            finding.dns_name,
        ),
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    source_label = args.source_label or source_label_for(findings)
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="Remediation Guide",
        pageCompression=0,
    )

    styles = build_styles()
    story = []
    story.extend(cover(styles, findings, source_label, args.report_month))
    story.append(PageBreak())
    story.extend(summary_page(styles, findings))
    story.append(PageBreak())
    story.extend(remediation_actions(styles, group_remediation_actions(findings)[: args.max_actions]))
    story.append(PageBreak())
    story.extend(validation_expectations(styles))

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    print(output_path)


def build_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title",
            parent=base["Title"],
            fontName=FONT_BOLD,
            fontSize=26,
            leading=32,
            textColor=colors.HexColor("#0f172a"),
            alignment=TA_CENTER,
            spaceAfter=8,
        ),
        "subtitle": ParagraphStyle(
            "subtitle",
            parent=base["BodyText"],
            fontName=FONT_REGULAR,
            fontSize=10,
            leading=15,
            textColor=colors.HexColor("#475569"),
            alignment=TA_CENTER,
            spaceAfter=18,
        ),
        "h1": ParagraphStyle(
            "h1",
            parent=base["Heading1"],
            fontName=FONT_BOLD,
            fontSize=16,
            leading=21,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=6,
            spaceAfter=10,
        ),
        "h2": ParagraphStyle(
            "h2",
            parent=base["Heading2"],
            fontName=FONT_BOLD,
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#075985"),
            spaceBefore=10,
            spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "body",
            parent=base["BodyText"],
            fontName=FONT_REGULAR,
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#334155"),
            spaceAfter=6,
        ),
        "small": ParagraphStyle(
            "small",
            parent=base["BodyText"],
            fontName=FONT_REGULAR,
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#64748b"),
        ),
        "meta": ParagraphStyle(
            "meta",
            parent=base["BodyText"],
            fontName=FONT_REGULAR,
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#475569"),
            backColor=colors.HexColor("#f8fafc"),
            borderColor=colors.HexColor("#cbd5e1"),
            borderWidth=0.5,
            borderPadding=6,
            spaceAfter=2,
        ),
        "code": ParagraphStyle(
            "code",
            parent=base["Code"],
            fontName="Courier",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#e2e8f0"),
            backColor=colors.HexColor("#0f172a"),
            borderColor=colors.HexColor("#334155"),
            borderWidth=0.7,
            borderPadding=8,
            spaceBefore=4,
            spaceAfter=8,
        ),
    }


def cover(styles: dict[str, ParagraphStyle], findings: list, source_label: str, report_month: str) -> list:
    total = sum(finding.record_count for finding in findings)
    critical = sum(finding.record_count for finding in findings if finding.severity == "Critical")
    high = sum(finding.record_count for finding in findings if finding.severity == "High")
    immediate = sum(finding.record_count for finding in findings if finding.patch_priority in {"P1", "P2"})
    exploitable = sum(finding.record_count for finding in findings if finding.exploit_available)

    return [
        Spacer(1, 30 * mm),
        Paragraph("Remediation Guide", styles["title"]),
        Paragraph(f"Tool Source: {escape(source_label)} | Report Month: {escape(report_month)}", styles["subtitle"]),
        kpi_table(
            [
                ["Total Findings", str(total)],
                ["Critical", str(critical)],
                ["High", str(high)],
                ["Immediate Patch Needed", str(immediate)],
                ["Exploit Available", str(exploitable)],
            ]
        ),
        Spacer(1, 12 * mm),
        Paragraph("Contents", styles["h1"]),
        contents_table(),
    ]


def summary_page(styles: dict[str, ParagraphStyle], findings: list) -> list:
    priority_counts = Counter()
    severity_counts = Counter()
    for finding in findings:
        priority_counts[finding.patch_priority] += finding.record_count
        severity_counts[finding.severity] += finding.record_count

    return [
        Paragraph("1. Report Summary", styles["h1"]),
        Paragraph(
            "This guide prioritizes remediation work using the approved MVA severity and exploit availability matrix. "
            "P1 and P2 items should be handled first because they represent the highest remediation priority.",
            styles["body"],
        ),
        Paragraph("Priority Distribution", styles["h2"]),
        distribution_table("Priority", ["P1", "P2", "P3", "P4"], priority_counts),
        Spacer(1, 8 * mm),
        Paragraph("Severity Distribution", styles["h2"]),
        distribution_table("Severity", ["Critical", "High", "Medium", "Low"], severity_counts),
        Spacer(1, 8 * mm),
        Paragraph("Remediation Execution Notes", styles["h2"]),
        Paragraph(
            "Validate a maintenance window for service-impacting changes, keep rollback evidence, apply fixes by priority, "
            "and confirm closure with a follow-up scan after the change window.",
            styles["body"],
        ),
    ]


def remediation_actions(styles: dict[str, ParagraphStyle], actions: list[tuple[object, int, list[str]]]) -> list:
    story = [Paragraph("2. Remediation Actions", styles["h1"])]
    for index, (finding, affected_count, assets) in enumerate(actions, start=1):
        # One action per page keeps long links, commands, and asset lists readable
        # without relying on ReportLab's fragile large-block pagination.
        if index > 1:
            story.append(PageBreak())
        block = [Paragraph(f"{index}. {escape(finding.vulnerability_name)}", styles["h2"])]
        references = unique_links(finding.kb_links)
        block.extend(
            metadata_block(
                [
                    ["Affected Assets", f"{affected_count} findings across {len(assets)} assets"],
                    ["Asset Examples", ", ".join(assets[:5])],
                    ["Severity / Priority", f"{finding.severity} / {finding.patch_priority}"],
                    ["CVE", finding.cve or "N/A"],
                ],
                styles["meta"],
            )
        )
        block.append(Paragraph("<b>Advisory links</b>", styles["body"]))
        block.append(reference_paragraph(references, styles["small"]))
        block.append(Paragraph("<b>Recommended remediation</b>", styles["body"]))
        block.append(Paragraph(escape(unique_remediation_text(finding.remediation)), styles["body"]))
        block.append(Paragraph("<b>Implementation and validation commands</b>", styles["body"]))
        block.append(command_box(styles["code"], command_for(finding)))
        block.append(Spacer(1, 5 * mm))
        story.extend(block)
    return story


def validation_expectations(styles: dict[str, ParagraphStyle]) -> list:
    return [
        Paragraph("3. Validation Expectations", styles["h1"]),
        Paragraph(
            "Use these controls for every remediation action. Product-specific vendor instructions and approved change procedures take precedence over example commands in this guide.",
            styles["body"],
        ),
        detail_table(
            [
                ["Before change", "Record the installed version, affected service state, maintenance window, backup or rollback method, and approved change reference."],
                ["After change", "Confirm the fixed version, required service restart or host reboot, application health, and business-owner acceptance."],
                ["Security validation", "Run a fresh authenticated scan, verify the finding is absent, retain scanner evidence, and investigate any recurrence."],
                ["Exception handling", "Document owner, compensating controls, target date, and formal risk acceptance when remediation cannot be completed."],
            ],
            styles["small"],
        ),
        Spacer(1, 8 * mm),
        Paragraph("Required Evidence", styles["h2"]),
        Paragraph(
            "Attach pre-change and post-change version output, implementation logs, restart or reboot confirmation, application validation, and the follow-up scan result to the change record.",
            styles["body"],
        ),
    ]


def group_remediation_actions(findings: list) -> list[tuple[object, int, list[str]]]:
    groups: dict[str, dict[str, object]] = {}
    for finding in findings:
        key = (finding.cve or finding.vulnerability_name or finding.source_vulnerability_id).strip().upper()
        group = groups.setdefault(key, {"finding": finding, "count": 0, "assets": set()})
        group["count"] += finding.record_count
        asset = finding.dns_name or finding.ip_address
        if asset:
            group["assets"].add(asset)
    return [
        (group["finding"], int(group["count"]), sorted(group["assets"]))
        for group in groups.values()
    ]


def kpi_table(rows: list[list[str]]) -> Table:
    table = Table(rows, colWidths=[85 * mm, 55 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
                ("FONTNAME", (0, 0), (0, -1), FONT_BOLD),
                ("FONTNAME", (1, 0), (1, -1), FONT_BOLD),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("ALIGN", (1, 0), (1, -1), "RIGHT"),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return table


def contents_table() -> Table:
    return kpi_table(
        [
            ["1", "Report Summary"],
            ["2", "Remediation Actions"],
            ["3", "Validation Expectations"],
        ]
    )


def distribution_table(label_title: str, labels: list[str], counts: Counter) -> Table:
    rows = [[label_title, "Count"]] + [[label, str(counts.get(label, 0))] for label in labels]
    table = Table(rows, colWidths=[85 * mm, 45 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e0f2fe")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#075985")),
                ("FONTNAME", (0, 0), (-1, 0), FONT_BOLD),
                ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#bae6fd")),
                ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                ("ALIGN", (1, 1), (1, -1), "RIGHT"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def detail_table(rows: list[list[object]], text_style: ParagraphStyle) -> Table:
    normalized_rows = [
        [Paragraph(escape(label), text_style), value if isinstance(value, Paragraph) else Paragraph(escape(value), text_style)]
        for label, value in rows
    ]
    table = Table(normalized_rows, colWidths=[36 * mm, 124 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
                ("FONTNAME", (0, 0), (0, -1), FONT_BOLD),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#334155")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return table


def metadata_block(rows: list[list[object]], style: ParagraphStyle) -> list[Paragraph]:
    return [
        Paragraph(f"<b>{escape(label)}:</b> {escape(value)}", style)
        for label, value in rows
    ]


def command_box(style: ParagraphStyle, command: str) -> Paragraph:
    return Paragraph(escape(command).replace("\n", "<br/>"), style)


def command_for(finding) -> str:
    name = finding.vulnerability_name.lower()
    if "log4j" in name:
        return "find /opt -name 'log4j-core-*.jar' -print\n# replace the vulnerable JAR through the approved application release\nsudo systemctl restart <affected-service>\nfind /opt -name 'log4j-core-*.jar' -print"
    if "tomcat" in name:
        return "/opt/tomcat/bin/version.sh\ngrep -n 'Connector.*AJP' /opt/tomcat/conf/server.xml\n# upgrade Tomcat and disable unused AJP or require a secret\nsudo systemctl restart tomcat\n/opt/tomcat/bin/version.sh"
    if "sql server" in name:
        return "SELECT @@VERSION;\n# upgrade to a supported SQL Server release or migrate workload\n# run validation scan after maintenance window"
    if "openssl" in name:
        return "openssl version -a\nsudo apt-get update\nsudo apt-get install --only-upgrade openssl\nsudo systemctl restart <affected-service>\nopenssl version -a"
    if "remote desktop" in name:
        return "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10\n# install the approved Microsoft security update and reboot if required\nGet-Service TermServLicensing\nGet-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10"
    if "chrome" in name:
        return "winget upgrade --id Google.Chrome --exact --silent --accept-source-agreements --accept-package-agreements\n(Get-Item 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe').VersionInfo.FileVersion"
    if "linux kernel" in name:
        return "uname -r\nsudo apt-get update\nsudo apt-get install --only-upgrade linux-image-generic\nsudo reboot\n# after reboot\nuname -r"
    if "cisco ios xe" in name:
        return "show version\nshow running-config | include ^ip http\n# stage and activate the vendor-fixed IOS XE image under the approved network change\nshow version"
    if "exchange" in name:
        return "Get-ExchangeServer | Format-List Name,Edition,AdminDisplayVersion\n# install the approved Exchange Security Update and reboot if required\nGet-ExchangeServer | Format-List Name,Edition,AdminDisplayVersion"
    return "# apply vendor security update\n# restart affected service if required\n# rerun vulnerability scan and confirm closure"


def unique_links(value: str) -> list[str]:
    links = []
    seen = set()
    for raw in str(value or "").replace(",", "|").split("|"):
        link = raw.strip()
        if link.startswith(("http://", "https://")) and link not in seen:
            seen.add(link)
            links.append(link)
    return links


def reference_paragraph(links: list[str], style: ParagraphStyle) -> Paragraph:
    if not links:
        return Paragraph("N/A", style)
    markup = "<br/>".join(
        f'<link href="{escape(link)}" color="#075985">{escape(link)}</link>'
        for link in links
    )
    return Paragraph(markup, style)


def unique_remediation_text(value: str) -> str:
    segments = []
    seen = set()
    for raw in str(value or "").split("|"):
        segment = " ".join(raw.split())
        key = segment.lower()
        if segment and key not in seen:
            seen.add(key)
            segments.append(segment)
    return " ".join(segments) or "Follow the vendor advisory and apply the supported security update."


def footer(canvas, doc) -> None:
    canvas.saveState()
    width, _ = A4
    canvas.setFont(FONT_REGULAR, 8)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.drawString(18 * mm, 10 * mm, "Remediation Guide")
    canvas.drawRightString(width - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def escape(value: object) -> str:
    text = "" if value is None else str(value)
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def source_label_for(findings: list) -> str:
    sources = {finding.source_tool for finding in findings}
    labels = {
        "tenable_sc": "Tenable.sc",
        "tenable_io": "Tenable.io",
        "qualys_monthly": "Qualys",
        "qualys_adhoc": "Qualys",
        "crowdstrike_vulnerabilities": "CrowdStrike",
        "crowdstrike_remediation_assets": "CrowdStrike",
    }
    return " + ".join(sorted({labels.get(source, source) for source in sources})) or "MVA"


if __name__ == "__main__":
    main()
