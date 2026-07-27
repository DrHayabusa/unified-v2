from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from generate_kb_remediation_pdf import ITEMS, RemediationItem


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "output" / "pdf"


styles = getSampleStyleSheet()
styles.add(
    ParagraphStyle(
        name="TitleCenter",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=21,
        leading=25,
        alignment=TA_CENTER,
        spaceAfter=8,
    )
)
styles.add(
    ParagraphStyle(
        name="SubtitleCenter",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#344054"),
        spaceAfter=12,
    )
)
styles.add(
    ParagraphStyle(
        name="Section",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        spaceBefore=9,
        spaceAfter=5,
    )
)
styles.add(
    ParagraphStyle(
        name="Subsection",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=10.5,
        leading=13,
        spaceBefore=6,
        spaceAfter=4,
    )
)
styles.add(
    ParagraphStyle(
        name="Body",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        spaceAfter=4,
    )
)
styles.add(
    ParagraphStyle(
        name="Small",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=7.7,
        leading=10,
        textColor=colors.HexColor("#344054"),
    )
)


def esc(value: object) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", "<br/>")
    )


def p(value: object, style: str = "Body") -> Paragraph:
    return Paragraph(esc(value), styles[style])


def doc(path: Path, title: str) -> SimpleDocTemplate:
    return SimpleDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=20 * mm,
        bottomMargin=18 * mm,
        title=title,
        author="MVA",
    )


def header_footer(label: str):
    def draw(canvas, document) -> None:
        width, height = A4
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#d0d5dd"))
        canvas.line(15 * mm, height - 14 * mm, width - 15 * mm, height - 14 * mm)
        canvas.line(15 * mm, 14 * mm, width - 15 * mm, 14 * mm)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawString(15 * mm, height - 10 * mm, label)
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(width - 15 * mm, height - 10 * mm, "Report Type: Remediation")
        canvas.drawString(15 * mm, 9 * mm, "Confidential")
        canvas.drawRightString(width - 15 * mm, 9 * mm, f"Page {document.page}")
        canvas.restoreState()

    return draw


def control_table(tool_source: str = "Tenable.sc") -> Table:
    rows = [
        ["Report Type", "Remediation"],
        ["Tool Source", tool_source],
        ["Reporting Date", "July 2026"],
        ["Document Type", "Remediation Guide"],
    ]
    data = [[p(left, "Small"), p(right, "Small")] for left, right in rows]
    table = Table(data, colWidths=[40 * mm, 136 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#d0d5dd")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e4e7ec")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f2f4f7")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def code_card(title: str, code: str) -> KeepTogether:
    code_style = ParagraphStyle(
        name=f"Code-{title[:8]}",
        fontName="Courier",
        fontSize=7.4,
        leading=9.4,
        textColor=colors.HexColor("#101828"),
    )
    label_style = ParagraphStyle(
        name=f"CodeLabel-{title[:8]}",
        fontName="Helvetica-Bold",
        fontSize=7.8,
        leading=10,
        textColor=colors.HexColor("#344054"),
    )
    table = Table(
        [[Paragraph(esc(title), label_style)], [Preformatted(code.strip(), code_style)]],
        colWidths=[176 * mm],
    )
    table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#d0d5dd")),
                ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#f2f4f7")),
                ("BACKGROUND", (0, 1), (0, 1), colors.HexColor("#fcfcfd")),
                ("LINEBELOW", (0, 0), (0, 0), 0.4, colors.HexColor("#d0d5dd")),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return KeepTogether([table, Spacer(1, 5)])


def toc_box(items: list[str]) -> Table:
    data = [[p(item, "Body")] for item in items]
    table = Table(data, colWidths=[176 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#d0d5dd")),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fcfcfd")),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def summary_table(items: list[RemediationItem]) -> Table:
    rows = [["Finding", "Asset", "CVE", "Primary Action"]]
    for item in items:
        rows.append([item.title, item.asset, item.cve, item.steps[0]])
    data = [[p(cell, "Small") for cell in row] for row in rows]
    table = Table(data, colWidths=[50 * mm, 40 * mm, 28 * mm, 58 * mm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#d0d5dd")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e4e7ec")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f2f4f7")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def item_metadata(item: RemediationItem) -> Table:
    rows = [
        ["Affected Asset", item.asset],
        ["CVE", item.cve],
        ["Reference Links", "\n".join(item.kb_links)],
    ]
    data = [[p(left, "Small"), p(right, "Small")] for left, right in rows]
    table = Table(data, colWidths=[35 * mm, 141 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#d0d5dd")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e4e7ec")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f2f4f7")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def bullets(values: tuple[str, ...]) -> list[Paragraph]:
    return [p(f"- {value}") for value in values]


def build_option_01() -> Path:
    path = OUT_DIR / "mva_pdf_option_01_executive_remediation_brief.pdf"
    story = [
        Spacer(1, 20),
        p("Executive Remediation Brief", "TitleCenter"),
        p("Board-ready view of remediation priorities and required actions.", "SubtitleCenter"),
        control_table(),
        Spacer(1, 14),
        p("Contents", "Section"),
        toc_box(["1. Executive Summary", "2. Priority Remediation Queue", "3. Remediation Actions", "4. Reference Links"]),
        PageBreak(),
        p("1. Executive Summary", "Section"),
        p("The current remediation window contains several findings requiring operational action. This brief gives leadership and remediation owners a clear view of what must be fixed, which systems are affected, and which reference links support the recommended steps."),
        p("2. Priority Remediation Queue", "Section"),
        summary_table(ITEMS),
        p("3. Remediation Actions", "Section"),
        *bullets(tuple(item.steps[0] for item in ITEMS)),
    ]
    document = doc(path, "Executive Remediation Brief")
    document.build(story, onFirstPage=header_footer("MVA Executive Remediation Brief"), onLaterPages=header_footer("MVA Executive Remediation Brief"))
    return path


def build_option_02() -> Path:
    path = OUT_DIR / "mva_pdf_option_02_technical_runbook.pdf"
    story = [
        p("Technical Remediation Runbook", "TitleCenter"),
        p("Detailed remediation procedure with command blocks and validation checks.", "SubtitleCenter"),
        control_table(),
        Spacer(1, 10),
        p("Contents", "Section"),
        toc_box(["1. Remediation Method", "2. Technical Procedures", "3. Validation Requirements"]),
        PageBreak(),
        p("1. Remediation Method", "Section"),
        p("Each procedure below is written as an implementation-ready work instruction. Commands must be reviewed against the target environment before execution."),
        p("2. Technical Procedures", "Section"),
    ]
    for idx, item in enumerate(ITEMS[:3], start=1):
        story.extend([p(f"2.{idx} {item.title}", "Section"), item_metadata(item), p("Steps to Remediate", "Subsection"), *bullets(item.steps), p("Commands", "Subsection")])
        for label, command in item.commands[:2]:
            story.append(code_card(label, command))
        story.extend([p("Validation", "Subsection"), *bullets(item.validation)])
    document = doc(path, "Technical Remediation Runbook")
    document.build(story, onFirstPage=header_footer("MVA Technical Remediation Runbook"), onLaterPages=header_footer("MVA Technical Remediation Runbook"))
    return path


def build_option_03() -> Path:
    path = OUT_DIR / "mva_pdf_option_03_change_advisory_pack.pdf"
    story = [
        p("Change Advisory Remediation Pack", "TitleCenter"),
        p("CAB-friendly remediation document with implementation, rollback, and validation sections.", "SubtitleCenter"),
        control_table(),
        Spacer(1, 10),
        p("Contents", "Section"),
        toc_box(["1. Change Summary", "2. Implementation Plan", "3. Rollback Guidance", "4. Validation Plan"]),
        PageBreak(),
        p("1. Change Summary", "Section"),
        summary_table(ITEMS[:3]),
        p("2. Implementation Plan", "Section"),
    ]
    for idx, item in enumerate(ITEMS[:3], start=1):
        story.extend(
            [
                p(f"2.{idx} {item.title}", "Section"),
                item_metadata(item),
                p("Pre-Change Checks", "Subsection"),
                *bullets((item.steps[0], "Confirm maintenance window and business owner approval.", "Confirm backup, snapshot, or rollback evidence exists.")),
                p("Implementation Steps", "Subsection"),
                *bullets(item.steps[1:]),
                p("Rollback Guidance", "Subsection"),
                p("If the change causes service impact, revert the configuration backup or restore the approved pre-change snapshot, restart the affected service, and validate service health before closing the change."),
                p("Command Examples", "Subsection"),
                code_card(item.commands[0][0], item.commands[0][1]),
            ]
        )
    document = doc(path, "Change Advisory Remediation Pack")
    document.build(story, onFirstPage=header_footer("MVA Change Advisory Pack"), onLaterPages=header_footer("MVA Change Advisory Pack"))
    return path


def build_option_04() -> Path:
    path = OUT_DIR / "mva_pdf_option_04_asset_owner_action_plan.pdf"
    owner_rows = [["Owner Team", "Finding", "Asset", "Required Action", "Evidence Required"]]
    owners = ["Application Team", "Network Team", "Database Team", "Windows Platform Team"]
    for owner, item in zip(owners, ITEMS):
        owner_rows.append([owner, item.title, item.asset, item.steps[0], item.validation[0]])
    table = Table([[p(cell, "Small") for cell in row] for row in owner_rows], colWidths=[34 * mm, 45 * mm, 33 * mm, 42 * mm, 42 * mm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#d0d5dd")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e4e7ec")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f2f4f7")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story = [
        p("Asset Owner Action Plan", "TitleCenter"),
        p("Task-oriented report for distributing remediation work to responsible teams.", "SubtitleCenter"),
        control_table(),
        Spacer(1, 10),
        p("Contents", "Section"),
        toc_box(["1. Owner Action Matrix", "2. Team Instructions", "3. Evidence Requirements"]),
        PageBreak(),
        p("1. Owner Action Matrix", "Section"),
        table,
        p("2. Team Instructions", "Section"),
    ]
    for owner, item in zip(owners, ITEMS):
        story.extend([p(f"{owner}: {item.title}", "Subsection"), *bullets(item.steps[:3]), code_card(item.commands[0][0], item.commands[0][1])])
    document = doc(path, "Asset Owner Action Plan")
    document.build(story, onFirstPage=header_footer("MVA Asset Owner Action Plan"), onLaterPages=header_footer("MVA Asset Owner Action Plan"))
    return path


def build_option_05() -> Path:
    path = OUT_DIR / "mva_pdf_option_05_evidence_validation_pack.pdf"
    rows = [["Finding", "Evidence Source", "Validation Required", "Closure Evidence"]]
    for item in ITEMS:
        rows.append([item.title, "\n".join(item.kb_links[:2]), item.validation[0], "Follow-up scan result, command output, and change record."])
    table = Table([[p(cell, "Small") for cell in row] for row in rows], colWidths=[48 * mm, 52 * mm, 48 * mm, 48 * mm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#d0d5dd")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e4e7ec")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f2f4f7")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story = [
        p("Evidence and Validation Pack", "TitleCenter"),
        p("Audit-friendly remediation evidence, validation commands, and closure requirements.", "SubtitleCenter"),
        control_table(),
        Spacer(1, 10),
        p("Contents", "Section"),
        toc_box(["1. Evidence Matrix", "2. Validation Commands", "3. Closure Checklist"]),
        PageBreak(),
        p("1. Evidence Matrix", "Section"),
        table,
        p("2. Validation Commands", "Section"),
    ]
    for item in ITEMS:
        story.extend([p(item.title, "Subsection"), code_card(item.commands[-1][0], item.commands[-1][1])])
    story.extend([p("3. Closure Checklist", "Section"), *bullets(("Attach command output to the change record.", "Attach follow-up scan evidence.", "Confirm asset, port, protocol, and plugin/definition ID no longer appear as open.", "Record exceptions separately with risk acceptance evidence."))])
    document = doc(path, "Evidence and Validation Pack")
    document.build(story, onFirstPage=header_footer("MVA Evidence and Validation Pack"), onLaterPages=header_footer("MVA Evidence and Validation Pack"))
    return path


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for path in [build_option_01(), build_option_02(), build_option_03(), build_option_04(), build_option_05()]:
        print(path)


if __name__ == "__main__":
    main()
