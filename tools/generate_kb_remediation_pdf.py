from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.enums import TA_LEFT
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
from reportlab.platypus.tableofcontents import TableOfContents


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "output" / "pdf"


@dataclass(frozen=True)
class RemediationItem:
    title: str
    asset: str
    cve: str
    kb_links: tuple[str, ...]
    source_basis: str
    steps: tuple[str, ...]
    commands: tuple[tuple[str, str], ...]
    validation: tuple[str, ...]


ITEMS = [
    RemediationItem(
        title="Apache Tomcat AJP Request Injection and Potential RCE",
        asset="10.20.1.234 / web-prod-01 / TCP 8009",
        cve="CVE-2020-1938",
        kb_links=(
            "https://tomcat.apache.org/security-9.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-1938",
        ),
        source_basis=(
            "Apache and NVD describe this as an AJP trust/configuration issue affecting Tomcat versions before "
            "9.0.31, 8.5.51, and 7.0.100 when the AJP connector is accessible to untrusted users."
        ),
        steps=(
            "Confirm whether the affected host is running a vulnerable Tomcat release and whether AJP is listening on TCP 8009.",
            "If AJP is not required, disable the AJP connector in server.xml and restart Tomcat.",
            "If AJP is required, upgrade Tomcat to a fixed release and restrict AJP to a trusted interface or loopback address.",
            "Configure an AJP shared secret when AJP must remain enabled, and align the reverse proxy connector with the same secret.",
            "Confirm TCP 8009 is not reachable from untrusted networks after the change.",
        ),
        commands=(
            (
                "Identify Tomcat version and AJP listener",
                """# Run on the Tomcat host
export CATALINA_BASE=${CATALINA_BASE:-/opt/tomcat}
export CATALINA_HOME=${CATALINA_HOME:-/opt/tomcat}
$CATALINA_HOME/bin/version.sh
sudo ss -lntp | grep ':8009' || true
sudo grep -R \"protocol=\\\"AJP\" \"$CATALINA_BASE/conf\" \"$CATALINA_HOME/conf\" 2>/dev/null""",
            ),
            (
                "Disable AJP when not required",
                """# Back up the config, comment out the AJP Connector in server.xml, then restart
sudo cp \"$CATALINA_BASE/conf/server.xml\" \"$CATALINA_BASE/conf/server.xml.bak.$(date +%F)\"
sudo vi \"$CATALINA_BASE/conf/server.xml\"
sudo systemctl restart tomcat || sudo systemctl restart tomcat9""",
            ),
            (
                "Secure AJP when it is required",
                """<!-- Example server.xml connector - adjust secret and address for the environment -->
<Connector protocol=\"AJP/1.3\"
           address=\"127.0.0.1\"
           port=\"8009\"
           secretRequired=\"true\"
           secret=\"CHANGE_ME_TO_A_LONG_RANDOM_SECRET\" />""",
            ),
        ),
        validation=(
            "Run a new authenticated vulnerability scan and confirm the CVE-2020-1938 finding is closed.",
            "Confirm TCP 8009 is reachable only from the approved reverse proxy or local host.",
            "Attach the changed server.xml and Tomcat version output to the change ticket.",
        ),
    ),
    RemediationItem(
        title="SSL Certificate Cannot Be Trusted",
        asset="10.20.1.235 / vpn-gw-02 / TCP 443",
        cve="Not provided",
        kb_links=(
            "https://www.tenable.com/plugins/nessus/51192",
            "https://docs.tenable.com/whitepapers/useful-plugins/Content/UsefulPlugins/Resolving51192.htm",
            "https://docs.openssl.org/3.0/man1/openssl-s_client/",
            "https://docs.openssl.org/3.0/man1/openssl-verify/",
        ),
        source_basis=(
            "Tenable plugin 51192 indicates the server certificate chain cannot be trusted. Tenable notes common causes such as an unknown/self-signed issuer, missing intermediates, invalid dates, or a signature that cannot be verified."
        ),
        steps=(
            "Identify the service, hostname, port, certificate subject, issuer, expiry, and chain presented by the affected asset.",
            "If the certificate is self-signed or issued by an internal CA, either replace it with an approved publicly trusted certificate or add the internal CA to the scanner trust configuration where appropriate.",
            "If the certificate chain is incomplete, install the required intermediate certificates on the service.",
            "If the certificate is expired or has the wrong subject/SAN, request and deploy a corrected certificate from the approved CA.",
            "Rerun the scan after the certificate chain validates cleanly.",
        ),
        commands=(
            (
                "Collect certificate and chain from the service",
                """# Replace DNS and port with the affected service from the CSV
openssl s_client -connect vpn-gw-02:443 -servername vpn-gw-02 -showcerts </dev/null > vpn-gw-02_chain.txt
openssl x509 -in vpn-gw-02_chain.txt -noout -subject -issuer -dates -ext subjectAltName""",
            ),
            (
                "Verify certificate chain with an approved CA bundle",
                """# Use the approved enterprise/public CA bundle path for the target environment
openssl verify -CAfile approved-ca-bundle.pem vpn-gw-02_leaf.pem""",
            ),
            (
                "Tenable scanner trust handling when an internal CA is valid",
                """# Tenable VM/Nessus: upload PEM encoded internal CA as documented by Tenable.
# Tenable.sc: create custom_CA.inc and custom_feed_info.inc, then upload the custom plugin feed bundle.""",
            ),
        ),
        validation=(
            "Confirm OpenSSL chain verification returns OK using the approved CA bundle.",
            "Confirm the service presents the complete chain after restart or reload.",
            "Rerun Tenable and confirm plugin 51192 is no longer reported for the asset/port.",
        ),
    ),
    RemediationItem(
        title="Microsoft SQL Server Unsupported Version Detection",
        asset="10.20.2.118 / sql-prod-03 / TCP 1433",
        cve="Not provided",
        kb_links=(
            "https://learn.microsoft.com/en-us/sql/sql-server/end-of-support/sql-server-end-of-support-overview",
            "https://learn.microsoft.com/en-us/troubleshoot/sql/releases/find-my-sql-version",
            "https://learn.microsoft.com/en-us/troubleshoot/sql/releases/download-and-install-latest-updates",
            "https://learn.microsoft.com/en-us/sql/database-engine/install-windows/upgrade-sql-server",
        ),
        source_basis=(
            "Microsoft states that SQL Server versions have a support lifecycle and that end of support means Microsoft no longer provides servicing and support. Microsoft recommends upgrade, migration, or ESU where eligible."
        ),
        steps=(
            "Confirm the SQL Server version, edition, product level, and build number.",
            "Compare the detected build with Microsoft lifecycle and latest-update guidance.",
            "Back up all affected databases and verify the backup before upgrade or migration.",
            "Choose the remediation path: in-place upgrade, side-by-side migration, Azure SQL migration, or Extended Security Updates when eligible.",
            "Patch to a supported SQL Server build and rerun validation queries after upgrade.",
        ),
        commands=(
            (
                "Identify SQL Server version and edition",
                """-- Run in SSMS or sqlcmd against the affected instance
SELECT @@VERSION;
SELECT
  SERVERPROPERTY('ProductVersion') AS ProductVersion,
  SERVERPROPERTY('ProductLevel') AS ProductLevel,
  SERVERPROPERTY('Edition') AS Edition;""",
            ),
            (
                "Back up and verify before remediation",
                """-- Replace DBName and path for the target environment
BACKUP DATABASE [DBName]
TO DISK = 'D:\\Backup\\DBName_pre_upgrade.bak'
WITH CHECKSUM, INIT;

RESTORE VERIFYONLY
FROM DISK = 'D:\\Backup\\DBName_pre_upgrade.bak'
WITH CHECKSUM;""",
            ),
            (
                "Post-upgrade validation",
                """SELECT @@VERSION;
SELECT name, state_desc, compatibility_level
FROM sys.databases
ORDER BY name;""",
            ),
        ),
        validation=(
            "Confirm the version/build maps to a supported Microsoft lifecycle state.",
            "Confirm application smoke tests and database jobs complete successfully.",
            "Rerun the vulnerability scan and confirm the unsupported SQL Server finding is closed.",
        ),
    ),
    RemediationItem(
        title="SMB Signing Not Required",
        asset="10.40.8.21 / win-file-07 / TCP 445",
        cve="Not provided",
        kb_links=(
            "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing",
            "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview",
            "https://learn.microsoft.com/en-us/powershell/module/smbshare/set-smbserverconfiguration",
        ),
        source_basis=(
            "Microsoft documents SMB signing as a control that verifies data integrity and helps prevent adversary-in-the-middle attacks. Microsoft provides PowerShell and Group Policy methods to require SMB signing."
        ),
        steps=(
            "Check whether SMB signing is required for both SMB client and SMB server configuration.",
            "Enable SMB server signing for inbound connections on file servers.",
            "Enable SMB client signing for outbound connections on endpoints and servers that initiate SMB sessions.",
            "For domain rollout, configure the matching Group Policy settings under Local Policies > Security Options.",
            "Validate configuration and monitor for legacy application or device compatibility issues.",
        ),
        commands=(
            (
                "Check current SMB signing status",
                """Get-SmbClientConfiguration | Format-List RequireSecuritySignature
Get-SmbServerConfiguration | Format-List RequireSecuritySignature""",
            ),
            (
                "Require SMB signing with PowerShell",
                """# Run from an elevated PowerShell session
Set-SmbClientConfiguration -RequireSecuritySignature $true
Set-SmbServerConfiguration -RequireSecuritySignature $true""",
            ),
            (
                "Validate after change",
                """Get-SmbClientConfiguration | Format-List RequireSecuritySignature
Get-SmbServerConfiguration | Format-List RequireSecuritySignature
gpupdate /force""",
            ),
        ),
        validation=(
            "Confirm both RequireSecuritySignature values return True where policy requires signing.",
            "Confirm SMB access still works for approved clients.",
            "Rerun the vulnerability scan and confirm SMB signing is no longer reported as not required.",
        ),
    ),
]


styles = getSampleStyleSheet()
styles.add(
    ParagraphStyle(
        name="DocTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.black,
        alignment=TA_CENTER,
        spaceAfter=10,
    )
)
styles.add(
    ParagraphStyle(
        name="CoverKicker",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#555555"),
        alignment=TA_CENTER,
        spaceAfter=8,
    )
)
styles.add(
    ParagraphStyle(
        name="DocSubtitle",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#333333"),
        alignment=TA_CENTER,
        spaceAfter=12,
    )
)
styles.add(
    ParagraphStyle(
        name="ExecutiveNote",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#222222"),
        borderColor=colors.HexColor("#d8d8d8"),
        borderWidth=0.7,
        borderPadding=8,
        backColor=colors.HexColor("#fafafa"),
        spaceBefore=4,
        spaceAfter=8,
    )
)
styles.add(
    ParagraphStyle(
        name="Section",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.black,
        spaceBefore=10,
        spaceAfter=6,
    )
)
styles.add(
    ParagraphStyle(
        name="Subsection",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=13,
        textColor=colors.black,
        spaceBefore=7,
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
        textColor=colors.black,
        spaceAfter=4,
    )
)
styles.add(
    ParagraphStyle(
        name="Small",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#333333"),
        spaceAfter=3,
    )
)


def esc(value: str) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", "<br/>")
    )


def para(value: str, style: str = "Body") -> Paragraph:
    return Paragraph(esc(value), styles[style])


def heading(value: str, style: str, level: int, key: str) -> Paragraph:
    item = para(value, style)
    item._tocLevel = level
    item._bookmarkName = key
    return item


def bullet_list(items: tuple[str, ...]) -> list[Paragraph]:
    return [para(f"- {item}") for item in items]


def command_block(label: str, command: str) -> list:
    code_style = ParagraphStyle(
        name=f"Code-{label[:10]}",
        fontName="Courier",
        fontSize=7.4,
        leading=9.4,
        leftIndent=0,
        textColor=colors.HexColor("#1f2933"),
    )
    label_style = ParagraphStyle(
        name=f"CodeLabel-{label[:10]}",
        fontName="Helvetica-Bold",
        fontSize=7.8,
        leading=10,
        textColor=colors.HexColor("#344054"),
        alignment=TA_LEFT,
    )
    table = Table(
        [[Paragraph(esc(label), label_style)], [Preformatted(command.strip(), code_style)]],
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
                ("TOPPADDING", (0, 0), (0, 0), 6),
                ("BOTTOMPADDING", (0, 0), (0, 0), 5),
                ("TOPPADDING", (0, 1), (0, 1), 7),
                ("BOTTOMPADDING", (0, 1), (0, 1), 7),
            ]
        )
    )
    return [KeepTogether([table, Spacer(1, 5)])]


def metadata_table(item: RemediationItem) -> Table:
    rows = [
        ["Affected Asset", item.asset],
        ["CVE", item.cve],
        ["Reference Links Used", "\n".join(item.kb_links)],
    ]
    data = [[para(left, "Small"), para(right, "Small")] for left, right in rows]
    table = Table(data, colWidths=[32 * mm, 144 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#888888")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#bbbbbb")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eeeeee")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def document_control_table(tool_source: str = "Tenable.sc") -> Table:
    rows = [
        ["Report Type", "Remediation"],
        ["Tool Source", tool_source],
        ["Reporting Date", "July 2026"],
        ["Document Type", "Remediation Guide"],
    ]
    data = [[para(left, "Small"), para(right, "Small")] for left, right in rows]
    table = Table(data, colWidths=[36 * mm, 140 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#d0d5dd")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e4e7ec")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f2f4f7")),
                ("BACKGROUND", (1, 0), (1, -1), colors.white),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def build_toc() -> TableOfContents:
    toc = TableOfContents()
    toc.dotsMinLevel = 0
    toc.levelStyles = [
        ParagraphStyle(
            name="TOCLevel1",
            fontName="Helvetica-Bold",
            fontSize=9.4,
            leading=15,
            leftIndent=0,
            firstLineIndent=0,
            spaceBefore=4,
            textColor=colors.HexColor("#101828"),
        ),
        ParagraphStyle(
            name="TOCLevel2",
            fontName="Helvetica",
            fontSize=8.7,
            leading=13,
            leftIndent=16,
            firstLineIndent=0,
            spaceBefore=3,
            textColor=colors.HexColor("#344054"),
        ),
    ]
    return toc


class MvaDocTemplate(SimpleDocTemplate):
    def afterFlowable(self, flowable) -> None:
        if not hasattr(flowable, "_tocLevel"):
            return
        text = flowable.getPlainText()
        key = flowable._bookmarkName
        self.canv.bookmarkPage(key)
        self.notify("TOCEntry", (flowable._tocLevel, text, self.page, key))


def page_header_footer(canvas, doc) -> None:
    width, height = A4
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#d0d5dd"))
    canvas.line(15 * mm, height - 14 * mm, width - 15 * mm, height - 14 * mm)
    canvas.line(15 * mm, 14 * mm, width - 15 * mm, 14 * mm)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawString(15 * mm, height - 10 * mm, "MVA Remediation Guide")
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(width - 15 * mm, height - 10 * mm, "Summary Date: July 2026")
    canvas.drawString(15 * mm, 9 * mm, "Confidential")
    canvas.drawRightString(width - 15 * mm, 9 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build_pdf() -> Path:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / "mva_sample_05_kb_remediation_steps.pdf"
    doc = MvaDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=20 * mm,
        bottomMargin=18 * mm,
        title="MVA Remediation Guide Sample",
        author="MVA",
    )

    story = [
        Spacer(1, 18),
        para("MVA UNIFIED AGENT", "CoverKicker"),
        para("Remediation Guide", "DocTitle"),
        para(
            "Remediation guidance with implementation commands and validation checks.",
            "DocSubtitle",
        ),
        Spacer(1, 6),
        document_control_table(),
        Spacer(1, 16),
        para("Contents", "Section"),
        build_toc(),
        PageBreak(),
        heading("1. Executive Overview", "Section", 0, "executive-overview"),
        para(
            "This guide gives remediation teams an execution-ready view of vulnerabilities, remediation steps, command examples, and validation checks. The command blocks are designed to be copied into a change plan after environment-specific review.",
            "ExecutiveNote",
        ),
        heading("2. Remediation Method", "Section", 0, "remediation-method"),
        para(
            "Each remediation item includes affected asset context, references, implementation steps, command examples, and validation requirements. Commands must be reviewed and adapted to the target environment before execution.",
            "Body",
        ),
        heading("3. Remediation Actions", "Section", 0, "remediation-actions"),
        Spacer(1, 8),
    ]

    for index, item in enumerate(ITEMS, start=1):
        if index > 1:
            story.append(Spacer(1, 10))
        story.extend(
            [
                heading(f"3.{index} {item.title}", "Section", 1, f"finding-{index}"),
                metadata_table(item),
                Spacer(1, 6),
                para("Reference Summary", "Subsection"),
                para(item.source_basis),
                para("Steps to Remediate", "Subsection"),
                *bullet_list(item.steps),
                para("Commands", "Subsection"),
            ]
        )
        for label, command in item.commands:
            story.extend(command_block(label, command))
        story.extend(
            [
                para("Validation After Remediation", "Subsection"),
                *bullet_list(item.validation),
            ]
        )

    story.extend(
        [
            Spacer(1, 10),
            heading("4. Validation Requirements", "Section", 0, "validation-requirements"),
            para(
                "Every remediation action should be verified through configuration evidence, service/application health checks, and a follow-up authenticated scan. Closure should be based on the vulnerability no longer appearing for the same asset, port, protocol, and plugin or definition identifier.",
                "Body",
            ),
            heading("5. Reference Appendix", "Section", 0, "reference-appendix"),
            para(
                "Reference links are included to support remediation planning and validation.",
                "Body",
            ),
        ]
    )

    doc.multiBuild(story, onFirstPage=page_header_footer, onLaterPages=page_header_footer)
    return path


if __name__ == "__main__":
    print(build_pdf())
