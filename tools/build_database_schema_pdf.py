#!/usr/bin/env python3
"""Build the email-ready MVA database schema PDF."""

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "output" / "pdf" / "MVA_Database_Schema_and_AI_Integration.pdf"
PAGE_W, PAGE_H = landscape(A4)

NAVY = colors.HexColor("#0B1220")
INK = colors.HexColor("#172033")
MUTED = colors.HexColor("#5C687A")
PALE = colors.HexColor("#F2F5F9")
LINE = colors.HexColor("#D9E0E8")
RED = colors.HexColor("#C92A35")
TEAL = colors.HexColor("#0B7285")
GREEN = colors.HexColor("#2B8A3E")
WHITE = colors.white


def register_fonts():
    candidates = [
        (
            "/System/Library/Fonts/Supplemental/Arial.ttf",
            "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
        ),
        (
            "/Library/Fonts/Arial.ttf",
            "/Library/Fonts/Arial Bold.ttf",
        ),
    ]
    for regular, bold in candidates:
        if Path(regular).exists() and Path(bold).exists():
            pdfmetrics.registerFont(TTFont("MVARegular", regular))
            pdfmetrics.registerFont(TTFont("MVABold", bold))
            return "MVARegular", "MVABold"
    return "Helvetica", "Helvetica-Bold"


REGULAR, BOLD = register_fonts()


def styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "Title", parent=base["Title"], fontName=BOLD, fontSize=29,
            leading=33, textColor=WHITE, alignment=TA_LEFT, spaceAfter=5 * mm,
        ),
        "subtitle": ParagraphStyle(
            "Subtitle", parent=base["Normal"], fontName=REGULAR, fontSize=12,
            leading=18, textColor=colors.HexColor("#D9E2EF"),
        ),
        "h1": ParagraphStyle(
            "H1", parent=base["Heading1"], fontName=BOLD, fontSize=20,
            leading=24, textColor=NAVY, spaceBefore=1 * mm, spaceAfter=4 * mm,
        ),
        "h2": ParagraphStyle(
            "H2", parent=base["Heading2"], fontName=BOLD, fontSize=13,
            leading=17, textColor=RED, spaceBefore=3 * mm, spaceAfter=2 * mm,
        ),
        "body": ParagraphStyle(
            "Body", parent=base["BodyText"], fontName=REGULAR, fontSize=8.6,
            leading=12.2, textColor=INK, spaceAfter=2.5 * mm,
        ),
        "small": ParagraphStyle(
            "Small", parent=base["BodyText"], fontName=REGULAR, fontSize=7.2,
            leading=9.5, textColor=MUTED,
        ),
        "cell": ParagraphStyle(
            "Cell", parent=base["BodyText"], fontName=REGULAR, fontSize=6.7,
            leading=8.5, textColor=INK,
        ),
        "cell_bold": ParagraphStyle(
            "CellBold", parent=base["BodyText"], fontName=BOLD, fontSize=6.7,
            leading=8.5, textColor=INK,
        ),
        "header_cell": ParagraphStyle(
            "HeaderCell", parent=base["BodyText"], fontName=BOLD, fontSize=6.7,
            leading=8.5, textColor=WHITE,
        ),
        "diagram_title": ParagraphStyle(
            "DiagramTitle", parent=base["Heading2"], fontName=BOLD, fontSize=9,
            leading=11, textColor=WHITE, alignment=TA_CENTER,
        ),
        "diagram_body": ParagraphStyle(
            "DiagramBody", parent=base["BodyText"], fontName=REGULAR, fontSize=6.3,
            leading=7.7, textColor=colors.HexColor("#E4EAF2"), alignment=TA_LEFT,
        ),
    }


ST = styles()


def paragraph(value, style="cell"):
    return Paragraph(str(value), ST[style])


def page_decor(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, PAGE_H - 15 * mm, PAGE_W, 15 * mm, stroke=0, fill=1)
    canvas.setFillColor(RED)
    canvas.rect(0, PAGE_H - 15.8 * mm, PAGE_W, 0.8 * mm, stroke=0, fill=1)
    canvas.setFont(BOLD, 8)
    canvas.setFillColor(WHITE)
    canvas.drawString(14 * mm, PAGE_H - 9.5 * mm, "MVA UNIFIED VULNERABILITY MANAGEMENT PLATFORM")
    canvas.setFont(REGULAR, 7)
    canvas.setFillColor(MUTED)
    canvas.drawRightString(PAGE_W - 14 * mm, 8 * mm, f"Database Schema and AI Integration  |  Page {doc.page}")
    canvas.restoreState()


def cover_page(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)
    canvas.setFillColor(RED)
    canvas.rect(0, 0, 8 * mm, PAGE_H, stroke=0, fill=1)
    canvas.setStrokeColor(colors.HexColor("#263248"))
    canvas.setLineWidth(0.6)
    for x in range(25, int(PAGE_W / mm), 18):
        canvas.line(x * mm, 0, x * mm, PAGE_H)
    for y in range(15, int(PAGE_H / mm), 18):
        canvas.line(0, y * mm, PAGE_W, y * mm)
    canvas.restoreState()


def table(data, widths, header=True, font_size=6.7, row_padding=3.2):
    converted = []
    for row_index, row in enumerate(data):
        converted.append([
            value if isinstance(value, Paragraph) else paragraph(value, "header_cell" if header and row_index == 0 else "cell")
            for value in row
        ])
    result = Table(converted, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    commands = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.35, LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), row_padding),
        ("RIGHTPADDING", (0, 0), (-1, -1), row_padding),
        ("TOPPADDING", (0, 0), (-1, -1), row_padding),
        ("BOTTOMPADDING", (0, 0), (-1, -1), row_padding),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, PALE]),
        ("FONTSIZE", (0, 0), (-1, -1), font_size),
    ]
    if header:
        commands.extend([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ])
    result.setStyle(TableStyle(commands))
    return result


def entity_card(title, fields, width=52 * mm):
    rows = [[paragraph(title, "diagram_title")], [paragraph("<br/>".join(fields), "diagram_body")]]
    card = Table(rows, colWidths=[width], rowHeights=[10 * mm, None])
    card.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), RED),
        ("BACKGROUND", (0, 1), (0, 1), NAVY),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#39465B")),
        ("LEFTPADDING", (0, 1), (0, 1), 4),
        ("RIGHTPADDING", (0, 1), (0, 1), 4),
        ("TOPPADDING", (0, 1), (0, 1), 5),
        ("BOTTOMPADDING", (0, 1), (0, 1), 5),
    ]))
    return card


TABLE_DIRECTORY = [
    ("customers", "Tenant/customer master", "id", "Parent for tenant-owned records"),
    ("users", "Platform identities", "id", "Sessions, memberships, creator and actor references"),
    ("customer_memberships", "Tenant access and role", "customer_id + user_id", "Customer and user"),
    ("auth_sessions", "Authenticated sessions and CSRF", "id", "User"),
    ("customer_teams", "Responsible groups", "id", "Customer"),
    ("customer_assets", "In-scope asset inventory", "id", "Customer and optional team"),
    ("customer_asset_aliases", "Alternate asset identities", "customer_id + alias", "Customer and asset"),
    ("scan_runs", "Saved analyses", "id", "Customer and optional creator"),
    ("ingestion_chunks", "Chunked upload ledger", "scan_run_id + chunk_index", "Scan run"),
    ("finding_observations", "Normalized findings", "scan_run_id + row_index", "Scan run"),
    ("threat_intel_imports", "Threat evidence imports", "id", "Customer and optional creator"),
    ("threat_intel_records", "Searchable scanner evidence", "import_id + row_index", "Import and customer"),
    ("threat_intel_enrichments", "Local-model outputs", "id", "Customer and optional creator"),
    ("audit_events", "Security audit trail", "id", "Optional user and customer"),
]


SCHEMA_GROUPS = [
    (
        "Tenant, identity, and asset tables",
        [
            ("customers", "id uuid PK; name; slug UNIQUE; status; asset_scope_mode; notes; created_at; updated_at"),
            ("users", "id uuid PK; email UNIQUE; full_name; password_hash; global_role; status; timestamps"),
            ("customer_memberships", "customer_id FK; user_id FK; role; asset_types[]; created_at; composite PK"),
            ("auth_sessions", "id uuid PK; user_id FK; token_hash UNIQUE; csrf_token; user_agent; ip_address; session timestamps"),
            ("customer_teams", "id uuid PK; customer_id FK; name; code; description; timestamps; tenant-unique name/code"),
            ("customer_assets", "id uuid PK; customer_id FK; asset_key; IP/DNS/host; platform; asset_type; tool; team_id; scope/exposure; timestamps"),
            ("customer_asset_aliases", "customer_id FK; asset_id FK; alias; created_at; composite PK"),
        ],
    ),
    (
        "Scan ingestion and findings",
        [
            ("scan_runs", "id uuid PK; customer_id FK; created_by FK; workflow; source; period; counters; status; dashboard JSON; timestamps"),
            ("ingestion_chunks", "scan_run_id FK; chunk_index; start_index; row_count; created_at; composite PK"),
            ("finding_observations", "scan/row PK; finding, scanner and asset identities; risk; lifecycle; guidance; network/scanner/OpenShift evidence; normalized JSON"),
        ],
    ),
    (
        "Threat intelligence and audit",
        [
            ("threat_intel_imports", "id uuid PK; customer_id FK; created_by FK; ingestion key; files; counters; status; timestamps"),
            ("threat_intel_records", "import/row PK; customer FK; CVE and asset/workload identity; risk; evidence; guidance; normalized JSON"),
            ("threat_intel_enrichments", "id uuid PK; customer_id FK; created_by FK; query; model; evidence_count; response_text; created_at"),
            ("audit_events", "id bigserial PK; actor_user_id FK; customer_id FK; event_type; event_data JSON; IP; created_at"),
        ],
    ),
]


FINDING_GROUPS = [
    ("Record identity", "scan_run_id, row_index, report_period, report_period_date, finding_key"),
    ("Scanner identity", "source_tool, source_tools[], source_display, source_vulnerability_id"),
    ("Asset identity", "ip_address, dns_name, product, platform_details"),
    ("Vulnerability", "vulnerability_name, cve, vulnerability_finding"),
    ("Risk", "severity, exploit_available, exploit_signal, epss_score, patch_priority, asset_exposure, cvss_score"),
    ("Guidance", "summary, description, remediation, kb_links"),
    ("Lifecycle", "first_discovered, last_observed, vulnerability_age_days, times_detected, record_count"),
    ("Network", "protocol, port, internet_exposed, internet_exposure_known"),
    ("Scanner evidence", "datacentre, vendor_severity_label, vulnerability_status, vulnerability_confidence, exploit_evidence_source, threat, impact"),
    ("OpenShift", "namespace, deployment, image, component, fixable, fixable_signal, fixed_in"),
    ("Original evidence", "normalized_payload jsonb"),
]


def build_story():
    story = []
    story.extend([
        Spacer(1, 38 * mm),
        Paragraph("MVA Unified Vulnerability<br/>Management Platform", ST["title"]),
        Paragraph("Database Schema and AI Integration Overview", ST["subtitle"]),
        Spacer(1, 12 * mm),
        HRFlowable(width=80 * mm, thickness=2, color=RED, hAlign="LEFT"),
        Spacer(1, 8 * mm),
        Paragraph(
            "Email-ready architecture reference for database, application, infrastructure, "
            "security, and local AI-platform teams.",
            ParagraphStyle("CoverBody", parent=ST["subtitle"], fontSize=10, leading=15, textColor=colors.HexColor("#B7C2D2")),
        ),
        Spacer(1, 22 * mm),
        paragraph("<b>Database</b>  PostgreSQL 17", "subtitle"),
        paragraph("<b>Application API</b>  Node.js / Fastify", "subtitle"),
        paragraph("<b>AI boundary</b>  Server-side localLlm.js adapter", "subtitle"),
        PageBreak(),
    ])

    story.extend([
        Paragraph("1. Schema at a Glance", ST["h1"]),
        Paragraph(
            "The platform uses fourteen application tables. Tenant-owned operational records are isolated by "
            "customer_id, scanner findings are retained under their scan run, and local-model outputs are recorded "
            "separately from source evidence.",
            ST["body"],
        ),
        table(
            [["Table", "Purpose", "Primary key", "Relationship"]] + TABLE_DIRECTORY,
            [43 * mm, 58 * mm, 48 * mm, 102 * mm],
            font_size=6.4,
            row_padding=2.8,
        ),
        Spacer(1, 4 * mm),
        Paragraph(
            "<b>Authoritative source:</b> server/migrations/001_initial.sql through "
            "011_openshift_workload_evidence.sql. The API applies migration files in sorted order at startup.",
            ST["small"],
        ),
        PageBreak(),
    ])

    story.extend([
        Paragraph("2. Relationship Model", ST["h1"]),
        Paragraph(
            "The relationship model is separated into readable domains. Lines below represent foreign-key ownership; "
            "optional creator and actor references preserve history by becoming null when a user is removed.",
            ST["body"],
        ),
    ])
    domain_rows = [
        [
            entity_card("TENANT & ACCESS", [
                "customers 1:N memberships",
                "users 1:N memberships",
                "users 1:N sessions",
                "customers 1:N teams",
            ], 76 * mm),
            entity_card("ASSET INVENTORY", [
                "customers 1:N assets",
                "teams 0..1:N assets",
                "assets 1:N aliases",
                "asset_key unique per tenant",
            ], 76 * mm),
            entity_card("SCAN EVIDENCE", [
                "customers 1:N scan_runs",
                "scan_runs 1:N chunks",
                "scan_runs 1:N findings",
                "delete scan cascades evidence",
            ], 76 * mm),
        ],
        [
            entity_card("THREAT INTELLIGENCE", [
                "customers 1:N imports",
                "imports 1:N records",
                "customers 1:N enrichments",
                "user creator is optional",
            ], 76 * mm),
            entity_card("AUDIT", [
                "user 0..1:N audit_events",
                "customer 0..1:N audit_events",
                "event_data stored as JSON",
                "actor deletion preserves event",
            ], 76 * mm),
            entity_card("RETENTION BOUNDARY", [
                "asset delete removes aliases",
                "historical findings remain",
                "customer delete cascades data",
                "explicit purge for full erasure",
            ], 76 * mm),
        ],
    ]
    domains = Table(domain_rows, colWidths=[82 * mm, 82 * mm, 82 * mm], hAlign="LEFT")
    domains.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3 * mm),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3 * mm),
        ("TOPPADDING", (0, 0), (-1, -1), 4 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4 * mm),
    ]))
    story.extend([domains, Spacer(1, 5 * mm)])
    relationship_rows = [
        ["Parent", "Child", "Cardinality", "Delete behavior"],
        ["customers", "memberships, teams, assets, scans, threat records", "1 to many", "Cascade"],
        ["users", "sessions and memberships", "1 to many", "Cascade"],
        ["users", "scan/import/enrichment creator and audit actor", "0/1 to many", "Set null"],
        ["customer_teams", "customer_assets", "0/1 to many", "Set team_id null"],
        ["customer_assets", "customer_asset_aliases", "1 to many", "Cascade"],
        ["scan_runs", "ingestion_chunks and finding_observations", "1 to many", "Cascade"],
        ["threat_intel_imports", "threat_intel_records", "1 to many", "Cascade"],
    ]
    story.extend([table(relationship_rows, [50 * mm, 90 * mm, 38 * mm, 70 * mm]), PageBreak()])

    story.extend([
        Paragraph("3. Detailed Table Dictionary", ST["h1"]),
        Paragraph(
            "This is a concise field-level directory. The migration SQL remains the authoritative definition for "
            "data types, defaults, check constraints, and indexes.",
            ST["body"],
        ),
    ])
    for title, rows in SCHEMA_GROUPS:
        story.append(Paragraph(title, ST["h2"]))
        story.append(table([["Table", "Columns and controls"]] + rows, [57 * mm, 190 * mm], font_size=6.5))
        story.append(Spacer(1, 2.5 * mm))
    story.append(PageBreak())

    story.extend([
        Paragraph("4. Normalized Finding Schema", ST["h1"]),
        Paragraph(
            "finding_observations is the analytical fact table. Each normalized row is tied to one scan run and "
            "retains both standardized fields and the original normalized payload.",
            ST["body"],
        ),
        table([["Field group", "Columns"]] + FINDING_GROUPS, [49 * mm, 198 * mm], font_size=6.6, row_padding=3.6),
        Spacer(1, 5 * mm),
        Paragraph("Database-enforced controls", ST["h2"]),
        table(
            [
                ["Control", "Rule"],
                ["Severity", "Critical, High, Medium, Low, Info, or Unknown"],
                ["Patch priority", "P1, P2, P3, or P4"],
                ["EPSS", "Null or 0 through 1"],
                ["Asset exposure", "0 through 1000"],
                ["CVSS", "Null or 0 through 10"],
                ["Age and counts", "Non-negative age; positive record and detection counts"],
            ],
            [60 * mm, 187 * mm],
        ),
        PageBreak(),
    ])

    story.extend([
        Paragraph("5. AI Integration in Simple Terms", ST["h1"]),
        Paragraph(
            "When an analyst clicks Generate PDF, the browser does not call the AI server. It calls the stable MVA "
            "API. Fastify authenticates the user, verifies tenant access, validates the request, and builds the "
            "instructions. The API then calls the single localLlm.js adapter.",
            ST["body"],
        ),
    ])
    flow = [
        ["1", "React UI", "POST /api/v1/customers/:customerId/ai/remediation"],
        ["2", "Fastify API", "Authenticate, authorize, validate, and build prompt"],
        ["3", "localLlm.js", "POST {OLLAMA_BASE_URL}/api/chat"],
        ["4", "Local AI server", "Return generated Markdown"],
        ["5", "Fastify API", "Audit model and target period; return Markdown"],
        ["6", "React UI", "Convert Markdown into the downloadable Remediation Guide PDF"],
    ]
    story.extend([
        table([["Step", "Component", "Action"]] + flow, [20 * mm, 55 * mm, 172 * mm], row_padding=4),
        Spacer(1, 6 * mm),
        Paragraph("What production normally changes", ST["h2"]),
        table(
            [
                ["Requirement", "Location"],
                ["AI server address", "OLLAMA_BASE_URL in the MVA API environment"],
                ["Model selection", "OLLAMA_MODEL in the MVA API environment"],
                ["Timeout", "OLLAMA_TIMEOUT_MS in the MVA API environment"],
                ["Protected endpoint key", "Docker secret mounted as OLLAMA_API_KEY_FILE"],
                ["Authentication format", "OLLAMA_AUTH_HEADER and OLLAMA_AUTH_SCHEME"],
                ["Native Ollama to OpenAI-compatible protocol", "Only server/src/localLlm.js"],
                ["Report instructions", "Prompt builder and Fastify system prompt"],
            ],
            [92 * mm, 155 * mm],
        ),
        Spacer(1, 5 * mm),
        Paragraph(
            "<b>Key point:</b> When the production AI service exposes the native Ollama API, the browser endpoints "
            "and Fastify routes remain unchanged. Configure the server environment and secret. Edit localLlm.js only "
            "when the AI server uses a different protocol, endpoint path, authentication method, request body, or "
            "response structure.",
            ST["body"],
        ),
        PageBreak(),
    ])

    story.extend([
        Paragraph("6. Production Security and Operations", ST["h1"]),
        Paragraph("Recommended production configuration boundary", ST["h2"]),
        table(
            [
                ["Setting", "Example", "Storage"],
                ["OLLAMA_BASE_URL", "https://ai.internal.example", "Server environment"],
                ["OLLAMA_MODEL", "gemma3:12b", "Server environment"],
                ["OLLAMA_TIMEOUT_MS", "600000", "Server environment"],
                ["OLLAMA_API_KEY_FILE", "/run/secrets/ollama_api_key", "Container environment points to secret"],
                ["OLLAMA_AUTH_HEADER", "Authorization", "Server environment"],
                ["OLLAMA_AUTH_SCHEME", "Bearer", "Server environment"],
            ],
            [64 * mm, 88 * mm, 95 * mm],
        ),
        Spacer(1, 6 * mm),
        Paragraph("Security controls", ST["h2"]),
        table(
            [
                ["Control", "Requirement"],
                ["Secret handling", "Never commit keys or place them in React, VITE variables, browser storage, or URLs"],
                ["Network path", "Allow only MVA API to local AI server on the approved TCP port"],
                ["Browser access", "Users access MVA; users do not require direct reachability to Ollama"],
                ["Authorization", "Tenant role is checked before test, remediation, or enrichment requests"],
                ["Request safety", "Timeouts and bounded token limits are enforced by localLlm.js"],
                ["Evidence handling", "Only normalized, request-relevant evidence is sent to the selected local model"],
                ["Auditability", "Model, action, customer, actor, target period, and evidence count are recorded"],
            ],
            [60 * mm, 187 * mm],
        ),
        Spacer(1, 7 * mm),
        Paragraph("Migration operation", ST["h2"]),
        Paragraph(
            "At startup, repository.js reads all SQL files under server/migrations, sorts them, and executes them. "
            "The existing files are designed to be repeatable. For stricter production governance, add a migration "
            "ledger with applied-version and checksum tracking.",
            ST["body"],
        ),
        Spacer(1, 8 * mm),
        HRFlowable(width="100%", thickness=0.8, color=LINE),
        Spacer(1, 4 * mm),
        Paragraph(
            "Document generated from the repository's current PostgreSQL migrations and AI call architecture. "
            "Validate the final production schema against PostgreSQL after deployment using psql or the approved "
            "database-management platform.",
            ST["small"],
        ),
    ])
    return story


def build_pdf():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    frame = Frame(13 * mm, 13 * mm, PAGE_W - 26 * mm, PAGE_H - 32 * mm, id="content")
    document = BaseDocTemplate(
        str(OUTPUT),
        pagesize=landscape(A4),
        leftMargin=13 * mm,
        rightMargin=13 * mm,
        topMargin=19 * mm,
        bottomMargin=13 * mm,
        title="MVA Database Schema and AI Integration Overview",
        author="MVA Unified Vulnerability Management Platform",
        subject="PostgreSQL schema, relationships, retention, and local AI integration",
    )
    document.addPageTemplates([
        PageTemplate(id="cover", frames=[frame], onPage=cover_page, autoNextPageTemplate="body"),
        PageTemplate(id="body", frames=[frame], onPage=page_decor),
    ])
    document.build(build_story())
    print(OUTPUT)


if __name__ == "__main__":
    build_pdf()
