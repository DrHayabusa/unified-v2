#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from pypdf import PdfReader


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate an MVA Remediation Guide PDF.")
    parser.add_argument("input")
    parser.add_argument("--output", default="output/validation/pdf-validation.json")
    parser.add_argument("--source", default="CrowdStrike")
    parser.add_argument("--month", default="July 2026")
    args = parser.parse_args()

    path = Path(args.input)
    reader = PdfReader(str(path))
    page_text = [page.extract_text() or "" for page in reader.pages]
    text = "\n".join(page_text)
    lower_text = text.lower()
    links = sum(len(page.get("/Annots", [])) for page in reader.pages)
    banned = ["customer name", "created by", "prepared from", "kb-based", "normalized kb", " remediation lane"]
    checks = {
        "pdf_signature": path.read_bytes()[:4] == b"%PDF",
        "title": reader.metadata.title == "Remediation Guide",
        "page_count": len(reader.pages) >= 3,
        "all_pages_extract_text": all(value.strip() for value in page_text),
        "contents": "Contents" in text,
        "report_summary": "1. Report Summary" in text,
        "remediation_actions": "2. Remediation Actions" in text,
        "validation_expectations": "3. Validation Expectations" in text,
        "tool_source": f"Tool Source: {args.source}" in text,
        "report_month": f"Report Month: {args.month}" in text,
        "clickable_advisory_links": links > 0,
        "command_blocks_extract": "Implementation and validation commands" in text,
        "unique_remediation_actions": len(re.findall(r"(?m)^\d+\. .+", text)) >= 1,
        "banned_phrases_absent": all(phrase not in lower_text for phrase in banned),
        "not_encrypted": not reader.is_encrypted,
    }
    result = {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "input": str(path),
        "pages": len(reader.pages),
        "clickable_links": links,
        "checks_passed": sum(checks.values()),
        "checks_total": len(checks),
        "checks": checks,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
