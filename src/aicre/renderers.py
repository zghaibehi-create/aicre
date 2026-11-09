from __future__ import annotations

import hashlib
import html
import json
import re
from typing import Any


def _markdown_inline(value: Any) -> str:
    """Escape untrusted text so it cannot create Markdown structure."""
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace(chr(96), r"\`")
    return re.sub(r"([\\*_{}\[\]()#+.!|~-])", r"\\\1", text)


def _markdown_cell(value: Any) -> str:
    return _markdown_inline(value)


def _fenced_json(value: Any) -> list[str]:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
    longest = max((len(run) for run in re.findall(chr(96) + r"+", payload)), default=0)
    fence = chr(96) * max(3, longest + 1)
    return [fence + "json", payload, fence]


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# AICRE scan report", "",
        f"- Scan ID: {_markdown_inline(report.get('scan_id', 'legacy'))}",
        f"- Generated: {_markdown_inline(report.get('generated_at', 'unknown'))}",
        f"- Profile: {_markdown_inline(report.get('profile', 'unknown'))}",
        "", "## Readiness", "", "| Dimension | Status | Explanation |", "|---|---|---|",
    ]
    for name, item in report.get("readiness", {}).items():
        lines.append(
            f"| {_markdown_cell(name)} | {_markdown_cell(item.get('status', 'unknown'))} "
            f"| {_markdown_cell(item.get('explanation', ''))} |"
        )
    if report.get("diff_counts"):
        lines.extend(["", "## Diff summary", "", "| Change | Count |", "|---|---:|"])
        lines.extend(
            f"| {_markdown_cell(name)} | {int(count)} |"
            for name, count in report["diff_counts"].items()
        )
    lines.extend(["", "## Findings", ""])
    for item in report.get("findings", []):
        identifier = item.get("check_id", item.get("id", "unknown"))
        status = item.get("status", "unknown")
        lines.extend([
            f"### {_markdown_inline(identifier)} — {_markdown_inline(status)}", "",
            f"Source: {_markdown_inline(item.get('source', 'unknown'))}", "",
            *_fenced_json(item.get("value")), "",
        ])
    return "\n".join(lines).rstrip() + "\n"


def render_html(report: dict[str, Any]) -> str:
    payload = json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    raw = html.escape(json.dumps(report, ensure_ascii=False, indent=2))
    title = html.escape("AICRE report " + str(report.get("scan_id", "legacy")))
    readiness_rows = []
    for name, item in report.get("readiness", {}).items():
        readiness_rows.append(
            "<tr><th scope=\"row\">" + html.escape(str(name)) + "</th><td>" +
            html.escape(str(item.get("status", "unknown"))) + "</td><td>" +
            html.escape(str(item.get("explanation", ""))) + "</td></tr>"
        )
    diff_summary = ""
    if report.get("diff_counts"):
        summary_rows = "".join(
            "<tr><th scope=\"row\">" + html.escape(str(name)) + "</th><td>" +
            html.escape(str(count)) + "</td></tr>"
            for name, count in report["diff_counts"].items()
        )
        diff_summary = "<h2>Diff summary</h2><table><tbody>" + summary_rows + "</tbody></table>"
    finding_cards = []
    for item in report.get("findings", []):
        finding_cards.append(
            '<section class="finding"><h3>' +
            html.escape(str(item.get("check_id", item.get("id", "unknown")))) +
            " — " + html.escape(str(item.get("status", "unknown"))) + "</h3><p>" +
            html.escape(str(item.get("category", "unknown"))) + " · " +
            html.escape(str(item.get("source", "unknown"))) + "</p><pre>" +
            html.escape(json.dumps(item.get("value"), ensure_ascii=False, indent=2, default=str)) +
            "</pre></section>"
        )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="aicre-report-sha256" content="' + digest + '">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src data:; base-uri \'none\'; form-action \'none\'; frame-ancestors \'none\'">'
        "<title>" + title + "</title>"
        "<style>:root{color-scheme:light dark;font:16px/1.5 system-ui}"
        "body{max-width:1000px;margin:2rem auto;padding:0 1rem}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere}"
        ".finding{border:1px solid GrayText;border-radius:.5rem;padding:1rem;margin:1rem 0;overflow-wrap:anywhere}"
        "table{width:100%;border-collapse:collapse}td,th{border:1px solid GrayText;padding:.5rem}"
        "@media(max-width:600px){body{padding:0 .75rem}}"
        "@media print{body{color:#000;background:#fff}.finding{break-inside:avoid}}</style>"
        "</head><body><h1>AICRE scan report</h1><p>Generated: " +
        html.escape(str(report.get("generated_at", "unknown"))) +
        "</p>" + diff_summary + "<h2>Readiness</h2><table><thead><tr><th>Dimension</th><th>Status</th><th>Explanation</th></tr></thead><tbody>" +
        "".join(readiness_rows) + "</tbody></table><h2>Findings</h2>" +
        "".join(finding_cards) +
        "<details><summary>Raw report JSON</summary><pre>" + raw + "</pre></details></body></html>"
    )


def render_pdf(report: dict[str, Any]) -> bytes:
    try:
        from io import BytesIO
        from xml.sax.saxutils import escape

        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            Paragraph,
            Preformatted,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise RuntimeError('PDF support requires the optional ReportLab dependency; install aicre[pdf]') from exc
    stream = BytesIO()
    doc = SimpleDocTemplate(stream, pagesize=A4, rightMargin=16*mm, leftMargin=16*mm)
    styles = getSampleStyleSheet()
    story = [Paragraph('AICRE scan report', styles['Title']), Spacer(1, 10), Paragraph(escape('Scan ID: ' + str(report.get('scan_id', 'legacy'))), styles['BodyText']), Spacer(1, 10), Paragraph('Readiness', styles['Heading2'])]
    readiness_rows = [["Dimension", "Status", "Explanation"]]
    for name, item in report.get("readiness", {}).items():
        readiness_rows.append([Paragraph(escape(name), styles["BodyText"]), Paragraph(escape(str(item.get("status", "unknown"))), styles["BodyText"]), Paragraph(escape(str(item.get("explanation", ""))), styles["BodyText"])])
    table = Table(readiness_rows, colWidths=[40*mm, 25*mm, 105*mm], repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.lightgrey), ("GRID", (0,0), (-1,-1), .4, colors.grey), ("VALIGN", (0,0), (-1,-1), "TOP"), ("PADDING", (0,0), (-1,-1), 5)]))
    story.extend([table, Spacer(1, 12)])
    if report.get("diff_counts"):
        story.append(Paragraph("Diff summary", styles["Heading2"]))
        diff_rows = [["Change", "Count"]] + [[str(name), str(count)] for name, count in report["diff_counts"].items()]
        story.append(Table(diff_rows, colWidths=[50*mm, 25*mm]))
        story.append(Spacer(1, 12))
    story.append(Paragraph('Findings', styles['Heading2']))
    for item in report.get('findings', []):
        story.extend([Spacer(1, 8), Paragraph(escape(str(item.get('id')) + ' — ' + str(item.get('status'))), styles['Heading3']), Preformatted(json.dumps(item.get('value'), ensure_ascii=False, indent=2, default=str), styles['Code'])])
    doc.build(story)
    return stream.getvalue()
