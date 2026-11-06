from __future__ import annotations
import html
import json
from typing import Any

def render_markdown(report: dict[str, Any]) -> str:
    lines = ['# AICRE scan report', '', f"- Scan ID: {report.get('scan_id', 'legacy')}", f"- Generated: {report.get('generated_at', 'unknown')}", '', '## Findings', '']
    for item in report.get('findings', []):
        lines.extend([f"### {item.get('check_id', item.get('id', 'unknown'))} — {item.get('status', 'unknown')}", '', f"Source: {item.get('source', 'unknown')}", '', '```json', json.dumps(item.get('value'), ensure_ascii=False, sort_keys=True, indent=2), '```', ''])
    return '\n'.join(lines).rstrip() + '\n'

def render_html(report: dict[str, Any]) -> str:
    raw = html.escape(json.dumps(report, ensure_ascii=False, indent=2))
    title = html.escape('AICRE report ' + str(report.get('scan_id', 'legacy')))
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src data:; base-uri \'none\'; form-action \'none\'; frame-ancestors \'none\'">'
        '<title>' + title + '</title><style>:root{color-scheme:light dark;font:16px/1.5 system-ui}body{max-width:1000px;margin:2rem auto;padding:0 1rem}pre{white-space:pre-wrap;overflow-wrap:anywhere}table{width:100%;border-collapse:collapse}td,th{border:1px solid GrayText;padding:.5rem}@media(max-width:600px){body{padding:0 .75rem}}@media print{body{color:#000;background:#fff}}</style>'
        '</head><body><h1>AICRE scan report</h1><p>Generated: ' + html.escape(str(report.get('generated_at', 'unknown'))) + '</p><h2>Readiness</h2><table><tbody>' + ''.join('<tr><th scope="row">' + html.escape(k) + '</th><td>' + html.escape(str(v.get('status'))) + '</td><td>' + html.escape(str(v.get('explanation'))) + '</td></tr>' for k,v in report.get('readiness',{}).items()) + '</tbody></table><h2>Findings</h2><pre>' + raw + '</pre></body></html>')

def render_pdf(report: dict[str, Any]) -> bytes:
    try:
        from io import BytesIO
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
        from xml.sax.saxutils import escape
    except ImportError as exc:
        raise RuntimeError('PDF support requires the optional ReportLab dependency; install aicre[pdf]') from exc
    stream = BytesIO()
    doc = SimpleDocTemplate(stream, pagesize=A4, rightMargin=16*mm, leftMargin=16*mm)
    styles = getSampleStyleSheet()
    story = [Paragraph('AICRE scan report', styles['Title']), Spacer(1, 10), Paragraph(escape('Scan ID: ' + str(report.get('scan_id', 'legacy'))), styles['BodyText'])]
    for item in report.get('findings', []):
        story.extend([Spacer(1, 8), Paragraph(escape(str(item.get('id')) + ' — ' + str(item.get('status'))), styles['Heading3']), Preformatted(json.dumps(item.get('value'), ensure_ascii=False, indent=2, default=str), styles['Code'])])
    doc.build(story)
    return stream.getvalue()
