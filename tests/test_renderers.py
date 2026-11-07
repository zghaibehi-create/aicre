import hashlib
import json

import pytest

from aicre.renderers import render_html, render_markdown, render_pdf


def sample():
    return {"scan_id":"abc", "generated_at":"2026-01-01T00:00:00Z", "findings":[
        {"id":"f1", "status":"detected", "source":"fixture <script>", "value":"<script>alert(1)</script>"}],
        "readiness":{"cpu":{"status":"pass","explanation":"Enough CPU"}}}

def test_markdown_contains_findings_and_escapable_json():
    text = render_markdown(sample())
    assert "f1" in text
    assert "<script>" in text

def test_html_is_self_contained_and_escapes_report_content():
    text = render_html(sample())
    assert "Content-Security-Policy" in text
    assert "aicre-report-sha256" in text
    payload = json.dumps(sample(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    assert hashlib.sha256(payload.encode("utf-8")).hexdigest() in text
    assert "default-src 'none'" in text
    assert "https://" not in text
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text


def test_pdf_renderer_when_optional_dependency_is_installed():
    pytest.importorskip('reportlab')
    assert render_pdf(sample()).startswith(b'%PDF-')


def test_diff_summary_is_visible_in_markdown_and_html():
    report = sample()
    report['diff_counts'] = {'new': 1, 'resolved': 0, 'unchanged': 2, 'changed': 1}
    assert 'Diff summary' in render_markdown(report)
    assert 'Diff summary' in render_html(report)



def test_markdown_escapes_untrusted_structure_and_uses_safe_json_fence():
    fence = chr(96) * 3
    report = {
        "scan_id": "id|\n# forged-heading",
        "generated_at": "now",
        "profile": "profile",
        "readiness": {
            "cpu|\n| injected": {
                "status": "pass|\n| forged",
                "explanation": "safe | cell\n# forged heading [link](https://example.invalid)",
            }
        },
        "findings": [{
            "check_id": "check\n# forged",
            "status": "detected",
            "source": "source|\n## forged",
            "value": "before\n" + fence + "\n## injected\n" + fence,
        }],
    }
    text = render_markdown(report)
    assert "cpu\\| \\| injected" in text
    assert "\\# forged heading" in text
    assert "[link]" not in text
    assert (chr(96) * 4) + "json" in text
    assert "## injected" in text  # remains inside the dynamically sized JSON fence
