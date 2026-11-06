import hashlib
import json
from aicre.renderers import render_html, render_markdown

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
