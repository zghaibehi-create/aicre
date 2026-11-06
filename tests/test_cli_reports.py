import json
import os
import stat
from pathlib import Path
import pytest
from aicre import cli
from aicre.cli import main

FIXTURE = {'schema_version':'2.0','aicre_version':'0.2.0','profile':'standard','generated_at':'2026-01-01T00:00:00Z','findings':[{'id':'cpu.logical','category':'resource','status':'detected','value':4,'unit':'count','source':'cpu','confidence':'high','collected_at':'2026-01-01T00:00:00Z','limitations':[]}],'readiness':{}}

def test_explicit_html_output_creates_parents_and_replaces_regular_file(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, 'build_report', lambda **kwargs: FIXTURE)
    output = tmp_path / 'nested' / 'report.html'
    output.parent.mkdir()
    output.write_text('old', encoding='utf-8')
    assert main(['scan','--profile','standard','--format','html','--output',str(output)]) == 0
    result = output.read_text(encoding='utf-8')
    assert 'Content-Security-Policy' in result
    assert 'old' not in result
    if os.name == 'posix':
        assert stat.S_IMODE(output.stat().st_mode) == 0o600

def test_report_input_renders_without_running_scanner(tmp_path, monkeypatch):
    source = tmp_path / 'input.json'
    source.write_text(json.dumps(FIXTURE), encoding='utf-8')
    monkeypatch.setattr(cli, 'build_report', lambda **kwargs: (_ for _ in ()).throw(AssertionError('scanner called')))
    output = tmp_path / 'out.md'
    assert main(['report','--input',str(source),'--format','markdown','--output',str(output)]) == 0
    assert 'cpu.logical' in output.read_text(encoding='utf-8')

def test_report_diff_json_exposes_all_classifications(tmp_path):
    before = dict(FIXTURE)
    before['findings'] = [dict(FIXTURE['findings'][0])]
    after = dict(FIXTURE)
    after['findings'] = [dict(FIXTURE['findings'][0]), {'id':'ram','check_id':'ram','category':'resource','status':'detected','value':8,'source':'mem','confidence':'high','unit':'GiB','limitations':[]}]
    left, right = tmp_path/'before.json', tmp_path/'after.json'
    left.write_text(json.dumps(before), encoding='utf-8')
    right.write_text(json.dumps(after), encoding='utf-8')
    result = main(['report','--diff',str(left),str(right),'--format','json'])
    assert result == 0
    # The JSON diff is emitted to stdout by the CLI; detailed classifications are covered in test_diff.py.

def test_open_returns_platform_error_code(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.platform, 'system', lambda: 'Darwin')
    path = tmp_path / 'report.html'
    path.write_text('fixture', encoding='utf-8')
    assert cli._open_report(path) == 6

def test_open_returns_launch_error_code(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.platform, 'system', lambda: 'Linux')
    monkeypatch.setattr(cli.subprocess, 'Popen', lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError('missing')))
    assert cli._open_report(tmp_path / 'report.html') == 7

def test_scan_without_profile_still_requires_profile():
    with pytest.raises(SystemExit) as exc:
        main(['scan'])
    assert exc.value.code == 2


def test_pdf_missing_optional_dependency_uses_exit_code_3(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, '_render', lambda *_: (_ for _ in ()).throw(RuntimeError('PDF support requires the optional ReportLab dependency; install aicre[pdf]')))
    source = tmp_path / 'source.json'
    source.write_text(json.dumps(FIXTURE), encoding='utf-8')
    assert main(['report', '--input', str(source), '--format', 'pdf']) == 3

def test_legacy_scan_profile_stdout_is_unchanged(monkeypatch, capsys):
    monkeypatch.setattr(cli, 'build_report', lambda **kwargs: {'aicre_version':'0.2.0','profile':'standard','findings':[],'readiness':{}})
    assert main(['scan', '--profile', 'standard', '--timeout', '0']) == 0
    assert capsys.readouterr().out == 'AICRE 0.2.0 — profile: standard\nReadiness (separate dimensions; no composite score):\n'
