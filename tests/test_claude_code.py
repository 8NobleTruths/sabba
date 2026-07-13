"""SABBA drives the whole Claude Code agent through `claude -p`.

These mock the subprocess so they run without the `claude` CLI installed: they check the
command line SABBA builds, that it parses `--output-format json` correctly, and that the
guards (missing binary, non-zero exit, timeout, error result) behave.
"""
import json
import subprocess

import pytest

from sabba.llm import claude_code
from sabba.llm.claude_code import ClaudeCodeUnavailable


def test_available_reflects_path(monkeypatch):
    monkeypatch.setattr(claude_code.shutil, "which", lambda _: "/usr/bin/claude")
    assert claude_code.available() is True
    monkeypatch.setattr(claude_code.shutil, "which", lambda _: None)
    assert claude_code.available() is False


def test_build_cmd_read_only_default():
    cmd = claude_code.build_cmd("fix the bug")
    assert cmd[:2] == ["claude", "-p"]
    assert "fix the bug" in cmd
    assert "--output-format" in cmd and "json" in cmd
    # read-only unless the caller asks otherwise
    assert cmd[cmd.index("--permission-mode") + 1] == "plan"


def test_build_cmd_all_flags():
    cmd = claude_code.build_cmd(
        "do it",
        add_dirs=["/a", "/b"],
        permission_mode="acceptEdits",
        allowed_tools=["Read", "Bash"],
        model="opus",
        mcp_config="sabba.json",
        system_append="be terse",
    )
    assert cmd.count("--add-dir") == 2
    assert cmd[cmd.index("--permission-mode") + 1] == "acceptEdits"
    assert cmd[cmd.index("--allowedTools") + 1] == "Read,Bash"
    assert cmd[cmd.index("--model") + 1] == "opus"
    assert cmd[cmd.index("--mcp-config") + 1] == "sabba.json"
    assert cmd[cmd.index("--append-system-prompt") + 1] == "be terse"


def test_parse_json_result():
    out = json.dumps({
        "type": "result", "subtype": "success", "is_error": False,
        "result": "done, tests pass", "num_turns": 4,
        "total_cost_usd": 0.0123, "duration_ms": 5400, "session_id": "abc",
    })
    r = claude_code.parse(out)
    assert r.ok is True
    assert r.text == "done, tests pass"
    assert r.turns == 4 and r.cost_usd == 0.0123 and r.duration_ms == 5400
    assert r.session_id == "abc" and r.error is None


def test_parse_error_result():
    out = json.dumps({"is_error": True, "result": "could not reach the model"})
    r = claude_code.parse(out)
    assert r.ok is False
    assert "could not reach" in r.error


def test_parse_plain_text_fallback():
    r = claude_code.parse("just some text, not json")
    assert r.ok is True
    assert r.text == "just some text, not json"
    assert r.raw is None


def test_run_raises_when_unavailable(monkeypatch):
    monkeypatch.setattr(claude_code, "available", lambda: False)
    with pytest.raises(ClaudeCodeUnavailable):
        claude_code.run("anything")


def test_run_parses_a_mocked_success(monkeypatch):
    monkeypatch.setattr(claude_code, "available", lambda: True)
    captured = {}

    def fake_run(cmd, cwd=None, capture_output=True, text=True, timeout=None):
        captured["cmd"] = cmd
        payload = json.dumps({"is_error": False, "result": "SABBA-OK", "num_turns": 1})

        class P:
            returncode = 0
            stdout = payload
            stderr = ""
        return P()

    monkeypatch.setattr(subprocess, "run", fake_run)
    r = claude_code.run("say ok", model="haiku")
    assert r.ok and r.text == "SABBA-OK" and r.turns == 1
    assert "--model" in captured["cmd"] and "haiku" in captured["cmd"]


def test_run_reports_nonzero_exit(monkeypatch):
    monkeypatch.setattr(claude_code, "available", lambda: True)

    def fake_run(cmd, **kw):
        class P:
            returncode = 1
            stdout = ""
            stderr = "not authenticated"
        return P()

    monkeypatch.setattr(subprocess, "run", fake_run)
    r = claude_code.run("go")
    assert r.ok is False and "not authenticated" in r.error


def test_run_reports_timeout(monkeypatch):
    monkeypatch.setattr(claude_code, "available", lambda: True)

    def fake_run(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 1)

    monkeypatch.setattr(subprocess, "run", fake_run)
    r = claude_code.run("go", timeout=1)
    assert r.ok is False and "timed out" in r.error
