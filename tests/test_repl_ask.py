"""The /ask slash command hands a task to the whole Claude Code agent from inside the REPL.

These stub the Repl and mock the claude_code module, so they run without the `claude` CLI:
they check the empty-arg usage line, graceful degradation when claude is absent, that a
result renders, and that a failure is reported.
"""
import io

from rich.console import Console

from sabba import repl
from sabba.llm import claude_code
from sabba.llm.claude_code import ClaudeResult


def _stub():
    class S:
        pass
    s = S()
    s.console = Console(file=io.StringIO(), force_terminal=False, width=100)
    s._sys = []
    s.sys = s._sys.append
    return s


def test_ask_usage_when_empty():
    s = _stub()
    repl.Repl.ask(s, "")
    assert any("usage" in m for m in s._sys)


def test_ask_degrades_when_claude_missing(monkeypatch):
    monkeypatch.setattr(claude_code, "available", lambda: False)
    s = _stub()
    repl.Repl.ask(s, "do something")
    assert any("not on PATH" in m for m in s._sys)


def test_ask_renders_result(monkeypatch):
    monkeypatch.setattr(claude_code, "available", lambda: True)
    monkeypatch.setattr(claude_code, "run",
                        lambda *a, **k: ClaudeResult(text="# Done\nit works", ok=True,
                                                     turns=2, cost_usd=0.01, duration_ms=1500))
    s = _stub()
    repl.Repl.ask(s, "fix it")
    out = s.console.file.getvalue()
    assert "Done" in out and "it works" in out
    assert "2 turns" in out and "$0.01" in out


def test_ask_reports_failure(monkeypatch):
    monkeypatch.setattr(claude_code, "available", lambda: True)
    monkeypatch.setattr(claude_code, "run",
                        lambda *a, **k: ClaudeResult(text="", ok=False, error="not authenticated"))
    s = _stub()
    repl.Repl.ask(s, "go")
    assert any("did not finish" in m for m in s._sys)


def test_slash_routes_ask_vs_claude_code():
    calls = []

    class S:
        pass
    s = S()
    s.ask = lambda a: calls.append(("ask", a))
    s.claude_session = lambda a: calls.append(("cc", a))
    repl.Repl.slash(s, "/ask find the bug")     # one-shot
    repl.Repl.slash(s, "/claude-code")          # full session, no arg
    repl.Repl.slash(s, "/cc do it")             # alias
    repl.Repl.slash(s, "/claude explain")       # alias
    assert calls == [("ask", "find the bug"), ("cc", ""), ("cc", "do it"), ("cc", "explain")]


def test_claude_session_degrades_when_missing(monkeypatch):
    monkeypatch.setattr(claude_code, "available", lambda: False)
    s = _stub()
    repl.Repl.claude_session(s, "")
    assert any("not on PATH" in m for m in s._sys)


def test_claude_session_launches_studio(monkeypatch):
    import subprocess
    monkeypatch.setattr(claude_code, "available", lambda: True)
    launched = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, *a, **k: launched.append(cmd))
    s = _stub()
    s.console.clear = lambda: None
    s.header = lambda: None
    repl.Repl.claude_session(s, "fix the bug")
    assert launched, "should launch a subprocess"
    cmd = launched[0]
    assert "studio" in cmd and "claude" in cmd and "fix the bug" in cmd
