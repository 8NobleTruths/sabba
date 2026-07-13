"""The Kali layer: scope authorization (the spine), the sandboxed runner, and the tool list.

Scope tests are the important ones -- an agent must not be able to run a tool against a target
the operator did not allow. These need no Kali tools installed; run_tool is exercised with echo.
"""
from sabba.kali import run as R
from sabba.kali.scope import Scope, extract_targets, host_of
from sabba.kali.tools import list_security_tools


# ---- scope: the authorization spine ----

def test_default_scope_allows_only_loopback_and_scanme():
    s = Scope()
    assert s.allows("127.0.0.1") and s.allows("localhost")
    assert s.allows("http://scanme.nmap.org/")
    assert not s.allows("example.com")
    assert not s.allows("8.8.8.8")


def test_operator_scope_domain_and_cidr():
    s = Scope(domains=["example.com"], cidrs=["10.0.0.0/8"])
    assert s.allows("api.example.com") and s.allows("example.com")
    assert s.allows("10.1.2.3")
    assert not s.allows("evil.com")
    assert not s.allows("192.168.1.1")


def test_host_of_strips_scheme_port_path():
    assert host_of("https://a.b.com:443/x") == "a.b.com"
    assert host_of("1.2.3.4:80") == "1.2.3.4"
    assert host_of("host") == "host"


def test_extract_targets_skips_flags_and_files():
    t = extract_targets(["-sV", "-oX", "-", "scanme.nmap.org", "wordlist.txt", "http://x.com/a"])
    assert "scanme.nmap.org" in t
    assert any("x.com" in x for x in t)
    assert "wordlist.txt" not in t and "-sV" not in t


def test_check_rejects_out_of_scope():
    ok, reason = Scope().check(["-sV", "evil.com"], network=True)
    assert not ok and "out of scope" in reason


def test_extract_targets_from_flag_value():
    # a target hidden in --flag=value must not slip past scope
    t = extract_targets(["--url=http://evil.com/x", "-u=1.2.3.4"])
    assert any("evil.com" in x for x in t) and "1.2.3.4" in t


def test_scope_blocks_target_in_flag_value():
    ok, reason = Scope().check(["--url=http://evil.com"], network=True)
    assert not ok and "out of scope" in reason


def test_audit_records_a_line(tmp_path, monkeypatch):
    import json

    from sabba import audit
    p = tmp_path / "audit.log"
    monkeypatch.setattr(audit, "_PATH", p)
    audit.record("kali_run", tool="nmap", allowed=False, scope="out of scope: evil.com")
    rec = json.loads(p.read_text().strip())
    assert rec["action"] == "kali_run" and rec["allowed"] is False and "ts" in rec


def test_check_allows_in_scope():
    ok, _ = Scope().check(["-sV", "127.0.0.1"], network=True)
    assert ok


def test_network_tool_without_a_target_is_blocked():
    ok, _ = Scope().check(["-sV"], network=True)
    assert not ok


def test_local_tool_without_a_target_is_allowed():
    ok, _ = Scope().check(["hashes.txt"], network=False)
    assert ok


# ---- runner ----

def test_run_missing_tool_is_clean_error():
    r = R.run_tool("definitely-not-a-tool-xyz", ["127.0.0.1"])
    assert "not installed" in r["error"]


def test_run_blocked_when_out_of_scope():
    r = R.run_tool("echo", ["evil.com"])          # echo defaults to network=True (deny-biased)
    assert r["error"] == "blocked by scope"
    assert "out of scope" in r["reason"]


def test_run_executes_when_in_scope():
    r = R.run_tool("echo", ["hi", "127.0.0.1"])
    assert "error" not in r
    assert r["exit_code"] == 0
    assert "127.0.0.1" in r["stdout"]


# ---- catalog / list ----

def test_list_security_tools_shape():
    r = list_security_tools()
    assert {"installed", "missing", "count_installed"} <= set(r)
    names = {t["name"] for t in r["installed"]} | set(r["missing"])
    assert "nmap" in names and "nuclei" in names


# ---- MCP surface ----

def test_kali_mcp_tools_registered():
    import asyncio

    from sabba import mcp_server as M
    tools = {t.name for t in asyncio.run(M.build_server().list_tools())}
    assert {"kali_run", "list_security_tools"} <= tools


def test_do_kali_run_enforces_scope():
    from sabba import mcp_server as M
    assert M.do_kali_run("echo", ["evil.com"])["error"] == "blocked by scope"
