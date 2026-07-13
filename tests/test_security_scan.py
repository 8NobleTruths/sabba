"""security_scan: run a Python skill under observation and report what it did.

These write benign skill files that exhibit the behaviors we want to catch (reading a
credential-looking path, opening a socket, spawning a subprocess) and assert the verdict.
"""
import asyncio

from sabba import mcp_server as M
from sabba.security import scan_skill


def _skill(tmp_path, name, body):
    p = tmp_path / name
    p.write_text(body)
    return str(p)


def test_clean_skill_is_clean(tmp_path):
    r = scan_skill(_skill(tmp_path, "clean.py", 'print("hello from a harmless skill")\n'))
    assert r["ran"] is True
    assert r["risk"] == "clean"
    assert r["observations"] == []


def test_credential_read_is_dangerous(tmp_path):
    body = 'data = open("/etc/passwd").read()\nprint(len(data))\n'
    r = scan_skill(_skill(tmp_path, "creds.py", body))
    assert r["risk"] == "dangerous"
    kinds = {o["kind"] for o in r["observations"]}
    assert "credential-read" in kinds
    assert any("/etc/passwd" in o["detail"] for o in r["observations"])


def test_network_is_suspicious(tmp_path):
    body = ('import socket\n'
            'try:\n'
            '    socket.create_connection(("127.0.0.1", 1), timeout=0.2)\n'
            'except Exception:\n'
            '    pass\n')
    r = scan_skill(_skill(tmp_path, "net.py", body))
    assert r["risk"] == "suspicious"
    assert any(o["kind"] == "network" for o in r["observations"])


def test_subprocess_is_suspicious(tmp_path):
    body = 'import subprocess\nsubprocess.run(["true"], capture_output=True)\n'
    r = scan_skill(_skill(tmp_path, "sub.py", body))
    assert r["risk"] == "suspicious"
    assert any(o["kind"] == "subprocess" for o in r["observations"])


def test_non_python_is_a_clean_error(tmp_path):
    p = tmp_path / "skill.sh"
    p.write_text("echo hi")
    r = scan_skill(str(p))
    assert "error" in r


def test_do_security_scan_wrapper_and_tool(tmp_path):
    r = M.do_security_scan(_skill(tmp_path, "ok.py", "x = 1\n"))
    assert r["risk"] == "clean"
    tools = {t.name for t in asyncio.run(M.build_server().list_tools())}
    assert "security_scan" in tools
