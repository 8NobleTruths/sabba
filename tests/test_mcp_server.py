"""The MCP surface: other agents spawn Sabba and command it.

These exercise the core tool logic directly (no MCP client needed) plus the FastMCP
registration, so the tools other agents see stay in lockstep with the CLI verbs.
"""
import asyncio
import shutil

import pytest

from sabba import llm
from sabba import mcp_server as M


def test_build_server_registers_the_expected_tools():
    srv = M.build_server()
    tools = asyncio.run(srv.list_tools())
    names = {t.name for t in tools}
    assert {"doctor", "list_provers", "verify", "solve", "hunt", "scan"} <= names


def test_doctor_and_list_provers():
    d = M.do_doctor()
    assert d["toolchains"] and any(r["component"] for r in d["toolchains"])
    provers = M.do_list_provers()["provers"]
    names = {p["name"] for p in provers}
    assert "NativeMemSafetyProver" in names
    native = next(p for p in provers if p["name"] == "NativeMemSafetyProver")
    assert native["domain"] == "native"          # the bug was: domain came back empty
    assert "c" in native["languages"]


def test_end_to_end_stdio_client_round_trip():
    """Spawn the server as a subprocess and drive it through a real MCP stdio client,
    proving the tools round-trip over the protocol, not just in-process."""
    import json
    import sys

    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def _run():
        params = StdioServerParameters(command=sys.executable, args=["-m", "sabba", "mcp"])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                names = {t.name for t in (await session.list_tools()).tools}
                assert {"doctor", "list_provers", "verify", "solve", "hunt", "scan"} <= names
                res = await session.call_tool("list_provers", {})
                data = res.structuredContent or json.loads(res.content[0].text)
                native = next(p for p in data["provers"]
                              if p["name"] == "NativeMemSafetyProver")
                assert native["domain"] == "native"
                return names

    names = asyncio.run(_run())
    assert "verify" in names


@pytest.mark.skipif(not shutil.which("clang"), reason="the native oracle needs clang")
def test_verify_returns_a_real_proof():
    r = M.do_verify("targets/cwe121_stack_overflow")
    assert r["verdict"]["verified"] is True
    assert r["verdict"]["class"] == "stack-buffer-overflow"
    assert "AddressSanitizer" in r["verdict"]["evidence"]


def test_missing_target_is_a_clean_error():
    assert "error" in M.do_verify("targets/does_not_exist_xyz")
    assert "error" in M.do_hunt("targets/does_not_exist_xyz")


def test_local_backend_selects_without_a_server(monkeypatch):
    monkeypatch.setenv("SABBA_LLM_BACKEND", "local")
    monkeypatch.setenv("SABBA_LOCAL_MODEL", "test-model")
    monkeypatch.setenv("SABBA_LOCAL_BASE_URL", "http://localhost:12345/v1")
    llm._PROVIDER_CACHE.clear()
    p = llm.get_provider()
    llm._PROVIDER_CACHE.clear()
    assert p.name == "local"
    assert p.model == "test-model"
    assert "localhost:12345" in str(p.client.base_url)
