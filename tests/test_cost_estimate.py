"""cost_estimate: surface which tools are token-free vs need a model."""
import asyncio

from sabba import mcp_server as M


def test_token_free_tool():
    r = M.do_cost_estimate("prove")
    assert r["token_free"] is True and r["needs_model"] is False


def test_needs_model_tool():
    assert M.do_cost_estimate("scan")["needs_model"] is True


def test_hunt_notes_the_no_model_path():
    r = M.do_cost_estimate("hunt")
    assert r["needs_model"] is True and "no_model" in r["note"]


def test_unknown_tool_is_soft():
    r = M.do_cost_estimate("frobnicate")
    assert r["token_free"] is None


def test_cost_estimate_tool_registered():
    tools = {t.name for t in asyncio.run(M.build_server().list_tools())}
    assert "cost_estimate" in tools
