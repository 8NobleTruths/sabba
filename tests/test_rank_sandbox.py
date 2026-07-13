"""rank (token-free ML risk ranking) and run_sandboxed (isolated command execution).

Both are token-free and need no clang: rank parses C with tree-sitter and scores with the
local model (or a heuristic); run_sandboxed uses the local subprocess sandbox.
"""
import asyncio

from sabba import mcp_server as M


def test_rank_orders_functions_by_risk():
    r = M.do_rank("targets/cwe121_stack_overflow")
    assert "error" not in r
    assert r["count"] >= 1
    risks = [f["risk"] for f in r["functions"]]
    assert risks == sorted(risks, reverse=True)          # highest risk first
    assert all("function" in f and "risk" in f for f in r["functions"])


def test_rank_missing_target_is_clean_error():
    assert "error" in M.do_rank("targets/does_not_exist_xyz")


def test_run_sandboxed_runs_and_captures():
    r = M.do_run_sandboxed("echo hello-sabba")
    assert r["tier"] == "local"
    assert r["exit_code"] == 0
    assert "hello-sabba" in r["stdout"]


def test_run_sandboxed_reports_exit_code():
    assert M.do_run_sandboxed("exit 3")["exit_code"] == 3


def test_run_sandboxed_enforces_timeout():
    r = M.do_run_sandboxed("sleep 5", timeout=0.5)
    assert r["timed_out"] is True


def test_run_sandboxed_container_tier():
    # where an engine is present the container tier runs; otherwise it is a clean error
    from sabba.sandbox.docker import engine_available
    r = M.do_run_sandboxed("echo hi-from-container", tier="container")
    if engine_available():
        assert r["tier"] == "container"
        assert r["exit_code"] == 0
        assert "hi-from-container" in r["stdout"]
    else:
        assert "error" in r and "container engine" in r["error"]


def test_rank_and_sandbox_tools_registered():
    tools = {t.name for t in asyncio.run(M.build_server().list_tools())}
    assert {"rank", "run_sandboxed"} <= tools
