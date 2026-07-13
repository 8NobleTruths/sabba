"""prove: a change is proven only when a check fails on the base and passes on the head.

These build a throwaway git repo (base commit where a test fails, working tree where it
passes) and drive it through prove_change / the MCP do_prove wrapper. Test mode needs only
git + a shell, no clang, so it runs everywhere."""
import subprocess
from pathlib import Path

import pytest

from sabba import mcp_server as M
from sabba.harness.prove import prove_change


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True,
                   capture_output=True, text=True)


@pytest.fixture()
def repo(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "t@t")
    _git(root, "config", "user.name", "t")
    # base commit: a test that checks for the word PASS in out.txt, which is absent
    (root / "check.sh").write_text('grep -q PASS out.txt')
    (root / "out.txt").write_text("nothing here\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    return root


def test_prove_true_when_base_fails_head_passes(repo):
    # the "change": make the check pass in the working tree (head)
    (repo / "out.txt").write_text("now it says PASS\n")
    r = prove_change(str(repo), base="HEAD", test="sh check.sh")
    assert r["mode"] == "test"
    assert r["proven"] is True
    assert r["base"]["passed"] is False and r["head"]["passed"] is True


def test_prove_false_when_change_does_nothing(repo):
    # no change: the check still fails on head
    r = prove_change(str(repo), base="HEAD", test="sh check.sh")
    assert r["proven"] is False
    assert "still fails on head" in r["reason"]


def test_prove_false_when_base_already_passes(repo):
    # make base already pass, commit it, then head also passes -> not proven by the change
    (repo / "out.txt").write_text("PASS\n")
    _git(repo, "commit", "-aqm", "already passing")
    r = prove_change(str(repo), base="HEAD", test="sh check.sh")
    assert r["proven"] is False
    assert "already passes on base" in r["reason"]


def test_prove_not_a_git_repo_is_clean_error(tmp_path):
    r = prove_change(str(tmp_path), test="true")
    assert "error" in r and "git repo" in r["error"]


def test_do_prove_wrapper_round_trips(repo):
    (repo / "out.txt").write_text("PASS\n")
    r = M.do_prove(str(repo), base="HEAD", test="sh check.sh")
    assert r["proven"] is True


def test_prove_registered_as_a_tool():
    import asyncio
    tools = {t.name for t in asyncio.run(M.build_server().list_tools())}
    assert "prove" in tools
