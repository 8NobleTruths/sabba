"""Prove a change works by running it, not by trusting it.

The one rule, applied to a diff instead of a bug: a change is proven only when a check
FAILS on the base and PASSES on the head. That is the whole difference between "the model
says it works" and "it works" -- the check has to actually catch the thing, or head-passing
means nothing. This is what a coding agent needs to trust its own edit.

Two modes, both differential over a git base ref (head is the working tree):

  test mode    a shell command; proven when it exits non-zero on base and zero on head.
               Language-agnostic; the general case for "did my change do what it claims".
  crash mode   a native C/C++ target with a known PoC; proven when the PoC crashes under
               AddressSanitizer on base and is clean on head (a proven fix). Reuses the oracle.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path


def _git_root(path: Path) -> Path | None:
    r = subprocess.run(["git", "-C", str(path), "rev-parse", "--show-toplevel"],
                       capture_output=True, text=True)
    return Path(r.stdout.strip()) if r.returncode == 0 else None


def _run(cmd: str, cwd: Path, timeout: float) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, shell=True, cwd=str(cwd), capture_output=True,
                           text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {int(timeout)}s"
    return p.returncode, ((p.stdout or "") + (p.stderr or ""))[-2000:]


def _worktree(root: Path, base: str):
    """Context-managed detached worktree checked out at `base`. Yields the path or None."""
    tmp = Path(tempfile.mkdtemp(prefix="sabba-base-"))
    wt = tmp / "base"
    add = subprocess.run(["git", "-C", str(root), "worktree", "add", "--detach", str(wt), base],
                         capture_output=True, text=True)
    ok = add.returncode == 0
    return wt if ok else None, tmp, (add.stderr.strip() if not ok else "")


def _cleanup(root: Path, wt: Path, tmp: Path) -> None:
    subprocess.run(["git", "-C", str(root), "worktree", "remove", "--force", str(wt)],
                   capture_output=True)
    shutil.rmtree(tmp, ignore_errors=True)


def _vj(v) -> dict:
    san = getattr(v, "sanitizer", None)
    return {
        "verified": bool(getattr(v, "verified", False)),
        "reason": getattr(v, "reason", ""),
        "class": getattr(san, "klass", None) if san else None,
        "evidence": (getattr(v, "evidence", "") or "")[:1500],
    }


def prove_change(target: str, base: str = "HEAD", test: str | None = None,
                 timeout: float = 300.0) -> dict:
    """Prove the change at `target` (working tree) against git `base`.

    With `test`, run it in both trees (base-fail / head-pass). Otherwise fall back to the
    native crash oracle if the target has a target.json with a known_poc."""
    d = Path(target).resolve()
    if not d.exists():
        return {"error": f"target not found: {d}"}
    root = _git_root(d)
    if root is None:
        return {"error": f"{d} is not inside a git repo; prove compares a base ref to the working tree"}
    rel = d.relative_to(root)
    if test:
        return _prove_test(root, rel, base, test, timeout)
    return _prove_crash(root, rel, d, base, timeout)


def _prove_test(root: Path, rel: Path, base: str, test: str, timeout: float) -> dict:
    wt, tmp, err = _worktree(root, base)
    if wt is None:
        return {"error": f"could not check out base {base!r}: {err}"}
    try:
        base_rc, base_out = _run(test, wt / rel, timeout)
        head_rc, head_out = _run(test, root / rel, timeout)
    finally:
        _cleanup(root, wt, tmp)
    base_fail, head_pass = base_rc != 0, head_rc == 0
    proven = base_fail and head_pass
    if proven:
        reason = "the check fails on base and passes on head"
    elif not base_fail:
        reason = "the check already passes on base; the change is not what makes it pass"
    else:
        reason = "the check still fails on head; the change does not make it pass"
    return {
        "mode": "test", "proven": proven, "reason": reason,
        "base": {"ref": base, "exit": base_rc, "passed": not base_fail, "output": base_out},
        "head": {"exit": head_rc, "passed": head_pass, "output": head_out},
    }


def _prove_crash(root: Path, rel: Path, d: Path, base: str, timeout: float) -> dict:
    from ..chat import _sources
    from ..harness import CCompileRunOracle
    from ..types import PoC
    tj = d / "target.json"
    if not tj.exists():
        return {"error": "no `test` given and no target.json with a known_poc; pass test=<command>"}
    try:
        spec = json.loads(tj.read_text())
    except json.JSONDecodeError:
        return {"error": "target.json is not valid JSON"}
    kp = spec.get("known_poc")
    if not kp:
        return {"error": "no `test` given and target.json has no known_poc"}
    head_sources = _sources(d)
    if not head_sources:
        return {"error": "no C or C++ sources in the target"}
    poc = PoC(argv=kp.get("argv", []), stdin=kp.get("stdin", ""))
    oracle = CCompileRunOracle()
    head_v = oracle.verify(head_sources, poc)

    wt, tmp, err = _worktree(root, base)
    if wt is None:
        return {"error": f"could not check out base {base!r}: {err}"}
    try:
        base_sources = _sources(wt / rel)
        base_v = oracle.verify(base_sources, poc) if base_sources else None
    finally:
        _cleanup(root, wt, tmp)

    base_crash = bool(base_v and base_v.verified)
    head_clean = not head_v.verified
    proven = base_crash and head_clean
    if proven:
        reason = "the PoC crashes on base and is clean on head (a proven fix)"
    elif not base_crash:
        reason = "the PoC did not crash on base; nothing to prove fixed"
    else:
        reason = "the PoC still crashes on head; the change does not fix it"
    return {
        "mode": "crash", "proven": proven, "reason": reason,
        "base": {"ref": base, "verdict": _vj(base_v) if base_v else None},
        "head": {"verdict": _vj(head_v)},
    }
