"""Vet a skill or plugin by running it and watching what it actually does.

Marketplace skills are code you did not write, and static pattern-matching misses obfuscated
payloads. So instead of guessing, run the skill in an isolated home and working directory and
observe its real behavior through Python's audit hooks (PEP 578): every file it opens, every
socket it connects, every subprocess it spawns. A credential-looking path plus an outbound
socket is the exfiltration shape; we report what it did, with evidence.

Boundary (honest): with `isolated=True` and a container engine present, the skill runs inside a
network-cut, read-only-root container, so it cannot exfiltrate or touch the host during the scan.
Without an engine it falls back to in-process observation (scrubbed env, sandboxed HOME and cwd, a
timeout), which watches behavior but still runs the skill with this process's privileges. v1
handles Python skills (.py); other runtimes (JS, shell) need their own tracer and are future work.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# credential-looking paths a benign skill has no reason to read
_CRED_PATTERNS = (
    ".ssh", ".aws", ".netrc", ".git-credentials", "credentials", "id_rsa", "id_ed25519",
    "/etc/passwd", "/etc/shadow", ".npmrc", ".pypirc", ".docker/config", "bash_history",
    "zsh_history", ".kube/config", ".gnupg",
)

# runner: read + compile the skill BEFORE installing the hook (so our own I/O is not recorded),
# then exec it under an audit hook that records the events we care about.
_RUNNER = r'''
import json, sys
_events, _rec = [], False
_skill = sys.argv[1]
with open(_skill) as _f:
    _code = compile(_f.read(), _skill, "exec")

def _hook(event, args):
    if not _rec:
        return
    try:
        if event == "open":
            _events.append(["open", str(args[0])])
        elif event == "socket.connect":
            _events.append(["network", str(args[1])])
        elif event == "socket.getaddrinfo":
            _events.append(["dns", str(args[0])])
        elif event == "subprocess.Popen":
            _events.append(["subprocess", str(args[0])])
        elif event == "os.system":
            _events.append(["subprocess", str(args[0])])
        elif event == "os.exec":
            _events.append(["exec", str(args[0])])
    except Exception:
        pass

sys.addaudithook(_hook)
_rec = True
try:
    exec(_code, {"__name__": "__main__", "__file__": _skill})
except SystemExit:
    pass
except BaseException as _e:
    _events.append(["error", type(_e).__name__ + ": " + str(_e)[:200]])
_rec = False
sys.stderr.write("SABBA_EVENTS:" + json.dumps(_events))
'''


def scan_skill(path: str, timeout: float = 30.0, isolated: bool = False) -> dict:
    """Run a Python skill under observation and return a risk verdict with evidence.

    With `isolated` and a container engine present, the skill runs inside a network-cut
    container so it cannot exfiltrate during the scan; otherwise it runs in-process under
    audit-hook observation. Either way the same events are recorded and classified.
    """
    d = Path(path).resolve()
    if not d.exists():
        return {"error": f"skill not found: {d}"}
    if d.is_dir() or d.suffix != ".py":
        return {"error": "security_scan v1 vets a single Python skill file (.py); "
                         "other runtimes need their own tracer (future)"}

    from ..sandbox.docker import engine_available
    if isolated and engine_available():
        return _scan_isolated(d, timeout)
    return _scan_in_process(d, timeout)


def _scan_in_process(d: Path, timeout: float) -> dict:
    sandbox = Path(tempfile.mkdtemp(prefix="sabba-scan-"))
    runner = sandbox / "_runner.py"
    runner.write_text(_RUNNER)
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(sandbox),
           "TMPDIR": str(sandbox), "SABBA_SCAN": "1"}
    try:
        p = subprocess.run([sys.executable, str(runner), str(d)], cwd=str(sandbox),
                           env=env, capture_output=True, text=True, timeout=timeout)
        stderr = p.stderr
    except subprocess.TimeoutExpired:
        return {"skill": str(d), "ran": False, "risk": "suspicious",
                "reason": f"the skill did not finish within {int(timeout)}s (possible hang or heavy work)",
                "observations": [], "isolated": False, "note": _NOTE}
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)

    out = _classify(d, _extract(stderr))
    out["isolated"] = False
    out["note"] = _NOTE
    return out


def _scan_isolated(d: Path, timeout: float) -> dict:
    """Run the same audit-hook runner, but inside a network-cut container.

    The skill sees a fresh filesystem and no network, so credential reads and connect
    attempts are still observed (the audit event fires on the call) while the network is
    actually cut, and nothing the skill does can touch the host or leave the box.
    """
    from ..sandbox.base import Limits
    from ..sandbox.docker import DockerSandbox
    work = Path(tempfile.mkdtemp(prefix="sabba-scan-"))
    try:
        (work / "_runner.py").write_text(_RUNNER)
        shutil.copy(str(d), str(work / d.name))
        r = DockerSandbox(image="python:3.11-slim").run(
            ["python", "/work/_runner.py", "/work/" + d.name],
            cwd=str(work), limits=Limits(wall_seconds=float(timeout)))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if r.timed_out:
        return {"skill": str(d), "ran": False, "risk": "suspicious",
                "reason": f"the skill did not finish within {int(timeout)}s (possible hang or heavy work)",
                "observations": [], "isolated": True, "note": _NOTE_ISO}
    out = _classify(d, _extract(r.stderr))
    out["isolated"] = True
    out["note"] = _NOTE_ISO
    return out


_NOTE = ("python audit-hook observation in a sandboxed home and cwd; not containment -- "
         "run with isolated=True (needs docker/podman) for truly hostile skills")
_NOTE_ISO = ("ran inside a network-cut, read-only-root container: file reads and connect "
             "attempts are observed via python audit hooks while the network is actually cut, "
             "so a hostile skill cannot exfiltrate or touch the host during the scan")


def _extract(stderr: str) -> list:
    marker = "SABBA_EVENTS:"
    i = stderr.rfind(marker)
    if i < 0:
        return []
    try:
        return json.loads(stderr[i + len(marker):])
    except json.JSONDecodeError:
        return []


def _classify(path: Path, events: list) -> dict:
    cred, net, sub = [], [], []
    for ev in events:
        kind = ev[0]
        if kind == "open" and any(pat in ev[1] for pat in _CRED_PATTERNS):
            cred.append(ev[1])
        elif kind in ("network", "dns"):
            net.append(ev[1])
        elif kind in ("subprocess", "exec"):
            sub.append(ev[1])

    obs = ([{"kind": "credential-read", "detail": x} for x in cred]
           + [{"kind": "network", "detail": x} for x in net]
           + [{"kind": "subprocess", "detail": x} for x in sub])

    if cred:
        risk = "dangerous"
        reason = ("reads credential-like paths"
                  + (" and opens the network (the exfiltration shape)" if net else ""))
    elif net or sub:
        risk = "suspicious"
        reason = "opens the network" if net else "spawns subprocesses"
    else:
        risk = "clean"
        reason = "no credential access, network, or subprocess observed while it ran"

    return {"skill": str(path), "ran": True, "risk": risk, "reason": reason,
            "observations": obs, "note": _NOTE}
