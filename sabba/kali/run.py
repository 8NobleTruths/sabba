"""Run a security tool: scope-checked, sandboxed, and best-effort parsed.

The order matters: resolve the binary, authorize the target against the operator scope, then
run it in the local sandbox (rlimits, scrubbed env, hard wall-clock kill). Structured output is
parsed only if the tool actually emitted it (pass the tool's machine-readable flag to get it).
Tool output is a candidate -- prove it with Sabba's oracle before trusting it.
"""
from __future__ import annotations

import json
import shutil

from .catalog import entry
from .scope import Scope


def _parse_nmap_xml(xml: str) -> dict | None:
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    hosts = []
    for h in root.findall("host"):
        addr = h.find("address")
        ports = []
        for p in h.findall(".//port"):
            st, svc = p.find("state"), p.find("service")
            ports.append({"port": int(p.get("portid", 0)), "proto": p.get("protocol"),
                          "state": st.get("state") if st is not None else None,
                          "service": svc.get("name") if svc is not None else None})
        hosts.append({"ip": addr.get("addr") if addr is not None else None, "ports": ports})
    return {"hosts": hosts}


def _parse(kind: str, stdout: str):
    s = (stdout or "").strip()
    if not s:
        return None
    try:
        if kind == "xml" and s.startswith("<?xml"):
            return _parse_nmap_xml(s)
        if kind == "jsonl":
            rows = [json.loads(ln) for ln in s.splitlines() if ln.strip().startswith("{")]
            return rows or None
        if kind == "json" and s[0] in "[{":
            return json.loads(s)
    except (json.JSONDecodeError, ValueError):
        return None
    return None


def run_tool(tool: str, args: list[str] | None = None, *, scope: Scope | None = None,
             timeout: float = 180.0, parse: bool = True, workdir: str | None = None) -> dict:
    """Run `tool args`, gated by scope, in the sandbox. Returns a structured result dict."""
    args = list(args or [])
    if shutil.which(tool) is None:
        return {"tool": tool, "error": f"{tool} is not installed on this host"}
    scope = scope or Scope.load()
    meta = entry(tool)
    ok, reason = scope.check(args, network=meta["network"])
    from ..audit import record
    record("kali_run", tool=tool, args=args, allowed=ok, scope=reason)
    if not ok:
        return {"tool": tool, "error": "blocked by scope", "reason": reason,
                "hint": "authorize the target: set SABBA_SCOPE to a JSON file with your "
                        "hosts / cidrs / domains (loopback and scanme.nmap.org are always allowed)"}

    from ..sandbox.base import Limits
    from ..sandbox.local import LocalSubprocessSandbox
    r = LocalSubprocessSandbox().run(
        [tool, *args], cwd=workdir,
        limits=Limits(wall_seconds=float(timeout), max_output_bytes=512 * 1024))

    result = {"tool": tool, "args": args, "scope": reason, "category": meta["category"],
              "exit_code": r.exit_code, "timed_out": r.timed_out,
              "stdout": (r.stdout or "")[:20000], "stderr": (r.stderr or "")[:4000]}
    if parse and meta["structured"] and not r.timed_out:
        parsed = _parse(meta["structured"], r.stdout)
        if parsed is not None:
            result["parsed"] = parsed
    return result
