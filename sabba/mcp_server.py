"""Sabba as an MCP server: other agents spawn it and command it.

Model Context Protocol is the common tongue that Claude Code, Codex, OpenCode, OpenClaw, and
any tool-calling model already speak. Exposing Sabba as an MCP server lets those agents call
it as a tool: they hand Sabba a target, Sabba runs the oracle or a prover, and hands back a
verdict that is a re-runnable proof, not a guess. The one rule holds across the boundary too,
a finding is returned only when the exploit reproduced.

The tools mirror the CLI verbs and reuse the same code paths, so the MCP surface and the
terminal stay in lockstep:

  doctor         which prover toolchains are present
  list_provers   the registered provers and the domains they cover
  verify <dir>   compile a native target under a sanitizer and run its known PoC
  solve  <dir>   let Z3 synthesize overflow inputs; the oracle confirms each
  hunt   <dir>   full hunt (retrieval, Z3, the model) or the fork prover for Solidity
  scan   <dir>   the reasoning model proposes, the oracle verifies
  prove  <dir>   prove a change works: a check that fails on the base and passes on the head

Run it with `sabba mcp` (stdio, the default every client understands) or `sabba mcp --http`.
The reasoning tools (hunt, scan) need a model configured in the server's environment; verify,
solve, and doctor need no model at all.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _noop(*_a: Any, **_k: Any) -> None:
    return None


# -- serialization: keep results compact and JSON-clean for the calling agent ----------------

def _verdict_json(v: Any) -> dict:
    san = getattr(v, "sanitizer", None)
    return {
        "verified": bool(getattr(v, "verified", False)),
        "reason": getattr(v, "reason", ""),
        "class": getattr(san, "klass", None) if san else None,
        "evidence": (getattr(v, "evidence", "") or "")[:2000],
    }


def _finding_json(f: Any) -> dict:
    v = getattr(f, "verdict", None)
    san = getattr(v, "sanitizer", None) if v else None
    return {
        "cwe": getattr(f, "cwe", ""),
        "title": getattr(f, "title", ""),
        "function": getattr(f, "function", ""),
        "file": getattr(f, "file", ""),
        "line": getattr(f, "line", None),
        "verified": bool(getattr(v, "verified", False)) if v else False,
        "reason": getattr(v, "reason", "") if v else "",
        "class": getattr(san, "klass", None) if san else None,
        "poc": f.poc.label() if getattr(f, "poc", None) else None,
        "evidence": (getattr(v, "evidence", "") or "")[:1500] if v else "",
        "rationale": (getattr(f, "rationale", "") or "")[:1500],
    }


def _spec(d: Path) -> dict:
    tj = d / "target.json"
    if tj.exists():
        try:
            return json.loads(tj.read_text())
        except Exception:  # noqa: BLE001
            return {}
    return {}


# -- core logic (plain functions, unit-testable without an MCP client) -----------------------

def do_doctor() -> dict:
    from .ui import environment
    rows = [{"component": label, "ok": ok, "detail": detail}
            for label, ok, detail in environment()]
    return {"toolchains": rows, "provers": do_list_provers()["provers"]}


def do_list_provers() -> dict:
    from .provers import provers
    out = []
    for p in provers():
        out.append({
            "name": p.__class__.__name__,
            "domain": getattr(p, "domain", "native"),
            "languages": list(getattr(p, "languages", ()) or ()),
            "vuln_classes": list(getattr(p, "vuln_classes", ()) or ()),
        })
    return {"provers": out}


def do_verify(target: str) -> dict:
    from .chat import _sources
    from .harness import CCompileRunOracle
    from .types import PoC
    d = Path(target).resolve()
    if not d.exists():
        return {"error": f"target not found: {d}"}
    spec = _spec(d)
    kp = spec.get("known_poc")
    if not kp:
        return {"error": "this target has no known_poc; use solve or hunt instead",
                "target": spec.get("name", d.name)}
    sources = _sources(d)
    if not sources:
        return {"error": "no C or C++ sources in this directory"}
    poc = PoC(argv=kp.get("argv", []), stdin=kp.get("stdin", ""))
    verdict = CCompileRunOracle().verify(sources, poc)
    return {"target": spec.get("name", d.name), "poc": poc.label(),
            "verdict": _verdict_json(verdict)}


def do_solve(target: str) -> dict:
    from .chat import _sources
    from .harness.symbolic.synth import hunt_symbolic
    from .provers import detect_domain
    d = Path(target).resolve()
    if not d.exists():
        return {"error": f"target not found: {d}"}
    dom = detect_domain(d, None)
    if dom != "native":
        return {"error": f"solve is native C/C++ only; use hunt for {dom} targets",
                "domain": dom}
    sources = _sources(d)
    if not sources:
        return {"error": "no C or C++ sources in this directory"}
    found = hunt_symbolic(sources, on_event=_noop)
    return {"target": d.name, "count": len(found),
            "findings": [_finding_json(f) for f in found]}


def do_hunt(target: str, model: str | None = None, no_model: bool = False,
            domain: str | None = None, top_k: int = 8) -> dict:
    from .harness.orchestrator import hunt as run_hunt
    d = Path(target).resolve()
    if not d.exists():
        return {"error": f"target not found: {d}"}
    spec = _spec(d)
    found = run_hunt(d, model=model, top_k=top_k, use_model=not no_model,
                     on_event=_noop, domain=domain)
    return {"target": spec.get("name", d.name), "count": len(found),
            "findings": [_finding_json(f) for f in found]}


def do_scan(target: str, model: str | None = None) -> dict:
    from .harness.agent import run_scan
    from .llm import LLMUnavailable
    d = Path(target).resolve()
    if not d.exists():
        return {"error": f"target not found: {d}"}
    spec = _spec(d)
    try:
        found = run_scan(d, model=model, on_event=_noop)
    except LLMUnavailable as e:
        return {"error": f"no model configured: {e}"}
    return {"target": spec.get("name", d.name), "count": len(found),
            "findings": [_finding_json(f) for f in found]}


def do_prove(target: str, base: str = "HEAD", test: str | None = None) -> dict:
    from .harness.prove import prove_change
    return prove_change(target, base=base, test=test)


def do_verify_change(path: str = ".", base: str = "HEAD", head: str | None = None,
                     test: str | None = None, build: str | None = None,
                     setup: str | None = None, sandbox: bool = False) -> dict:
    """Prove a code change works by running it, via Magga: a newly added test must fail on the
    base ref and pass on the head. Shells out to the public @8nobletruths/magga (Node)."""
    import json as _json
    import shutil
    import subprocess
    from .audit import record
    npx = shutil.which("npx")
    if not npx:
        return {"error": "npx (Node.js) not found; Magga needs Node. Install Node, or use the "
                         "native prove tool for C/C++/EVM changes."}
    cmd = [npx, "-y", "@8nobletruths/magga", "verify", path, "--base", base, "--json"]
    if head:
        cmd += ["--head", head]
    if setup:
        cmd += ["--setup", setup]
    if build:
        cmd += ["--build", build]
    if test:
        cmd += ["--test", test]
    if sandbox:
        cmd += ["--sandbox"]
    record("verify_change", path=path, base=base, sandbox=sandbox)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    except subprocess.TimeoutExpired:
        return {"error": "magga verify timed out"}
    out = (proc.stdout or "").strip()
    verdict = {}
    i = out.rfind("{")
    if i >= 0:
        try:
            verdict = _json.loads(out[i:])
        except Exception:
            verdict = {}
    verdict.setdefault("verified", proc.returncode == 0)
    verdict.setdefault("exit_code", proc.returncode)
    if not out and proc.stderr:
        verdict["stderr"] = proc.stderr[:2000]
    return verdict


def do_security_scan(path: str) -> dict:
    from .audit import record
    from .sandbox.docker import engine_available
    from .security import scan_skill
    # vet a hostile skill in the safest mode available: a network-cut container if an
    # engine is present, otherwise in-process observation.
    r = scan_skill(path, isolated=engine_available() is not None)
    record("security_scan", path=path, risk=r.get("risk"), isolated=r.get("isolated"))
    return r


def do_rank(target: str, top_k: int = 15) -> dict:
    from .chat import _sources
    from .harness.cpg import build
    from .ml.ranker import RiskRanker
    d = Path(target).resolve()
    if not d.exists():
        return {"error": f"target not found: {d}"}
    sources = _sources(d)
    if not sources:
        return {"error": "no C or C++ sources to rank (the risk ranker is native C/C++ for now)"}
    funcs = [r for r in build(sources) if r.get("function") and r.get("code")]
    ranker = RiskRanker.load()
    ranked = ranker.rank(funcs)[:top_k]
    out = [{"function": r.get("function"), "file": r.get("file"), "line": r.get("line"),
            "sinks": r.get("sinks", []), "risk": r.get("risk")} for r in ranked]
    return {"target": d.name, "trained": ranker.trained, "count": len(out), "functions": out}


def do_run_sandboxed(cmd: str, tier: str = "local", timeout: float = 10.0,
                     image: str = "alpine:3") -> dict:
    from .audit import record
    from .sandbox.base import Limits
    limits = Limits(wall_seconds=float(timeout))
    if tier in ("container", "docker"):
        from .sandbox.docker import DockerSandbox, engine_available
        eng = engine_available()
        if not eng:
            record("run_sandboxed", cmd=cmd, tier="container", error="no engine")
            return {"error": "no container engine (docker or podman) on this host; "
                             "install one, or use tier=local for process isolation"}
        record("run_sandboxed", cmd=cmd, tier="container", engine=eng)
        r = DockerSandbox(image=image, engine=eng).run(["sh", "-c", cmd], limits=limits)
        return {"tier": "container", "engine": eng, "image": image,
                "exit_code": r.exit_code, "timed_out": r.timed_out, "signal": r.signal,
                "stdout": (r.stdout or "")[:4000], "stderr": (r.stderr or "")[:4000]}
    from .sandbox.local import LocalSubprocessSandbox
    record("run_sandboxed", cmd=cmd, tier="local")
    r = LocalSubprocessSandbox().run(["sh", "-c", cmd], limits=limits)
    return {"tier": "local", "exit_code": r.exit_code, "timed_out": r.timed_out,
            "signal": r.signal, "stdout": (r.stdout or "")[:4000], "stderr": (r.stderr or "")[:4000]}


# tools that run on CPU (no LLM call) vs tools that use the configured model
_TOKEN_FREE = {"verify", "solve", "prove", "verify_change", "rank", "security_scan",
               "run_sandboxed", "doctor", "list_provers", "cost_estimate"}
_NEEDS_MODEL = {"hunt", "scan"}


def do_kali_run(tool: str, args: list | None = None, timeout: float = 180.0) -> dict:
    from .kali.run import run_tool
    return run_tool(tool, list(args or []), timeout=float(timeout))


def do_list_security_tools() -> dict:
    from .kali.tools import list_security_tools
    return list_security_tools()


def do_cost_estimate(task: str) -> dict:
    t = (task or "").strip().lower()
    if t in _TOKEN_FREE:
        return {"tool": t, "token_free": True, "needs_model": False,
                "estimate": "0 model tokens (deterministic: it runs on CPU, not on the model)",
                "note": "the point of Sabba: most of the work is compute, not tokens"}
    if t in _NEEDS_MODEL:
        note = ("hunt can run token-free with no_model=true (Z3 + the oracle only)"
                if t == "hunt" else "scan asks the model to propose candidates")
        return {"tool": t, "token_free": False, "needs_model": True,
                "estimate": "uses the configured model; cost scales with target size and model",
                "note": note}
    return {"tool": t, "token_free": None, "needs_model": None,
            "estimate": "unknown tool", "note": "token-free: verify, solve, prove, rank, "
            "security_scan, run_sandboxed; needs a model: hunt, scan"}


# -- the MCP server --------------------------------------------------------------------------

def build_server():
    """Construct the FastMCP server with the tools registered. Imported lazily so `import
    sabba` never requires the mcp package."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("the MCP server needs: pip install mcp") from e

    mcp = FastMCP("sabba", instructions=(
        "Sabba proves security bugs by triggering them. Give a tool a target directory; it "
        "runs the oracle or a language prover and returns a verdict. A finding is returned "
        "only when the exploit actually reproduced, so results are proofs, not guesses."))

    @mcp.tool()
    def doctor() -> dict:
        """Report which prover toolchains and models are available on this machine."""
        return do_doctor()

    @mcp.tool()
    def list_provers() -> dict:
        """List the registered provers and the language or chain domains they cover."""
        return do_list_provers()

    @mcp.tool()
    def verify(target: str) -> dict:
        """Compile a native C/C++ target under AddressSanitizer and run its known PoC.
        Returns a verdict: verified true only if the sanitizer reported a real crash.
        target is a path to a directory containing sources and a target.json with a known_poc.
        """
        return do_verify(target)

    @mcp.tool()
    def solve(target: str) -> dict:
        """Let Z3 synthesize overflow inputs for a native C/C++ target; the oracle confirms
        each by running it under a sanitizer. Needs no model. Returns the confirmed findings."""
        return do_solve(target)

    @mcp.tool()
    def hunt(target: str, model: str | None = None, no_model: bool = False,
             domain: str | None = None, top_k: int = 8) -> dict:
        """Full hunt on a target directory: retrieval, Z3, and the reasoning model for C/C++,
        or the fork prover for a Solidity target. Every candidate is run before it is returned,
        so findings are proven. Set no_model=true to use only Z3 and the oracle. This can take
        a while on a real target. domain forces the prover (native or evm)."""
        return do_hunt(target, model=model, no_model=no_model, domain=domain, top_k=top_k)

    @mcp.tool()
    def scan(target: str, model: str | None = None) -> dict:
        """Reasoning-only pass: the model proposes candidate bugs and the oracle verifies each.
        Returns only what reproduced. Needs a model configured in the server environment."""
        return do_scan(target, model=model)

    @mcp.tool()
    def prove(target: str, base: str = "HEAD", test: str | None = None) -> dict:
        """Prove a code change works by running it, not by trusting it. Differential over a git
        base ref (head is the working tree at target). With test=<shell command>, proven means
        the command FAILS on base and PASSES on head. Without test, if target has a target.json
        with a known_poc, proven means the PoC crashes under a sanitizer on base and is clean on
        head (a proven fix). Needs no model. Use this to check an agent's own edit really did it."""
        return do_prove(target, base=base, test=test)

    @mcp.tool()
    def verify_change(path: str = ".", base: str = "HEAD", head: str | None = None,
                      test: str | None = None, build: str | None = None,
                      setup: str | None = None, sandbox: bool = False) -> dict:
        """Prove a code change actually works by running it (Magga engine): build the change,
        run the suite, and confirm a newly added test FAILS on the git base and PASSES on the
        head, so a hollow change that passes either way is caught. This is the correctness half
        of Sabba; prove, hunt, and security_scan are the security half. Set test/build/setup if
        they are not auto-detected; sandbox=True runs an untrusted change in a no-network
        container. Needs Node.js (npx). Detects 16 languages. No model."""
        return do_verify_change(path, base=base, head=head, test=test, build=build,
                                setup=setup, sandbox=sandbox)

    @mcp.tool()
    def security_scan(path: str) -> dict:
        """Vet a Python skill or plugin (.py) by running it under observation and reporting what
        it actually did: credential-looking file reads, outbound network, subprocesses spawned.
        Returns a risk verdict (clean / suspicious / dangerous) with evidence, so you can catch a
        malicious marketplace skill before installing it. Runs inside a network-cut container when
        docker or podman is present (so a hostile skill cannot exfiltrate during the scan), and
        falls back to in-process observation otherwise. The result's `isolated` says which. Needs
        no model."""
        return do_security_scan(path)

    @mcp.tool()
    def rank(target: str, top_k: int = 15) -> dict:
        """Rank the functions in a native C/C++ target by bug likelihood, so you look at the risky
        ones first. Token-free: a local ML model (or a heuristic when untrained) scores each
        function; returns the top_k with their risk score, file, line, and dangerous sinks."""
        return do_rank(target, top_k=top_k)

    @mcp.tool()
    def run_sandboxed(cmd: str, tier: str = "local", timeout: float = 10.0,
                      image: str = "alpine:3") -> dict:
        """Run a shell command in an isolated sandbox and return its exit code, output, and
        whether it was killed. Use this to execute untrusted or generated code safely through
        Sabba. tier=local uses process isolation (rlimits, scrubbed env, hard wall-clock kill);
        tier=container runs it in a network-cut, read-only-root, capability-dropped container
        (needs docker or podman) with `image` as the base. Needs no model."""
        return do_run_sandboxed(cmd, tier=tier, timeout=timeout, image=image)

    @mcp.tool()
    def cost_estimate(task: str) -> dict:
        """Report whether a Sabba tool runs token-free (deterministic, on CPU) or needs the
        configured model, with a rough cost note. Most tools (verify, solve, prove, rank,
        security_scan, run_sandboxed) are token-free; only hunt and scan use a model. Use this to
        decide what to delegate to Sabba to keep your own token spend near zero."""
        return do_cost_estimate(task)

    @mcp.tool()
    def list_security_tools() -> dict:
        """List the security tools (nmap, nuclei, ffuf, sqlmap, httpx, subfinder, ...) installed
        on this host, by category, and which curated ones are missing. Use before kali_run to see
        what recon and scanning is available. Needs no model."""
        return do_list_security_tools()

    @mcp.tool()
    def kali_run(tool: str, args: list | None = None, timeout: float = 180.0) -> dict:
        """Run an installed security tool (nmap, nuclei, ffuf, httpx, subfinder, sqlmap, ...) and
        return its output, with structured parsing for the machine-readable ones (pass the tool's
        JSON/XML flag, e.g. nmap -oX -). AUTHORIZED TARGETS ONLY: every run is checked against the
        operator scope (SABBA_SCOPE) and refused if the target is out of scope; loopback and
        scanme.nmap.org are the only defaults. Runs in a sandbox with a hard timeout. Tool output
        is a candidate -- confirm exploitable findings with verify/hunt. Needs no model."""
        return do_kali_run(tool, args=args, timeout=timeout)

    return mcp


def run(http: bool = False, host: str = "127.0.0.1", port: int = 8765) -> None:
    """Serve over stdio (default, understood by every MCP client) or streamable HTTP."""
    mcp = build_server()
    if http:
        mcp.settings.host = host
        mcp.settings.port = port
        mcp.run(transport="streamable-http")
    else:
        mcp.run()
