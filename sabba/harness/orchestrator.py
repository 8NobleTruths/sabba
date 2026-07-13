"""The hunt driver: cheap analysis first, the model only where it is still needed.

Order of work on a target:

  1. Rank functions by dangerous-sink and reachability (retrieval).
  2. Try the Z3 synthesizer on every source. These are cheap and need no model, and
     they resolve the common strcpy/malloc-size overflows outright.
  3. If a model is configured, run the reasoning agent over what is left, seeded with the
     retrieval hints, for the bugs the synthesizer cannot express yet.

Every candidate, whether it came from Z3 or the model, is only reported after the oracle
compiles it under a sanitizer and the crash reproduces. The oracle is the single gate.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..llm import LLMUnavailable
from ..types import Finding
from .agent import run_scan
from .retrieval import format_hints, rank_candidates
from .symbolic.synth import hunt_symbolic


def _key(f: Finding):
    return (f.function, f.line, f.cwe)


def _glob_sources(d: Path) -> list[Path]:
    return (list(d.rglob("*.c")) + list(d.rglob("*.h"))
            + list(d.rglob("*.cc")) + list(d.rglob("*.cpp")))


class SabbaAgent:
    """Drives a target through retrieval, symbolic synthesis, and the reasoning agent."""

    def __init__(self, *, model: str | None = None, top_k: int = 8):
        self.model = model
        self.top_k = top_k

    def hunt(self, target_dir, *, use_model: bool = True, on_event=None,
             domain: str | None = None) -> list[Finding]:
        log = on_event or (lambda _m: None)
        target_dir = Path(target_dir).resolve()
        tj = target_dir / "target.json"
        spec: dict = {}
        if tj.exists():
            try:
                spec = json.loads(tj.read_text())
            except Exception:
                spec = {}

        # Pick the prover for this target. Native C/C++ falls through to the pipeline
        # below unchanged; a Solidity/Foundry target routes to the EVM prover instead.
        from ..provers import detect_domain
        dom = domain or detect_domain(target_dir, spec)
        if dom == "evm":
            log("[stage] EVM/Solidity target: routing to the fork prover")
            from ..provers.evm.prover import evm_hunt
            return evm_hunt(target_dir, model=self.model, on_event=log)
        if dom == "python":
            log("[stage] Python target: routing to the fuzzing prover")
            from ..provers.python.prover import py_hunt
            return py_hunt(target_dir, model=self.model, on_event=log)
        if dom == "go":
            log("[stage] Go target: routing to the fuzzing prover")
            from ..provers.golang.prover import go_hunt
            return go_hunt(target_dir, model=self.model, on_event=log)
        if dom == "java":
            log("[stage] Java target: routing to the fuzzing prover")
            from ..provers.java.prover import java_hunt
            return java_hunt(target_dir, model=self.model, on_event=log)
        if dom == "node":
            log("[stage] Node (JS/TS) target: routing to the fuzzing prover")
            from ..provers.node.prover import node_hunt
            return node_hunt(target_dir, model=self.model, on_event=log)

        if spec.get("sources"):
            sources = [target_dir / s for s in spec["sources"]]
        else:
            sources = _glob_sources(target_dir)

        candidates = rank_candidates(target_dir, top_k=self.top_k)
        if candidates:
            log(format_hints(candidates))

        log("[stage] symbolic synthesis (Z3)")
        findings = hunt_symbolic(sources, on_event=log)
        seen = {_key(f) for f in findings}
        log(f"[stage] symbolic found {len(findings)} verified finding(s)")

        if use_model and not tj.exists():
            log("[stage] the model scan needs a target.json; ran the solver only")
        elif use_model:
            try:
                hints = format_hints(candidates)
                if findings:
                    hints += "\n\nAlready confirmed by the solver (look for different bugs):\n"
                    hints += "\n".join(f"  - {f.function} @ line {f.line}: {f.title}"
                                       for f in findings)
                log("[stage] reasoning agent")
                for f in run_scan(target_dir, model=self.model, hints=hints, on_event=log):
                    if _key(f) not in seen:
                        seen.add(_key(f))
                        findings.append(f)
            except LLMUnavailable as e:
                log(f"[stage] no model configured, keeping symbolic results only ({e})")

        # Leave labeled data behind: each surfaced function, labeled by whether the oracle
        # proved a bug in it. Fail-safe, so the flywheel never breaks a hunt.
        try:
            from ..water.traces import TraceStore, enabled
            if enabled() and candidates:
                n = TraceStore().record_hunt(target_dir, candidates, findings)
                if n:
                    log(f"[stage] recorded {n} labeled trace(s) for the ranker")
        except Exception:  # noqa: BLE001
            pass

        return findings


def hunt(target_dir, *, model=None, top_k=8, use_model=True, on_event=None,
         domain=None) -> list[Finding]:
    return SabbaAgent(model=model, top_k=top_k).hunt(
        target_dir, use_model=use_model, on_event=on_event, domain=domain)
