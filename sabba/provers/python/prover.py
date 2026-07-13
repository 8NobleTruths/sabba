"""The Python fuzzing prover and the hunt that drives it.

Two phases, so a model-written harness cannot fabricate a finding:

  Discovery. Atheris runs the model's harness and finds an input that makes it crash. From
  this phase Sabba takes exactly one thing, the candidate PoC bytes. It takes nothing from
  the fuzzer's stdout and ignores any artifact file the harness wrote. A forged crash here
  only yields a candidate input, which the next phase rejects.

  Verification. A Sabba-owned reproducer (verify.py), not the model's, re-runs the PoC in a
  scratch dir with the harness's stdout and stderr nulled, and decides the verdict from
  unforgeable channels only: the structured exception (its class and its real stack frames)
  for a caught crash, or the parent's own measurement of a killed child plus the runtime's
  own stack dump. Attribution requires a real frame in a target file, never the reproducer.

Before either phase, static gates (gates.py) reject a harness that could run code at load or
manufacture its own crash. Verification does not need atheris, so it runs on any Python.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable

from ...types import Finding, Verdict
from ..base import ProofBundle
from .classify import CrashInfo
from .detect import is_python_target
from .gates import scan_harness
from .runner import PyHarness, atheris_available, run_fuzz
from .verify import Outcome, target_stems, verdict_from_outcome, verify_poc

SYSTEM = """You write Atheris fuzz harnesses for Python libraries. You output only JSON. You \
pick one entry point that takes attacker-controlled bytes or text and drive it from raw \
fuzz input, so a crash points at one place in the target.

Return STRICT JSON only, no prose, with this shape:
{
  "entry": "short note on which function you fuzz",
  "imports": "the import line(s) that load the target module, for example: import vuln",
  "body": "the body of TestOneInput(data) where data is bytes. Turn data into the argument \
the entry point expects and call it. Use atheris.FuzzedDataProvider(data) if you need a \
typed value such as a string or an int."
}

Sabba wraps your imports and body and runs it, so do not write atheris.Setup or atheris.Fuzz \
yourself. Import only the target module (and atheris). Do not import os, sys, subprocess or \
anything else, and do not run code on the import line. In the body, call exactly one target \
entry point. Do not raise, exit, print, write files, change the recursion or resource \
limits, or write your own recursion or large allocation; the crash must come from the \
target, not from your harness."""


class PyFuzzProver:
    domain = "python"
    languages = ("python",)
    vuln_classes = ("stack-exhaustion", "memory-exhaustion", "algorithmic-complexity",
                    "native-crash")

    def matches(self, target_dir: Path, spec: dict | None) -> bool:
        return is_python_target(Path(target_dir), spec)

    def prove(self, target_dir: Path, candidate: PyHarness, *, secs: int = 30,
              timeout: int = 10, seed: bytes | None = None) -> Verdict:
        verdict, _cwe, _out = self._prove(target_dir, candidate, secs=secs,
                                          timeout=timeout, seed=seed)
        return verdict

    def prove_poc(self, target_dir: Path, candidate: PyHarness, poc: bytes, *,
                  timeout: int = 10) -> tuple[Verdict, str, Outcome | None]:
        """Verify a known PoC directly, skipping discovery. Used when a candidate input is
        already in hand (and in tests, where atheris need not be installed)."""
        target_dir = Path(target_dir)
        stems = target_stems(target_dir)
        reason = scan_harness(candidate, stems)
        if reason:
            return (Verdict(verified=False, reason="unsound_harness", evidence=reason),
                    "", None)
        outcome = verify_poc(target_dir, candidate, poc, timeout=timeout)
        verdict, cwe = verdict_from_outcome(outcome, stems)
        return verdict, cwe, outcome

    def _prove(self, target_dir: Path, candidate: PyHarness, *, secs: int,
               timeout: int, seed: bytes | None = None) -> tuple[Verdict, str, Outcome | None]:
        target_dir = Path(target_dir)
        stems = target_stems(target_dir)

        # Gate first: a harness that could run code at load or fake a crash is never fuzzed.
        reason = scan_harness(candidate, stems)
        if reason:
            return (Verdict(verified=False, reason="unsound_harness", evidence=reason),
                    "", None)

        if not atheris_available():
            return (Verdict(verified=False, reason="prover_unavailable",
                            evidence="atheris not installed. pip install atheris, then re-run."),
                    "", None)

        # Discovery: take only the candidate PoC bytes, nothing else.
        crash = run_fuzz(target_dir, candidate, secs=secs, per_input_timeout=timeout, seed=seed)
        poc = crash.poc_bytes
        if not poc:
            return (Verdict(verified=False, reason="no_crash",
                            evidence="discovery found no crashing input"), "", None)

        # Verification: the Sabba reproducer decides, from unforgeable channels only.
        outcome = verify_poc(target_dir, candidate, poc, timeout=timeout)
        verdict, cwe = verdict_from_outcome(outcome, stems)
        return verdict, cwe, outcome

    def write_bundle(self, target_dir: Path, candidate: PyHarness, verdict: Verdict,
                     out_dir: Path, *, crash: Outcome | None = None) -> ProofBundle:
        out_dir.mkdir(parents=True, exist_ok=True)
        for py in Path(target_dir).rglob("*.py"):
            (out_dir / py.name).write_text(py.read_text(errors="replace"))
        from .runner import assemble
        (out_dir / "harness.py").write_text(assemble(candidate))
        if crash and crash.poc:
            (out_dir / "crash.bin").write_bytes(crash.poc)
        script = ('#!/usr/bin/env bash\nset -e\ncd "$(dirname "$0")"\n'
                  'python harness.py crash.bin\n')
        rerun = out_dir / "run.sh"
        rerun.write_text(script)
        rerun.chmod(0o755)
        return ProofBundle(
            domain="python", target={"sources": [p.name for p in Path(target_dir).rglob("*.py")]},
            witness={"harness": "harness.py", "poc": "crash.bin"},
            checker={"kind": verdict.reason}, rerun="run.sh", dir=str(out_dir))


def py_hunt(target_dir, *, model: str | None = None, on_event=None, secs: int = 30,
            timeout: int = 10, max_tries: int = 4,
            judge_fn: Callable[[str, str], str] | None = None) -> list[Finding]:
    """Have the model write an Atheris harness, fuzz, and report only a proven crash."""
    log = on_event or (lambda _m: None)
    target_dir = Path(target_dir).resolve()
    if not atheris_available():
        log("[py] atheris not installed. pip install atheris, then re-run.")
        return []

    spec = _read_spec(target_dir)
    prover = PyFuzzProver()
    survey = _survey(target_dir)
    judge_fn = judge_fn or _default_judge(model)
    user = (f"Python target `{target_dir.name}`. Source files:\n{survey}\n\n"
            "Write the harness JSON now.")

    err = ""
    for attempt in range(max_tries):
        prompt = user if not err else user + f"\n\nYour previous harness failed:\n{err[-1500:]}\nFix it."
        log(f"[py] writing harness (attempt {attempt + 1}/{max_tries})")
        harness = _parse_harness(judge_fn(SYSTEM, prompt))
        if harness is None:
            err = "your output was not valid JSON with imports and body"
            continue
        log(f"[py] fuzzing: {harness.entry or '(entry)'} for {secs}s")
        verdict, cwe, outcome = prover._prove(target_dir, harness, secs=secs, timeout=timeout)
        log(f"[py] verdict: {verdict.reason} (verified={verdict.verified})")
        if verdict.verified:
            bundle = prover.write_bundle(target_dir, harness, verdict,
                                         target_dir / "sabba-proof", crash=outcome)
            log(f"[py] proof written to {bundle.dir}")
            return [Finding(
                cwe=cwe or spec.get("cwe", "CWE-400"),
                title=spec.get("title", f"{verdict.reason} in {target_dir.name}"),
                file=spec.get("file", ""), function=spec.get("function", ""),
                verdict=verdict,
                rationale=f"Atheris found an input that triggers {verdict.reason}, and the "
                          f"Sabba reproducer confirmed it in the target. "
                          f"Proof: {bundle.dir}. Re-run with ./run.sh.")]
        if verdict.reason in ("harness_error", "unsound_harness"):
            err = verdict.evidence
    log("[py] no crash proven this run")
    return []


# -- helpers ---------------------------------------------------------------

def _read_spec(target_dir: Path) -> dict:
    tj = target_dir / "target.json"
    if tj.exists():
        try:
            return json.loads(tj.read_text())
        except Exception:
            return {}
    return {}


def _survey(target_dir: Path, limit: int = 16_000) -> str:
    out, total = [], 0
    for py in sorted(target_dir.rglob("*.py")):
        if py.name == "harness.py":
            continue
        body = py.read_text(errors="replace")
        chunk = f"# {py.relative_to(target_dir)}\n{body}\n"
        if total + len(chunk) > limit:
            out.append(f"# {py.relative_to(target_dir)} (truncated)\n{body[:1500]}\n")
            break
        out.append(chunk)
        total += len(chunk)
    return "\n".join(out) or "(no .py sources)"


def _parse_harness(text: str) -> PyHarness | None:
    if not text:
        return None
    t = text.strip()
    m = re.search(r"```(?:json)?\s*(.*?)```", t, re.DOTALL)
    if m:
        t = m.group(1).strip()
    a, b = t.find("{"), t.rfind("}")
    if a < 0 or b <= a:
        return None
    try:
        d = json.loads(t[a:b + 1])
    except Exception:
        return None
    if not d.get("body"):
        return None
    return PyHarness(imports=str(d.get("imports", "")), body=str(d["body"]),
                     entry=str(d.get("entry", "")))


def _default_judge(model: str | None) -> Callable[[str, str], str]:
    from ...llm import judge

    def _run(system: str, user: str) -> str:
        return judge(system, user, model)
    return _run
