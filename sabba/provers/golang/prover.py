"""The Go fuzzing prover and the hunt that drives it.

Two phases keep a model-written harness from faking a crash. First the fuzzer only discovers
a candidate PoC (bytes); nothing is read from its output. Then a Sabba-owned reproducer
re-runs the PoC and decides the verdict from unforgeable channels: the recovered panic's real
runtime.Stack on fd 3, or the runtime's own fatal or SIGQUIT dump on fd 2. Attribution comes
only from those structured frames, and a verified crash must land in a target .go file, not in
the reproducer wrapper.

Static gates run before anything executes. The import line must be a single plain import of
the target module (no os, no fmt, no side-effect import, no break-out of the import block).
The body may not manufacture a crash or write output (no panic, no recover, no os or fmt or
runtime or log or reflect, no testing.T), may not define its own func or pass a callback into
the target, and may not spin (no bare infinite loop and no always-true loop condition such as
for len(data) >= 0), and it must actually call the target. A harness that fails any gate is
rejected as unsound_harness and never fuzzed.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable

from ...types import Finding, Verdict
from ..base import ProofBundle
from .classify import classify_outcome, frames_hit_target
from .detect import is_go_target
from .runner import (FUZZ_FUNC, FUZZ_PKG, Discovery, GoHarness, Outcome, assemble,
                     discover_poc, go_available, module_path, verify_poc)

# Standard-library roots we reject in an import when the target module path is unknown. When
# go.mod is present the import must be under that module, which is the real check.
_STD_ROOTS = {
    "os", "fmt", "io", "net", "syscall", "runtime", "reflect", "unsafe", "bufio", "log",
    "path", "time", "strings", "bytes", "encoding", "crypto", "math", "sort", "sync",
    "context", "errors", "strconv", "regexp", "hash", "compress", "archive", "database",
    "html", "text", "mime", "plugin", "debug", "os/exec", "internal", "embed", "testing",
}

# Body tokens that manufacture a crash or write output. Blocking the output and control levers
# is defense in depth; the real backstop is that kind and attribution come from the structured
# stack, not from anything the body prints. recover is blocked so a panic reaches the wrapper.
# func is blocked so the body cannot define a recursive helper or a callback it passes into the
# target: a harness callback that recurses through a target frame is not a target bug.
_FORBIDDEN_RE = re.compile(
    r"\bpanic\b|\brecover\b|\bprintln\b|\bprint\b|\bfunc\b"
    r"|\bos\.|\bfmt\.|\blog\.|\bruntime\.|\bdebug\.|\bsyscall\.|\bunsafe\.|\breflect\.|\bbufio\."
    r"|\bt\."
    r"|\bfor\s*\{|\bselect\s*\{")

# A loop condition that is always true or empty spins forever no matter what the target does, so
# a harness can use it to force a wall-clock timeout and then attribute the running goroutine to
# the target. `for len(data) >= 0 {}` is the canonical bypass of a plain `for {}` check. Bounded
# loops are fine: a three-clause `for i := 0; i < n; i++` and a `for ... range ...` both make
# progress, so they are allowed. These headers are the always-true or empty ones we reject.
_ALWAYS_TRUE_COND_RE = re.compile(
    r"\A(?:true"
    r"|1\s*==\s*1|0\s*==\s*0|1\s*<=\s*1|0\s*<\s*1"
    r"|len\s*\([^()]*\)\s*(?:>=\s*0|>\s*-1)"
    r"|cap\s*\([^()]*\)\s*(?:>=\s*0|>\s*-1))\Z")


SYSTEM = """You write Go fuzz harness bodies for Go packages. You output only JSON. You pick \
one exported function that takes attacker-controlled bytes (or a value you build from bytes) \
and drive it from the fuzz input, so a crash points at one place in the target.

Return STRICT JSON only, no prose, with this shape:
{
  "entry": "short note on which function you fuzz",
  "import": "a single plain import spec for the target package only. Use a named import so \
the selector is unambiguous, for example: vuln \\"goobtarget\\". Import nothing else.",
  "body": "the statements that go inside the fuzz body. data is a []byte. Turn it into the \
argument the entry point expects and call the target through the package you imported."
}

Sabba wraps your import and body and runs the target itself, so do not write the package \
clause, the import block, or the fuzz function yourself, and import only the target package. \
Call exactly one target function through the package you imported. Do not use panic, recover, \
os, fmt, log, runtime, reflect, or the testing.T value, do not define your own func or pass a \
callback into the target, and do not write a loop whose condition is always true (no `for {}`, \
no `for len(data) >= 0 {}`); the crash must come from the target, not from your harness."""


class GoFuzzProver:
    domain = "go"
    languages = ("go",)
    vuln_classes = ("panic-dos", "stack-exhaustion", "memory-exhaustion",
                    "algorithmic-complexity")

    def matches(self, target_dir: Path, spec: dict | None) -> bool:
        return is_go_target(Path(target_dir), spec)

    def prove(self, target_dir: Path, candidate: GoHarness, *, secs: int = 20,
              timeout: int = 10, seed: bytes | None = None) -> Verdict:
        verdict, _cwe, _outcome = self._prove(target_dir, candidate, secs=secs,
                                              timeout=timeout, seed=seed)
        return verdict

    def _prove(self, target_dir: Path, candidate: GoHarness, *, secs: int,
               timeout: int, seed: bytes | None = None
               ) -> tuple[Verdict, str, Outcome | None]:
        target_dir = Path(target_dir)
        # -- static gates, before anything runs --
        imp_err = _gate_import(candidate.import_line, module_path(target_dir))
        if imp_err:
            return (Verdict(verified=False, reason="unsound_harness",
                            evidence="import gate: " + imp_err), "", None)
        bad = _gate_body(candidate.body or "")
        if bad:
            return (Verdict(verified=False, reason="unsound_harness",
                            evidence="body gate rejects: " + ", ".join(bad)), "", None)
        aliases = _import_aliases(candidate.import_line)
        if not aliases or not _calls_target(candidate.body or "", aliases):
            return (Verdict(verified=False, reason="unsound_harness",
                            evidence="harness body does not call the target package"), "", None)
        if not go_available():
            return (Verdict(verified=False, reason="prover_unavailable",
                            evidence="go toolchain not found. install Go 1.18+, then re-run."),
                    "", None)

        # -- phase 1: discovery. take only the candidate PoC bytes --
        disc: Discovery = discover_poc(target_dir, candidate, secs=secs,
                                       per_input_timeout=timeout, seed=seed)
        if disc.kind == "build_error":
            return (Verdict(verified=False, reason="harness_error",
                            evidence=disc.output), "", None)
        if disc.poc is None:
            return (Verdict(verified=False, reason="no_crash",
                            evidence=disc.output), "", None)

        # -- phase 2: verification. the Sabba reproducer decides the truth --
        outcome: Outcome = verify_poc(target_dir, candidate, disc.poc, wall=timeout)
        outcome.poc_name = disc.poc_name
        verdict, cwe = classify_outcome(outcome, _target_stems(target_dir))
        return verdict, cwe, outcome

    def write_bundle(self, target_dir: Path, candidate: GoHarness, verdict: Verdict,
                     out_dir: Path, *, outcome: Outcome | None = None) -> ProofBundle:
        out_dir.mkdir(parents=True, exist_ok=True)
        staged = []
        for src in Path(target_dir).rglob("*.go"):
            if src.name.endswith("_test.go"):
                continue
            (out_dir / src.name).write_text(src.read_text(errors="replace"))
            staged.append(src.name)
        gomod = Path(target_dir) / "go.mod"
        if gomod.exists():
            (out_dir / "go.mod").write_text(gomod.read_text(errors="replace"))
        fuzz_dir = out_dir / FUZZ_PKG
        fuzz_dir.mkdir(parents=True, exist_ok=True)
        (fuzz_dir / "fuzz_test.go").write_text(assemble(candidate))
        poc_name = ""
        if outcome and outcome.poc:
            poc_name = outcome.poc_name or "poc"
            corpus = fuzz_dir / "testdata" / "fuzz" / FUZZ_FUNC
            corpus.mkdir(parents=True, exist_ok=True)
            (corpus / poc_name).write_bytes(_go_corpus(outcome.poc))
        script = ('#!/usr/bin/env bash\nset -e\ncd "$(dirname "$0")"\n'
                  f'go test -run=^{FUZZ_FUNC}$ -v ./{FUZZ_PKG}\n')
        rerun = out_dir / "run.sh"
        rerun.write_text(script)
        rerun.chmod(0o755)
        return ProofBundle(
            domain="go", target={"sources": staged, "module": "go.mod"},
            witness={"harness": f"{FUZZ_PKG}/fuzz_test.go", "poc": poc_name},
            checker={"kind": verdict.reason}, rerun="run.sh", dir=str(out_dir))


def go_hunt(target_dir, *, model: str | None = None, on_event=None, secs: int = 20,
            timeout: int = 10, max_tries: int = 4,
            judge_fn: Callable[[str, str], str] | None = None) -> list[Finding]:
    """Have the model write a Go fuzz body, fuzz, and report only a proven crash."""
    log = on_event or (lambda _m: None)
    target_dir = Path(target_dir).resolve()
    if not go_available():
        log("[go] go toolchain not found. install Go 1.18+, then re-run.")
        return []

    spec = _read_spec(target_dir)
    prover = GoFuzzProver()
    survey = _survey(target_dir)
    judge_fn = judge_fn or _default_judge(model)
    user = (f"Go target `{target_dir.name}`. Module and sources:\n{survey}\n\n"
            "Write the harness JSON now.")

    err = ""
    for attempt in range(max_tries):
        prompt = user if not err else user + f"\n\nYour previous harness failed:\n{err[-1500:]}\nFix it."
        log(f"[go] writing harness (attempt {attempt + 1}/{max_tries})")
        harness = _parse_harness(judge_fn(SYSTEM, prompt))
        if harness is None:
            err = "your output was not valid JSON with import and body"
            continue
        log(f"[go] fuzzing: {harness.entry or '(entry)'} for {secs}s")
        verdict, cwe, outcome = prover._prove(target_dir, harness, secs=secs, timeout=timeout)
        log(f"[go] verdict: {verdict.reason} (verified={verdict.verified})")
        if verdict.verified:
            bundle = prover.write_bundle(target_dir, harness, verdict,
                                         target_dir / "sabba-proof", outcome=outcome)
            log(f"[go] proof written to {bundle.dir}")
            return [Finding(
                cwe=cwe or spec.get("cwe", "CWE-400"),
                title=spec.get("title", f"{verdict.reason} in {target_dir.name}"),
                file=spec.get("file", ""), function=spec.get("function", ""),
                verdict=verdict,
                rationale=f"Go fuzzing found an input that triggers {verdict.reason}. "
                          f"Proof: {bundle.dir}. Re-run with ./run.sh.")]
        if verdict.reason in ("harness_error", "unsound_harness"):
            err = verdict.evidence
    log("[go] no crash proven this run")
    return []


# -- static gates ----------------------------------------------------------

def _gate_import(import_line: str, module: str) -> str | None:
    """The import must be a single plain import spec loading only the target module. This is
    what stops the harness running code at load or breaking out of the import block, which is
    in turn what lets the reproducer trust its private result channels."""
    line = _strip_comments(import_line or "").strip()
    if not line:
        return "no import given"
    m = re.fullmatch(r'(?:([A-Za-z_]\w*)\s+)?"([^"\n\\]+)"', line)
    if not m:
        return "import must be one plain spec: an optional alias then a quoted target path"
    alias, path = m.group(1), m.group(2)
    if alias in ("_",):
        return "a blank side-effect import is not allowed"
    if module:
        if not (path == module or path.startswith(module + "/")):
            return f"import must load the target module {module!r}, not {path!r}"
        return None
    first_two = "/".join(path.split("/")[:2])
    first = path.split("/", 1)[0]
    if "." not in first and (first in _STD_ROOTS or first_two in _STD_ROOTS):
        return f"import must load the target, not the package {path!r}"
    return None


def _gate_body(body: str) -> list[str]:
    src = _strip_go(body or "")
    hits = {m.group(0).strip() for m in _FORBIDDEN_RE.finditer(src)}
    hits.update(_spin_loops(src))
    return sorted(hits)


def _spin_loops(src: str) -> list[str]:
    """Loop headers whose condition is always true or empty, so the loop spins regardless of the
    target. src is already comment- and string-stripped by _strip_go."""
    bad = []
    for m in re.finditer(r"\bfor\b([^{]*)\{", src):
        header = m.group(1).strip()
        if _header_is_spin(header):
            bad.append(("for " + header).strip())
    return bad


def _header_is_spin(header: str) -> bool:
    if header == "":
        return True                              # bare for {}
    if re.search(r"\brange\b", header):
        return False                             # range is bounded by its operand
    if ";" in header:
        parts = header.split(";")
        cond = parts[1].strip() if len(parts) >= 2 else ""
        return cond == "" or _cond_always_true(cond)   # empty or always-true middle clause
    return _cond_always_true(header)             # while-form: for <cond> {


def _cond_always_true(cond: str) -> bool:
    c = cond.strip()
    if _ALWAYS_TRUE_COND_RE.match(c):
        return True
    return "|| true" in c or "true ||" in c


def _calls_target(body: str, aliases: set[str]) -> bool:
    sbody = _strip_go(body or "")
    return any(re.search(rf"\b{re.escape(a)}\s*\.", sbody) for a in aliases)


def _import_aliases(import_line: str) -> set[str]:
    """The names a body can use to reach the target: an explicit alias and the path's base."""
    m = re.search(r'^\s*([A-Za-z_]\w*)?\s*"([^"]+)"', _strip_comments(import_line or ""))
    if not m:
        return set()
    names = set()
    if m.group(1) and m.group(1) != "_":
        names.add(m.group(1))
    if m.group(2):
        names.add(m.group(2).rsplit("/", 1)[-1])
    return names


def _strip_go(code: str) -> str:
    code = re.sub(r"/\*.*?\*/", " ", code, flags=re.DOTALL)
    code = re.sub(r"//[^\n]*", " ", code)
    code = re.sub(r'"(?:\\.|[^"\\])*"', '""', code)
    return re.sub(r"`[^`]*`", "``", code)


def _strip_comments(code: str) -> str:
    code = re.sub(r"/\*.*?\*/", " ", code, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", " ", code)


# -- helpers ---------------------------------------------------------------

def _target_stems(target_dir: Path) -> set[str]:
    return {p.stem for p in Path(target_dir).rglob("*.go")
            if not p.name.endswith("_test.go")}


def _go_corpus(poc: bytes) -> bytes:
    """Encode raw PoC bytes as a Go fuzz corpus file so the re-run harness replays them."""
    body = "".join(f"\\x{b:02x}" for b in poc)
    return (f'go test fuzz v1\n[]byte("{body}")\n').encode()


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
    gomod = target_dir / "go.mod"
    if gomod.exists():
        out.append(f"# go.mod\n{gomod.read_text(errors='replace')}\n")
    for src in sorted(target_dir.rglob("*.go")):
        if src.name.endswith("_test.go"):
            continue
        body = src.read_text(errors="replace")
        chunk = f"# {src.relative_to(target_dir)}\n{body}\n"
        if total + len(chunk) > limit:
            out.append(f"# {src.relative_to(target_dir)} (truncated)\n{body[:1500]}\n")
            break
        out.append(chunk)
        total += len(chunk)
    return "\n".join(out) or "(no .go sources)"


def _parse_harness(text: str) -> GoHarness | None:
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
    return GoHarness(import_line=str(d.get("import", "")), body=str(d["body"]),
                     entry=str(d.get("entry", "")))


def _default_judge(model: str | None) -> Callable[[str, str], str]:
    from ...llm import judge

    def _run(system: str, user: str) -> str:
        return judge(system, user, model)
    return _run
