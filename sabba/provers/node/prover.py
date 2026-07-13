"""The Node (JavaScript and TypeScript) fuzzing prover and the hunt that drives it.

Same shape as the other fuzzing provers, and the same hard rule: a Finding is minted only
from a Verdict that is verified, and a Verdict is verified only when a real security crash
happened inside the target. The harness is the model's and is untrusted, so the verdict never
comes from anything the harness can influence.

Two phases (see docs/PROVER_SOUNDNESS.md):

  1. Discovery. Jazzer.js runs the harness and finds an input that crashes it. We take from
     this phase exactly one thing: the candidate PoC bytes. Nothing from its stdout, no
     artifact file it may have written.
  2. Verification. A Sabba-owned reproducer (reproducer.py, Sabba source generated at run
     time) re-runs the PoC with the harness stdout and stderr nulled, and reads the outcome
     over channels the harness cannot forge: a caught exception's real class and stack, or the
     parent's own measurement of a killed child plus Node's diagnostic report. The kind comes
     from that structured outcome and the target attribution from the real stack frames, never
     from a substring scan of mixed output or a harness-written file.

Before either phase the static gates reject a harness that could manufacture its own crash or
run code at load. The requires line must be import/require statements only, loading just the
target or the fuzzer API; the body may not throw, print, touch process, require, eval, write a
file, change the stack limit, or spin a bare infinite loop; and the body must actually call
the target. The gates are what let the reproducer trust its private result channel.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable

from ...types import Finding, Verdict
from ..base import ProofBundle
from .classify import Outcome, classify_outcome
from .detect import is_node_target
from .reproducer import verify_poc
from .runner import NodeHarness, assemble, discover, toolchain_available

_STEM_EXT = ("js", "mjs", "cjs", "ts", "mts", "cts")

# Computed member access on the stripped body: an identifier, a call result, an index result,
# or a (now-emptied) string literal followed by `[`. This is what closed the round-1 hole:
# module["require"]("fs")["writeFileSync"](...) reads through a computed key, so the old
# name-only regex missed it. Array literals (`[` after `=`, `(`, `,`, an operator, or a
# statement start) are not member access and are not matched. The body must use dot access.
_COMPUTED_MEMBER = re.compile('(?:[\\w$)\\]]|""|' + "''" + '|``)\\s*\\[')

# Body tokens that could fake a crash or a hang, run code, reach the module/global object, or
# write output where a forged "target.js:line" could be planted. Attribution reads structured
# frames from an authenticated channel, not printed text, so this is defense in depth; the
# requires whitelist plus body-scope isolation are the real backstops. See round 2 in
# docs/PROVER_SOUNDNESS.md.
_FORBIDDEN_BODY = [
    (re.compile(r"\bthrow\b"), "throw"),
    (re.compile(r"\bprocess\b"), "process"),
    (re.compile(r"\bconsole\b"), "console"),
    (re.compile(r"\brequire\b"), "require"),
    (re.compile(r"\bimport\b"), "import"),
    (re.compile(r"\beval\b"), "eval"),
    (re.compile(r"\bnew\s+Function\b"), "new Function"),
    (re.compile(r"\bFunction\s*\("), "Function()"),
    (re.compile(r"\bglobalThis\b"), "globalThis"),
    (re.compile(r"\bglobal\b"), "global"),
    (re.compile(r"\bthis\b"), "this"),
    (re.compile(r"\bmodule\b"), "module"),
    (re.compile(r"\bexports\b"), "exports"),
    (re.compile(r"\bconstructor\b"), "constructor"),
    (re.compile(r"__proto__"), "__proto__"),
    (re.compile(r"\b__dirname\b"), "__dirname"),
    (re.compile(r"\b__filename\b"), "__filename"),
    (re.compile(r"\bReflect\b"), "Reflect"),
    (re.compile(r"\bWebAssembly\b"), "WebAssembly"),
    (re.compile(r"\barguments\b"), "arguments"),
    (re.compile(r"\bvm\b"), "vm"),
    (re.compile(r"\bfs\b"), "fs"),
    (re.compile(r"\b(?:writeFileSync|appendFileSync|createWriteStream|openSync|writeSync)\b"),
     "file write"),
    (re.compile(r"\bstackTraceLimit\b"), "stackTraceLimit"),
    (_COMPUTED_MEMBER, "computed member access"),
    # No harness-defined function or callback. A recursive helper crashes in the harness, not
    # the target; a callable passed into the target lets a harness frame be the innermost
    # (crashing) frame while a target frame merely sits below it. Both are forbidden.
    (re.compile(r"\bfunction\b"), "function definition"),
    (re.compile(r"=>"), "arrow function"),
    (re.compile(r"\bwhile\s*\(\s*(?:true|1)\s*\)"), "while(true)"),
    (re.compile(r"\bfor\s*\(\s*;\s*;"), "for(;;)"),
    (re.compile(r"\bdo\b[\s\S]*?\bwhile\s*\(\s*(?:true|1)\s*\)"), "do..while(true)"),
    # An always-true or side-effect-free loop condition, not only the literal true or 1:
    # `while (data.length >= 0)`, `> -1`, `!= null/undefined`, `|| true`, `|| 1`.
    (re.compile(r"\bwhile\s*\([^{;]*?(?:>=\s*0|>\s*-\s*1"
                r"|!==?\s*(?:null|undefined)|\|\|\s*(?:true|1)\b)"),
     "always-true loop condition"),
    (re.compile(r"\bwhile\s*\([^)]*\)\s*(?:\{\s*\}|;)"), "empty loop body"),
    (re.compile(r"\bfor\s*\([^)]*\)\s*(?:\{\s*\}|;)"), "empty loop body"),
]

# A requires statement may take exactly one of these forms and nothing else.
_ASSIGN_REQUIRE = re.compile(
    r'^(?:const|let|var)\s+(?:\{[^{}]*\}|[A-Za-z_$][\w$]*)\s*=\s*'
    r'require\(\s*(["\'])([^"\']+)\1\s*\)$')
_BARE_REQUIRE = re.compile(r'^require\(\s*(["\'])([^"\']+)\1\s*\)$')
_IMPORT_FROM = re.compile(r'^import\s+[^;]+?\s+from\s+(["\'])([^"\']+)\1$')
_IMPORT_BARE = re.compile(r'^import\s+(["\'])([^"\']+)\1$')

_BIND_ASSIGN = re.compile(r'^(?:const|let|var)\s+(\{[^{}]*\}|[A-Za-z_$][\w$]*)\s*=\s*require\(')
_BIND_IMPORT = re.compile(r'^import\s+(.+?)\s+from\s')
_CLAUSE_KEYWORDS = {"as", "default", "from", "import"}

SYSTEM = """You write Jazzer.js fuzz harness bodies for Node packages, JavaScript or \
TypeScript. You output only JSON. You pick one entry point that takes attacker-controlled \
bytes (a Buffer) or a value you build from them and drive it from the fuzz input, so a crash \
points at one place in the target.

Return STRICT JSON only, no prose, with this shape:
{
  "entry": "short note on which function you fuzz",
  "requires": "the require line(s) that load the target, for example: const vuln = \
require(\\"./vuln\\");",
  "body": "the body of fuzz(data), where data is a Buffer. Turn it into the argument the \
entry point expects and call the target, for example: vuln.run(data); . For a typed value \
you may use: const { FuzzedDataProvider } = require(\\"@jazzer.js/core\\"); const fdp = new \
FuzzedDataProvider(data);"
}

Sabba wraps your requires and body in module.exports.fuzz = function (data) { ... } and runs \
it under Jazzer.js, so do not write the fuzz wrapper yourself.

Hard rules, enforced before your harness runs:
- requires must be import or require statements only, and may load only the target (a \
relative path like "./vuln") or "@jazzer.js/core". No other module, no code on those lines.
- the body may not throw, print, or touch console or process; may not require, import, eval, \
or use Function/Reflect/vm/module/exports/global/globalThis/this; may not write a file or \
change Error.stackTraceLimit; and may not spin an infinite or empty loop. The crash must come \
from the target, not from your harness.
- use dot access only (vuln.run, not vuln["run"]): computed member access with [] is rejected.
- do not define your own function or arrow, and do not pass a callback into the target: the \
crash must happen inside the target's own frames.
- the body must actually call the target through the name you bound in requires."""


class NodeFuzzProver:
    domain = "node"
    languages = ("javascript", "typescript")
    vuln_classes = ("prototype-pollution", "command-injection", "path-traversal", "redos",
                    "stack-exhaustion", "memory-exhaustion", "algorithmic-complexity")

    def matches(self, target_dir: Path, spec: dict | None) -> bool:
        return is_node_target(Path(target_dir), spec)

    def prove(self, target_dir: Path, candidate: NodeHarness, *, secs: int = 20,
              timeout: int = 10, seed: bytes | None = None) -> Verdict:
        verdict, _cwe, _out = self._prove(target_dir, candidate, secs=secs,
                                          timeout=timeout, seed=seed)
        return verdict

    def _prove(self, target_dir: Path, candidate: NodeHarness, *, secs: int,
               timeout: int, seed: bytes | None = None
               ) -> tuple[Verdict, str, Outcome | None]:
        reason = check_harness(candidate)
        if reason:
            return (Verdict(verified=False, reason="unsound_harness", evidence=reason),
                    "", None)
        if not toolchain_available():
            return (Verdict(verified=False, reason="prover_unavailable",
                            evidence="node or the Jazzer.js launcher not found. install Node "
                                     "and @jazzer.js/core (set SABBA_JAZZERJS_HOME), then re-run."),
                    "", None)

        disc = discover(target_dir, candidate, secs=secs, per_input_timeout=timeout, seed=seed)
        if disc.kind == "build_error":
            return (Verdict(verified=False, reason="harness_error",
                            evidence=disc.output[-1500:]), "", None)
        if disc.kind != "candidate":
            return (Verdict(verified=False, reason="no_crash",
                            evidence="no crashing input found"), "", None)
        return self._verify_candidate(target_dir, candidate, disc.poc_bytes, timeout=timeout)

    def _verify_candidate(self, target_dir: Path, candidate: NodeHarness, poc_bytes: bytes, *,
                          timeout: int = 10, mem_mb: int = 256
                          ) -> tuple[Verdict, str, Outcome | None]:
        """Phase two on its own: re-run candidate bytes in the Sabba reproducer and decide.

        Needs only `node`, so this is the sound path exercised by the offline forge tests and
        the node-gated real fixture, independent of whether Jazzer.js is installed."""
        outcome = verify_poc(target_dir, candidate, poc_bytes,
                             mem_mb=mem_mb, timeout=max(timeout, 8) + 5)
        verdict, cwe = classify_outcome(outcome, target_file_basenames(target_dir))
        return verdict, cwe, outcome

    def write_bundle(self, target_dir: Path, candidate: NodeHarness, verdict: Verdict,
                     out_dir: Path, *, crash: Outcome | None = None) -> ProofBundle:
        out_dir.mkdir(parents=True, exist_ok=True)
        srcs = [p for p in Path(target_dir).rglob("*")
                if p.is_file() and p.suffix in (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts")]
        for src in srcs:
            (out_dir / src.name).write_text(src.read_text(errors="replace"))
        (out_dir / "fuzz.js").write_text(assemble(candidate))
        if crash and crash.poc_bytes:
            (out_dir / "crash.bin").write_bytes(crash.poc_bytes)
        script = ('#!/usr/bin/env bash\nset -e\ncd "$(dirname "$0")"\n'
                  'jz="${SABBA_JAZZERJS_HOME:-$HOME/jazzerjs}"\n'
                  'ln -sf "$jz/node_modules" node_modules 2>/dev/null || true\n'
                  '"$jz/node_modules/.bin/jazzer" fuzz crash.bin --sync\n')
        rerun = out_dir / "run.sh"
        rerun.write_text(script)
        rerun.chmod(0o755)
        return ProofBundle(
            domain="node", target={"sources": [p.name for p in srcs]},
            witness={"harness": "fuzz.js", "poc": "crash.bin"},
            checker={"kind": verdict.reason}, rerun="run.sh", dir=str(out_dir))


def node_hunt(target_dir, *, model: str | None = None, on_event=None, secs: int = 20,
              timeout: int = 10, max_tries: int = 4,
              judge_fn: Callable[[str, str], str] | None = None) -> list[Finding]:
    """Have the model write a Jazzer.js harness, fuzz, and report only a proven crash."""
    log = on_event or (lambda _m: None)
    target_dir = Path(target_dir).resolve()
    if not toolchain_available():
        log("[node] node or the Jazzer.js launcher is missing. install Node and "
            "@jazzer.js/core (set SABBA_JAZZERJS_HOME), then re-run.")
        return []

    spec = _read_spec(target_dir)
    prover = NodeFuzzProver()
    survey = _survey(target_dir)
    judge_fn = judge_fn or _default_judge(model)
    user = (f"Node target `{target_dir.name}`. Source files:\n{survey}\n\n"
            "Write the harness JSON now.")

    err = ""
    for attempt in range(max_tries):
        prompt = user if not err else user + f"\n\nYour previous harness failed:\n{err[-1500:]}\nFix it."
        log(f"[node] writing harness (attempt {attempt + 1}/{max_tries})")
        harness = _parse_harness(judge_fn(SYSTEM, prompt))
        if harness is None:
            err = "your output was not valid JSON with requires and body"
            continue
        log(f"[node] fuzzing: {harness.entry or '(entry)'} for {secs}s")
        verdict, cwe, crash = prover._prove(target_dir, harness, secs=secs, timeout=timeout)
        log(f"[node] verdict: {verdict.reason} (verified={verdict.verified})")
        if verdict.verified:
            bundle = prover.write_bundle(target_dir, harness, verdict,
                                         target_dir / "sabba-proof", crash=crash)
            log(f"[node] proof written to {bundle.dir}")
            return [Finding(
                cwe=cwe or spec.get("cwe", "CWE-400"),
                title=spec.get("title", f"{verdict.reason} in {target_dir.name}"),
                file=spec.get("file", ""), function=spec.get("function", ""),
                verdict=verdict,
                rationale=f"Jazzer.js found an input that triggers {verdict.reason}, proven by "
                          f"re-running it in the Sabba reproducer. Proof: {bundle.dir}.")]
        if verdict.reason in ("harness_error", "unsound_harness"):
            err = verdict.evidence
    log("[node] no crash proven this run")
    return []


# -- static gates ----------------------------------------------------------

def check_harness(candidate: NodeHarness) -> str | None:
    """Return a rejection reason if the harness is unsound, else None. Runs before any fuzz."""
    reason = _check_requires(candidate.requires or "")
    if reason:
        return reason
    reason = _check_body(candidate.body or "")
    if reason:
        return reason
    binds = _target_bindings(candidate.requires or "")
    if not binds:
        return "harness requires no target module to call"
    body = _strip_js(candidate.body or "")
    if not any(re.search(rf"\b{re.escape(b)}\s*[.(\[]", body) for b in binds):
        return "harness body does not call the required target (no call or member access)"
    return None


def _check_requires(requires: str) -> str | None:
    stmts = _statements(requires)
    if not stmts:
        return "harness requires nothing; it must require the target"
    for s in stmts:
        spec = _import_spec(s)
        if spec is None:
            return f"requires must be import/require statements only, rejected: {s[:80]}"
        if not _spec_whitelisted(spec):
            return f"requires may load only the target or @jazzer.js/core, not: {spec}"
    return None


def _check_body(body: str) -> str | None:
    s = _strip_js(body or "")
    hits = sorted({name for rx, name in _FORBIDDEN_BODY if rx.search(s)})
    if hits:
        return "harness body may not use: " + ", ".join(hits)
    return None


def _statements(requires: str) -> list[str]:
    text = _strip_comments(requires or "")
    out = []
    for line in text.split("\n"):
        for part in line.split(";"):
            part = part.strip()
            if part:
                out.append(part)
    return out


def _import_spec(stmt: str) -> str | None:
    for rx in (_ASSIGN_REQUIRE, _BARE_REQUIRE, _IMPORT_FROM, _IMPORT_BARE):
        m = rx.match(stmt)
        if m:
            return m.group(2)
    return None


def _spec_whitelisted(spec: str) -> bool:
    return spec.startswith("./") or spec.startswith("../") or spec == "@jazzer.js/core"


def _target_bindings(requires: str) -> set[str]:
    """Identifiers bound to the TARGET (a relative require/import), the names a body must call.

    Bindings to @jazzer.js/core (FuzzedDataProvider) are not target bindings; calling only the
    fuzzer helper is not calling the target."""
    names: set[str] = set()
    for stmt in _statements(requires):
        spec = _import_spec(stmt)
        if spec is None or not (spec.startswith("./") or spec.startswith("../")):
            continue
        m = _BIND_ASSIGN.match(stmt)
        if m:
            names.update(_names_from_clause(m.group(1)))
            continue
        m = _BIND_IMPORT.match(stmt)
        if m:
            names.update(_names_from_clause(m.group(1)))
    return names


def _names_from_clause(clause: str) -> set[str]:
    return {n for n in re.findall(r"[A-Za-z_$][\w$]*", clause or "")
            if n not in _CLAUSE_KEYWORDS}


def target_file_basenames(target_dir: Path) -> set[str]:
    """Basenames of the target's own sources, used to attribute a stack frame. Includes the
    transpiled .js name for a .ts source, since frames after transpile name the .js file."""
    names: set[str] = set()
    for p in Path(target_dir).rglob("*"):
        if not (p.is_file() and p.suffix.lstrip(".") in _STEM_EXT):
            continue
        if p.stem in ("fuzz", "harness", "repro"):
            continue
        names.add(p.name)
        if p.suffix in (".ts", ".mts", ".cts"):
            names.add(p.stem + ".js")
    return names


# -- helpers ---------------------------------------------------------------

def _strip_comments(code: str) -> str:
    code = re.sub(r"/\*.*?\*/", " ", code, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", " ", code)


def _strip_js(code: str) -> str:
    code = _strip_comments(code)
    code = re.sub(r'"(?:\\.|[^"\\])*"', '""', code)
    code = re.sub(r"'(?:\\.|[^'\\])*'", "''", code)
    return re.sub(r"`(?:\\.|[^`\\])*`", "``", code)


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
    for src in sorted(target_dir.rglob("*")):
        if not (src.is_file() and src.suffix.lstrip(".") in _STEM_EXT):
            continue
        body = src.read_text(errors="replace")
        chunk = f"// {src.relative_to(target_dir)}\n{body}\n"
        if total + len(chunk) > limit:
            out.append(f"// {src.relative_to(target_dir)} (truncated)\n{body[:1500]}\n")
            break
        out.append(chunk)
        total += len(chunk)
    return "\n".join(out) or "(no .js or .ts sources)"


def _parse_harness(text: str) -> NodeHarness | None:
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
    return NodeHarness(requires=str(d.get("requires", "")), body=str(d["body"]),
                       entry=str(d.get("entry", "")))


def _default_judge(model: str | None) -> Callable[[str, str], str]:
    from ...llm import judge

    def _run(system: str, user: str) -> str:
        return judge(system, user, model)
    return _run
