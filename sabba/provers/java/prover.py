"""The Java (JVM) fuzzing prover and the hunt that drives it.

Same shape as the other fuzzing provers: the model writes only the body of
fuzzerTestOneInput(byte[] data), and an independent run decides the truth. Sabba owns the
Harness class, the discovery loop (Jazzer, in runner.discover_poc), the reproducer that proves
a candidate (runner.verify_poc), and the crash gate (classify.classify_outcome).

Two phases keep a hostile harness from faking a finding:

  - Discovery runs the harness under Jazzer only to find a candidate PoC (bytes). Nothing about
    the verdict is read from Jazzer's output or from any artifact the harness may have written.
  - Verification re-runs those bytes through a Sabba-owned reproducer that nulls the harness
    output and reads the outcome over unforgeable channels: a caught Throwable's real frames, or
    the JVM's own dump for a killed child. The kind and the target attribution come only from
    that structured outcome, never from a substring of harness-writable text.

Static gates (below) run before the harness is ever executed. They stop the harness from
manufacturing its own structured crash or from running code at class load, which is what lets
the reproducer trust its result channel.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable

from ...types import Finding, Verdict
from ..base import ProofBundle
from .classify import Outcome, classify_outcome, cwe_for_issue  # noqa: F401 (re-exported)
from .detect import is_java_target
from .runner import (JavaHarness, assemble, discover_poc, java_available, javac_available,
                     jazzer_available, toolchain_available, verify_available, verify_poc)

# Body tokens that let a harness manufacture its own crash, hang, output, dynamic code, or a
# write to the parent's result channel. The real backstop is that attribution comes from the
# structured stack and the result channel is a nonce-authenticated parent-held pipe, but these
# are cheap to reject up front. Matched against the body with strings and comments stripped.
#
# Java has no per-file import isolation: a fully qualified name like `new
# java.io.RandomAccessFile(...)` or `java.nio.file.Files.newOutputStream(...)` needs no import,
# so the import gate cannot see it and a short-name blacklist misses it. We therefore reject the
# fully qualified IO, NIO, reflection, and internal package prefixes in the body directly, on
# top of the short names. The body has no reason to touch any file, stream, fd, reflection, or
# the process environment; it turns bytes into one call on the target.
_FORBIDDEN_BODY = (
    "throw ", "throw(", "system.exit", "runtime.getruntime", ".halt(", "system.load",
    "stackoverflowerror", "outofmemoryerror",
    "while (true", "while(true", "for (;;", "for(;;",
    "thread.sleep", "new thread", "static {", "static{",
    "system.out", "system.err", ".print", "printstream", "printwriter",
    # fully qualified IO and file access, which need no import and so slip past _check_imports
    "java.io", "java.nio", "randomaccessfile", "filechannel", "fileoutputstream", "filewriter",
    "newoutputstream", "newbytechannel", "newinputstream", "files.write", "files.newoutput",
    "filedescriptor", "/dev/fd", "outputstream", "outputstreamwriter",
    # reflection and dynamic code, short and fully qualified
    "class.forname", ".forname", ".getclass(", "setaccessible", "getdeclaredmethod",
    "getmethod(", "method.invoke", ".invoke(", "methodhandles", "java.lang.reflect",
    "java.lang.invoke", "scriptengine", "unsafe", "classloader", "processbuilder",
    "sun.", "jdk.internal",
    # reading the process environment or command line, which is how a body would hunt for the
    # nonce the parent hands only to the reproducer wrapper
    "getenv", "getproperty", "getproperties", "sun.java.command",
)
# a local type declaration is how a body would sneak in its own recursive helper. The negative
# lookbehind keeps it from matching a ".class" literal or a word ending in class.
_LOCAL_TYPE_RE = re.compile(r"(?<![.\w])(class|interface|enum)\s+\w")
_CLASS_DECL_RE = re.compile(r"\b(?:public\s+|final\s+|abstract\s+)*(?:class|interface|enum)\s+(\w+)")
_PACKAGE_RE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.MULTILINE)
_IMPORT_RE = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+(?:\.\*)?)\s*;\s*$")
# the fuzzer API the harness is allowed to import (Jazzer's FuzzedDataProvider and friends)
_ALLOWED_IMPORT_PREFIXES = ("com.code_intelligence.jazzer.",)

SYSTEM = """You write Jazzer fuzz harnesses for Java libraries. You output only JSON. You \
pick one entry point that takes attacker-controlled bytes and drive it from the raw fuzz \
input, so a crash points at one place in the target.

Return STRICT JSON only, no prose, with this shape:
{
  "entry": "short note on which method you fuzz",
  "imports": "optional import lines, one per line, importing only the target's own packages \
or the Jazzer API; leave empty if not needed",
  "body": "the body of fuzzerTestOneInput(byte[] data). Turn data into the argument the \
entry point expects and call it, for example: Vuln.deep(data, 0);"
}

Sabba wraps your body in `public class Harness { public static void \
fuzzerTestOneInput(byte[] data) { <your body> } }`, compiles it with the target, and re-runs \
any candidate crash through its own reproducer, so do not write the class or method header \
yourself. Call exactly one entry point on the target class through its name. Do not throw, do \
not force a StackOverflowError or OutOfMemoryError, do not call System.exit, do not print or \
write to any file, stream, or file descriptor (not through a short name and not through a \
fully qualified java.io or java.nio class either), do not use reflection, do not read the \
environment or system properties, do not declare your own class or recursive helper, and do \
not spin an infinite loop; the crash must come from the target, not from your harness."""


class JavaFuzzProver:
    domain = "java"
    languages = ("java",)
    vuln_classes = ("ssrf", "sql-injection", "os-command-injection", "path-traversal",
                    "deserialization", "stack-exhaustion", "memory-exhaustion",
                    "algorithmic-complexity")

    def matches(self, target_dir: Path, spec: dict | None) -> bool:
        return is_java_target(Path(target_dir), spec)

    def prove(self, target_dir: Path, candidate: JavaHarness, *, secs: int = 30,
              timeout: int = 25, seed: bytes | None = None) -> Verdict:
        verdict, _cwe, _outcome = self._prove(target_dir, candidate, secs=secs,
                                              timeout=timeout, seed=seed)
        return verdict

    def _prove(self, target_dir: Path, candidate: JavaHarness, *, secs: int,
               timeout: int, seed: bytes | None = None,
               poc: bytes | None = None) -> tuple[Verdict, str, Outcome | None]:
        target_dir = Path(target_dir)
        gate = self._gate(target_dir, candidate)
        if gate is not None:
            return gate, "", None

        # Verification needs only javac plus java; discovery also needs Jazzer. When a PoC is
        # supplied we skip discovery, so we only require the verify toolchain.
        if poc is None and not toolchain_available():
            miss = "javac" if not javac_available() else "the Jazzer launcher"
            return (Verdict(verified=False, reason="prover_unavailable",
                            evidence=f"{miss} not found. Install a JDK 17 and Jazzer (set "
                                     "SABBA_JAZZER_HOME or put jazzer on PATH), then re-run."),
                    "", None)
        if not verify_available():
            miss = "javac" if not javac_available() else "java"
            return (Verdict(verified=False, reason="prover_unavailable",
                            evidence=f"{miss} not found. Install a JDK 17, then re-run."), "", None)

        # phase 1: discover a candidate PoC (bytes only). A supplied PoC or seed skips the fuzzer.
        candidate_poc = poc if poc is not None else seed
        if candidate_poc is None:
            candidate_poc = discover_poc(target_dir, candidate, secs=secs,
                                         per_input_timeout=timeout, seed=seed)
        if candidate_poc is None:
            return (Verdict(verified=False, reason="no_crash",
                            evidence="Jazzer found no crashing input"), "", None)

        # phase 2: prove the candidate with the Sabba-owned reproducer
        outcome = verify_poc(target_dir, candidate, candidate_poc, wall=max(timeout, 20))
        verdict, cwe = classify_outcome(outcome, _target_java_names(target_dir))
        return verdict, cwe, outcome

    def _gate(self, target_dir: Path, candidate: JavaHarness) -> Verdict | None:
        """Static gates. Return a rejecting Verdict, or None when the harness is admissible."""
        body = candidate.body or ""
        stripped = _strip_java(body)
        low = stripped.lower()

        bad = [w for w in _FORBIDDEN_BODY if w in low]
        if _LOCAL_TYPE_RE.search(stripped):
            bad.append("declares its own type/recursive helper")
        depth_problem = _brace_escape(stripped)
        if depth_problem:
            bad.append(depth_problem)
        if "reflect" in low:
            bad.append("uses reflection")
        if any(_always_true_condition(c) for c in _loop_conditions(stripped)):
            bad.append("always-true or side-effect-free loop condition")
        if bad:
            return Verdict(verified=False, reason="unsound_harness",
                           evidence="harness may fake a crash or run its own code: "
                                    + ", ".join(bad))

        imp_bad = _check_imports(candidate.imports or "", _target_packages(target_dir))
        if imp_bad:
            return Verdict(verified=False, reason="unsound_harness",
                           evidence="import lines must be imports of the target or the fuzzer "
                                    "API only: " + ", ".join(imp_bad))

        classes = _target_classes(target_dir)
        if classes and not _calls_target(stripped, classes):
            return Verdict(verified=False, reason="unsound_harness",
                           evidence="harness does not call the target class ("
                                    + ", ".join(sorted(classes)) + ")")
        return None

    def write_bundle(self, target_dir: Path, candidate: JavaHarness, verdict: Verdict,
                     out_dir: Path, *, outcome: Outcome | None = None) -> ProofBundle:
        out_dir.mkdir(parents=True, exist_ok=True)
        sources = [p for p in Path(target_dir).rglob("*.java")
                   if p.name not in ("Harness.java", "SabbaReproducer.java")]
        for src in sources:
            (out_dir / src.name).write_text(src.read_text(errors="replace"))
        (out_dir / "Harness.java").write_text(assemble(candidate))
        if outcome and outcome.poc_bytes:
            (out_dir / "crash.bin").write_bytes(outcome.poc_bytes)
        script = ('#!/usr/bin/env bash\nset -e\ncd "$(dirname "$0")"\n'
                  'jazzer="${SABBA_JAZZER_HOME:+$SABBA_JAZZER_HOME/}jazzer"\n'
                  'mkdir -p classes\n'
                  'javac -d classes *.java\n'
                  '"$jazzer" --cp=classes --target_class=Harness crash.bin\n')
        rerun = out_dir / "run.sh"
        rerun.write_text(script)
        rerun.chmod(0o755)
        return ProofBundle(
            domain="java",
            target={"sources": [p.name for p in sources]},
            witness={"harness": "Harness.java", "poc": "crash.bin"},
            checker={"kind": verdict.reason}, rerun="run.sh", dir=str(out_dir))


def java_hunt(target_dir, *, model: str | None = None, on_event=None, secs: int = 30,
              timeout: int = 25, max_tries: int = 4,
              judge_fn: Callable[[str, str], str] | None = None) -> list[Finding]:
    """Have the model write a Jazzer harness, fuzz, and report only a proven crash."""
    log = on_event or (lambda _m: None)
    target_dir = Path(target_dir).resolve()
    if not toolchain_available():
        log("[java] javac or the Jazzer launcher is missing. Install a JDK 17 and Jazzer "
            "(set SABBA_JAZZER_HOME or put jazzer on PATH), then re-run.")
        return []

    spec = _read_spec(target_dir)
    prover = JavaFuzzProver()
    survey = _survey(target_dir)
    judge_fn = judge_fn or _default_judge(model)
    user = (f"Java target `{target_dir.name}`. Source files:\n{survey}\n\n"
            "Write the harness JSON now.")

    err = ""
    for attempt in range(max_tries):
        prompt = user if not err else user + f"\n\nYour previous harness failed:\n{err[-1500:]}\nFix it."
        log(f"[java] writing harness (attempt {attempt + 1}/{max_tries})")
        harness = _parse_harness(judge_fn(SYSTEM, prompt))
        if harness is None:
            err = "your output was not valid JSON with a body"
            continue
        log(f"[java] fuzzing: {harness.entry or '(entry)'} for {secs}s")
        verdict, cwe, outcome = prover._prove(target_dir, harness, secs=secs, timeout=timeout)
        log(f"[java] verdict: {verdict.reason} (verified={verdict.verified})")
        if verdict.verified:
            bundle = prover.write_bundle(target_dir, harness, verdict,
                                         target_dir / "sabba-proof", outcome=outcome)
            log(f"[java] proof written to {bundle.dir}")
            return [Finding(
                cwe=cwe or spec.get("cwe", "CWE-400"),
                title=spec.get("title", f"{verdict.reason} in {target_dir.name}"),
                file=spec.get("file", ""), function=spec.get("function", ""),
                verdict=verdict,
                rationale=f"Jazzer found an input that triggers {verdict.reason}, proven by "
                          f"re-running it through the Sabba reproducer. Proof: {bundle.dir}. "
                          f"Re-run with ./run.sh.")]
        if verdict.reason in ("harness_error", "unsound_harness"):
            err = verdict.evidence
    log("[java] no crash proven this run")
    return []


# -- static gate helpers ----------------------------------------------------

def _strip_java(code: str) -> str:
    """Drop // and /* */ comments and the contents of string and char literals.

    Token scans and the brace-balance check run on this so a keyword or a brace inside a string
    or a comment is not read as code.
    """
    out = []
    i, n = 0, len(code)
    while i < n:
        c = code[i]
        two = code[i:i + 2]
        if two == "//":
            j = code.find("\n", i)
            i = n if j < 0 else j
            continue
        if two == "/*":
            j = code.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if c == '"':
            i += 1
            while i < n and code[i] != '"':
                i += 2 if code[i] == "\\" else 1
            i += 1
            out.append('""')
            continue
        if c == "'":
            i += 1
            while i < n and code[i] != "'":
                i += 2 if code[i] == "\\" else 1
            i += 1
            out.append("''")
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _loop_conditions(stripped: str) -> list[str]:
    """Return the condition text of every while, for, and do-while loop in the body.

    A for loop's condition is its middle clause; a while or do-while condition is the whole
    parenthesized test. Used to reject a loop that never terminates, which is how a body hangs
    itself so the parent's timeout carries a forged frame.
    """
    conds: list[str] = []
    for m in re.finditer(r"\b(while|for)\b\s*\(", stripped):
        kind = m.group(1)
        i = m.end() - 1                       # index of the opening paren
        depth, j = 0, i
        while j < len(stripped):
            ch = stripped[j]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        inner = stripped[i + 1:j]
        if kind == "for":
            parts = inner.split(";")
            conds.append(parts[1].strip() if len(parts) >= 2 else "")
        else:
            conds.append(inner.strip())
    return conds


def _always_true_condition(cond: str) -> bool:
    """True when a loop condition can never become false, so the loop is an infinite loop.

    Catches the literal forms (true, 1, an empty for test), a magnitude compared against a bound
    it can never cross (a length or size is never negative, so `data.length >= 0` and
    `data.length > -1` are always true), and a self-comparison tautology like `x == x`. This is a
    superset of the bare `while (true)` and `for (;;)` string checks, catching the disguised
    `while (data.length >= 0) {}` the round-1 gate let through.
    """
    c = cond.replace(" ", "").replace("\t", "").lower()
    if c in ("", "true", "1", "!false", "!0"):
        return True
    if re.search(r"(?:length|size\(\)|length\(\))>=0", c):
        return True
    if re.search(r"(?:length|size\(\)|length\(\))>-1", c):
        return True
    m = re.fullmatch(r"(.+?)(?:==|>=|<=)(.+)", c)
    if m and m.group(1) == m.group(2):        # x == x, x >= x, x <= x
        return True
    return False


def _brace_escape(stripped: str) -> str:
    """Reject a body that could break out of fuzzerTestOneInput to declare class-level code.

    The body is textually spliced inside a method. If its brace nesting ever drops below zero it
    has closed the method early and can inject a static initializer or a sibling method that runs
    at class load; if it ends unbalanced the class will not compile as intended. Either is
    rejected.
    """
    depth = 0
    for ch in stripped:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                return "escapes the method body (unbalanced closing brace)"
    if depth != 0:
        return "unbalanced braces"
    return ""


def _check_imports(imports: str, target_packages: set[str]) -> list[str]:
    """Every non-blank import line must be an import of a target package or the fuzzer API."""
    bad: list[str] = []
    allowed = tuple(target_packages) + _ALLOWED_IMPORT_PREFIXES
    for raw in _strip_java(imports).splitlines():
        line = raw.strip()
        if not line:
            continue
        m = _IMPORT_RE.match(line)
        if not m:
            bad.append(f"not an import statement: {line[:60]}")
            continue
        qual = m.group(1)
        if not any(qual == p.rstrip(".") or qual.startswith(p) or qual.startswith(p + ".")
                   for p in allowed):
            bad.append(f"disallowed import: {qual}")
    return bad


def _calls_target(stripped: str, classes: set[str]) -> bool:
    """Require a real call or member access through a target class name, not a bare mention."""
    for c in classes:
        esc = re.escape(c)
        if re.search(rf"\b{esc}\s*\.", stripped):        # Vuln.deep(...) or Vuln.FIELD
            return True
        if re.search(rf"\bnew\s+{esc}\s*\(", stripped):  # new Vuln(...)
            return True
    return False


def _target_java_names(target_dir: Path) -> set[str]:
    return {p.name for p in Path(target_dir).rglob("*.java")
            if p.name not in ("Harness.java", "SabbaReproducer.java")}


def _target_packages(target_dir: Path) -> set[str]:
    pkgs: set[str] = set()
    for src in Path(target_dir).rglob("*.java"):
        if src.name in ("Harness.java", "SabbaReproducer.java"):
            continue
        m = _PACKAGE_RE.search(_strip_java(src.read_text(errors="replace")))
        if m:
            pkgs.add(m.group(1))
    return pkgs


def _target_classes(target_dir: Path) -> set[str]:
    """Simple names of the types declared in the target sources (not the harness)."""
    names: set[str] = set()
    for src in Path(target_dir).rglob("*.java"):
        if src.name in ("Harness.java", "SabbaReproducer.java"):
            continue
        for m in _CLASS_DECL_RE.finditer(_strip_java(src.read_text(errors="replace"))):
            names.add(m.group(1))
    names.discard("Harness")
    return names


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
    for src in sorted(target_dir.rglob("*.java")):
        if src.name in ("Harness.java", "SabbaReproducer.java"):
            continue
        body = src.read_text(errors="replace")
        chunk = f"// {src.relative_to(target_dir)}\n{body}\n"
        if total + len(chunk) > limit:
            out.append(f"// {src.relative_to(target_dir)} (truncated)\n{body[:1500]}\n")
            break
        out.append(chunk)
        total += len(chunk)
    return "\n".join(out) or "(no .java sources)"


def _parse_harness(text: str) -> JavaHarness | None:
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
    return JavaHarness(body=str(d["body"]), entry=str(d.get("entry", "")),
                       imports=str(d.get("imports", "")))


def _default_judge(model: str | None) -> Callable[[str, str], str]:
    from ...llm import judge

    def _run(system: str, user: str) -> str:
        return judge(system, user, model)
    return _run
