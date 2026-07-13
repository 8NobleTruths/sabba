"""Decide a verdict from the reproducer's structured outcome, not from mixed fuzzer output.

The old classifier read the crash kind out of the fuzzer's stdout and matched a "Vuln.java:9"
substring anywhere in that output. Both are harness writable, so a model-written harness could
print a magic phrase and a forged frame and mint a finding without the target ever crashing.

This classifier never looks at harness-writable text. It takes an Outcome that the Sabba
reproducer produced over an unforgeable channel: for a caught crash, the Throwable's own class
and its real StackTraceElement frames; for a killed child, the parent's own measurement (a
wall-clock timeout or a fatal signal) plus the frames parsed out of the JVM's own stack dump.
The harness cannot forge a genuine Throwable's structured stack, and it cannot forge the JVM
thread dump the runtime writes on SIGQUIT. The static gates in prover.py stop it from throwing
a fake structured error or running code at class load, which is what lets us trust the channel.

Attribution comes only from the structured frames: a verified crash must carry at least one
frame whose source file is a target .java file (not Harness.java, not the reproducer). Kind
comes only from the structured outcome. Where a resource crash cannot be attributed to a target
frame, we return unverified rather than guess.

Verified kinds:
  - stack_exhaustion  (CWE-674): a StackOverflowError with a target frame.
  - native_crash      (CWE-787): a fatal signal (SIGSEGV, SIGABRT) from JNI, with a target frame.
  - security_issue               : a Jazzer bug detector (FuzzerSecurityIssue*) arriving as a
    structured Throwable, with a target frame. Matched on the detector's own class, never on a
    loose phrase in output.

A timeout and an out-of-memory kill are never findings: neither can be soundly attributed to
the target rather than harness-driven pressure (a loop around the call, or a harness that
pre-fills the heap), so they come back as unverified candidates (unverified_hang_candidate,
unverified_oom_candidate). This is soundness over coverage; see docs/PROVER_SOUNDNESS.md.
Everything else, including a benign application exception or a caught OutOfMemoryError, is
also unverified.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ...types import Verdict


@dataclass
class Frame:
    """One real stack frame, from a StackTraceElement or the JVM's own thread dump."""
    cls: str = ""
    method: str = ""
    file: str = ""       # the source file name, e.g. "Vuln.java", or "" if unknown
    line: int = -1


@dataclass
class Outcome:
    """What the Sabba reproducer established over an unforgeable channel.

    kind is one of:
      "throwable"   a Throwable was caught in the reproducer (exc_class, message, frames set)
      "timeout"     the parent's wall clock was exceeded (frames from the SIGQUIT thread dump)
      "signal"      the child was killed by a fatal signal (frames from the JVM crash dump)
      "oom_kill"    the child was killed for running out of memory
      "none"        the reproducer ran the PoC and nothing security relevant happened
      "build_error" the target plus harness did not compile
      "error"       the reproducer could not run (toolchain or internal problem)
    """
    kind: str = "none"
    exc_class: str = ""              # the Throwable class, e.g. "java.lang.StackOverflowError"
    message: str = ""                # Throwable.getMessage(), if any
    frames: list[Frame] = field(default_factory=list)
    raw: str = ""                    # the JVM's own dump (timeout/signal), for evidence only
    signal: int | None = None
    poc_bytes: bytes = b""


# a keyword in the Jazzer security-issue text -> the CWE it maps to. Order matters: the
# first phrase that appears in the report wins. Default is CWE-20 when nothing matches.
_ISSUE_CWE = (
    ("os command injection", "CWE-78"),
    ("command injection", "CWE-78"),
    ("sql injection", "CWE-89"),
    ("server side request forgery", "CWE-918"),
    ("ssrf", "CWE-918"),
    ("path traversal", "CWE-22"),
    ("file read", "CWE-22"),
    ("file write", "CWE-22"),
    ("deserialization", "CWE-502"),
    ("remote code execution", "CWE-502"),
    ("ldap injection", "CWE-90"),
    ("xpath injection", "CWE-643"),
    ("expression language", "CWE-94"),
    ("script engine", "CWE-94"),
)

# reproducer and wrapper source files are never a target frame
_NON_TARGET = {"Harness.java", "SabbaReproducer.java"}


def attributed_to_target(frames: list[Frame], target_files: set[str]) -> bool:
    """True when at least one real frame is in a target source file, not the harness/wrapper.

    It reads structured frames the harness cannot forge, never a substring of harness-writable
    output. This is the weaker "any frame present" signal; classify_outcome uses the stricter
    innermost_is_target instead, and this stays for callers that want the loose check.
    """
    for f in frames:
        name = (f.file or "").strip()
        if name and name in target_files and name not in _NON_TARGET:
            return True
    return False


def innermost_is_target(frames: list[Frame], target_files: set[str]) -> bool:
    """True when the innermost frame Sabba owns (target or harness) is a target frame.

    Attribution must sit at the crash site, not merely somewhere in the stack. Scanning from the
    innermost frame outward we skip JDK and third-party frames (a genuine target-driven crash can
    raise inside a library method the target called), and the first frame that is either a target
    file or the harness/reproducer decides it: a target frame means the target crashed, a harness
    or reproducer frame innermost of the target means the harness crashed itself. This rejects the
    callback-recursion forge, where a harness lambda passed into the target recurses so target
    frames appear in the stack but the deepest owned frame is the harness.
    """
    for f in frames:
        name = (f.file or "").strip()
        if not name:
            continue
        if name in _NON_TARGET:
            return False
        if name in target_files:
            return True
    return False


def classify_outcome(outcome: Outcome, target_files: set[str]) -> tuple[Verdict, str]:
    """Return (verdict, cwe). verified is True only for an attributed, security-relevant crash."""
    ev = _evidence(outcome)
    kind = outcome.kind

    if kind in ("build_error",):
        return Verdict(verified=False, reason="harness_error", evidence=ev), ""
    if kind in ("none", "", "error"):
        return Verdict(verified=False, reason="no_crash", evidence=ev), ""

    # A hang or an out-of-memory kill cannot be soundly attributed to the target rather than
    # harness-driven pressure, so neither is a finding: both come back as unverified candidates.
    if kind == "timeout":
        return Verdict(verified=False, reason="unverified_hang_candidate", evidence=ev), ""
    if kind == "oom_kill":
        return Verdict(verified=False, reason="unverified_oom_candidate", evidence=ev), ""

    reason, cwe = _kind_to_finding(outcome)
    if not reason:
        simple = (outcome.exc_class or "unknown").rsplit(".", 1)[-1]
        return Verdict(verified=False, reason=f"unconfirmed_exception:{simple}", evidence=ev), ""

    # Attribution is mandatory for every verified kind, including a signal, and it must sit at
    # the crash site: the innermost owned frame has to be the target. A crash whose deepest owned
    # frame is Harness.java, or a callback the harness recursed through the target, is the harness
    # crashing itself, not the target.
    if not innermost_is_target(outcome.frames, target_files):
        return Verdict(verified=False, reason="crash_not_in_target", evidence=ev), ""
    return Verdict(verified=True, reason=reason, evidence=ev), cwe


def _kind_to_finding(outcome: Outcome) -> tuple[str, str]:
    """Map a structured signal or throwable to (reason, cwe), or ("", "") if not a finding.

    A timeout and an out-of-memory kill are handled earlier in classify_outcome as unverified
    candidates, so they never reach here.
    """
    kind = outcome.kind
    if kind == "signal":
        return "native_crash", "CWE-787"
    if kind == "throwable":
        cls = outcome.exc_class or ""
        simple = cls.rsplit(".", 1)[-1]
        if simple == "StackOverflowError":
            return "stack_exhaustion", "CWE-674"
        # A caught OutOfMemoryError is an unconfirmed exception, not a finding: a benign target
        # can hit the heap limit on crafted input, and a real out-of-memory arrives on the kill
        # path (oom_kill) instead, which is itself only an unverified candidate.
        if simple == "OutOfMemoryError":
            return "", ""
        if "FuzzerSecurityIssue" in cls:
            return "security_issue", cwe_for_issue(simple + " " + (outcome.message or ""))
        # a plain NullPointerException, IllegalArgumentException, etc. is not a finding
        return "", ""
    return "", ""


def cwe_for_issue(text: str) -> str:
    """Map a Jazzer security-issue report to a CWE, defaulting to CWE-20 (improper input)."""
    low = (text or "").lower()
    for phrase, cwe in _ISSUE_CWE:
        if phrase in low:
            return cwe
    return "CWE-20"


def _evidence(outcome: Outcome) -> str:
    head = f"kind={outcome.kind}"
    if outcome.exc_class:
        head += f" exception={outcome.exc_class}"
    if outcome.signal is not None:
        head += f" signal={outcome.signal}"
    frames = "\n".join(
        f"    at {f.cls}.{f.method}({f.file}:{f.line})" for f in outcome.frames[:40])
    tail = (outcome.raw or "")[-1000:]
    return "\n".join(p for p in (head, frames, tail) if p)
