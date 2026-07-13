"""Phase two, part two: turn a structured Outcome into a Verdict.

The Outcome comes from the Sabba-owned reproducer (reproducer.py), never from the harness.
It carries the crash kind established from an unforgeable channel (a caught exception's real
class and message, or the parent's own measurement of a killed child plus the runtime's own
stack dump) and the real stack frames. This module reads only those structured fields. It
never substring-scans harness-writable output, and it never reads an artifact file the
harness may have written. That is the whole point of the split: the old classifier read the
kind and the target attribution out of the fuzzer's mixed stdout, which the harness could
forge; this one cannot be fooled that way.

Verified as findings, each only when a real target frame is in the structured stack:
  - stack_exhaustion (CWE-674): a RangeError whose message is V8's "maximum call stack size
    exceeded". The harness body cannot throw (gated), so this class and message can only come
    from V8 overflowing a real target call chain.
  - native_crash (CWE-787): a fatal signal the parent observed (a native addon), with a
    target frame in the report.
  - security_issue: a Jazzer.js bug-detector Finding that arrives as a structured throwable,
    matched on the detector's own class and banner, with a target frame.

A timeout and a heap out-of-memory kill are never findings: neither can be soundly attributed
to the target rather than harness-driven pressure (a loop around the call, or a harness that
pre-fills the heap), so both come back as unverified candidates (unverified_hang_candidate,
unverified_oom_candidate). Anything else, including a benign TypeError or a caught allocation
RangeError, is also unverified. Losing an unattributable crash is deliberate: soundness over
coverage (see docs/PROVER_SOUNDNESS.md, honest residual limits).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ...types import Verdict

_STACK = "maximum call stack size exceeded"

# a phrase in a Jazzer.js detector Finding -> the CWE it maps to, most specific first
_SECURITY = [
    ("os command injection", "CWE-78"),
    ("command injection", "CWE-78"),
    ("path traversal", "CWE-22"),
    ("arbitrary file", "CWE-22"),
    ("prototype pollution", "CWE-1321"),
    ("server side request forgery", "CWE-918"),
    ("ssrf", "CWE-918"),
    ("code injection", "CWE-94"),
    ("regular expression denial", "CWE-1333"),
    ("redos", "CWE-1333"),
]


@dataclass
class Outcome:
    """The structured result of re-running a candidate PoC in the Sabba reproducer.

    Every field here is either the parent's own measurement or a value the runtime, not the
    harness, produced. kind is one of:
      "exception"  a caught throwable; error_class/message are V8's or a detector's
      "oom"        a heap out-of-memory kill the parent observed
      "timeout"    the parent's wall clock was exceeded
      "signal"     a fatal signal the parent observed (SIGSEGV/SIGABRT from native code)
      "none"       the harness returned without crashing
      "load_error" the harness or target failed to load, or a repro/toolchain problem
    frame_files are the source files named in the real stack frames; attribution reads only
    these. raw is a short Sabba-generated evidence excerpt, never harness stdout.
    """
    kind: str = "none"
    error_class: str = ""
    message: str = ""
    frame_files: list[str] = field(default_factory=list)
    frame_sample: list[str] = field(default_factory=list)
    signal: int | None = None
    raw: str = ""
    poc_bytes: bytes = b""


def classify_outcome(outcome: Outcome, target_files: set[str]) -> tuple[Verdict, str]:
    """Return (verdict, cwe). verified is True only for a security-relevant crash that a real
    stack frame pins to a target source file."""
    ev = (outcome.raw or "")[:1600]
    attributed = _attributed_to_target(outcome.frame_files, target_files)

    if outcome.kind == "exception":
        text = ((outcome.error_class or "") + " " + (outcome.message or "")).lower()
        kind, cwe = _exception_kind(outcome, text)
        if not kind:
            return (Verdict(verified=False,
                            reason=f"unconfirmed_exception:{outcome.error_class or 'unknown'}",
                            evidence=ev), "")
        if not attributed:
            return (Verdict(verified=False, reason="crash_not_in_target", evidence=ev), "")
        return Verdict(verified=True, reason=kind, evidence=ev), cwe

    if outcome.kind == "signal":
        if not attributed:
            return (Verdict(verified=False, reason="crash_not_in_target", evidence=ev), "")
        return Verdict(verified=True, reason="native_crash", evidence=ev), "CWE-787"

    if outcome.kind in ("oom", "timeout"):
        # A hang or out-of-memory cannot be soundly attributed to the target rather than
        # harness-driven pressure, so it is an unverified candidate, never a confirmed finding.
        reason = ("unverified_hang_candidate" if outcome.kind == "timeout"
                  else "unverified_oom_candidate")
        return Verdict(verified=False, reason=reason, evidence=ev), ""

    if outcome.kind == "load_error":
        return Verdict(verified=False, reason="harness_error", evidence=ev), ""
    return Verdict(verified=False, reason="no_crash", evidence=ev), ""


def _exception_kind(outcome: Outcome, text: str) -> tuple[str, str]:
    if _STACK in text:
        return "stack_exhaustion", "CWE-674"
    # A memory phrase in a caught exception's message is not a finding: a benign target can
    # throw "invalid array length" from input. A real heap out-of-memory arrives on the
    # runtime kill path (kind "oom"), which the harness cannot influence.
    # a Jazzer.js detector Finding is a structured throwable whose class is the detector's own,
    # not a phrase loose in output. Require the class to look like a detector Finding AND a
    # known banner, so a plain Error carrying an injected phrase is not a finding.
    if _looks_like_detector(outcome.error_class):
        for phrase, cwe in _SECURITY:
            if phrase in text:
                return "security_issue", cwe
    return "", ""


def _looks_like_detector(error_class: str) -> bool:
    cls = (error_class or "").lower()
    return "finding" in cls or "securityissue" in cls or cls.endswith("error") is False and \
        ("jazzer" in cls or "fuzzer" in cls)


def _attributed_to_target(frame_files: list[str], target_files: set[str]) -> bool:
    """True only when the INNERMOST attributable frame, the one that raised, is a target file.

    frame_files is innermost first (the reproducer parses the stack top to bottom). We walk from
    the innermost frame and stop at the first frame that is either a target file or the
    harness/wrapper (fuzz.js or repro.js). If that first known frame is a target, the crash is
    the target's; if it is fuzz.js or repro.js, the crash raised in harness code (a recursive
    helper, or a callback the target called back into) and merely has a target frame sitting
    below it, so it is not a target bug. Node-internal frames are skipped, not decisive.

    Attribution reads the STRUCTURED frame files the runtime reported, never a substring in
    harness-writable output. target_files holds the basenames of the target's own sources.
    """
    if not target_files:
        return False
    for f in frame_files or []:
        base = f.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        if base in target_files:
            return True
        if base in ("fuzz.js", "repro.js"):
            return False
    return False
