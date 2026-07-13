"""Decide the verdict from the reproducer's structured outcome, never from mixed output.

Go is memory safe, so the security-relevant crash class is denial of service. The kind comes
only from the structured channel the reproducer filled: the recovered panic value, or the
runtime's own fatal or SIGQUIT dump. Attribution comes only from the real stack frames in
that channel, and it is deliberately narrow: the crashing frame must be the target. We walk
the frames from innermost (the top of the trace, where the crash happened) outward, skip the
reproducer's own machinery and any runtime or standard-library frame, and require the first
frame that is either a target file or the harness body to be a target file. Merely having a
target frame somewhere deeper in the trace is not enough: a harness that crashes itself, or
recurses through a callback that happens to pass through a target frame, has the harness body
as its innermost user frame and is rejected.

Where a crash carries no target frame at the crashing position, the result is unverified
rather than a guess.

A timeout and an out-of-memory are never verified findings. A hang or an allocation blowup
cannot be soundly separated from harness-driven pressure (a loop spinning fast target calls,
or a harness that pre-fills the heap), so both come back as unverified candidates. This is
soundness over coverage; see docs/PROVER_SOUNDNESS.md.

Verified kinds:
  - panic_crash: a recovered runtime panic (index or slice out of range, nil dereference,
    integer divide by zero, or a generic panic) whose crashing frame is the target.
  - stack_exhaustion (CWE-674): a fatal stack overflow whose crashing frame is the target.
  - native_crash (CWE-787): a fatal signal (cgo) whose crashing frame is the target.

Unverified candidates (surfaced for triage, never minted as findings):
  - unverified_hang_candidate: the parent's wall clock was exceeded.
  - unverified_oom_candidate: the runtime reported out-of-memory.
"""
from __future__ import annotations

import re

from ...types import Verdict
from .runner import Outcome

# substring in the panic value -> the specific CWE, most specific first
_PANIC_CWE = [
    ("index out of range", "CWE-125"),
    ("slice bounds out of range", "CWE-125"),
    ("nil pointer dereference", "CWE-476"),
    ("invalid memory address", "CWE-476"),
    ("integer divide by zero", "CWE-369"),
]

# a real Go stack frame line: an absolute or relative path ending in file.go:line
_FRAME_RE = re.compile(r"([A-Za-z0-9_./+\-]+?)\.go:(\d+)")

# The reproducer's own files. zz_sabba_main holds the recover defer and main, which always sit
# at the top of a recovered-panic dump and at the bottom as the entry point, so it is pure
# machinery and is skipped when walking frames. zz_sabba_body holds the model body: if it is
# the innermost user frame the crash came from the harness, not the target.
_MACHINERY_STEM = "zz_sabba_main"
_BODY_STEM = "zz_sabba_body"


def frames_hit_target(frames: str, target_stems: set[str]) -> bool:
    """True when a real frame names a target .go file anywhere in the trace. Kept for callers
    that only need presence; attribution now uses crash_frame_is_target, which is stricter."""
    for m in _FRAME_RE.finditer(frames or ""):
        stem = m.group(1).rsplit("/", 1)[-1]
        if stem in target_stems:
            return True
    return False


def crash_frame_is_target(frames: str, target_stems: set[str]) -> bool:
    """Walk frames from innermost (top of the trace) outward. Skip the reproducer main and defer
    (zz_sabba_main) and any runtime or standard-library frame whose file is neither the target
    nor the harness body. The first frame that is a target file or the harness body decides: a
    target file means the crash originated in the target, the harness body (zz_sabba_body) means
    it originated in the harness. A target frame that only appears below the harness body is not
    attributed."""
    for m in _FRAME_RE.finditer(frames or ""):
        stem = m.group(1).rsplit("/", 1)[-1]
        if stem in target_stems:
            return True
        if stem == _BODY_STEM:
            return False
        # zz_sabba_main and runtime or stdlib frames: skip and keep walking outward.
    return False


def classify_outcome(outcome: Outcome, target_stems: set[str]) -> tuple[Verdict, str]:
    """Return (verdict, cwe). verified is True only for a security-relevant crash whose
    structured stack lands in the target at the crashing frame."""
    ch = outcome.channel
    if ch == "unavailable":
        return Verdict(verified=False, reason="prover_unavailable", evidence=outcome.output), ""
    if ch == "build_error":
        return Verdict(verified=False, reason="harness_error", evidence=outcome.output), ""
    if ch == "none":
        return Verdict(verified=False, reason="no_crash", evidence=outcome.output), ""

    if ch == "recover":
        cwe = _panic_cwe(outcome.panic_value)
        if not crash_frame_is_target(outcome.frames, target_stems):
            return _not_in_target(outcome), ""
        return Verdict(verified=True, reason="panic_crash",
                       evidence=_ev(outcome, outcome.panic_value)), cwe

    if ch == "timeout":
        # A hang cannot be soundly attributed to the target rather than harness-driven
        # pressure (a loop spinning fast target calls), so it is an unverified candidate.
        return Verdict(verified=False, reason="unverified_hang_candidate",
                       evidence=_ev(outcome)), ""

    if ch == "fatal":
        f = outcome.frames or ""
        if "goroutine stack exceeds" in f or "stack overflow" in f:
            reason, cwe = "stack_exhaustion", "CWE-674"
        elif "out of memory" in f:
            # out-of-memory cannot be soundly attributed to the target vs harness-driven
            # allocation, so it is an unverified candidate, not a confirmed finding.
            return Verdict(verified=False, reason="unverified_oom_candidate",
                           evidence=_ev(outcome)), ""
        elif "SIGSEGV" in f or "signal SIGSEGV" in f:
            reason, cwe = "native_crash", "CWE-787"
        elif "panic:" in f or "runtime error:" in f:
            reason, cwe = "panic_crash", _panic_cwe(f)
        else:
            return Verdict(verified=False, reason="unconfirmed_failure",
                           evidence=outcome.output), ""
        if not crash_frame_is_target(f, target_stems):
            return _not_in_target(outcome), ""
        return Verdict(verified=True, reason=reason, evidence=_ev(outcome)), cwe

    return Verdict(verified=False, reason="no_crash", evidence=outcome.output), ""


def _not_in_target(outcome: Outcome) -> Verdict:
    return Verdict(verified=False, reason="crash_not_in_target", evidence=outcome.output)


def _ev(outcome: Outcome, value: str = "") -> str:
    head = (value + "\n") if value else ""
    return (head + (outcome.frames or ""))[-1800:]


def _panic_cwe(text: str) -> str:
    for needle, cwe in _PANIC_CWE:
        if needle in (text or ""):
            return cwe
    return "CWE-248"
