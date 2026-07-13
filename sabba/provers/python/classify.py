"""Discovery-side bookkeeping for the Python fuzzer.

This module used to decide the verdict by substring-matching the fuzzer's mixed output. It
no longer does. The verdict is decided in verify.py, from the structured outcome of a
Sabba-owned reproducer, over channels the harness cannot forge. Discovery keeps only what it
needs to hand the next phase a candidate PoC: a small record of what libFuzzer reported, of
which the sole trusted field is poc_bytes. The kind here is a hint for logs, never a verdict.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class CrashInfo:
    """What discovery saw. Only poc_bytes is carried into verification; the rest is a log
    hint and is never trusted for the verdict."""
    kind: str = ""            # "exception" | "timeout" | "oom" | "signal" | "none"
    exception: str = ""       # a best-effort label from the traceback, for logs only
    signal: int | None = None
    output: str = ""          # the fuzzer's mixed output, kept for logs, never for a verdict
    poc_path: str = ""
    poc_bytes: bytes = b""


_EXC_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception|Exit|Interrupt))\b",
                     re.MULTILINE)


def parse_exception(output: str) -> str:
    """Best-effort label of the exception class from a discovery traceback, for logs only.

    This is not used to decide anything. The real exception class comes from the reproducer's
    structured type(e).__name__ in verify.py.
    """
    if not output:
        return ""
    names = _EXC_RE.findall(output)
    if not names:
        return ""
    return names[-1].split(".")[-1]
