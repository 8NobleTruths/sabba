"""Core data types shared across the Sabba system.

Everything the harness emits flows through these. The cardinal rule (ADR 0001):
a Finding is only ever produced from a confirmed Verdict, never from model text alone.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class ExecResult:
    """Result of running a command inside a sandbox."""
    exit_code: int                 # process exit code (negative => killed by signal -N)
    stdout: str
    stderr: str
    timed_out: bool = False
    signal: int | None = None      # signal number if killed, else None

    @property
    def crashed(self) -> bool:
        return self.signal is not None or self.timed_out


@dataclass
class SanitizerReport:
    """Parsed output of a sanitizer (ASan/UBSan/TSan) run."""
    triggered: bool                 # True ONLY for a real bug detection (recognized class)
    klass: str | None = None        # e.g. "stack-buffer-overflow", "heap-use-after-free"
    summary: str = ""               # the SUMMARY: line, if any
    raw_excerpt: str = ""           # trimmed sanitizer report for evidence
    internal_error: bool = False    # ASan/UBSan failed to start (env/oracle problem, NOT a finding)


@dataclass
class PoC:
    """A concrete reproduction input for a candidate vulnerability."""
    argv: list[str] = field(default_factory=list)
    stdin: str = ""

    def label(self) -> str:
        shown = [a if len(a) <= 24 else f"{a[:21]}...<{len(a)}B>" for a in self.argv]
        return f"argv={shown} stdin={len(self.stdin)}B"


@dataclass
class Verdict:
    """The output of the verification oracle. The ONLY thing allowed to mint a Finding."""
    verified: bool
    reason: str                     # "sanitizer_triggered" | "no_crash" | "compile_error" | ...
    sanitizer: SanitizerReport | None = None
    exec_result: ExecResult | None = None
    evidence: str = ""              # human-readable proof excerpt


@dataclass
class Finding:
    """A confirmed vulnerability. Emitted only when verdict.verified is True."""
    cwe: str                        # e.g. "CWE-121"
    title: str
    function: str = ""
    file: str = ""
    line: int | None = None
    poc: PoC | None = None
    verdict: Verdict | None = None
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d
