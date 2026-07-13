"""The verification oracle for C/C++ targets.

Given source files and a candidate PoC, it:
  1. compiles with AddressSanitizer (+ UBSan) and debug info,
  2. runs the binary with the PoC (argv / stdin) inside a sandbox,
  3. parses the sanitizer output into a Verdict.

This is the single most important Phase-0 component: it converts an unreliable
guess into a *proven* finding. Naptime/Big Sleep/XBOW all converge on exactly this
"deterministic verification oracle", it is what turns 0.05 into 1.00.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Sequence

from ..sandbox import LocalSubprocessSandbox, Sandbox, Limits
from ..types import ExecResult, PoC, SanitizerReport, Verdict

# ASan exit code we force via ASAN_OPTIONS, to distinguish a sanitizer abort from
# an ordinary nonzero exit.
_ASAN_EXITCODE = 99

_SANITIZER_CLASSES = (
    "stack-buffer-overflow",
    "heap-buffer-overflow",
    "global-buffer-overflow",
    "stack-buffer-underflow",
    "heap-use-after-free",
    "stack-use-after-return",
    "stack-use-after-scope",
    "use-after-poison",
    "double-free",
    "alloc-dealloc-mismatch",
    "dynamic-stack-buffer-overflow",
    "stack-overflow",                  # stack exhaustion (e.g. unbounded recursion, CWE-674)
    "SEGV",
    "FPE",
    "undefined-behavior",
)

_CC = os.environ.get("SABBA_CC", "clang")
_SAN_FLAGS = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g", "-O1"]


class CompileError(Exception):
    def __init__(self, stderr: str):
        super().__init__(stderr)
        self.stderr = stderr


class CCompileRunOracle:
    """Compile-with-sanitizers + run-PoC + parse verification oracle for C/C++."""

    def __init__(self, sandbox: Sandbox | None = None, cc: str = _CC):
        self.sandbox = sandbox or LocalSubprocessSandbox()
        self.cc = cc

    # -- compilation -------------------------------------------------------
    def compile(self, sources: Sequence[Path], out_dir: Path) -> Path:
        if shutil.which(self.cc) is None:
            raise CompileError(
                f"compiler not found: {self.cc!r}. The oracle compiles and runs the PoC with "
                f"it, so install clang and LLVM first (Linux: apt-get install clang, "
                f"macOS: brew install llvm).")
        binary = out_dir / "target"
        cmd = [self.cc, *_SAN_FLAGS, *map(str, sources), "-o", str(binary)]
        res = self.sandbox.run(cmd, limits=Limits(wall_seconds=60, cpu_seconds=60))
        if res.exit_code != 0 or not binary.exists():
            raise CompileError(res.stderr or res.stdout)
        return binary

    # -- running -----------------------------------------------------------
    def run_poc(self, binary: Path, poc: PoC) -> ExecResult:
        env = {"ASAN_OPTIONS": f"detect_leaks=0:abort_on_error=0:exitcode={_ASAN_EXITCODE}",
               "UBSAN_OPTIONS": f"halt_on_error=1:exitcode={_ASAN_EXITCODE}:print_stacktrace=1"}
        return self.sandbox.run(
            [str(binary), *poc.argv],
            stdin=poc.stdin,
            env=env,
            limits=Limits(wall_seconds=10, cpu_seconds=8),
        )

    # -- verdict -----------------------------------------------------------
    def verify(self, sources: Sequence[Path], poc: PoC) -> Verdict:
        """Compile the target, run the PoC, and return a Verdict. The truth-teller."""
        with tempfile.TemporaryDirectory(prefix="sabba-oracle-") as td:
            out_dir = Path(td)
            try:
                binary = self.compile(sources, out_dir)
            except CompileError as e:
                return Verdict(
                    verified=False, reason="compile_error",
                    evidence=_tail(e.stderr, 2000),
                )
            res = self.run_poc(binary, poc)
            report = parse_sanitizer(res.stderr)

            # An ASan/UBSan startup failure (e.g. shadow-memory reservation) is an
            # oracle/environment error, emphatically NOT a verified finding.
            if report.internal_error:
                return Verdict(
                    verified=False, reason="oracle_error",
                    sanitizer=report, exec_result=res,
                    evidence=_tail(res.stderr, 1200),
                )

            crashed = report.triggered or res.crashed
            if crashed:
                reason = "sanitizer_triggered" if report.triggered else (
                    "timeout" if res.timed_out else "crash_signal")
                ev = report.raw_excerpt or _tail(res.stderr, 2000) or \
                    f"process terminated (exit={res.exit_code}, signal={res.signal})"
                # A timeout alone is not a memory-safety proof; flag it but don't claim a CWE.
                verified = report.triggered or (res.signal is not None and not res.timed_out)
                return Verdict(
                    verified=verified,
                    reason=reason if verified else "timeout_unconfirmed",
                    sanitizer=report if report.triggered else None,
                    exec_result=res,
                    evidence=ev,
                )
            return Verdict(verified=False, reason="no_crash", exec_result=res,
                           evidence=_tail(res.stdout + res.stderr, 800))


# Signatures that mean the sanitizer ITSELF failed to start/run, not a bug it found.
_SAN_INTERNAL_ERRORS = (
    "ReserveShadowMemoryRange failed",
    "failed to allocate",
    "Shadow memory range interleaves",
    "Failed to mmap",
    "AddressSanitizer cannot",
    "Sanitizer CHECK failed",
    "out of memory",
)


def parse_sanitizer(stderr: str) -> SanitizerReport:
    """Extract a sanitizer verdict from stderr.

    Distinguishes three cases:
      - a real bug detection (recognized vulnerability class)  -> triggered=True
      - a sanitizer internal/startup failure                   -> internal_error=True
      - nothing                                                -> triggered=False
    """
    has_san_marker = ("AddressSanitizer" in stderr or "UndefinedBehaviorSanitizer" in stderr
                      or "runtime error:" in stderr)
    if not has_san_marker:
        return SanitizerReport(triggered=False)

    # Sanitizer couldn't run, environment/oracle problem, never a finding.
    if any(sig in stderr for sig in _SAN_INTERNAL_ERRORS):
        excerpt = _excerpt(stderr)
        return SanitizerReport(triggered=False, internal_error=True, raw_excerpt=excerpt)

    klass = None
    for c in _SANITIZER_CLASSES:
        if c in stderr:
            klass = c
            break
    if klass is None and "runtime error:" in stderr:
        klass = "undefined-behavior"

    # A real ASan finding always emits "ERROR: AddressSanitizer: <class>". Require a
    # recognized class (or a UBSan runtime error) before claiming a detection, a bare
    # "AddressSanitizer" mention without a class is not a confirmed bug.
    if klass is None:
        return SanitizerReport(triggered=False, raw_excerpt=_excerpt(stderr))

    summary = ""
    m = re.search(r"^SUMMARY:.*$", stderr, re.MULTILINE)
    if m:
        summary = m.group(0).strip()

    return SanitizerReport(triggered=True, klass=klass, summary=summary, raw_excerpt=_excerpt(stderr))


def _excerpt(stderr: str) -> str:
    for marker in ("ERROR: AddressSanitizer", "ERROR:", "runtime error:"):
        idx = stderr.find(marker)
        if idx >= 0:
            return stderr[idx: idx + 2400]
    return stderr[-2400:]


def _tail(s: str, n: int) -> str:
    s = s or ""
    return s[-n:]
