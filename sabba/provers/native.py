"""The native memory-safety prover.

This wraps the existing C/C++ oracle without changing it. The oracle stays the anchor:
compile with clang under AddressSanitizer and UBSan, run the PoC, decide. The prover adds
the registry contract around it. It also exposes verify(sources, poc) so it is a drop-in
wherever a CCompileRunOracle is used today.

Scope is what clang can build under a sanitizer: C, C++, and Objective-C. Rust and Zig are
memory-safe surfaces that need their own toolchain and prover, so they are not claimed here.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from ..harness.oracle import CCompileRunOracle, _SAN_FLAGS
from ..sandbox import Sandbox
from ..types import PoC, Verdict
from .base import ProofBundle

_C_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".m", ".h", ".hpp")


@dataclass
class NativeCandidate:
    """What the native prover proves: source files plus a reproducing input."""
    sources: Sequence[Path]
    poc: PoC


class NativeMemSafetyProver:
    domain = "native"
    languages = ("c", "c++", "objective-c")
    vuln_classes = ("memory-safety",)

    def __init__(self, sandbox: Sandbox | None = None):
        self.oracle = CCompileRunOracle(sandbox=sandbox)

    # drop-in for CCompileRunOracle at every existing call site
    def verify(self, sources: Sequence[Path], poc: PoC) -> Verdict:
        return self.oracle.verify(sources, poc)

    def matches(self, target_dir: Path, spec: dict | None) -> bool:
        if spec:
            if spec.get("language") in ("c", "c++", "cpp", "objective-c"):
                return True
            srcs = spec.get("sources")
            if srcs:
                return any(str(s).endswith(_C_SUFFIXES) for s in srcs)
        # rglob returns a lazy generator; next(..., None) is the truthy check, not the
        # generator object (which is always truthy).
        return any(next(target_dir.rglob(f"*{suf}"), None) is not None
                   for suf in (".c", ".cc", ".cpp", ".cxx", ".m"))

    def prove(self, target_dir: Path, candidate: NativeCandidate) -> Verdict:
        return self.oracle.verify(candidate.sources, candidate.poc)

    def write_bundle(self, target_dir: Path, candidate: NativeCandidate,
                     verdict: Verdict, out_dir: Path) -> ProofBundle:
        out_dir.mkdir(parents=True, exist_ok=True)
        copied = []
        for s in candidate.sources:
            s = Path(s)
            if s.exists():
                (out_dir / s.name).write_text(s.read_text(errors="replace"))
                copied.append(s.name)
        poc = candidate.poc
        (out_dir / "poc.json").write_text(json.dumps({"argv": poc.argv, "stdin": poc.stdin}))
        flags = " ".join(_SAN_FLAGS)
        argv = " ".join(_sh_quote(a) for a in poc.argv)
        stdin_pipe = "cat poc_stdin 2>/dev/null | " if poc.stdin else ""
        if poc.stdin:
            (out_dir / "poc_stdin").write_text(poc.stdin)
        script = (
            "#!/usr/bin/env bash\n"
            "set -e\n"
            "cd \"$(dirname \"$0\")\"\n"
            f"clang {flags} {' '.join(copied)} -o target\n"
            "export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0\n"
            f"{stdin_pipe}./target {argv}\n"
        )
        rerun = out_dir / "run.sh"
        rerun.write_text(script)
        rerun.chmod(0o755)
        return ProofBundle(
            domain="native",
            target={"sources": copied, "compiler": "clang", "flags": _SAN_FLAGS},
            witness={"argv": poc.argv, "stdin_bytes": len(poc.stdin)},
            checker={"sanitizer": "address,undefined", "reason": verdict.reason},
            rerun="run.sh",
            dir=str(out_dir),
        )


def _sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"
