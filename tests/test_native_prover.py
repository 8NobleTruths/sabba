"""The native prover wraps the oracle without changing its verdict. clang-gated, like
test_oracle.py.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from sabba.harness import CCompileRunOracle
from sabba.provers.native import NativeCandidate, NativeMemSafetyProver
from sabba.types import PoC

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ROOT / "targets"

pytestmark = pytest.mark.skipif(
    shutil.which("clang") is None and shutil.which("cc") is None,
    reason="no C compiler available",
)


def _load(target: str):
    d = TARGETS / target
    spec = json.loads((d / "target.json").read_text())
    return d, [d / s for s in spec["sources"]], spec


def test_prover_matches_oracle_on_known_bug():
    d, sources, spec = _load("cwe121_stack_overflow")
    poc = PoC(argv=spec["known_poc"]["argv"], stdin=spec["known_poc"].get("stdin", ""))

    oracle_verdict = CCompileRunOracle().verify(sources, poc)
    prover = NativeMemSafetyProver()
    prover_verify = prover.verify(sources, poc)
    prover_prove = prover.prove(d, NativeCandidate(sources=sources, poc=poc))

    assert oracle_verdict.verified
    assert prover_verify.verified == oracle_verdict.verified
    assert prover_prove.verified == oracle_verdict.verified
    assert prover_prove.reason == oracle_verdict.reason


def test_prover_matches_selects_native():
    d, _sources, _spec = _load("cwe121_stack_overflow")
    assert NativeMemSafetyProver().matches(d, None)
