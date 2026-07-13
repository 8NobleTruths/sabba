"""Phase-0 Milestone M0: the verification oracle proves a known bug, no LLM needed.

Run: `.venv/bin/pytest -q`  (requires clang with AddressSanitizer, i.e. any recent
Apple clang or LLVM clang).
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from sabba.harness import CCompileRunOracle
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
    sources = [d / s for s in spec["sources"]]
    return spec, sources


ALL_TARGETS = ["cwe121_stack_overflow", "cwe122_heap_overflow"]


@pytest.mark.parametrize("target", ALL_TARGETS)
def test_known_poc_is_verified(target):
    spec, sources = _load(target)
    oracle = CCompileRunOracle()
    poc = PoC(argv=spec["known_poc"]["argv"], stdin=spec["known_poc"].get("stdin", ""))

    verdict = oracle.verify(sources, poc)

    assert verdict.verified, f"{target}: oracle failed to confirm known bug: {verdict.reason}\n{verdict.evidence}"
    assert verdict.reason == "sanitizer_triggered"
    assert verdict.sanitizer is not None
    assert verdict.sanitizer.klass == spec["ground_truth"]["sanitizer_class"]


def test_benign_input_is_not_a_finding():
    """A short, safe input must NOT be reported as a vulnerability (false-positive guard)."""
    _spec, sources = _load("cwe121_stack_overflow")
    oracle = CCompileRunOracle()

    verdict = oracle.verify(sources, PoC(argv=["alice"]))

    assert not verdict.verified
    assert verdict.reason == "no_crash"
