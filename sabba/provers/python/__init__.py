"""Python prover: fuzz with a model-written Atheris harness (discovery), then prove the crash
in the target with a Sabba-owned reproducer (verification)."""
from .classify import CrashInfo, parse_exception
from .detect import is_python_target
from .gates import scan_harness
from .prover import PyFuzzProver, py_hunt
from .runner import PyHarness, assemble, atheris_available, run_fuzz
from .verify import (Outcome, has_target_frame, innermost_is_target, target_stems,
                     verdict_from_outcome, verify_poc)

__all__ = [
    "PyFuzzProver", "py_hunt", "PyHarness", "CrashInfo", "parse_exception",
    "is_python_target", "assemble", "atheris_available", "run_fuzz",
    "scan_harness", "verify_poc", "verdict_from_outcome", "Outcome",
    "has_target_frame", "innermost_is_target", "target_stems",
]
