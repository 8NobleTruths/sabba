"""Go prover: fuzz to discover a candidate, prove it with a Sabba-owned reproducer."""
from .classify import classify_outcome, frames_hit_target
from .detect import is_go_target
from .prover import GoFuzzProver, go_hunt
from .runner import (Discovery, GoHarness, Outcome, assemble, discover_poc, go_available,
                     go_path, module_path, verify_poc)

__all__ = [
    "GoFuzzProver", "go_hunt", "GoHarness", "Discovery", "Outcome",
    "classify_outcome", "frames_hit_target", "is_go_target",
    "assemble", "discover_poc", "verify_poc", "module_path",
    "go_available", "go_path",
]
