"""Node prover: fuzz JavaScript and TypeScript with a model-written Jazzer.js harness.

Two phases: discovery finds a candidate PoC with Jazzer.js, then a Sabba-owned reproducer
re-runs it and decides the verdict from unforgeable channels. See docs/PROVER_SOUNDNESS.md.
"""
from .classify import Outcome, classify_outcome
from .detect import is_node_target
from .prover import (NodeFuzzProver, check_harness, node_hunt, target_file_basenames)
from .reproducer import verify_poc
from .runner import (Discovery, NodeHarness, assemble, discover, jazzerjs_available,
                     jazzerjs_home, node_available, toolchain_available)

__all__ = [
    "NodeFuzzProver", "node_hunt", "NodeHarness", "Discovery", "Outcome",
    "classify_outcome", "verify_poc", "check_harness", "target_file_basenames",
    "is_node_target", "assemble", "discover",
    "node_available", "jazzerjs_available", "jazzerjs_home", "toolchain_available",
]
