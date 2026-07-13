"""Java prover: fuzz with a model-written Jazzer harness, prove a security-relevant crash.

Two phases: Jazzer discovers a candidate PoC, a Sabba-owned reproducer re-runs it and reads
the verdict over unforgeable channels (a caught Throwable's real frames, or the JVM's own dump
for a killed child). The kind and the target attribution come only from that structured
outcome, never from the fuzzer's mixed output or a harness-written artifact.
"""
from .classify import (Frame, Outcome, attributed_to_target, classify_outcome, cwe_for_issue,
                       innermost_is_target)
from .detect import is_java_target
from .prover import JavaFuzzProver, java_hunt
from .runner import (JavaHarness, JazzerTools, assemble, discover_poc, find_jazzer,
                     java_available, javac_available, jazzer_available, toolchain_available,
                     verify_available, verify_poc)

__all__ = [
    "JavaFuzzProver", "java_hunt", "JavaHarness", "JazzerTools",
    "Frame", "Outcome", "attributed_to_target", "innermost_is_target", "classify_outcome",
    "cwe_for_issue", "is_java_target", "assemble", "discover_poc", "verify_poc", "find_jazzer",
    "java_available", "javac_available", "jazzer_available", "toolchain_available",
    "verify_available",
]
