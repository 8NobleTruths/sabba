"""The prover registry.

The oracle became a registry of provers, one per language and vulnerability class, all
obeying the same rule: a Finding is minted only from a verified Verdict. The native
memory-safety prover is always here. The EVM prover registers too, but lazily, so importing
sabba never requires Foundry or any EVM dependency; if its import fails the rest of Sabba is
unaffected.
"""
from .base import ProofBundle, Prover, SupportsVerify
from .native import NativeCandidate, NativeMemSafetyProver
from .registry import NoProver, detect_domain, provers, register, select

register(NativeMemSafetyProver())

try:  # EVM is optional; a missing dependency must never break native
    from .evm.prover import EvmForkProver

    register(EvmForkProver())
except Exception:  # noqa: BLE001 - registration is best-effort by design
    pass

try:  # Python fuzzing prover; atheris is only needed to run, not to register
    from .python.prover import PyFuzzProver

    register(PyFuzzProver())
except Exception:  # noqa: BLE001
    pass

try:  # Java fuzzing prover; the JVM toolchain is only needed to run, not to register
    from .java.prover import JavaFuzzProver

    register(JavaFuzzProver())
except Exception:  # noqa: BLE001
    pass

try:  # Go fuzzing prover; the go toolchain is only needed to run, not to register
    from .golang.prover import GoFuzzProver

    register(GoFuzzProver())
except Exception:  # noqa: BLE001
    pass

try:  # Node (JS/TS) fuzzing prover; Node and Jazzer.js are only needed to run
    from .node.prover import NodeFuzzProver

    register(NodeFuzzProver())
except Exception:  # noqa: BLE001
    pass

__all__ = [
    "Prover", "SupportsVerify", "ProofBundle",
    "NativeMemSafetyProver", "NativeCandidate",
    "register", "select", "detect_domain", "provers", "NoProver",
]
