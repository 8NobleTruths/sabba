"""The prover contract.

A prover is one instance of the oracle idea, specialized to a language and a way of
proving a bug. The C/C++ sanitizer oracle is the first prover. An EVM fork checker is the
second. Every prover obeys the same rule the oracle already obeys (ADR 0001): it returns a
Verdict, and a Finding is minted only from a Verdict that is verified. Provers are added,
never forked.

The pieces:

  matches       does this prover own the target's language and layout
  prove         run the candidate and decide, deterministically, in a sandbox
  write_bundle  emit a re-runnable proof for a confirmed finding

The candidate type is domain specific. Native takes (sources, PoC). EVM takes an exploit
contract. The Verdict type is shared and unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, Sequence, runtime_checkable

from ..types import PoC, Verdict


@runtime_checkable
class SupportsVerify(Protocol):
    """The native verify contract, unchanged. This is what CCompileRunOracle already is,
    so the native prover is a drop-in anywhere an oracle is expected today."""

    def verify(self, sources: Sequence[Path], poc: PoC) -> Verdict: ...


@dataclass
class ProofBundle:
    """A re-runnable proof for one confirmed finding. One shape across domains.

    A maintainer or a bounty triager learns it once: the pinned target, the witness that
    drives it, the checker that decides, and a single script that rebuilds and re-runs.
    """
    domain: str                       # "native" | "evm"
    target: dict = field(default_factory=dict)   # pinned sources+build, or fork url+block
    witness: dict = field(default_factory=dict)   # argv/stdin, or the exploit contract
    checker: dict = field(default_factory=dict)   # sanitizer flags, or the invariant
    rerun: str = "run.sh"             # the re-run script, relative to the bundle dir
    dir: str = ""                     # where the bundle was written


@runtime_checkable
class Prover(Protocol):
    """What every prover implements. Kept small on purpose."""

    domain: str                       # "native" | "evm"
    languages: tuple[str, ...]
    vuln_classes: tuple[str, ...]

    def matches(self, target_dir: Path, spec: dict | None) -> bool: ...

    def prove(self, target_dir: Path, candidate: Any) -> Verdict: ...

    def write_bundle(self, target_dir: Path, candidate: Any, verdict: Verdict,
                     out_dir: Path) -> ProofBundle: ...
