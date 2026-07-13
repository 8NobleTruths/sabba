"""The prover registry and target detection.

One place decides which prover owns a target. Precedence is explicit: a prover that
claims a specific language and layout is tried before the native fallback, so a
Solidity project is never swallowed by the native default. Native is the back-compat
default when nothing else matches, which keeps every existing C/C++ target on the same
path it runs today.
"""
from __future__ import annotations

from pathlib import Path

from .base import Prover


class NoProver(RuntimeError):
    """No registered prover matches the target."""


_PROVERS: list[Prover] = []


def register(p: Prover) -> None:
    _PROVERS.append(p)


def provers() -> list[Prover]:
    return list(_PROVERS)


def select(target_dir: Path, spec: dict | None = None) -> Prover:
    """Return the prover for a target. Specific provers win over the native fallback."""
    target_dir = Path(target_dir)
    specific = [p for p in _PROVERS if p.domain != "native"]
    native = [p for p in _PROVERS if p.domain == "native"]
    for p in specific + native:
        if p.matches(target_dir, spec):
            return p
    raise NoProver(f"no prover matches {target_dir}")


def detect_domain(target_dir: Path, spec: dict | None = None) -> str:
    """Name the domain for a target, defaulting to native for back-compat."""
    try:
        return select(target_dir, spec).domain
    except NoProver:
        return "native"
