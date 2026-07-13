"""Sandbox protocol + resource limits."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence

from ..types import ExecResult


@dataclass
class Limits:
    """Per-execution resource limits. The verifier runs hostile code, keep these tight."""
    wall_seconds: float = 10.0      # hard wall-clock kill
    cpu_seconds: int = 8            # RLIMIT_CPU
    address_space_mb: int = 2048    # RLIMIT_AS (best-effort on macOS)
    max_output_bytes: int = 256 * 1024


class Sandbox(Protocol):
    """Runs a command and returns its result, enforcing `Limits`.

    Implementations MUST guarantee termination (wall-clock kill) and SHOULD enforce
    isolation appropriate to their trust model. The harness treats every target as
    hostile and never trusts a result the sandbox couldn't bound.
    """

    def run(
        self,
        cmd: Sequence[str],
        *,
        cwd: str | None = None,
        stdin: str = "",
        env: dict[str, str] | None = None,
        limits: Limits | None = None,
    ) -> ExecResult: ...
