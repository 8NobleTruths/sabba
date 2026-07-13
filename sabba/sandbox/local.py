"""Local subprocess sandbox: rlimits + wall-clock timeout + minimal env.

⚠️ TRUST MODEL: this provides RESOURCE bounding (CPU/mem/time), NOT isolation.
It does not sandbox the filesystem or network on macOS. Use it only on a trusted
dev machine against known targets to de-risk the harness (Phase 0). For RLVR
rollouts and production verification of arbitrary repos, use an isolated backend
(Firecracker / rootless container), see `docker.py` and `infra/sandbox/`.
"""
from __future__ import annotations

import os
import subprocess
from typing import Sequence

from ..types import ExecResult
from .base import Limits


def _preexec(limits: Limits):  # pragma: no cover - exercised via subprocess
    """Apply POSIX resource limits in the child before exec."""
    import resource

    def apply():
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
        except (ValueError, OSError):
            pass
        # NOTE: deliberately NOT setting RLIMIT_AS. AddressSanitizer/UBSan reserve a
        # huge virtual shadow-memory region at startup; an RLIMIT_AS cap makes ASan
        # abort with "ReserveShadowMemoryRange failed" before it can run. Sanitizers
        # and RLIMIT_AS are incompatible. Real memory bounding (address_space_mb) is
        # enforced by the container backend's cgroup, not by rlimit, see docker.py.
        os.setsid()  # own process group, so we can kill the whole tree on timeout

    return apply


class LocalSubprocessSandbox:
    """A `Sandbox` backed by `subprocess.run` with rlimits and a hard timeout."""

    def run(
        self,
        cmd: Sequence[str],
        *,
        cwd: str | None = None,
        stdin: str = "",
        env: dict[str, str] | None = None,
        limits: Limits | None = None,
    ) -> ExecResult:
        limits = limits or Limits()
        # Minimal, explicit env (do not inherit the operator's secrets).
        run_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/tmp"}
        if env:
            run_env.update(env)

        try:
            proc = subprocess.run(
                list(cmd),
                cwd=cwd,
                input=stdin,
                capture_output=True,
                text=True,
                timeout=limits.wall_seconds,
                env=run_env,
                preexec_fn=_preexec(limits),
            )
        except subprocess.TimeoutExpired as e:
            out = (e.stdout or "") if isinstance(e.stdout, str) else (e.stdout or b"").decode(errors="replace")
            err = (e.stderr or "") if isinstance(e.stderr, str) else (e.stderr or b"").decode(errors="replace")
            return ExecResult(
                exit_code=-9,
                stdout=out[: limits.max_output_bytes],
                stderr=err[: limits.max_output_bytes],
                timed_out=True,
                signal=9,
            )

        sig = -proc.returncode if proc.returncode < 0 else None
        return ExecResult(
            exit_code=proc.returncode,
            stdout=proc.stdout[: limits.max_output_bytes],
            stderr=proc.stderr[: limits.max_output_bytes],
            timed_out=False,
            signal=sig,
        )
