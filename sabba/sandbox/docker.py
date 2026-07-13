"""Container sandbox: run untrusted code in an ephemeral, network-cut container.

`LocalSubprocessSandbox` bounds CPU, memory, and wall-clock, but it does not isolate the
filesystem or the network -- hostile code still runs with the host process's reach. This
backend adds real containment for arbitrary or model-generated code:

  - no network (`--network none`)
  - cgroup CPU / memory / PID caps
  - a read-only root with a small writable tmpfs, torn down when the container exits
  - every Linux capability dropped, and no privilege escalation
  - a non-root user (the caller's own uid/gid, so a bind-mounted dir stays writable)
  - a hard wall-clock kill, with a force-remove of the container on timeout

It speaks the same `Sandbox` protocol as `LocalSubprocessSandbox`, so the harness and the
MCP tools swap backends with no other change. Needs a container engine (docker or podman)
on PATH; `engine_available()` reports whether one is present.
"""
from __future__ import annotations

import itertools
import os
import shutil
import subprocess
from typing import Sequence

from ..types import ExecResult
from .base import Limits

_counter = itertools.count(1)


def engine_available() -> str | None:
    """Return the container engine on PATH ('docker' or 'podman'), or None if neither."""
    for e in ("docker", "podman"):
        if shutil.which(e):
            return e
    return None


def _text(x) -> str:
    if x is None:
        return ""
    return x if isinstance(x, str) else x.decode(errors="replace")


class DockerSandbox:
    """A `Sandbox` that runs each command in a locked-down, throwaway container."""

    def __init__(self, image: str = "alpine:3", engine: str | None = None):
        self.image = image
        self.engine = engine or engine_available()

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
        if not self.engine:
            raise RuntimeError(
                "no container engine on PATH (need docker or podman); use "
                "LocalSubprocessSandbox for the resource-only tier")

        name = f"sabba-{os.getpid()}-{next(_counter)}"
        mem = f"{max(64, int(limits.address_space_mb))}m"
        run = [
            self.engine, "run", "--rm", "-i", "--name", name,
            "--network", "none",
            "--cpus", "1.0",
            "--memory", mem, "--memory-swap", mem,
            "--pids-limit", "256",
            "--read-only",
            "--tmpfs", "/tmp:rw,size=128m",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "-e", "HOME=/tmp",
        ]
        for k, v in (env or {}).items():
            run += ["-e", f"{k}={v}"]
        if cwd:
            run += ["-v", f"{os.path.abspath(cwd)}:/work", "--workdir", "/work"]
        else:
            run += ["--tmpfs", "/work:rw,size=128m", "--workdir", "/work"]
        run += [self.image, *cmd]

        try:
            proc = subprocess.run(
                run, input=stdin, capture_output=True, text=True,
                timeout=limits.wall_seconds)
        except subprocess.TimeoutExpired as e:
            self._force_remove(name)
            return ExecResult(
                exit_code=-9,
                stdout=_text(e.stdout)[: limits.max_output_bytes],
                stderr=_text(e.stderr)[: limits.max_output_bytes],
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

    def _force_remove(self, name: str) -> None:
        # the run client was killed on timeout; the container may still be alive
        try:
            subprocess.run([self.engine, "rm", "-f", name],
                           capture_output=True, timeout=15)
        except Exception:
            pass
