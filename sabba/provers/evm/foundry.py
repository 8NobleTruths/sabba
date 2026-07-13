"""The Foundry fork runner.

Everything runs through the shared Sandbox so a wall-clock kill is guaranteed, the same
way the C oracle runs the target. We use forge's fork cheatcode with a pinned block
rather than a standalone anvil daemon, which is deterministic and needs no background
process. A pinned block plus forge's on-disk fork cache is what separates a repeatable
proof from a flaky one.

The dev box has no forge yet. evm_doctor reports that without raising, and the prover
turns an absent toolchain into a loud, actionable verdict instead of a silent no-op.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from ...sandbox import Limits, LocalSubprocessSandbox, Sandbox
from ...types import ExecResult

_TOOLS = ("forge", "anvil", "cast")


def evm_doctor() -> dict[str, str | None]:
    """Where each Foundry tool is, or None. Never raises."""
    return {t: shutil.which(t) for t in _TOOLS}


class Foundry:
    """Runs forge inside the sandbox."""

    def __init__(self, sandbox: Sandbox | None = None):
        self.sandbox = sandbox or LocalSubprocessSandbox()

    def available(self) -> bool:
        return evm_doctor()["forge"] is not None

    def version(self) -> str:
        if not self.available():
            return ""
        res = self.sandbox.run(["forge", "--version"], limits=Limits(wall_seconds=20))
        return (res.stdout or res.stderr).strip().splitlines()[0] if (res.stdout or res.stderr) else ""

    def test(self, project: Path, *, match_contract: str, match_test: str,
             rpc: str | None = None, block: int | None = None,
             wall_seconds: float = 240) -> ExecResult:
        """Run a single exploit test, output as JSON.

        With an rpc, run against a pinned fork of a live chain. Without one, run against a
        fresh local EVM, which is enough for a self-contained target that deploys the
        vulnerable contract itself. We restrict to one contract and one test so a
        model-authored file that also contains other, possibly vacuous, tests cannot
        influence the verdict.
        """
        cmd = ["forge", "test",
               "--match-contract", match_contract,
               "--match-test", match_test,
               "--json", "-vvv"]
        if rpc:
            cmd += ["--fork-url", rpc]
            if block:
                cmd += ["--fork-block-number", str(block)]
        return self.sandbox.run(cmd, cwd=str(project),
                                limits=Limits(wall_seconds=wall_seconds,
                                              cpu_seconds=int(wall_seconds)))

    def build(self, project: Path, wall_seconds: float = 180) -> ExecResult:
        return self.sandbox.run(["forge", "build"], cwd=str(project),
                                limits=Limits(wall_seconds=wall_seconds,
                                              cpu_seconds=int(wall_seconds)))
