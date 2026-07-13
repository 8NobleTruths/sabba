"""The EVM prover and the exploit-writing hunt.

This mirrors the proven fuzz path (the model writes code, the oracle proves it), moved to
Solidity. The model writes an exploit contract; Sabba runs it against a pinned fork and
believes only what the checker confirms. The checker is ProfitCheck.sol, which Sabba owns,
so the model proposes the attack but never grades it. See checkers.py for the soundness
rules that keep a generated exploit from faking its own win.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ...types import Finding, Verdict
from ..base import ProofBundle
from .checkers import forbidden_cheatcodes, parse_forge_json
from .detect import is_foundry_project
from .foundry import Foundry, evm_doctor

_TEMPLATES = Path(__file__).parent / "templates"
_DEFAULT_BLOCK = 19_000_000
_CONTRACT = "Exploit"

SYSTEM = """You write a Solidity exploit that PROVES a vulnerability by ending richer than \
you started, on a forked chain. You do not describe a bug; you drain it.

You are given the target contracts and a base contract ProfitCheck. Write exactly one \
contract, `Exploit is ProfitCheck`, that implements two functions:
- setUpTarget(): deploy or attach to the target at its real fork address, and set up the \
scenario, for example fund an independent victim.
- attack(): carry out the exploit through real calls.

The attacker is your own contract, address(this). It starts with whatever the fork gives \
it and must finish strictly richer in ETH. Profit is counted in ETH because ETH cannot be \
minted, it can only be taken from the target; if the bug pays out in tokens, swap them to \
ETH through a real market inside attack() so the gain shows up as ETH. Sabba measures this; \
you cannot change how the win is counted, and it runs only test_exploit.

Rules that keep the proof real:
- attack() is real calls only. Inside attack() you may NOT use any cheatcode: no deal, \
hoax, prank, vm.store, vm.etch, vm.mockCall, or vm.ffi. A win that a cheatcode manufactured \
is rejected.
- setUpTarget() may use vm.deal and vm.prank to build the scenario, for example to fund an \
independent victim or act as another user. It may never use vm.store, vm.etch, vm.mockCall, \
or vm.ffi, which would invent a chain state that does not exist.
- If the attacker needs capital, take a flash loan inside attack() and repay it in the same \
call, or fund the attacker in setUpTarget (that is counted before the attack starts).
- The fork url and block are set outside your code; do not fork inside the contract.

Return only the Solidity source for one file, starting with the pragma."""


@dataclass
class EvmExploit:
    contract: str
    solidity: str


class EvmForkProver:
    domain = "evm"
    languages = ("solidity",)
    vuln_classes = ("attacker-profit", "reentrancy", "access-control", "price-manipulation")

    def matches(self, target_dir: Path, spec: dict | None) -> bool:
        if spec:
            if spec.get("domain") == "evm":
                return True
            if spec.get("language") in ("solidity", "evm"):
                return True
        return is_foundry_project(Path(target_dir))

    def prove(self, target_dir: Path, candidate: EvmExploit, *,
              rpc: str | None = None, block: int | None = None) -> Verdict:
        # On a live fork the funds are real, so no funding cheatcodes at all. A local
        # self-contained target may fund an independent victim in setUp.
        bad = forbidden_cheatcodes(candidate.solidity, allow_setup_funding=rpc is None)
        if bad:
            return Verdict(verified=False, reason="unsound_cheatcode",
                           evidence="exploit uses balance or state faking cheatcodes: "
                                    + ", ".join(bad))
        fd = Foundry()
        if not fd.available():
            return Verdict(verified=False, reason="prover_unavailable",
                           evidence="Foundry not found. Install it with foundryup, then "
                                    "re-run. For a live-chain target also set SABBA_ETH_RPC.")
        # A fork needs an rpc; a self-contained target that deploys the vulnerable
        # contract itself runs on a fresh local EVM with no rpc.
        with tempfile.TemporaryDirectory(prefix="sabba-evm-") as td:
            proj = _stage_project(target_dir, candidate, Path(td))
            res = fd.test(proj, match_contract=candidate.contract,
                          match_test="test_exploit", rpc=rpc, block=block)
            return parse_forge_json(res)

    def write_bundle(self, target_dir: Path, candidate: EvmExploit, verdict: Verdict,
                     out_dir: Path, *, block: int | None = None) -> ProofBundle:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "src").mkdir(exist_ok=True)
        (out_dir / "test").mkdir(exist_ok=True)
        # copy the target sources and the harness, drop the exploit and a re-run script
        src = Path(target_dir) / "src"
        if src.is_dir():
            for sol in src.rglob("*.sol"):
                (out_dir / "src" / sol.name).write_text(sol.read_text(errors="replace"))
        (out_dir / "test" / "ProfitCheck.sol").write_text(
            (_TEMPLATES / "ProfitCheck.sol").read_text())
        (out_dir / "test" / f"{candidate.contract}.t.sol").write_text(candidate.solidity)
        (out_dir / "foundry.toml").write_text((_TEMPLATES / "foundry.toml.tmpl").read_text())
        head = ('#!/usr/bin/env bash\nset -e\ncd "$(dirname "$0")"\n')
        if block:
            run = (head + ': "${SABBA_ETH_RPC:?set SABBA_ETH_RPC to an archive RPC url}"\n'
                   f"forge test --match-contract {candidate.contract} --match-test test_exploit "
                   f'--fork-url "$SABBA_ETH_RPC" --fork-block-number {block} -vvv\n')
        else:
            run = (head + f"forge test --match-contract {candidate.contract} "
                   "--match-test test_exploit -vvv\n")
        rerun = out_dir / "run.sh"
        rerun.write_text(run)
        rerun.chmod(0o755)
        return ProofBundle(
            domain="evm",
            target={"project": str(target_dir), "fork_block": block},
            witness={"exploit": f"test/{candidate.contract}.t.sol"},
            checker={"kind": "attacker-profit", "test": "test_exploit",
                     "reason": verdict.reason},
            rerun="run.sh",
            dir=str(out_dir),
        )


def evm_hunt(target_dir, *, model: str | None = None, on_event=None,
             rpc: str | None = None, block: int | None = None,
             max_tries: int = 3, judge_fn: Callable[[str, str], str] | None = None,
             ) -> list[Finding]:
    """Have the model write an exploit, prove it on a fork, report only what holds."""
    log = on_event or (lambda _m: None)
    target_dir = Path(target_dir).resolve()

    doc = evm_doctor()
    if doc["forge"] is None:
        log("[evm] Foundry not installed. Install it with foundryup, then re-run. "
            "This target needs forge to prove anything.")
        return []

    spec = _read_spec(target_dir)
    forks = _spec_has_fork(spec)
    rpc = rpc or _rpc() or None
    if forks and not rpc:
        log("[evm] this target forks a live chain. Set SABBA_ETH_RPC and re-run.")
        return []
    block = block or (_spec_block(spec) if forks else None)
    prover = EvmForkProver()

    sources = _survey_sources(target_dir)
    base = (_TEMPLATES / "ProfitCheck.sol").read_text()
    user = (f"Target Foundry project at {target_dir.name}, forked at block {block}.\n\n"
            f"Base contract you must inherit (do not modify it):\n```solidity\n{base}\n```\n\n"
            f"Target sources:\n{sources}\n\n"
            "Write the Exploit contract now.")

    judge_fn = judge_fn or _default_judge(model)
    err = ""
    for attempt in range(max_tries):
        prompt = user if not err else user + f"\n\nYour previous attempt failed:\n{err[-1500:]}\nFix it."
        log(f"[evm] writing exploit (attempt {attempt + 1}/{max_tries})")
        solidity = _extract_solidity(judge_fn(SYSTEM, prompt))
        if not solidity:
            err = "no Solidity returned"
            continue
        candidate = EvmExploit(contract=_CONTRACT, solidity=_force_name(solidity, _CONTRACT))
        log("[evm] running the exploit" + (" against the fork" if forks else " on a local EVM"))
        verdict = prover.prove(target_dir, candidate, rpc=rpc if forks else None, block=block)
        log(f"[evm] verdict: {verdict.reason} (verified={verdict.verified})")
        if verdict.verified:
            bundle = prover.write_bundle(target_dir, candidate,
                                         verdict, target_dir / "sabba-proof", block=block)
            log(f"[evm] proof written to {bundle.dir}")
            return [Finding(
                cwe=spec.get("cwe", "CWE-841"),
                title=spec.get("title", "on-chain value drain proven on a fork"),
                file=spec.get("file", ""), function=spec.get("function", ""),
                verdict=verdict,
                rationale=f"Exploit contract profits on a pinned fork. Proof: {bundle.dir}. "
                          f"Re-run with ./run.sh and SABBA_ETH_RPC set.",
            )]
        err = verdict.evidence or verdict.reason
    log("[evm] no exploit proven this run")
    return []


# -- helpers ---------------------------------------------------------------

def _rpc() -> str:
    return os.environ.get("SABBA_ETH_RPC", "").strip()


def _read_spec(target_dir: Path) -> dict:
    tj = target_dir / "target.json"
    if tj.exists():
        import json
        try:
            return json.loads(tj.read_text())
        except Exception:
            return {}
    return {}


def _spec_has_fork(spec: dict) -> bool:
    """True when the target forks a live chain (so it needs an archive rpc)."""
    if not isinstance(spec, dict):
        return False
    fork = spec.get("fork")
    if isinstance(fork, dict) and (fork.get("block") or fork.get("url") or fork.get("chain")):
        return True
    return bool(spec.get("chain"))


def _spec_block(spec: dict) -> int:
    fork = spec.get("fork") if isinstance(spec, dict) else None
    if isinstance(fork, dict) and fork.get("block"):
        return int(fork["block"])
    return _DEFAULT_BLOCK


def _survey_sources(target_dir: Path, limit: int = 24_000) -> str:
    src = target_dir / "src"
    out, total = [], 0
    for sol in sorted(src.rglob("*.sol")) if src.is_dir() else []:
        body = sol.read_text(errors="replace")
        chunk = f"// {sol.relative_to(target_dir)}\n{body}\n"
        if total + len(chunk) > limit:
            out.append(f"// {sol.relative_to(target_dir)} (truncated)\n{body[:2000]}\n")
            break
        out.append(chunk)
        total += len(chunk)
    return "\n".join(out) or "(no .sol sources under src/)"


def _stage_project(target_dir: Path, candidate: EvmExploit, work: Path) -> Path:
    proj = work / "proj"
    shutil.copytree(target_dir, proj, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("out", "cache", "sabba-proof", ".git"))
    test_dir = proj / "test"
    test_dir.mkdir(exist_ok=True)
    (test_dir / "ProfitCheck.sol").write_text((_TEMPLATES / "ProfitCheck.sol").read_text())
    (test_dir / f"{candidate.contract}.t.sol").write_text(candidate.solidity)
    # force the ffi lockdown regardless of the target's own config
    (proj / "foundry.toml").write_text((_TEMPLATES / "foundry.toml.tmpl").read_text())
    return proj


def _extract_solidity(text: str) -> str:
    if not text:
        return ""
    m = re.search(r"```(?:solidity|sol)?\s*(.*?)```", text, re.DOTALL)
    body = m.group(1) if m else text
    idx = body.find("pragma")
    return body[idx:].strip() if idx >= 0 else body.strip()


def _force_name(solidity: str, name: str) -> str:
    """Make sure the exploit contract is named as expected, so --match-contract finds it."""
    if re.search(rf"contract\s+{name}\b", solidity):
        return solidity
    return re.sub(r"contract\s+(\w+)\s+is\s+ProfitCheck",
                  f"contract {name} is ProfitCheck", solidity, count=1)


def _default_judge(model: str | None) -> Callable[[str, str], str]:
    from ...llm import judge

    def _run(system: str, user: str) -> str:
        return judge(system, user, model)
    return _run
