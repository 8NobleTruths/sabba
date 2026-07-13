"""The prover registry selects the right prover by target type, and the native prover is a
drop-in for the oracle. Pure filesystem, no toolchain needed, always runs.
"""
from __future__ import annotations

from sabba.provers import (NativeMemSafetyProver, detect_domain, select)
from sabba.provers.base import SupportsVerify
from sabba.provers.evm import EvmForkProver


def _c_tree(tmp_path):
    (tmp_path / "main.c").write_text("int main(void){return 0;}\n")
    return tmp_path


def _foundry_tree(tmp_path):
    (tmp_path / "foundry.toml").write_text("[profile.default]\nsrc='src'\n")
    src = tmp_path / "src"
    src.mkdir()
    (src / "A.sol").write_text("pragma solidity ^0.8.0; contract A {}\n")
    return tmp_path


def test_c_tree_is_native(tmp_path):
    d = _c_tree(tmp_path)
    assert detect_domain(d, None) == "native"
    assert isinstance(select(d, None), NativeMemSafetyProver)


def test_foundry_tree_is_evm(tmp_path):
    d = _foundry_tree(tmp_path)
    assert detect_domain(d, None) == "evm"
    assert isinstance(select(d, None), EvmForkProver)


def test_spec_language_wins(tmp_path):
    # an explicit spec forces the domain even without on-disk markers
    assert detect_domain(tmp_path, {"language": "solidity"}) == "evm"
    assert detect_domain(tmp_path, {"domain": "evm"}) == "evm"
    assert detect_domain(tmp_path, {"language": "c"}) == "native"


def test_empty_dir_defaults_native(tmp_path):
    # back-compat: nothing matches -> native, never a crash
    assert detect_domain(tmp_path, None) == "native"


def test_native_prover_is_drop_in_for_oracle():
    p = NativeMemSafetyProver()
    assert isinstance(p, SupportsVerify)
    assert hasattr(p, "verify")
