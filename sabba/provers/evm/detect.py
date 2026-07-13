"""Detect a Foundry Solidity project.

Slice 1 is Foundry only. Hardhat and Truffle projects are out of scope until they get
their own environment builder. A directory is a Foundry project when it carries a
foundry.toml, a forge-std library, or Solidity sources under src.
"""
from __future__ import annotations

from pathlib import Path


def is_foundry_project(target_dir: Path) -> bool:
    target_dir = Path(target_dir)
    if (target_dir / "foundry.toml").exists():
        return True
    if (target_dir / "lib" / "forge-std").exists():
        return True
    src = target_dir / "src"
    if src.is_dir() and next(src.rglob("*.sol"), None) is not None:
        return True
    return False
