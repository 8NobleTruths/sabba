"""Detect a Node (JavaScript or TypeScript) target.

Match a directory as Node when the spec says so, or when it holds .js/.ts sources and is
not a C, Solidity, Python, Go, or Java project. The other-language guard keeps a target
that only ships a helper script in another ecosystem on that ecosystem's path.
"""
from __future__ import annotations

from pathlib import Path

_NODE_EXT = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts")
_OTHER = (".c", ".cc", ".cpp", ".cxx", ".sol", ".py", ".go", ".java")


def is_node_target(target_dir: Path, spec: dict | None = None) -> bool:
    if spec:
        if spec.get("domain") == "node":
            return True
        if spec.get("language") in ("node", "javascript", "typescript", "js", "ts"):
            return True
    target_dir = Path(target_dir)
    has_node = any(next(target_dir.rglob(f"*{e}"), None) is not None for e in _NODE_EXT)
    if not has_node:
        return False
    has_other = any(next(target_dir.rglob(f"*{e}"), None) is not None for e in _OTHER)
    return not has_other
