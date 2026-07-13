"""Detect a Java (JVM) target.

Match a directory as Java when the spec says so, or when it holds .java sources and is not
a C or Solidity project. The C-or-Solidity guard keeps a native repo that ships a few helper
sources on the native path, rather than pulling it into the JVM fuzzer.
"""
from __future__ import annotations

from pathlib import Path

_C = (".c", ".cc", ".cpp", ".cxx")


def is_java_target(target_dir: Path, spec: dict | None = None) -> bool:
    if spec:
        if spec.get("domain") == "java":
            return True
        if spec.get("language") in ("java", "jvm"):
            return True
    target_dir = Path(target_dir)
    if next(target_dir.rglob("*.java"), None) is None:
        return False
    has_c = any(next(target_dir.rglob(f"*{e}"), None) is not None for e in _C)
    has_sol = next(target_dir.rglob("*.sol"), None) is not None
    return not has_c and not has_sol
