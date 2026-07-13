"""Code-graph features for the retrieval layer (call graph + dangerous-sink annotations).

The harness needs "which functions reach a dangerous sink, and who calls them", a call
graph with sink annotations, to rank candidate targets for the reasoner. We extract this
with tree-sitter (reliable, no build system required). Joern `c2cpg` adds precise
inter-procedural dataflow/taint where source->sink paths matter; here the call graph is
the retrieval substrate.

  python -m sabba.harness.cpg <file.c | dir> --out graph.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


# ── generic tree-sitter C helpers (self-contained; no build/label dependencies) ──
def _parser():
    from tree_sitter import Language, Parser
    import tree_sitter_c
    return Parser(Language(tree_sitter_c.language()))


def _func_name(fn_node, src: bytes) -> str | None:
    """Best-effort function name from a `function_definition` node."""
    cur = fn_node.child_by_field_name("declarator")
    while cur is not None and cur.type != "function_declarator":
        cur = cur.child_by_field_name("declarator") or (
            cur.named_children[0] if cur.named_children else None)
    if cur is None:
        return None
    name = cur.child_by_field_name("declarator")
    while name is not None and name.type != "identifier":
        name = name.child_by_field_name("declarator") or (
            name.named_children[0] if name.named_children else None)
    return src[name.start_byte:name.end_byte].decode(errors="replace") if name else None


# Dangerous sinks (memory-safety relevant). Reaching one from untrusted input is the
# signal the retrieval layer ranks on.
SINKS = {"strcpy", "strcat", "sprintf", "vsprintf", "gets", "memcpy", "memmove",
         "alloca", "scanf", "sscanf", "system", "strncpy", "snprintf", "realloc",
         "malloc", "free", "read", "recv"}


def _callees(fn_node, src: bytes) -> list[str]:
    """Names of functions called within a function_definition node."""
    out = []

    def walk(n):
        if n.type == "call_expression":
            fnf = n.child_by_field_name("function")
            if fnf is not None and fnf.type == "identifier":
                out.append(src[fnf.start_byte:fnf.end_byte].decode(errors="replace"))
        for c in n.children:
            walk(c)

    walk(fn_node)
    return out


def graph_for_source(src: bytes, parser) -> list[dict]:
    """Per-function call/sink features for one translation unit."""
    tree = parser.parse(src)
    rows = []

    def find_fns(n):
        if n.type == "function_definition":
            yield n
            return
        for c in n.children:
            yield from find_fns(c)

    for fn in find_fns(tree.root_node):
        name = _func_name(fn, src)
        if not name:
            continue
        calls = _callees(fn, src)
        params = fn.child_by_field_name("declarator")
        n_params = 0
        if params is not None:
            n_params = sum(1 for c in params.children if c.type == "parameter_list"
                           for _ in c.named_children)
        code = src[fn.start_byte:fn.end_byte].decode(errors="replace")
        rows.append({
            "function": name,
            "line": fn.start_point[0] + 1,
            "calls": sorted(set(calls)),
            "sinks": sorted({c for c in calls if c in SINKS}),
            "n_calls": len(calls),
            "n_params": n_params,
            "code": code[:8000],           # function source, for the ML risk ranker
            "parse_quality": "ok",
        })
    return rows


def build(paths: list[Path]) -> list[dict]:
    """Build call-graph rows for a list of C files, adding reverse-edges (callers)."""
    parser = _parser()
    rows = []
    for p in paths:
        try:
            src = p.read_bytes()
            for r in graph_for_source(src, parser):
                r["file"] = str(p)
                rows.append(r)
        except Exception as e:
            rows.append({"file": str(p), "function": "", "parse_quality": f"error:{e}"})
    # reverse edges: who calls each function (so retrieval can walk sinks -> entries)
    name_to_idx = {r["function"]: i for i, r in enumerate(rows) if r.get("function")}
    for r in rows:
        r.setdefault("callers", [])
    for r in rows:
        for callee in r.get("calls", []):
            j = name_to_idx.get(callee)
            if j is not None:
                rows[j]["callers"].append(r["function"])
    for r in rows:
        if "callers" in r:
            r["callers"] = sorted(set(r["callers"]))
    return rows


def _c_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    return [p for p in root.rglob("*.c")] + [p for p in root.rglob("*.h")]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sabba.harness.cpg")
    p.add_argument("path")
    p.add_argument("--out", default="-")
    args = p.parse_args(argv)
    rows = build(_c_files(Path(args.path).expanduser()))
    out = sys.stdout if args.out == "-" else open(args.out, "w")
    for r in rows:
        out.write(json.dumps(r) + "\n")
    if out is not sys.stdout:
        out.close()
    ok = sum(1 for r in rows if r.get("parse_quality") == "ok")
    sinks = sum(1 for r in rows if r.get("sinks"))
    print(f"[cpg] {len(rows)} functions ({ok} ok), {sinks} with dangerous sinks -> {args.out}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
