"""A small labeled corpus to bring up and test the risk ranker without external data.

Each sample is a short C function with a label: 1 for a memory-unsafe shape (an unbounded copy,
an unchecked index, an off-by-one allocation) and 0 for the safe counterpart (a bounded copy, a
checked index, a correct allocation). Identifiers and sizes are randomized so the classifier
must learn the risky patterns, not memorize names.

This exists to prove the pipeline end to end and to give a usable default model. It is not a
claim about real-world accuracy. Production training uses the same JSONL format,
{"code": ..., "label": 0 or 1}, over the real labeled corpus; see docs/WATER_LAYER_DESIGN.md.
"""
from __future__ import annotations

import json
import random
from pathlib import Path

_NAMES = ["handle", "parse", "copy_in", "read_rec", "load", "decode", "fill", "ingest",
          "build", "process", "unpack", "store", "recv", "format_out", "append", "scan_line"]
_BUFS = ["buf", "tmp", "dst", "out", "data", "line", "name", "path", "rec", "b"]
_ARGS = ["src", "input", "s", "in", "raw", "arg", "msg", "p"]


def _risky(rng: random.Random) -> str:
    fn, b, a = rng.choice(_NAMES), rng.choice(_BUFS), rng.choice(_ARGS)
    n = rng.choice([8, 16, 32, 64, 128])
    shape = rng.randint(0, 5)
    if shape == 0:
        return f"void {fn}(const char *{a}) {{\n    char {b}[{n}];\n    strcpy({b}, {a});\n}}"
    if shape == 1:
        return f"void {fn}(const char *{a}) {{\n    char {b}[{n}];\n    sprintf({b}, \"%s\", {a});\n}}"
    if shape == 2:
        return f"void {fn}(const char *{a}) {{\n    char {b}[{n}];\n    strcat({b}, {a});\n}}"
    if shape == 3:
        return (f"void {fn}(const char *{a}, int len) {{\n    char {b}[{n}];\n"
                f"    memcpy({b}, {a}, len);\n}}")
    if shape == 4:
        return (f"int {fn}(int *{b}, int i, int v) {{\n    {b}[i] = v;\n    return {b}[i];\n}}")
    return (f"char *{fn}(const char *{a}) {{\n    char *{b} = malloc(strlen({a}));\n"
            f"    strcpy({b}, {a});\n    return {b};\n}}")


def _safe(rng: random.Random) -> str:
    fn, b, a = rng.choice(_NAMES), rng.choice(_BUFS), rng.choice(_ARGS)
    n = rng.choice([8, 16, 32, 64, 128])
    shape = rng.randint(0, 5)
    if shape == 0:
        return (f"void {fn}(const char *{a}) {{\n    char {b}[{n}];\n"
                f"    strncpy({b}, {a}, {n} - 1);\n    {b}[{n} - 1] = 0;\n}}")
    if shape == 1:
        return (f"void {fn}(const char *{a}) {{\n    char {b}[{n}];\n"
                f"    snprintf({b}, {n}, \"%s\", {a});\n}}")
    if shape == 2:
        return (f"void {fn}(const char *{a}, int len) {{\n    char {b}[{n}];\n"
                f"    if (len < {n}) memcpy({b}, {a}, len);\n}}")
    if shape == 3:
        return (f"int {fn}(int *{b}, int i, int len, int v) {{\n"
                f"    if (i >= 0 && i < len) {{ {b}[i] = v; return {b}[i]; }}\n    return -1;\n}}")
    if shape == 4:
        return (f"char *{fn}(const char *{a}) {{\n    size_t n = strlen({a}) + 1;\n"
                f"    char *{b} = malloc(n);\n    if ({b}) memcpy({b}, {a}, n);\n    return {b};\n}}")
    return f"int {fn}(int a, int b) {{\n    return a + b;\n}}"


def make_corpus(n_per_class: int = 300, seed: int = 0) -> list[dict]:
    """A balanced list of {"code", "label"} samples, deterministic for a given seed."""
    rng = random.Random(seed)
    rows = [{"code": _risky(rng), "label": 1} for _ in range(n_per_class)]
    rows += [{"code": _safe(rng), "label": 0} for _ in range(n_per_class)]
    rng.shuffle(rows)
    return rows


def write_jsonl(rows: list[dict], path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return p
