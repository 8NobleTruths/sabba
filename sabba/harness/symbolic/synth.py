"""Constraint-based input synthesis for buffer-overflow sinks.

This is the symbolic half of the harness. It reads a C source, models the arithmetic
that relates a buffer's size to how many bytes get written into it, and asks Z3 for an
input length that makes the write exceed the buffer. The candidate input is then handed
to the oracle, which compiles under AddressSanitizer and runs it. Z3 proposes; the oracle
decides. Nothing is reported unless a sanitizer actually fires.

The first cut covers the two most common shapes:

  1. strcpy/strcat/stpcpy into a fixed-size stack array
         char buf[16]; strcpy(buf, s);      overflow when strlen(s) >= 16
  2. strcpy into a heap buffer sized from strlen without the +1 for the NUL
         n = strlen(s); p = malloc(n); strcpy(p, s);   writes n+1 into n bytes

The source of the copy is traced one hop back to argv[i] through the enclosing
function's parameter, so the synthesized argv actually reaches the sink. The size model
is deliberately explicit so harder cases (integer overflow in the size expression,
signed/unsigned truncation) slot in later without changing the pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ..cpg import _parser
from ..oracle import CCompileRunOracle
from ...types import Finding, PoC

MAX_LEN = 4096
MAX_FILES = 250       # cap per run so a huge repo does not hang; logged when it applies
_CWE = {
    "stack-buffer-overflow": "CWE-121",
    "dynamic-stack-buffer-overflow": "CWE-121",
    "heap-buffer-overflow": "CWE-122",
    "global-buffer-overflow": "CWE-787",
}
_COPY_NUL = {"strcpy", "stpcpy", "strcat"}   # write strlen(src) + 1 bytes


@dataclass
class SinkSpec:
    """One overflow candidate: where it is, and the size arithmetic Z3 will solve."""
    function: str
    line: int
    sink: str
    buffer: str
    size_kind: str         # "const" for char buf[N]; "len" for malloc(strlen(src) + k)
    size_const: int        # N when const, else the +k added to the input length
    argv_index: int        # which argv the tainted length comes from (argv sources)
    source_kind: str = "argv"   # "argv" or "stdin"


def _text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode(errors="replace")


def _cint(s: str):
    """Parse a C integer literal (handles 0x/0b, digit separators, u/l suffixes). None on fail."""
    s = s.strip().replace("'", "").rstrip("uUlL")
    for base in (0, 10):
        try:
            return int(s, base)
        except ValueError:
            continue
    return None


def _walk(node):
    yield node
    for c in node.children:
        yield from _walk(c)


def _ident_under(node):
    """Descend a declarator to its identifier node, or None."""
    n = node
    seen = 0
    while n is not None and n.type != "identifier" and seen < 8:
        nxt = n.child_by_field_name("declarator")
        if nxt is None:
            nxt = n.named_children[0] if n.named_children else None
        n = nxt
        seen += 1
    return n if (n is not None and n.type == "identifier") else None


def _call(node, src: bytes):
    """(callee_name, [arg_nodes]) for a call_expression, else (None, [])."""
    if node.type != "call_expression":
        return None, []
    fn = node.child_by_field_name("function")
    args = node.child_by_field_name("arguments")
    if fn is None or fn.type != "identifier" or args is None:
        return None, []
    arg_nodes = [c for c in args.named_children]
    return _text(fn, src), arg_nodes


def _strlen_of(node, src: bytes):
    """If node is strlen(X) or strlen(X)+K, return (X_name, K); else None."""
    base, k = node, 0
    if node.type == "binary_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if right is not None and right.type == "number_literal" and left is not None:
            kv = _cint(_text(right, src))
            if kv is None:
                return None
            base, k = left, kv
        elif left is not None and left.type == "number_literal" and right is not None:
            kv = _cint(_text(left, src))
            if kv is None:
                return None
            base, k = right, kv
    name, cargs = _call(base, src)
    if name == "strlen" and len(cargs) == 1 and cargs[0].type == "identifier":
        return _text(cargs[0], src), k
    return None


def _argv_index(node, src: bytes):
    """If node is argv[i], return i; else None."""
    if node.type != "subscript_expression":
        return None
    arr = node.child_by_field_name("argument") or (node.named_children[0] if node.named_children else None)
    idx = node.child_by_field_name("index")
    if arr is not None and _text(arr, src) == "argv" and idx is not None and idx.type == "number_literal":
        return _cint(_text(idx, src))
    return None


def _functions(root, src: bytes) -> dict:
    """name -> {node, params:[identifier names in order]}."""
    out = {}
    for n in _walk(root):
        if n.type != "function_definition":
            continue
        decl = n.child_by_field_name("declarator")
        fname = _ident_under(decl) if decl else None
        if fname is None:
            continue
        params = []
        # find the parameter_list under the function_declarator
        for d in _walk(decl):
            if d.type == "parameter_list":
                for pd in d.named_children:
                    pid = _ident_under(pd.child_by_field_name("declarator") or pd)
                    params.append(_text(pid, src) if pid else "")
                break
        out[_text(fname, src)] = {"node": n, "params": params}
    return out


def _caller_argv(funcs: dict, fname: str, param_index: int, src: bytes):
    """Find a call fname(...) whose arg at param_index is argv[i]; return i or None."""
    for info in funcs.values():
        for n in _walk(info["node"]):
            callee, cargs = _call(n, src)
            if callee == fname and param_index < len(cargs):
                i = _argv_index(cargs[param_index], src)
                if i is not None:
                    return i
    return None


def find_overflow_sinks(source: bytes) -> list[SinkSpec]:
    """Extract strcpy-family overflow candidates whose length traces to argv."""
    parser = _parser()
    root = parser.parse(source).root_node
    funcs = _functions(root, source)
    specs: list[SinkSpec] = []

    for fname, info in funcs.items():
        fnode = info["node"]
        arrays: dict[str, int] = {}          # buf -> N  (char buf[N])
        len_binds: dict[str, tuple] = {}     # var -> (src_var, k)  from `var = strlen(src)+k`
        mallocs: dict[str, tuple] = {}       # buf -> (src_var, k)
        local_argv: dict[str, int] = {}      # var -> i  from `var = argv[i]`

        for n in _walk(fnode):
            if n.type == "assignment_expression":
                left = n.child_by_field_name("left")
                right = n.child_by_field_name("right")
                if left is not None and left.type == "identifier" and right is not None:
                    di = _argv_index(right, source)
                    if di is not None:
                        local_argv[_text(left, source)] = di
            if n.type == "declaration":
                for d in _walk(n):
                    if d.type == "array_declarator":
                        bid = _ident_under(d.child_by_field_name("declarator") or d)
                        size = d.child_by_field_name("size")
                        if bid is not None and size is not None and size.type == "number_literal":
                            sz = _cint(_text(size, source))
                            if sz is not None:
                                arrays[_text(bid, source)] = sz
                    if d.type == "init_declarator":
                        vid = _ident_under(d.child_by_field_name("declarator") or d)
                        val = d.child_by_field_name("value")
                        if vid is None or val is None:
                            continue
                        vname = _text(vid, source)
                        di = _argv_index(val, source)
                        if di is not None:
                            local_argv[vname] = di
                        sl = _strlen_of(val, source)
                        if sl is not None:
                            len_binds[vname] = sl
                        mname, margs = _call(val, source)
                        if mname == "malloc" and len(margs) == 1:
                            a = margs[0]
                            sl2 = _strlen_of(a, source)
                            if sl2 is not None:
                                mallocs[vname] = sl2
                            elif a.type == "identifier" and _text(a, source) in len_binds:
                                mallocs[vname] = len_binds[_text(a, source)]

        for n in _walk(fnode):
            callee, cargs = _call(n, source)
            if not callee:
                continue
            line = n.start_point[0] + 1

            # stdin sinks: gets(buf) or scanf("...%s...", buf) into a fixed buffer
            if callee == "gets" and cargs and cargs[0].type == "identifier" \
                    and _text(cargs[0], source) in arrays:
                dst = _text(cargs[0], source)
                specs.append(SinkSpec(fname, line, "gets", dst, "const", arrays[dst], 0, "stdin"))
                continue
            if callee in ("scanf", "__isoc99_scanf") and len(cargs) >= 2 \
                    and "%s" in _text(cargs[0], source) and cargs[1].type == "identifier" \
                    and _text(cargs[1], source) in arrays:
                dst = _text(cargs[1], source)
                specs.append(SinkSpec(fname, line, "scanf", dst, "const", arrays[dst], 0, "stdin"))
                continue

            # copy sinks: strcpy-family into a fixed or malloc(strlen) buffer
            if callee not in _COPY_NUL or len(cargs) < 2 or cargs[0].type != "identifier":
                continue
            dst = _text(cargs[0], source)

            # resolve the copied source to an argv index: argv[i] used directly, a local
            # assigned from argv, or a parameter passed argv at a call site.
            srcarg = cargs[1]
            srcvar = _text(srcarg, source) if srcarg.type == "identifier" else None
            argv_i = _argv_index(srcarg, source)
            if argv_i is None and srcvar is not None:
                if srcvar in local_argv:
                    argv_i = local_argv[srcvar]
                elif srcvar in info["params"]:
                    argv_i = _caller_argv(funcs, fname, info["params"].index(srcvar), source)
            if argv_i is None:
                continue

            if dst in arrays:
                size_kind, size_const = "const", arrays[dst]
            elif srcvar is not None and dst in mallocs and mallocs[dst][0] == srcvar:
                size_kind, size_const = "len", mallocs[dst][1]
            else:
                continue

            specs.append(SinkSpec(fname, line, callee, dst, size_kind, size_const, argv_i))
    return specs


def solve_length(spec: SinkSpec) -> int | None:
    """Smallest input length L making the write exceed the buffer, via Z3. None if safe."""
    from z3 import Int, Optimize, sat
    L = Int("L")
    opt = Optimize()
    opt.add(L >= 1, L <= MAX_LEN)
    write = L + 1                                    # strcpy writes strlen(src)+1
    size = spec.size_const if spec.size_kind == "const" else L + spec.size_const
    opt.add(write > size)
    opt.minimize(L)
    if opt.check() != sat:
        return None
    return opt.model()[L].as_long()


def synthesize(sources: Iterable[Path]) -> list[tuple[SinkSpec, PoC, Path]]:
    """For each source, find sinks, solve for a length, build an argv PoC.

    Each result carries the file it came from, so verification can compile just that file
    rather than the whole tree (which lets this run over a loose directory of sources).
    """
    out = []
    for path in sources:
        path = Path(path)
        try:
            data = path.read_bytes()
            specs = find_overflow_sinks(data)
        except Exception:
            continue
        for spec in specs:
            try:
                n = solve_length(spec)
                if n is None:
                    continue
                if spec.source_kind == "stdin":
                    poc = PoC(argv=[], stdin="A" * n)
                else:
                    if spec.argv_index < 1:
                        continue
                    argv = ["x"] * spec.argv_index
                    argv[spec.argv_index - 1] = "A" * n
                    poc = PoC(argv=argv, stdin="")
                out.append((spec, poc, path))
            except Exception:
                continue
    return out


def hunt_symbolic(sources, *, file_hint: str = "", on_event=None, oracle=None) -> list[Finding]:
    """Solve, verify each candidate against its own file, emit only confirmed findings."""
    log = on_event or (lambda _m: None)
    oracle = oracle or CCompileRunOracle()
    src_paths = [Path(s) for s in sources]
    if len(src_paths) > MAX_FILES:
        log(f"[note] {len(src_paths)} source files; analyzing the first {MAX_FILES} "
            f"(point at a smaller directory or a single file for the rest)")
        src_paths = sorted(src_paths)[:MAX_FILES]
    findings: list[Finding] = []
    for spec, poc, path in synthesize(src_paths):
        log(f"[z3] {spec.function} {spec.sink} into {spec.buffer} "
            f"(size={spec.size_kind}:{spec.size_const}) in {path.name} -> try {poc.label()}")
        try:
            verdict = oracle.verify([path], poc)
        except Exception as e:
            log(f"     verify error ({str(e)[:80]})")
            continue
        if not verdict.verified:
            log(f"     not confirmed ({verdict.reason})")
            continue
        klass = verdict.sanitizer.klass if verdict.sanitizer else None
        cwe = _CWE.get(klass or "", "CWE-787")
        log(f"     confirmed {klass}")
        findings.append(Finding(
            cwe=cwe,
            title=f"{klass or 'buffer overflow'} via {spec.sink} into {spec.buffer}",
            function=spec.function,
            file=file_hint or path.name,
            line=spec.line,
            poc=poc,
            verdict=verdict,
            rationale=(f"Z3 solved a {len(poc.stdin)}-byte stdin input"
                       if spec.source_kind == "stdin"
                       else f"Z3 solved argv[{spec.argv_index}] length {len(poc.argv[spec.argv_index - 1])}")
                      + "; AddressSanitizer confirmed the write is out of bounds.",
        ))
    return findings
