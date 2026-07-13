"""Static gates on a model-written harness, run before it is ever executed.

The harness is untrusted. It is model-written, and the model reads the target's source, so a
hostile target can steer it. These gates strip the harness of every lever it could use to
fake a crash or to run its own code at load, which is what lets the reproducer in verify.py
trust its private result channel. The real backstop is still that attribution comes from the
structured stack, not from anything the harness prints; the gates are defense in depth.

Four rules, from the soundness doc:

1. Scan both the import section and the body, not just the body.
2. The import section is import statements only, and may load only the target module and the
   fuzzer API (atheris). Anything else, or any statement that is not a bare import, is
   rejected. This is what stops the harness running code at load.
3. The body may not manufacture a crash or write output: no raise, no exit, no recursion or
   resource-limit change, no writer to a fd or file, no reflection or eval, no bare infinite
   loop.
4. The body must actually call the target through the bound name, not merely mention it.

A harness that fails any gate is rejected as unsound_harness and never fuzzed.
"""
from __future__ import annotations

import ast
from typing import Iterable

# The fuzzer API the harness is allowed to import besides the target itself.
_ALLOWED_IMPORT = {"atheris"}

# Names the body may not reference at all: modules that reach the filesystem, the process,
# the network, or the interpreter's limits, and the builtins that write, exit, or run code.
_FORBIDDEN_NAMES = {
    "os", "sys", "subprocess", "socket", "ctypes", "resource", "faulthandler",
    "signal", "multiprocessing", "importlib", "builtins", "threading", "gc",
    "pathlib", "shutil", "tempfile", "mmap", "fcntl", "pty", "select",
    "eval", "exec", "compile", "__import__", "open", "print", "input",
    "getattr", "setattr", "delattr", "vars", "globals", "locals",
    "exit", "quit", "breakpoint", "help", "__builtins__", "__loader__",
}

# Attribute names the body may not use, so it cannot reach a forbidden call through an
# already-bound object (for example sys.setrecursionlimit when sys is added by the wrapper).
_FORBIDDEN_ATTRS = {
    "setrecursionlimit", "setrlimit", "write", "writelines", "flush", "fileno",
    "_exit", "system", "popen", "exit", "abort", "fdopen", "dup2", "dup",
    "fork", "kill", "spawnv", "spawnl", "spawnvp", "connect", "bind", "listen",
    "truncate", "makedirs", "remove", "unlink", "rmtree",
    # reflection: the classic sandbox escape reaches builtins through dunder attributes
    "__class__", "__bases__", "__subclasses__", "__globals__", "__builtins__",
    "__dict__", "__getattribute__", "__import__", "__reduce__", "mro",
}


def scan_harness(harness, target_stems: Iterable[str]) -> str | None:
    """Return a rejection reason, or None if the harness passes every gate."""
    stems = set(target_stems)
    reason = _scan_imports(getattr(harness, "imports", "") or "", stems)
    if reason:
        return reason
    return _scan_body(getattr(harness, "body", "") or "", stems)


def _scan_imports(src: str, stems: set[str]) -> str | None:
    if not src.strip():
        return "harness imports nothing; it must import the target module"
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        return f"import section is not valid Python: {e}"
    allowed = stems | _ALLOWED_IMPORT
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top not in allowed:
                    return f"import section loads a non-target module: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            if node.level != 0:
                return "relative imports are not allowed in the harness"
            top = (node.module or "").split(".")[0]
            if top not in allowed:
                return f"import section loads a non-target module: {node.module}"
        else:
            return "the import section must contain import statements only"
    return None


def _scan_body(src: str, stems: set[str]) -> str | None:
    if not src.strip():
        return "harness body is empty"
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        return f"harness body is not valid Python: {e}"
    calls_target = False
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            return "the harness body may not import modules"
        if isinstance(node, ast.Raise):
            return "the harness body may not raise its own exception"
        # No function, lambda, or class of its own. A recursive helper the body defines, or a
        # callable it passes into the target, would recurse through a target frame and forge
        # attribution; the reproducer also requires the innermost frame to be the target, but
        # a harness that only calls the target has no reason to define anything.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda,
                             ast.ClassDef)):
            return "the harness body may not define a function, lambda, or class"
        if isinstance(node, ast.While):
            reason = _bad_loop(node)
            if reason:
                return reason
        if isinstance(node, ast.Name):
            # Leading-underscore names are the reproducer's own (_emit, _FD, _NONCE, _report)
            # and the reflection dunders. The body has no legitimate use for any of them.
            if node.id.startswith("_"):
                return f"the harness body may not use a leading-underscore name: {node.id}"
            if node.id in _FORBIDDEN_NAMES:
                return f"the harness body may not use {node.id}"
        if isinstance(node, ast.Attribute):
            if node.attr.startswith("_"):
                return f"the harness body may not use a leading-underscore attribute: .{node.attr}"
            if node.attr in _FORBIDDEN_ATTRS:
                return f"the harness body may not use .{node.attr}"
        if isinstance(node, ast.Call) and _root_name(node.func) in stems:
            calls_target = True
        if isinstance(node, ast.Attribute) and _root_name(node) in stems:
            calls_target = True
    if not calls_target:
        return "the harness body never calls the target module"
    return None


def _root_name(node: ast.AST) -> str | None:
    """The leftmost Name id of an attribute/call/subscript chain, or None."""
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)):
        node = node.value if isinstance(node, (ast.Attribute, ast.Subscript)) else node.func
    return node.id if isinstance(node, ast.Name) else None


def _is_truthy_const(test: ast.AST) -> bool:
    return isinstance(test, ast.Constant) and bool(test.value)


def _bad_loop(loop: ast.While) -> str | None:
    """Reject an always-true or side-effect-free loop condition, not only a literal.

    A loop with a break can terminate, so it is allowed. A break-less loop with a truthy
    constant test (while True, while 1) is a bare infinite loop. A break-less loop whose test
    references no name that the loop body assigns can never change value, so if it starts true
    it never ends: `while len(data) >= 0: pass` is the canonical dodge. Only a loop whose
    test depends on a name the body mutates can terminate on its own.
    """
    if _has_break(loop):
        return None
    if _is_truthy_const(loop.test):
        return "the harness body may not spin a bare infinite loop"
    used = {n.id for n in ast.walk(loop.test) if isinstance(n, ast.Name)}
    stored = _stored_names(loop)
    if not (used & stored):
        return "the harness body may not spin a loop whose condition never changes"
    return None


def _stored_names(loop: ast.While) -> set[str]:
    """Names the loop body assigns, so its test could change and the loop could end."""
    names: set[str] = set()
    for stmt in loop.body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                names.add(node.id)
    return names


def _has_break(loop: ast.While) -> bool:
    for node in ast.walk(loop):
        if isinstance(node, ast.Break):
            return True
    return False
