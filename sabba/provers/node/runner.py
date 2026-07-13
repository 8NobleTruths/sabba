"""Phase one: discover a candidate PoC with a model-written Jazzer.js harness.

This is the discovery half of the two-phase prover. The fuzzing loop is Sabba's, but the
harness inside it is the model's and is untrusted. So from a fuzz run we take exactly one
thing: the candidate input bytes that libFuzzer saved when the harness crashed. We take
nothing from the fuzzer's stdout, and we do not trust which artifact prefix (crash-, oom-,
timeout-) the file carries. Whether those bytes are a real, target-attributed security bug
is decided in phase two by the Sabba-owned reproducer (reproducer.py), never here.

Node and Jazzer.js are only needed to run a discovery fuzz, never to import this module, so
a box without them can still load the prover and report the toolchain missing.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

MAX_LEN = 16384
RSS_LIMIT_MB = 2048

# artifact prefixes libFuzzer writes for a saved input, preference order. The prefix is a
# hint only; phase two re-runs the bytes and decides the kind for itself.
_ARTIFACT_PREFIXES = ("crash-", "oom-", "timeout-")


@dataclass
class NodeHarness:
    requires: str         # the require line(s) that load the target
    body: str             # the body of fuzz(data), where data is a Buffer
    entry: str = ""


@dataclass
class Discovery:
    """What phase one hands to phase two: candidate PoC bytes, nothing more."""
    kind: str = "none"        # "candidate" | "none" | "build_error"
    poc_bytes: bytes = b""
    output: str = ""          # kept for a build_error message only, never for a verdict


def jazzerjs_home() -> str:
    return os.environ.get("SABBA_JAZZERJS_HOME") or os.path.expanduser("~/jazzerjs")


def _launcher() -> str:
    return os.path.join(jazzerjs_home(), "node_modules", ".bin", "jazzer")


def _tsc() -> str:
    return os.path.join(jazzerjs_home(), "node_modules", ".bin", "tsc")


def node_available() -> bool:
    return shutil.which("node") is not None


def jazzerjs_available() -> bool:
    return node_available() and os.path.exists(_launcher())


def toolchain_available() -> bool:
    return jazzerjs_available()


# Names shadowed to undefined inside the body's scope, so the body cannot reach the module
# object, require, the global object, process, reflection, or the Function constructor even if
# a static gate ever missed a spelling. `import`, `eval`, `arguments`, and `this` cannot be
# parameter names in strict mode; `import`/`eval` are gated in the body and `this` is undefined
# because the body runs with an undefined receiver.
_SHADOW = ("require", "module", "exports", "global", "globalThis", "process", "Reflect",
           "WebAssembly", "Function", "__dirname", "__filename", "self", "window", "top",
           "fetch")


def assemble(h: NodeHarness) -> str:
    """Wrap the model's requires and body into module.exports.fuzz, with body-scope isolation.

    The requires load the target at module scope with the real require, gated to the target or
    the fuzzer API only. The body then runs inside a strict-mode inner function whose parameters
    shadow every escape hatch (require, module, exports, the global object, process, reflection,
    the Function constructor) to undefined, invoked with an undefined receiver so `this` is
    undefined too. The body cannot reach the module object, so it cannot require fs or touch the
    inherited result fd, and it never sees the parent's nonce. See docs/PROVER_SOUNDNESS.md,
    round 2 (body-scope isolation).
    """
    body = (h.body or "").strip() or "return;"
    shadow = ", ".join(_SHADOW)
    return (
        '"use strict";\n'
        f"{(h.requires or '').strip()}\n\n"
        "module.exports.fuzz = function (data) {\n"
        '  "use strict";\n'
        f"  return (function (data, {shadow}) {{\n"
        '    "use strict";\n'
        f"{_indent(body, 4)}\n"
        "  }).call(undefined, data);\n"
        "};\n"
    )


def node_bin() -> str:
    return shutil.which("node") or "node"


def discover(target_dir, harness: NodeHarness, *, secs: int = 20,
             per_input_timeout: int = 10, seed: bytes | None = None,
             workdir: Path | None = None) -> Discovery:
    """Fuzz the target with the harness for secs and return candidate PoC bytes, or none.

    The return carries only the saved input bytes. Nothing about the crash kind or where it
    happened is taken from this phase; phase two establishes both from unforgeable channels.
    """
    home = jazzerjs_home()
    launcher = _launcher()
    own_work = workdir is None
    work = Path(workdir or tempfile.mkdtemp(prefix="sabba-nodefuzz-"))
    try:
        _stage_sources(Path(target_dir), work)
        build_err = _transpile_ts(work, home)
        if build_err:
            return Discovery(kind="build_error", output=build_err)
        _link_node_modules(work, home)
        (work / "fuzz.js").write_text(assemble(harness))
        corpus = work / "corpus"
        corpus.mkdir(exist_ok=True)
        (corpus / "seed0").write_bytes(seed if seed is not None else b"seed")

        cmd = [launcher, "fuzz", "corpus", "--sync", "--",
               f"-max_total_time={secs}", f"-timeout={per_input_timeout}",
               f"-rss_limit_mb={RSS_LIMIT_MB}", f"-max_len={MAX_LEN}"]
        env = dict(os.environ)
        node_dir = os.path.dirname(shutil.which("node") or "")
        if node_dir:
            env["PATH"] = node_dir + os.pathsep + env.get("PATH", "")
        try:
            subprocess.run(cmd, cwd=str(work), capture_output=True, text=True,
                           timeout=secs + 90, env=env)
        except subprocess.TimeoutExpired:
            pass  # a wedged fuzzer still may have saved an artifact; look for it below

        poc = _first_artifact_bytes(work)
        if poc is not None:
            return Discovery(kind="candidate", poc_bytes=poc)
        return Discovery(kind="none")
    finally:
        if own_work:
            shutil.rmtree(work, ignore_errors=True)


def _first_artifact_bytes(work: Path) -> bytes | None:
    for prefix in _ARTIFACT_PREFIXES:
        for p in sorted(work.glob(prefix + "*")):
            try:
                return p.read_bytes()
            except OSError:
                continue
    return None


def _link_node_modules(work: Path, home: str) -> None:
    nm = work / "node_modules"
    if not nm.exists():
        try:
            os.symlink(os.path.join(home, "node_modules"), nm)
        except OSError:
            pass


def _transpile_ts(work: Path, home: str) -> str:
    """Compile any .ts sources to .js in place. Returns an error string, or '' on success."""
    ts_files = [p for p in work.rglob("*.ts") if not p.name.endswith(".d.ts")]
    if not ts_files:
        return ""
    tsc = _tsc()
    if not os.path.exists(tsc):
        return "a .ts target needs typescript (tsc) in the Jazzer.js home; install it there"
    cmd = [tsc, "--allowJs", "--skipLibCheck", "--module", "commonjs",
           "--target", "es2020", "--outDir", ".",
           *[str(p.relative_to(work)) for p in ts_files]]
    try:
        p = subprocess.run(cmd, cwd=str(work), capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"tsc failed: {e}"
    # tsc emits .js even on type errors by default; only fail if nothing was produced
    if p.returncode != 0 and next(work.rglob("*.js"), None) is None:
        return (p.stderr or p.stdout or "tsc produced no output")[-1500:]
    return ""


def _stage_sources(target_dir: Path, work: Path) -> None:
    for src in target_dir.rglob("*"):
        if src.is_file() and src.suffix in (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts",
                                            ".json"):
            rel = src.relative_to(target_dir)
            dst = work / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(src.read_text(errors="replace"))


def _indent(text: str, n: int = 2) -> str:
    pad = " " * n
    return "\n".join(pad + ln if ln.strip() else ln for ln in text.splitlines())
