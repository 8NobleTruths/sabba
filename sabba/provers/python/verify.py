"""The Sabba-owned reproducer: re-run a candidate PoC and decide the verdict from channels
the harness cannot forge.

Discovery (runner.py) only hands us candidate bytes. It takes nothing else: not the fuzzer's
stdout, not any artifact file the harness wrote. Verification re-runs those bytes through a
reproducer script that Sabba generates at run time, never the model's, in a scratch dir.

The reproducer:

  - opens a private pipe inherited from the parent and writes its result there, so a result
    on that channel is Sabba's own, never the harness's,
  - redirects the harness's stdout and stderr to os.devnull, so anything the harness prints
    is gone before it can be mistaken for evidence,
  - sets RLIMIT_AS for the memory limit and faulthandler.dump_traceback_later for the hang,
    both of which emit a real traceback the harness cannot forge,
  - enables faulthandler on fatal signals, so a C-extension segfault dumps the real Python
    stack that led into the crash,
  - imports the harness and calls TestOneInput(poc) under try/except BaseException, then
    reports type(e).__name__ and traceback.extract_tb frames as JSON on the private pipe.

The parent reads the pipe and the child's exit status. Attribution comes only from the
structured frames: at least one frame whose source file is a target .py file, never the
reproducer or a wrapper. Kind comes only from the structured outcome. Where a resource crash
cannot be attributed to a target frame, the verdict is unverified rather than a guess.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path

from ...types import Verdict

# Files that are never a target: the reproducer wrapper (the harness body is compiled with
# the filename sabba_harness.py, so its frames carry that stem) and conventional non-source
# names. A frame in any of these is the harness or Sabba, never the target.
_WRAPPER_STEMS = {"sabba_repro", "sabba_harness", "harness", "__init__"}

# Structured exception class -> (verdict reason, cwe). Only these caught classes verify.
# MemoryError is deliberately absent: an out-of-memory cannot be soundly attributed to the
# target rather than harness-driven allocation pressure, so it is not a confirmed finding.
_VERIFIED_EXC = {
    "RecursionError": ("stack_exhaustion", "CWE-674"),
}

# Lines the runtime writes in a faulthandler dump: File "<path>", line <n> in <name>.
_DUMP_FRAME = re.compile(r'File "([^"]+)", line (\d+)(?: in (\S+))?')


@dataclass
class Outcome:
    """What the reproducer observed, over unforgeable channels only.

    kind is one of: "exception", "signal", "timeout", "none", "error". frames are the real
    stack frames (from the caught exception or the runtime dump); the harness cannot fake
    them. raw is a short excerpt of the private channel for evidence, never harness stdout.
    """
    kind: str = "none"
    exc: str = ""
    signal: int | None = None
    frames: list[dict] = field(default_factory=list)
    raw: str = ""
    error: str = ""
    poc: bytes = b""


def target_stems(target_dir: Path) -> set[str]:
    """The set of file stems that count as target source, excluding wrapper files."""
    return {p.stem for p in Path(target_dir).rglob("*.py")
            if p.stem not in _WRAPPER_STEMS}


def has_target_frame(frames: list[dict], stems: set[str]) -> bool:
    """True when at least one structured frame is in a target file, not a wrapper."""
    for f in frames:
        stem = Path(f.get("file", "")).stem
        if stem in stems and stem not in _WRAPPER_STEMS:
            return True
    return False


def innermost_is_target(frames: list[dict], stems: set[str]) -> bool:
    """True when the innermost frame, the one that raised, is a target frame.

    Attribution is the crashing frame, not merely any frame present. Frames are ordered
    outermost first (extract_tb order, and _frames_from_dump normalizes the runtime dump to
    match), so the innermost is the last one. A harness that recurses a helper of its own
    through a target call leaves the target frame higher up but the harness frame innermost,
    so requiring the last frame to be a target frame rejects it. A missing frame is not a
    target frame.
    """
    if not frames:
        return False
    stem = Path(frames[-1].get("file", "")).stem
    return stem in stems and stem not in _WRAPPER_STEMS


def verify_poc(target_dir, harness, poc_bytes: bytes, *, timeout: int = 8,
               mem_mb: int | None = None, python_exe: str | None = None) -> Outcome:
    """Re-run poc_bytes through the Sabba reproducer and return a structured Outcome.

    This does not use atheris; it is the verification phase and runs on any Python. mem_mb,
    when set, caps address space via RLIMIT_AS (best effort, some platforms ignore it).
    """
    python_exe = python_exe or sys.executable
    work = Path(tempfile.mkdtemp(prefix="sabba-pyrepro-"))
    try:
        _stage_sources(Path(target_dir), work)
        (work / "sabba_repro.py").write_text(_build_reproducer(harness, mem_mb, timeout))
        (work / "poc.bin").write_bytes(poc_bytes or b"")

        # A random per-run nonce authenticates the reproducer's own messages. Only the
        # wrapper is told the nonce; the harness body never sees it, so it cannot forge a
        # message the parent will accept.
        nonce = secrets.token_hex(16)
        r_fd, w_fd = os.pipe()
        os.set_inheritable(w_fd, True)
        env = dict(os.environ)
        env["SABBA_FD"] = str(w_fd)
        env["SABBA_NONCE"] = nonce
        proc = subprocess.Popen(
            [python_exe, "sabba_repro.py", "poc.bin"], cwd=str(work),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, pass_fds=(w_fd,), env=env)
        os.close(w_fd)

        # Drain the private channel concurrently: a runtime dump of a deep stack can exceed
        # the pipe buffer, so the child must never block waiting for us to read.
        sink: dict[str, bytes] = {}
        reader = threading.Thread(target=_reader, args=(r_fd, sink), daemon=True)
        reader.start()

        hard_timeout = False
        try:
            proc.wait(timeout=timeout + 8)
        except subprocess.TimeoutExpired:
            hard_timeout = True
            proc.kill()
            try:
                proc.wait(timeout=5)
            except Exception:  # noqa: BLE001
                pass

        reader.join(timeout=5)
        os.close(r_fd)
        raw = sink.get("raw", b"").decode(errors="replace")
        outcome = _outcome_from_report(raw, proc.returncode, hard_timeout, nonce)
        outcome.poc = poc_bytes or b""
        return outcome
    finally:
        shutil.rmtree(work, ignore_errors=True)


def verdict_from_outcome(outcome: Outcome, stems: set[str]) -> tuple[Verdict, str]:
    """Turn a structured Outcome into (Verdict, cwe). Kind from the structured outcome only,
    attribution from the structured frames only."""
    ev = (outcome.raw or "")[-1600:]
    if outcome.kind == "error":
        return Verdict(verified=False, reason="harness_error",
                       evidence=outcome.error or ev), ""
    if outcome.kind in ("", "none"):
        return Verdict(verified=False, reason="no_crash", evidence=ev), ""

    # Attribution is the innermost (crashing) frame, not any frame present. A harness cannot
    # borrow a real target frame that sits higher up the stack while its own frame is the one
    # that actually raised.
    attributed = innermost_is_target(outcome.frames, stems)

    if outcome.kind == "exception":
        hit = _VERIFIED_EXC.get(outcome.exc)
        if not hit:
            return Verdict(verified=False, reason=f"unconfirmed_exception:{outcome.exc}",
                           evidence=ev), ""
        if not attributed:
            return Verdict(verified=False, reason="crash_not_in_target", evidence=ev), ""
        return Verdict(verified=True, reason=hit[0], evidence=ev), hit[1]

    if outcome.kind == "signal":
        if not attributed:
            return Verdict(verified=False, reason="crash_not_in_target", evidence=ev), ""
        return Verdict(verified=True, reason="native_crash", evidence=ev), "CWE-787"

    if outcome.kind == "timeout":
        # A hang cannot be soundly attributed to the target rather than harness-driven
        # pressure (a benign linear target on an inflated input, or a loop around the call),
        # so a timeout is an unverified candidate, never a confirmed finding.
        return Verdict(verified=False, reason="unverified_hang_candidate", evidence=ev), ""

    return Verdict(verified=False, reason="no_crash", evidence=ev), ""


# -- reproducer source ------------------------------------------------------

def _build_reproducer(harness, mem_mb: int | None, timeout: int) -> str:
    imports = (getattr(harness, "imports", "") or "").strip() or "pass"
    body = (getattr(harness, "body", "") or "").strip() or "pass"
    # The body becomes the body of TestOneInput(data), compiled with the wrapper filename so
    # any frame it contributes is attributed to the wrapper, never the target.
    harness_src = "def TestOneInput(data):\n" + _indent(body)
    mem = int(mem_mb) if mem_mb else 0
    return _TEMPLATE.format(mem=mem, timeout=int(timeout),
                            imports_lit=repr(imports), harness_lit=repr(harness_src))


# The reproducer. Sabba source; the harness imports and body arrive as opaque string
# literals and run in a fresh namespace, never spliced into this module. It never trusts
# stdout/stderr (nulled) and writes its result only to the inherited pipe, tagged with a
# nonce the harness body cannot see.
_TEMPLATE = '''\
import os, sys, json, traceback, faulthandler, resource

# The private result channel and the per-run nonce arrive from the parent by environment.
# Read them once, then delete them from the environment. The harness body runs in a fresh
# namespace that contains neither _FD, _NONCE, _emit, nor os, so it cannot reach the channel
# or forge a message the parent will accept.
_FD = int(os.environ.pop("SABBA_FD"))
_NONCE = os.environ.pop("SABBA_NONCE")
_report = os.fdopen(_FD, "w", buffering=1)


def _emit(obj):
    obj["nonce"] = _NONCE
    data = (json.dumps(obj) + "\\n").encode()
    try:
        while data:
            n = os.write(_FD, data)
            data = data[n:]
    except Exception:
        pass


def _frames(tb):
    # Dedupe frames: a deep recursion repeats one frame thousands of times, which would
    # overflow the pipe. Attribution needs only distinct (file, name, line) frames, and the
    # order (outermost first, innermost last) is preserved by keeping the first occurrence.
    seen, out = set(), []
    for fr in traceback.extract_tb(tb):
        key = (fr.filename, fr.name, fr.lineno)
        if key in seen:
            continue
        seen.add(key)
        out.append({{"file": fr.filename, "name": fr.name, "line": fr.lineno}})
        if len(out) >= 200:
            break
    return out


_MEM_MB = {mem}
if _MEM_MB:
    try:
        _b = _MEM_MB * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (_b, _b))
    except Exception:
        pass

# A fatal signal (segfault, abort) dumps the real Python stack to the private channel.
try:
    faulthandler.enable(file=_report, all_threads=True)
except Exception:
    pass
# A hang past the deadline dumps the real stack to the private channel, then hard-exits.
try:
    faulthandler.dump_traceback_later({timeout}, exit=True, file=_report)
except Exception:
    pass

# The harness namespace: fresh, with no handle on the result channel, the nonce, the emit
# function, or this module. Seed only the fuzzer API. The target import runs here, so the
# bound target name lives in the body's own namespace, never as an attribute of this module.
_ns = {{"__builtins__": __builtins__}}
try:
    import atheris  # present during a real hunt; bodies may use FuzzedDataProvider
    _ns["atheris"] = atheris
except Exception:
    pass

# Null the harness stdout and stderr: anything it prints is gone.
_null = os.open(os.devnull, os.O_WRONLY)
os.dup2(_null, 1)
os.dup2(_null, 2)

try:
    exec(compile({imports_lit}, "sabba_harness.py", "exec"), _ns)
except BaseException as _e:
    _emit({{"channel": "sabba", "kind": "import_error", "exc": type(_e).__name__}})
    os._exit(3)

exec(compile({harness_lit}, "sabba_harness.py", "exec"), _ns)
_test = _ns["TestOneInput"]


def _main():
    with open(sys.argv[1], "rb") as _f:
        poc = _f.read()
    # The wrapper, not the body, emits the outcome, from its own scope after the body returns
    # or raises. The body has no way to emit on its own.
    try:
        _test(poc)
    except BaseException as e:
        _emit({{"channel": "sabba", "kind": "exception",
                "exc": type(e).__name__, "frames": _frames(e.__traceback__)}})
        return
    _emit({{"channel": "sabba", "kind": "none", "exc": "", "frames": []}})


_main()
'''


# -- parent-side parsing ----------------------------------------------------

def _outcome_from_report(raw: str, rc: int | None, hard_timeout: bool, nonce: str) -> Outcome:
    result = _last_sabba_json(raw, nonce)
    if result is not None:
        kind = result.get("kind", "")
        if kind == "exception":
            frames = [{"file": f.get("file", ""), "name": f.get("name", ""),
                       "line": f.get("line")} for f in result.get("frames", [])]
            return Outcome(kind="exception", exc=str(result.get("exc", "")),
                           frames=frames, raw=raw[-1600:])
        if kind == "import_error":
            return Outcome(kind="error", raw=raw[-1600:],
                           error="harness import failed: " + str(result.get("exc", "")))
        # kind == "none": the harness ran the target with no crash.
        return Outcome(kind="none", raw=raw[-1600:])

    # No structured result: the child died or dumped. Read the outcome from the parent's own
    # measurement plus the runtime's dump on the private channel.
    frames = _frames_from_dump(raw)
    if rc is not None and rc < 0:
        return Outcome(kind="signal", signal=-rc, frames=frames, raw=raw[-1600:])
    if hard_timeout or "Timeout (" in raw:
        return Outcome(kind="timeout", frames=frames, raw=raw[-1600:])
    # Exited without a result and without a dump: an infrastructure or harness failure.
    return Outcome(kind="error", raw=raw[-1600:],
                   error="reproducer produced no result on the private channel")


def _last_sabba_json(raw: str, nonce: str) -> dict | None:
    # Accept only a message carrying this run's nonce. The harness body never sees the nonce,
    # so a line it managed to place on the channel (it cannot, but defense in depth) is
    # ignored. Without a nonce match there is no structured result.
    for line in reversed((raw or "").splitlines()):
        s = line.strip()
        if not (s.startswith("{") and s.endswith("}")):
            continue
        try:
            d = json.loads(s)
        except Exception:  # noqa: BLE001
            continue
        if isinstance(d, dict) and d.get("channel") == "sabba" and d.get("nonce") == nonce:
            return d
    return None


def _frames_from_dump(raw: str) -> list[dict]:
    # Read only the running thread's stack. faulthandler labels it "Current thread" and dumps
    # it most-recent-call first; a parked background thread is not the crash. Take that block
    # alone and reverse it so frames come out innermost last, matching extract_tb order.
    text = raw or ""
    idx = text.find("Current thread")
    if idx >= 0:
        block = text[idx:]
        nxt = block.find("\nThread ", 1)
        if nxt >= 0:
            block = block[:nxt]
    else:
        block = text
    frames = []
    for m in _DUMP_FRAME.finditer(block):
        frames.append({"file": m.group(1), "line": int(m.group(2)),
                       "name": m.group(3) or ""})
    frames.reverse()
    return frames


def _reader(r_fd: int, sink: dict) -> None:
    chunks = []
    while True:
        try:
            b = os.read(r_fd, 65536)
        except OSError:
            break
        if not b:
            break
        chunks.append(b)
    sink["raw"] = b"".join(chunks)


def _stage_sources(target_dir: Path, work: Path) -> None:
    for py in target_dir.rglob("*.py"):
        rel = py.relative_to(target_dir)
        dst = work / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(py.read_text(errors="replace"))


def _indent(text: str, n: int = 4) -> str:
    pad = " " * n
    return "\n".join(pad + ln if ln.strip() else ln for ln in text.splitlines())
