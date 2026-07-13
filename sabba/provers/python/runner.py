"""Run a model-written Atheris harness and report the first crash it triggers.

The fuzzing loop is Sabba's, not the model's. The model supplies only the import of the
target and the body that turns fuzz bytes into a call. Sabba wraps that in the atheris
Setup and Fuzz boilerplate, runs it under resource limits, and reproduces any crash on the
saved input. Whether that crash is a real finding is decided in classify.py, not here.

Atheris is only needed to run a fuzz, never to import this module, so a box without atheris
can still load the prover and report it missing.
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .classify import CrashInfo, parse_exception

MAX_LEN = 8192
RSS_LIMIT_MB = 2048


@dataclass
class PyHarness:
    imports: str          # module-level imports of the target, run under instrumentation
    body: str             # the body of TestOneInput(data)
    entry: str = ""       # a short note on what is fuzzed


def atheris_available() -> bool:
    return importlib.util.find_spec("atheris") is not None


def assemble(h: PyHarness) -> str:
    imports = _indent(h.imports.strip() or "pass")
    body = _indent(h.body.strip() or "pass")
    return (
        "import atheris\n"
        "import sys\n"
        "with atheris.instrument_imports():\n"
        f"{imports}\n\n"
        "def TestOneInput(data):\n"
        f"{body}\n\n"
        "atheris.Setup(sys.argv, TestOneInput)\n"
        "atheris.Fuzz()\n"
    )


def run_fuzz(target_dir, harness: PyHarness, *, secs: int = 30,
             per_input_timeout: int = 10, python_exe: str | None = None,
             workdir: Path | None = None, seed: bytes | None = None) -> CrashInfo:
    """Fuzz the target with the harness for secs. Return the crash, or kind='none'.

    seed, when given, is written to a starting corpus so libFuzzer runs it first. Real hunts
    do not seed; it is here to make a known crash reproduce quickly and deterministically.
    """
    python_exe = python_exe or sys.executable
    target_dir = Path(target_dir)
    own_work = workdir is None
    work = Path(workdir or tempfile.mkdtemp(prefix="sabba-pyfuzz-"))
    try:
        _stage_sources(target_dir, work)
        (work / "harness.py").write_text(assemble(harness))
        cmd = [python_exe, "harness.py",
               f"-max_total_time={secs}", f"-timeout={per_input_timeout}",
               f"-rss_limit_mb={RSS_LIMIT_MB}", f"-max_len={MAX_LEN}", "-print_final_stats=0"]
        if seed is not None:
            corpus = work / "corpus"
            corpus.mkdir(exist_ok=True)
            (corpus / "seed0").write_bytes(seed)
            cmd.append("corpus")
        try:
            proc = subprocess.run(cmd, cwd=str(work), capture_output=True, text=True,
                                  timeout=secs + 90)
            out = (proc.stdout or "") + (proc.stderr or "")
        except subprocess.TimeoutExpired as e:
            out = _decode(e.stdout) + _decode(e.stderr)

        timeout_f = _first(work, "timeout-")
        oom_f = _first(work, "oom-")
        crash_f = _first(work, "crash-")
        if timeout_f:
            return CrashInfo(kind="timeout", output=out, poc_path=timeout_f,
                             poc_bytes=_read(timeout_f))
        if oom_f:
            return CrashInfo(kind="oom", output=out, poc_path=oom_f, poc_bytes=_read(oom_f))
        if crash_f:
            return _reproduce(python_exe, work, crash_f, per_input_timeout)
        if "out-of-memory" in out.lower():
            return CrashInfo(kind="oom", output=out)
        return CrashInfo(kind="none", output=out)
    finally:
        if own_work:
            shutil.rmtree(work, ignore_errors=True)


def _reproduce(python_exe: str, work: Path, crash_file: str,
               per_input_timeout: int) -> CrashInfo:
    poc = _read(crash_file)
    try:
        p = subprocess.run([python_exe, "harness.py", os.path.basename(crash_file)],
                           cwd=str(work), capture_output=True, text=True,
                           timeout=per_input_timeout + 10)
        out = (p.stdout or "") + (p.stderr or "")
        if p.returncode is not None and p.returncode < 0:
            return CrashInfo(kind="signal", signal=-p.returncode, output=out,
                             poc_path=crash_file, poc_bytes=poc)
        return CrashInfo(kind="exception", exception=parse_exception(out), output=out,
                         poc_path=crash_file, poc_bytes=poc)
    except subprocess.TimeoutExpired:
        return CrashInfo(kind="timeout", output="the saved input hung on replay",
                         poc_path=crash_file, poc_bytes=poc)


def _stage_sources(target_dir: Path, work: Path) -> None:
    for py in target_dir.rglob("*.py"):
        rel = py.relative_to(target_dir)
        dst = work / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(py.read_text(errors="replace"))


def _first(work: Path, prefix: str) -> str:
    for p in sorted(work.glob(prefix + "*")):
        return str(p)
    return ""


def _read(path: str) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError:
        return b""


def _decode(s) -> str:
    if s is None:
        return ""
    return s if isinstance(s, str) else s.decode(errors="replace")


def _indent(text: str, n: int = 4) -> str:
    pad = " " * n
    return "\n".join(pad + ln if ln.strip() else ln for ln in text.splitlines())
