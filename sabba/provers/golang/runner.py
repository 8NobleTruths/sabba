"""Two phases: discover a candidate PoC, then prove it with a Sabba-owned reproducer.

The old runner read the verdict from the fuzzer's mixed output and from the corpus files a
harness can write. That was forgeable. This one splits the work:

Discovery. The model's body goes inside a go test -fuzz harness (assemble). The fuzzer runs
it and, if it crashes, saves a minimized crashing input. From this phase we take exactly one
thing, the candidate PoC bytes. We take nothing from the fuzzer's stdout and we do not trust
its classification. A forged crash here only yields candidate bytes, which the next phase
re-runs and rejects if the target does not actually crash.

Verification. Sabba builds a reproducer it owns, a standalone Go program (not go test), and
runs the candidate bytes through it. The model's body lives in a file that imports only the
target, so it cannot reach os, fmt, or runtime. The reproducer nulls the Go-level stdout and
stderr, reads the PoC from a Sabba-chosen path, and wraps the body call in a deferred recover
that captures runtime.Stack and writes it to fd 3, a channel the body cannot write (it is
gated against file and fd writes, and it cannot call recover so its panic reaches the
wrapper). A fatal crash the runtime cannot recover (stack overflow, out of memory) is dumped
by the Go runtime to the real fd 2, which the parent captures; the body's own output never
reaches fd 2 because the Go stderr variable is nulled. For a hang the parent sends SIGQUIT
after a wall deadline, which makes the runtime dump every goroutine stack to fd 2. The
outcome, its kind and its structured frames, comes only from these channels.

The go toolchain is only needed to run, never to import this module, so a box without go can
still load the prover and report it missing.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path

# The discovery wrapper package name. It lives in its own subdirectory of the staged module
# so it never collides with the target's package, and it imports the target by module path.
FUZZ_PKG = "sabbafuzz"
FUZZ_FUNC = "FuzzTarget"

# The reproducer package name and its two files. The body file imports only the target, so
# the model body cannot see os, fmt, or runtime (Go imports are per file). The main file
# owns the recover, the fd-3 channel, and the stdout/stderr nulling.
REPRO_PKG = "sabbarepro"
REPRO_BODY = "zz_sabba_body.go"
REPRO_MAIN = "zz_sabba_main.go"


@dataclass
class GoHarness:
    import_line: str      # what goes inside the import block, e.g. vuln "goobtarget"
    body: str             # the body that turns bytes into a call; data is the []byte input
    entry: str = ""       # a short note on what is fuzzed


@dataclass
class Discovery:
    """What the discovery phase produced. Only poc is load bearing; the rest is evidence."""
    poc: bytes | None = None      # the candidate crashing input, or None if none was found
    kind: str = "none"            # "candidate" | "build_error" | "none"
    output: str = ""              # trimmed fuzzer output, for a build error or debugging
    poc_name: str = ""            # the corpus file name, when one was saved


@dataclass
class Outcome:
    """What the reproducer observed. kind and frames come only from unforgeable channels."""
    channel: str = "none"         # recover | fatal | timeout | oom | none | build_error | unavailable
    panic_value: str = ""         # the recovered panic value (recover channel)
    frames: str = ""              # the structured stack: fd 3 for recover, the fd 2 dump otherwise
    output: str = ""              # trimmed evidence
    poc: bytes = b""
    poc_name: str = ""


def go_path() -> str | None:
    return shutil.which("go")


def go_available() -> bool:
    return go_path() is not None


# -- discovery -------------------------------------------------------------

def assemble(h: GoHarness, seeds: list[bytes] | None = None) -> str:
    """Wrap the model's import and body in the FuzzTarget the fuzzer plugs into."""
    imp = (h.import_line or "").strip()
    body = _indent(h.body.strip() or "_ = data", 2)
    adds = "".join(f"\tf.Add({_go_bytes(s)})\n" for s in (seeds or []))
    return (
        f"package {FUZZ_PKG}\n\n"
        "import (\n"
        "\t\"testing\"\n"
        f"\t{imp}\n"
        ")\n\n"
        f"func {FUZZ_FUNC}(f *testing.F) {{\n"
        f"{adds}"
        "\tf.Fuzz(func(t *testing.T, data []byte) {\n"
        "\t\t_ = t\n"
        f"{body}\n"
        "\t})\n"
        "}\n"
    )


def discover_poc(target_dir, harness: GoHarness, *, secs: int = 20,
                 per_input_timeout: int = 10, go_exe: str | None = None,
                 seed: bytes | None = None) -> Discovery:
    """Fuzz the target and return only the candidate PoC bytes.

    A saved corpus entry is the candidate. When a seed was planted (a known input, used to
    make a fixture reproduce quickly) it is a trustworthy candidate on its own, since the
    reproducer decides the truth regardless of where the bytes came from. Nothing here is
    trusted to classify a crash.
    """
    go_exe = go_exe or go_path()
    if not go_exe:
        return Discovery(kind="none", output="go toolchain not found")
    target_dir = Path(target_dir)
    work = Path(tempfile.mkdtemp(prefix="sabba-gofuzz-"))
    fuzz_dir = work / FUZZ_PKG
    corpus_dir = fuzz_dir / "testdata" / "fuzz" / FUZZ_FUNC
    try:
        _stage_module(target_dir, work)
        fuzz_dir.mkdir(parents=True, exist_ok=True)
        (fuzz_dir / "fuzz_test.go").write_text(
            assemble(harness, seeds=[seed] if seed is not None else None))
        env = _go_env(work)
        cmd = [go_exe, "test", "-run=^$", f"-fuzz=^{FUZZ_FUNC}$",
               f"-fuzztime={secs}s", f"-timeout={secs + per_input_timeout + 30}s"]
        try:
            proc = subprocess.run(cmd, cwd=str(fuzz_dir), capture_output=True, text=True,
                                  env=env, timeout=secs + per_input_timeout + 120)
            out = (proc.stdout or "") + (proc.stderr or "")
        except subprocess.TimeoutExpired as e:
            out = _decode(e.stdout) + _decode(e.stderr)

        if _looks_like_build_error(out):
            return Discovery(kind="build_error", output=out[-1500:])

        crash_file = _first_corpus(corpus_dir)
        if crash_file is not None:
            return Discovery(poc=_read(crash_file), kind="candidate",
                             output=out[-800:], poc_name=crash_file.name)
        if seed is not None:
            # a planted, Sabba-owned input. The reproducer, not the fuzzer, decides the truth.
            return Discovery(poc=seed, kind="candidate", output=out[-800:], poc_name="seed")
        return Discovery(kind="none", output=out[-800:])
    finally:
        shutil.rmtree(work, ignore_errors=True)


# -- verification: the Sabba-owned reproducer ------------------------------

def verify_poc(target_dir, harness: GoHarness, poc: bytes, *, wall: int = 10,
               go_exe: str | None = None) -> Outcome:
    """Build the reproducer, run the PoC through it, and report the unforgeable outcome."""
    go_exe = go_exe or go_path()
    if not go_exe:
        return Outcome(channel="unavailable", output="go toolchain not found")
    target_dir = Path(target_dir)
    work = Path(tempfile.mkdtemp(prefix="sabba-gorepro-"))
    repro_dir = work / REPRO_PKG
    try:
        _stage_module(target_dir, work)
        repro_dir.mkdir(parents=True, exist_ok=True)
        (repro_dir / REPRO_BODY).write_text(_repro_body(harness))
        (repro_dir / REPRO_MAIN).write_text(_REPRO_MAIN_SRC)
        env = _go_env(work)
        binary = work / "sabba-repro-bin"
        build = subprocess.run(
            [go_exe, "build", "-o", str(binary), f"./{REPRO_PKG}"],
            cwd=str(work), capture_output=True, text=True, env=env,
            timeout=180)
        if build.returncode != 0:
            return Outcome(channel="build_error", poc=poc,
                           output=((build.stdout or "") + (build.stderr or ""))[-1500:])
        try:
            binary.chmod(0o755)   # some umasks drop the exec bit go build would set
        except OSError:
            pass
        poc_file = work / "sabba-poc.bin"
        poc_file.write_bytes(poc)
        return _run_reproducer(str(binary), env, str(poc_file), wall, poc)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _run_reproducer(binary: str, env: dict, poc_path: str, wall: int, poc: bytes) -> Outcome:
    """Run the reproducer binary. Read the recover channel on the private report pipe and the
    runtime dump on the real fd 2; on a wall-clock overrun send SIGQUIT so the runtime dumps
    every goroutine. The parent drains the report pipe and fd 2 on threads so a large dump can
    never deadlock.
    """
    r, w = os.pipe()
    run_env = dict(env)
    run_env["SABBA_POC"] = poc_path
    # Report over a private pipe. Pass the write end by its real number and tell the child
    # which fd to use, rather than dup2-ing to a fixed 3 in a preexec hook, because close_fds
    # runs after preexec and would close a hand-placed fd 3. pass_fds keeps this one open.
    run_env["SABBA_REPORT_FD"] = str(w)

    proc = subprocess.Popen([binary], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                            pass_fds=(w,), env=run_env)
    os.close(w)

    fd3_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []

    def _drain(fileobj, sink):
        try:
            while True:
                b = fileobj.read(65536) if hasattr(fileobj, "read") else os.read(fileobj, 65536)
                if not b:
                    break
                sink.append(b)
        except OSError:
            pass

    t3 = threading.Thread(target=_drain, args=(r, fd3_chunks), daemon=True)
    t2 = threading.Thread(target=_drain, args=(proc.stderr, stderr_chunks), daemon=True)
    t3.start()
    t2.start()

    timed_out = False
    try:
        proc.wait(timeout=wall)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            proc.send_signal(signal.SIGQUIT)   # Go dumps every goroutine stack to fd 2
        except OSError:
            pass
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    t3.join(timeout=2)
    t2.join(timeout=2)
    try:
        os.close(r)
    except OSError:
        pass

    fd3 = b"".join(fd3_chunks).decode(errors="replace")
    fd2 = b"".join(stderr_chunks).decode(errors="replace")
    return _outcome(timed_out, fd3, fd2, proc.returncode, poc)


def _outcome(timed_out: bool, fd3: str, fd2: str, rc: int | None, poc: bytes) -> Outcome:
    if timed_out:
        # The parent's own wall clock decided this is a hang. Attribution comes from the
        # runtime's SIGQUIT goroutine dump, not from anything the harness printed.
        return Outcome(channel="timeout", frames=fd2, output=fd2[-1800:], poc=poc)
    value, stack = _parse_fd3(fd3)
    if stack:
        # A recovered panic wrote the real runtime.Stack to the report channel and exited 97.
        return Outcome(channel="recover", panic_value=value, frames=stack,
                       output=stack[-1800:], poc=poc)
    # The fatal channel is the runtime's own dump on the real fd 2. Only trust it when the
    # process actually died abnormally, so a target that merely prints a fake dump and returns
    # cleanly is not read as a crash. A clean exit (0) is never a fatal crash.
    if rc not in (0, None) and _has_fatal_dump(fd2):
        return Outcome(channel="fatal", frames=fd2, output=fd2[-1800:], poc=poc)
    return Outcome(channel="none", output=fd2[-800:], poc=poc)


def _parse_fd3(fd3: str) -> tuple[str, str]:
    fd3 = (fd3 or "").strip()
    if not fd3:
        return "", ""
    import json
    try:
        d = json.loads(fd3)
        return str(d.get("value", "")), str(d.get("stack", ""))
    except Exception:
        return "", ""


def _has_fatal_dump(out: str) -> bool:
    return any(t in out for t in (
        "fatal error:", "panic:", "goroutine stack exceeds", "runtime: out of memory",
        "SIGSEGV", "signal SIGSEGV", "runtime error:"))


# The reproducer main. It is Sabba source, never the model's. It imports os, runtime, fmt and
# encoding/json; because Go imports are per file, the model body (in the body file) cannot see
# any of them. It nulls the Go stdout and stderr variables, reads the PoC from a Sabba path,
# and on a recovered panic writes the panic value and the real runtime.Stack to fd 3.
_REPRO_MAIN_SRC = """package main

import (
\t"encoding/json"
\t"fmt"
\t"os"
\t"runtime"
\t"strconv"
)

func main() {
\treportFD := uintptr(3)
\tif v, err := strconv.Atoi(os.Getenv("SABBA_REPORT_FD")); err == nil {
\t\treportFD = uintptr(v)
\t}
\trep := os.NewFile(reportFD, "sabba-report")
\tif dn, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0); err == nil {
\t\tos.Stdout = dn
\t\tos.Stderr = dn
\t}
\tdata, _ := os.ReadFile(os.Getenv("SABBA_POC"))
\tdefer func() {
\t\tif rec := recover(); rec != nil {
\t\t\tbuf := make([]byte, 1<<20)
\t\t\tn := runtime.Stack(buf, false)
\t\t\tif rep != nil {
\t\t\t\tb, _ := json.Marshal(map[string]string{
\t\t\t\t\t"value": fmt.Sprintf("%v", rec),
\t\t\t\t\t"stack": string(buf[:n]),
\t\t\t\t})
\t\t\t\trep.Write(b)
\t\t\t\trep.Close()
\t\t\t}
\t\t\tos.Exit(97)
\t\t}
\t}()
\tsabbaRunBody(data)
}
"""


def _repro_body(h: GoHarness) -> str:
    """The body file: package main, import only the target, sabbaRunBody carries the model
    body. Because this file imports nothing but the target, the body cannot name os, fmt, or
    runtime even if the gate missed it, and referencing them fails the build."""
    imp = (h.import_line or "").strip()
    body = _indent(h.body.strip() or "_ = data", 1)
    return (
        "package main\n\n"
        f"import {imp}\n\n"
        "func sabbaRunBody(data []byte) {\n"
        f"{body}\n"
        "}\n"
    )


# -- staging and helpers ---------------------------------------------------

def _stage_module(target_dir: Path, work: Path) -> None:
    """Copy the target's .go sources and its go.mod into the throwaway module."""
    for src in target_dir.rglob("*.go"):
        if src.name.endswith("_test.go"):
            continue
        rel = src.relative_to(target_dir)
        dst = work / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(src.read_text(errors="replace"))
    gomod = target_dir / "go.mod"
    if gomod.exists():
        (work / "go.mod").write_text(gomod.read_text(errors="replace"))


def module_path(target_dir: Path) -> str:
    """The module path declared in go.mod, or empty if none. Used by the import gate."""
    gomod = Path(target_dir) / "go.mod"
    if not gomod.exists():
        return ""
    for line in gomod.read_text(errors="replace").splitlines():
        line = line.strip()
        if line.startswith("module "):
            return line[len("module "):].strip()
    return ""


def _go_env(work: Path) -> dict:
    env = os.environ.copy()
    env["GOPROXY"] = "off"
    env["GOFLAGS"] = "-mod=mod"
    env["GOTOOLCHAIN"] = "local"
    env["GOCACHE"] = str(work / ".gocache")
    env.setdefault("GOPATH", str(work / ".gopath"))
    return env


def _first_corpus(corpus_dir: Path) -> Path | None:
    if not corpus_dir.is_dir():
        return None
    for p in sorted(corpus_dir.iterdir()):
        if p.is_file():
            return p
    return None


def _looks_like_build_error(out: str) -> bool:
    return any(t in out for t in ("build failed", "cannot find package", "undefined:",
                                  "syntax error", "expected declaration", "is not in std",
                                  "no required module provides package"))


def _read(path: Path) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError:
        return b""


def _decode(s) -> str:
    if s is None:
        return ""
    return s if isinstance(s, str) else s.decode(errors="replace")


def _go_bytes(b: bytes) -> str:
    return "[]byte{" + ", ".join(str(x) for x in b) + "}"


def _indent(text: str, tabs: int = 1) -> str:
    pad = "\t" * tabs
    return "\n".join(pad + ln if ln.strip() else ln for ln in text.splitlines())
