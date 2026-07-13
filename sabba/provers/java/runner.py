"""Two phases: Jazzer discovers a candidate PoC, a Sabba reproducer proves it.

Discovery (discover_poc) runs the model's harness under Jazzer only to find an input that
makes it crash. From that phase we take exactly one thing, the candidate PoC bytes. We take
nothing from Jazzer's stdout, and the only reason we read a crash-, oom-, or timeout- artifact
is to recover those bytes; a forged artifact just hands us candidate input the next phase
rejects.

Verification (verify_poc) re-runs the PoC through a reproducer Sabba owns and the harness
cannot control. The reproducer (SabbaReproducer, source below, generated at run time and never
the model's) nulls System.out and System.err before it ever calls the harness, runs in a
scratch directory, and reports the outcome over channels the harness cannot forge:

  - a caught Throwable's own class and its real StackTraceElement frames, written as JSON to a
    parent-held anonymous pipe (never a file in the harness cwd) and stamped with a random
    per-run nonce the parent hands only to the reproducer wrapper. The body runs inside
    Harness.fuzzerTestOneInput and never sees the nonce, the pipe fd, or the emit path, and the
    gate blocks it from reaching a file, a stream, an fd, or the process environment; a message
    it forges to the pipe lacks the nonce and the parent drops it,
  - for a hang, the JVM's own thread dump: the parent measures the wall clock, sends SIGQUIT,
    and reads the dump the runtime writes to the real stdout (System.setOut cannot suppress it).
    The parent reads only that dump, never the pipe, on a timeout, and attributes only within
    the thread that ran fuzzerTestOneInput, not a parked background thread,
  - for a fatal JNI signal, the parent observes the signal and reads the crash dump.

The JVM toolchain is only needed to run, never to import this module, so a box without it can
still load the prover and report it missing. Discovery needs javac plus the Jazzer launcher.
Verification needs only javac plus java, so a genuine StackOverflowError, OutOfMemoryError, or
hang reproduces without Jazzer at all.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path

from .classify import Frame, Outcome

RSS_LIMIT_MB = 2048
HARNESS_CLASS = "Harness"
REPRODUCER_CLASS = "SabbaReproducer"
# heap ceiling for verification: a genuine target allocation blowup raises a catchable
# OutOfMemoryError under this limit, which the reproducer reports with real frames.
VERIFY_XMX_MB = 512


@dataclass
class JavaHarness:
    body: str             # the body of fuzzerTestOneInput(byte[] data)
    entry: str = ""       # a short note on what is fuzzed
    imports: str = ""     # optional import lines, gated to import-only of allowed packages


@dataclass
class JazzerTools:
    launcher: str                       # path to the jazzer launcher binary
    jars: list[str] = field(default_factory=list)   # jars to add to the classpath


def javac_available() -> bool:
    return shutil.which("javac") is not None


def java_available() -> bool:
    return shutil.which("java") is not None


def jazzer_home() -> Path | None:
    env = os.environ.get("SABBA_JAZZER_HOME", "").strip()
    if env and Path(env).is_dir():
        return Path(env)
    home = Path.home() / "jazzer"
    if home.is_dir():
        return home
    return None


def find_jazzer() -> JazzerTools | None:
    """Locate the Jazzer launcher and its jars, or None. Never raises."""
    home = jazzer_home()
    if home is not None:
        launcher = home / "jazzer"
        if launcher.exists():
            return JazzerTools(launcher=str(launcher),
                               jars=sorted(str(p) for p in home.glob("*.jar")))
    which = shutil.which("jazzer")
    if which:
        near = Path(which).resolve().parent
        return JazzerTools(launcher=which, jars=sorted(str(p) for p in near.glob("*.jar")))
    return None


def jazzer_available() -> bool:
    return find_jazzer() is not None


def toolchain_available() -> bool:
    """Discovery needs javac plus the Jazzer launcher."""
    return javac_available() and jazzer_available()


def verify_available() -> bool:
    """Verification needs only javac plus java, no Jazzer."""
    return javac_available() and java_available()


def _jazzer_jars() -> list[str]:
    tools = find_jazzer()
    return tools.jars if tools else []


def assemble(h: JavaHarness) -> str:
    """Wrap the model's body (and its gated imports) in the Sabba-owned Harness class."""
    imports = (h.imports or "").strip()
    prefix = imports + "\n\n" if imports else ""
    body = _indent(h.body.strip() or "// no body")
    return (
        f"{prefix}"
        "public class Harness {\n"
        "    public static void fuzzerTestOneInput(byte[] data) {\n"
        f"{body}\n"
        "    }\n"
        "}\n"
    )


# ---- phase 1: discovery (Jazzer finds candidate PoC bytes) -----------------

def discover_poc(target_dir, harness: JavaHarness, *, secs: int = 30,
                 per_input_timeout: int = 25, workdir: Path | None = None,
                 seed: bytes | None = None) -> bytes | None:
    """Fuzz the harness under Jazzer and return the candidate PoC bytes, or None.

    We ignore Jazzer's verdict entirely. We read the crash-, oom-, or timeout- artifact only to
    recover the bytes; verification decides whether they crash the target. seed, when given, is
    run first so a known crash reproduces quickly; real hunts do not seed.
    """
    tools = find_jazzer()
    javac = shutil.which("javac")
    if javac is None or tools is None:
        return None

    target_dir = Path(target_dir)
    own_work = workdir is None
    work = Path(workdir or tempfile.mkdtemp(prefix="sabba-javafuzz-"))
    try:
        srcs = _stage_sources(target_dir, work)
        (work / "Harness.java").write_text(assemble(harness))
        srcs.append(work / "Harness.java")

        classes = work / "classes"
        classes.mkdir(exist_ok=True)
        cp = os.pathsep.join(tools.jars)
        jcmd = [javac, "-d", str(classes)]
        if cp:
            jcmd += ["-cp", cp]
        jcmd += [str(p) for p in srcs]
        cproc = subprocess.run(jcmd, cwd=str(work), capture_output=True, text=True, timeout=180)
        if cproc.returncode != 0:
            return None  # a build failure is surfaced by verify_poc, not here

        run_cp = os.pathsep.join([str(classes)] + tools.jars)
        cmd = [tools.launcher, f"--cp={run_cp}", f"--target_class={HARNESS_CLASS}",
               f"-max_total_time={secs}", f"-timeout={per_input_timeout}",
               f"-rss_limit_mb={RSS_LIMIT_MB}", "-print_final_stats=0"]
        if seed is not None:
            corpus = work / "corpus"
            corpus.mkdir(exist_ok=True)
            (corpus / "seed0").write_bytes(seed)
            cmd.append("corpus")
        try:
            subprocess.run(cmd, cwd=str(work), capture_output=True, text=True,
                           timeout=secs + 120)
        except subprocess.TimeoutExpired:
            pass

        for prefix in ("crash-", "oom-", "timeout-"):
            art = _first(work, prefix)
            if art:
                data = _read(art)
                if data:
                    return data
        return None
    finally:
        if own_work:
            shutil.rmtree(work, ignore_errors=True)


# ---- phase 2: verification (Sabba reproducer re-runs the PoC) --------------

def verify_poc(target_dir, harness: JavaHarness, poc_bytes: bytes, *, wall: int = 20,
               xmx_mb: int = VERIFY_XMX_MB) -> Outcome:
    """Re-run poc_bytes through the Sabba reproducer and return the structured Outcome.

    The reproducer nulls the harness output, calls Harness.fuzzerTestOneInput(poc) in a
    try/catch(Throwable), and reports the class and real frames over a parent-held pipe, stamped
    with a per-run nonce. A hang is measured by this parent (wall clock) and read from the JVM's
    SIGQUIT thread dump. A fatal JNI signal is observed by this parent and read from the JVM
    crash dump.
    """
    javac = shutil.which("javac")
    java = shutil.which("java")
    if javac is None or java is None:
        return Outcome(kind="error", raw="javac or java not found", poc_bytes=poc_bytes)

    work = Path(tempfile.mkdtemp(prefix="sabba-javaverify-"))
    try:
        rc0, err, classes = _compile(target_dir, harness, work, javac)
        if rc0 != 0:
            return Outcome(kind="build_error", raw=err[-1600:], poc_bytes=poc_bytes)

        poc_file = work / "poc.bin"
        poc_file.write_bytes(poc_bytes or b"")
        nonce = secrets.token_hex(16)

        run_cp = os.pathsep.join([str(classes)] + _jazzer_jars())
        cmd = [java, f"-Xmx{xmx_mb}m", "-XX:-OmitStackTraceInFastThrow",
               "-cp", run_cp, REPRODUCER_CLASS, str(poc_file)]

        fd_text, dump_text, rc, timed_out = _run_reproducer(cmd, work, wall, nonce)
        return _decide_outcome(timed_out, rc, fd_text, dump_text, nonce, poc_bytes)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _decide_outcome(timed_out: bool, rc: int | None, fd_text: str, dump_text: str,
                    nonce: str, poc_bytes: bytes) -> Outcome:
    """Turn the raw channels into an Outcome, in the order soundness demands.

    Timeout is decided first and reads only the JVM's own thread dump, never the pipe: a body
    that hangs after writing a forged message to the pipe must not be believed. A structured
    Throwable is accepted only from a pipe message carrying the matching nonce, so a message the
    body writes to the inherited fd (it never learns the nonce) is ignored. A fatal signal reads
    the crash dump. Everything else is no crash.
    """
    if timed_out:
        return Outcome(kind="timeout", raw=dump_text[-4000:],
                       frames=_running_thread_frames(dump_text), poc_bytes=poc_bytes)
    msg = _authenticated_message(fd_text, nonce)
    if msg is not None:
        return _outcome_from_json(msg, poc_bytes)
    if rc is not None and rc < 0:
        sig = -rc
        kind = "oom_kill" if sig == signal.SIGKILL else "signal"
        return Outcome(kind=kind, signal=sig, raw=dump_text[-4000:],
                       frames=_running_thread_frames(dump_text), poc_bytes=poc_bytes)
    # exited without an authenticated Throwable and without being killed: the PoC did not crash
    return Outcome(kind="none", raw=dump_text[-1600:], poc_bytes=poc_bytes)


def _authenticated_message(fd_text: str, nonce: str) -> str | None:
    """Return the last pipe line that is JSON carrying the matching nonce, or None.

    The reproducer wrapper frames its message with newlines and stamps it with the nonce the
    parent gave it. The body never sees the nonce, so any bytes it writes to the inherited fd
    parse to a line without the nonce and are dropped here. An empty nonce accepts nothing.
    """
    if not nonce:
        return None
    best: str | None = None
    for line in (fd_text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        if isinstance(d, dict) and d.get("nonce") == nonce:
            best = line
    return best


def _run_reproducer(cmd, work: Path, wall: int,
                    nonce: str) -> tuple[str, str, int | None, bool]:
    """Run the reproducer, returning (pipe_text, dump_text, returncode, timed_out).

    The result comes over an anonymous pipe the parent opens: the child inherits only the write
    end (kept by pass_fds), and learns its fd number and the run nonce from its environment,
    which the body is gated from reading. We never hand the child a file in its cwd, so it cannot
    write the parent's result channel, and a nonce it never sees means a message it forges to the
    pipe is not accepted. The parent drains the pipe on a thread so a large report can never
    deadlock against the stdout capture.

    stdout and stderr are captured for the JVM's own dump. On a wall-clock overrun we send
    SIGQUIT so the JVM dumps every thread stack to its real stdout, wait briefly to capture it,
    then kill. System.setOut in the reproducer cannot hide that dump, so the captured output
    holds the runtime's own frames and nothing the harness printed (it printed to the nulled
    stream, before we ever signalled).
    """
    r, w = os.pipe()
    env = dict(os.environ)
    env["SABBA_REPORT_FD"] = str(w)
    env["SABBA_NONCE"] = nonce
    proc = subprocess.Popen(cmd, cwd=str(work), stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, pass_fds=(w,), env=env)
    os.close(w)

    fd_chunks: list[bytes] = []

    def _drain() -> None:
        try:
            while True:
                b = os.read(r, 65536)
                if not b:
                    break
                fd_chunks.append(b)
        except OSError:
            pass

    t = threading.Thread(target=_drain, daemon=True)
    t.start()

    dump, timed_out = "", False
    try:
        dump, _ = proc.communicate(timeout=wall)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            proc.send_signal(signal.SIGQUIT)
        except ProcessLookupError:
            pass
        try:
            dump, _ = proc.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            proc.kill()
            dump, _ = proc.communicate()

    t.join(timeout=2)
    try:
        os.close(r)
    except OSError:
        pass
    fd_text = b"".join(fd_chunks).decode("utf-8", "replace")
    return fd_text, dump or "", proc.returncode, timed_out


def _compile(target_dir, harness: JavaHarness, work: Path,
             javac: str) -> tuple[int, str, Path]:
    """Stage sources plus the harness plus the reproducer and compile them. Return (rc, err, classes)."""
    srcs = _stage_sources(target_dir, work)
    (work / "Harness.java").write_text(assemble(harness))
    srcs.append(work / "Harness.java")
    (work / f"{REPRODUCER_CLASS}.java").write_text(_REPRODUCER_SRC)
    srcs.append(work / f"{REPRODUCER_CLASS}.java")

    classes = work / "classes"
    classes.mkdir(exist_ok=True)
    jcmd = [javac, "-d", str(classes)]
    jars = _jazzer_jars()
    if jars:
        jcmd += ["-cp", os.pathsep.join(jars)]
    jcmd += [str(p) for p in srcs]
    cproc = subprocess.run(jcmd, cwd=str(work), capture_output=True, text=True, timeout=180)
    return cproc.returncode, (cproc.stdout or "") + (cproc.stderr or ""), classes


def _outcome_from_json(raw: str, poc_bytes: bytes) -> Outcome:
    try:
        d = json.loads(raw)
    except Exception:
        return Outcome(kind="error", raw=raw[-1600:], poc_bytes=poc_bytes)
    kind = d.get("kind", "none")
    if kind != "throwable":
        return Outcome(kind="none", poc_bytes=poc_bytes)
    frames = [Frame(cls=str(f.get("cls", "")), method=str(f.get("method", "")),
                    file=str(f.get("file", "")), line=int(f.get("line", -1)))
              for f in d.get("frames", [])]
    return Outcome(kind="throwable", exc_class=str(d.get("class", "")),
                   message=str(d.get("message", "")), frames=frames, poc_bytes=poc_bytes)


# a real JVM stack-dump frame, as written by a SIGQUIT thread dump ("\tat Vuln.deep(Vuln.java:9)")
# or an hs_err java frame. We read the file name and line the runtime itself printed.
_DUMP_FRAME_RE = re.compile(r"at\s+([\w.$]+)\.([\w$<>]+)\(([\w$]+\.java):(\d+)\)")


def _frames_from_dump(dump: str) -> list[Frame]:
    frames: list[Frame] = []
    for m in _DUMP_FRAME_RE.finditer(dump or ""):
        frames.append(Frame(cls=m.group(1), method=m.group(2),
                            file=m.group(3), line=int(m.group(4))))
    return frames


def _thread_blocks(dump: str) -> list[str]:
    """Split a JVM thread dump into per-thread blocks.

    A HotSpot SIGQUIT dump lists every thread, each block starting with a quoted thread name
    ("main" #1 ...) followed by its `\tat ...` frames. We split on the quoted-name lines so we
    can look at one thread's stack in isolation, never mixing a parked background thread's frames
    into the thread that actually ran the harness.
    """
    blocks: list[str] = []
    cur: list[str] = []
    for line in (dump or "").splitlines():
        if line[:1] == '"':
            if cur:
                blocks.append("\n".join(cur))
            cur = [line]
        else:
            cur.append(line)
    if cur:
        blocks.append("\n".join(cur))
    return blocks


def _running_thread_frames(dump: str) -> list[Frame]:
    """Frames of the one thread that ran the harness, innermost first, from the JVM's own dump.

    On a timeout or a fatal signal we attribute only within the thread whose stack holds
    Harness.fuzzerTestOneInput, the thread that ran the body. A frame a parked GC, finalizer, or
    compiler thread happens to show, or one a background thread the harness spawned parks on, is
    not the running stack and must not be read as the crash site. If no block owns the harness
    frame we return nothing, so attribution fails closed rather than guessing.
    """
    for blk in _thread_blocks(dump):
        if "Harness.fuzzerTestOneInput" in blk:
            return _frames_from_dump(blk)
    return []


def _stage_sources(target_dir: Path, work: Path) -> list[Path]:
    target_dir = Path(target_dir)
    staged: list[Path] = []
    for src in target_dir.rglob("*.java"):
        if src.name in ("Harness.java", f"{REPRODUCER_CLASS}.java"):
            continue
        rel = src.relative_to(target_dir)
        dst = work / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(src.read_text(errors="replace"))
        staged.append(dst)
    return staged


def _first(work: Path, prefix: str) -> str:
    for p in sorted(work.glob(prefix + "*")):
        return str(p)
    return ""


def _read(path: str) -> bytes:
    if not path:
        return b""
    try:
        return Path(path).read_bytes()
    except OSError:
        return b""


def _indent(text: str, n: int = 8) -> str:
    pad = " " * n
    return "\n".join(pad + ln if ln.strip() else ln for ln in text.splitlines())


# The reproducer is Sabba source, a fixed string, never the model's. It nulls the harness
# output before calling it, catches every Throwable, and writes the class, message, and real
# frames as JSON to the parent-held pipe. Every message is stamped with the run nonce the parent
# put in the environment; the parent accepts only a message carrying that nonce. The body runs
# in a different class and method and never sees the nonce, the pipe fd, or this emit path.
# StackOverflowError, OutOfMemoryError, and a Jazzer FuzzerSecurityIssue all arrive here as
# Throwables with real frames.
_REPRODUCER_SRC = r"""
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Paths;

public final class SabbaReproducer {
    public static void main(String[] args) {
        String nonce = System.getenv("SABBA_NONCE");
        if (nonce == null) nonce = "";
        String fdEnv = System.getenv("SABBA_REPORT_FD");
        String fdPath = (fdEnv == null || fdEnv.isEmpty()) ? "/dev/fd/3" : "/dev/fd/" + fdEnv;
        byte[] poc;
        try {
            poc = Files.readAllBytes(Paths.get(args[0]));
        } catch (Throwable t) {
            write(fdPath, "{\"nonce\":\"" + esc(nonce) + "\",\"kind\":\"error\"}");
            Runtime.getRuntime().halt(2);
            return;
        }
        PrintStream nul = new PrintStream(new OutputStream() {
            public void write(int b) {}
            public void write(byte[] b, int off, int len) {}
        });
        System.setOut(nul);
        System.setErr(nul);
        String json;
        try {
            Harness.fuzzerTestOneInput(poc);
            json = "{\"nonce\":\"" + esc(nonce) + "\",\"kind\":\"none\"}";
        } catch (Throwable t) {
            json = encode(nonce, t);
        }
        write(fdPath, json);
        Runtime.getRuntime().halt(0);
    }

    private static String encode(String nonce, Throwable t) {
        StringBuilder sb = new StringBuilder(4096);
        sb.append("{\"nonce\":\"").append(esc(nonce))
          .append("\",\"kind\":\"throwable\",\"class\":\"").append(esc(t.getClass().getName()))
          .append("\",\"message\":\"").append(esc(String.valueOf(t.getMessage())))
          .append("\",\"frames\":[");
        StackTraceElement[] st = t.getStackTrace();
        int n = Math.min(st.length, 400);
        for (int i = 0; i < n; i++) {
            StackTraceElement e = st[i];
            if (i > 0) sb.append(',');
            sb.append("{\"cls\":\"").append(esc(e.getClassName()))
              .append("\",\"method\":\"").append(esc(e.getMethodName()))
              .append("\",\"file\":\"").append(esc(String.valueOf(e.getFileName())))
              .append("\",\"line\":").append(e.getLineNumber()).append('}');
        }
        sb.append("]}");
        return sb.toString();
    }

    private static void write(String fdPath, String json) {
        try {
            // frame the message with newlines so anything the body may have written to the pipe
            // before us stays on its own line, which the parent drops for lacking the nonce
            OutputStream ch = new FileOutputStream(new File(fdPath));
            ch.write(("\n" + json + "\n").getBytes("UTF-8"));
            ch.flush();
            ch.close();
        } catch (Throwable ignored) {
            // the pipe is the only result channel; if it is not present, the parent falls back to
            // its own measurement (signal or timeout) and treats the run as no structured crash
        }
    }

    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' || c == '"') b.append('\\').append(c);
            else if (c == '\n') b.append("\\n");
            else if (c == '\r') b.append("\\r");
            else if (c == '\t') b.append("\\t");
            else if (c < 0x20) b.append(' ');
            else b.append(c);
        }
        return b.toString();
    }
}
"""
