"""Phase two: the Sabba-owned reproducer that decides the verdict.

Discovery (runner.py) hands us candidate PoC bytes and nothing else. This module re-runs
those bytes through a reproducer that Sabba writes and the harness cannot control, and reads
the outcome only over channels the harness cannot forge.

The reproducer is a small Node script (REPRO_JS below). It is Sabba source, generated at run
time, never the model's. It:

  - sets Error.stackTraceLimit high so a real overflow keeps its target frames,
  - reads the PoC from a path Sabba passes, before the harness runs,
  - requires the model's assembled harness (fuzz.js) and calls fuzz(poc) in try/catch,
  - replaces process.stdout.write and process.stderr.write with no-ops, so anything the
    harness or target prints is gone and cannot carry a forged verdict,
  - on a caught throwable, writes the real class, message, and parsed stack frames as JSON,
    tagged with the parent's per-run nonce, to the write end of a parent-held anonymous pipe
    passed as an inherited fd. It is never a file in the harness cwd (the round-1 hole), and the
    parent accepts only a message carrying the matching nonce. The harness cannot reach the fd
    (its process object is shadowed and its requires are import-only, both gated) and never sees
    the nonce, so it cannot forge an accepted message.

For a crash that kills the child instead of throwing (a heap out-of-memory, a fatal signal
from a native addon) Node writes a diagnostic report to a Sabba directory because we pass
--report-on-fatalerror; the parent reads its javascriptStack. For a hang the parent's own
wall clock is the measurement: it kills the child after the deadline and reads whatever
report exists. In both kill cases attribution comes only from the frames in that runtime
report; where none survive, the caller returns unverified rather than guess.

Only `node` is needed here, never Jazzer.js, so phase two runs even on a box that can only
discover through an installed launcher elsewhere. Import never requires Node.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path

from .classify import Outcome
from .runner import (_link_node_modules, _stage_sources, _transpile_ts, assemble,
                     jazzerjs_home, node_bin)

# The reproducer. Sabba source. It writes its structured result, tagged with the parent's
# per-run nonce, to the write end of a parent-held anonymous pipe passed as an inherited fd. It
# never writes a file in the harness cwd, and never trusts, reads, or emits anything the harness
# controls. The nonce arrives in an env var that this script deletes before the harness loads,
# and the fd number is stripped from argv, so even a harness that somehow reached the global
# process object would learn neither the nonce nor the fd. The body is isolated anyway (its
# module object, require, and process are shadowed), but the channel holds without relying on
# that: an accepted message must carry the nonce, and the body never sees it.
REPRO_JS = r"""
"use strict";
const fs = require("fs");
const RESULT_FD = Number(process.argv[3]);
const POC_PATH = process.argv[2];
const NONCE = process.env.SABBA_RESULT_NONCE || "";
// Take the secret out of the environment and the fd number out of argv before anything the
// harness could observe runs. The harness has no process access (gated), but the channel is
// designed to survive a full escape: without the nonce, no message it writes is accepted.
delete process.env.SABBA_RESULT_NONCE;
try { process.argv = process.argv.slice(0, 2); } catch (e) {}
Error.stackTraceLimit = 1000000;

function emit(obj) {
  obj.nonce = NONCE;
  try { fs.writeSync(RESULT_FD, JSON.stringify(obj)); } catch (e) {}
}

// Pull real source files and a small sample out of a genuine V8 stack. The file in each
// frame is decided by V8 from the actual source location, so a harness cannot forge it into
// a target file; its own recursion stays in fuzz.js.
function parseFrames(err) {
  const files = [];
  const seen = new Set();
  const sample = [];
  const re = /(?:\(([^()]+):(\d+):(\d+)\)|at\s+([^\s()]+):(\d+):(\d+))\s*$/;
  // Skip the message header (name + message) before scanning frames. The message is
  // attacker-influenced and can carry newlines and a fake "at file:line" line, so scanning
  // it would let a harness forge an innermost target frame with no real crash.
  const name = (err && err.name != null) ? String(err.name) : "Error";
  const msg = (err && err.message != null) ? String(err.message) : "";
  const header = msg ? name + ": " + msg : name;
  const skip = header.split("\n").length;
  const lines = String((err && err.stack) || "").split("\n");
  for (let i = skip; i < lines.length; i++) {
    const m = lines[i].match(re);
    if (!m) continue;
    const file = m[1] || m[4];
    const line = m[2] || m[5];
    if (!file) continue;
    if (!seen.has(file)) { seen.add(file); files.push(file); }
    if (sample.length < 40) sample.push(file + ":" + line);
    if (seen.size > 500) break;
  }
  return { files: files, sample: sample };
}

let poc;
try {
  poc = fs.readFileSync(POC_PATH);
} catch (e) {
  emit({ kind: "load_error", message: "cannot read poc: " + String((e && e.message) || e) });
  process.exit(0);
}

let fuzz;
try {
  const mod = require("./fuzz.js");
  fuzz = mod && mod.fuzz;
} catch (e) {
  const f = parseFrames(e);
  emit({ kind: "load_error",
         error_class: (e && e.constructor) ? e.constructor.name : typeof e,
         message: String((e && e.message) || e), files: f.files, sample: f.sample });
  process.exit(0);
}
if (typeof fuzz !== "function") {
  emit({ kind: "load_error", message: "harness did not export fuzz()" });
  process.exit(0);
}

// From here on, silence everything the harness or target writes. The verdict never reads it.
process.stdout.write = function () { return true; };
process.stderr.write = function () { return true; };

try {
  fuzz(poc);
  emit({ kind: "none" });
} catch (e) {
  const f = parseFrames(e);
  emit({
    kind: "exception",
    error_class: (e && e.constructor) ? e.constructor.name : typeof e,
    message: String((e && e.message) || e),
    files: f.files,
    sample: f.sample
  });
}
process.exit(0);
"""


def verify_poc(target_dir, harness, poc_bytes: bytes, *, mem_mb: int = 256,
               timeout: int = 15, workdir: Path | None = None) -> Outcome:
    """Re-run candidate PoC bytes through the Sabba reproducer and return a structured Outcome.

    Needs only `node`. The Outcome's kind and frames come from unforgeable channels: a caught
    exception's real class and stack over fd 3, or the parent's measurement of a killed child
    plus Node's own diagnostic report.
    """
    home = jazzerjs_home()
    own_work = workdir is None
    work = Path(workdir or tempfile.mkdtemp(prefix="sabba-noderepro-"))
    try:
        _stage_sources(Path(target_dir), work)
        build_err = _transpile_ts(work, home)
        if build_err:
            return Outcome(kind="load_error", message=build_err, raw=build_err,
                           poc_bytes=poc_bytes)
        _link_node_modules(work, home)
        (work / "fuzz.js").write_text(assemble(harness))
        (work / "repro.js").write_text(REPRO_JS)
        poc_path = work / "poc.bin"
        poc_path.write_bytes(poc_bytes or b"")
        reports = work / "reports"
        reports.mkdir(exist_ok=True)

        # The result channel is an anonymous pipe the parent owns, never a file in the harness
        # cwd. The parent keeps the read end (non-inheritable) and passes the write end to the
        # child as an inherited fd; pass_fds keeps that exact number open in the child. A
        # per-run nonce goes to the child only through an env var it deletes before the harness
        # loads. The harness cannot reach this fd (its process object is shadowed) and never
        # sees the nonce, so it cannot forge a message the parent will accept.
        nonce = secrets.token_hex(16)
        r_fd, w_fd = os.pipe()
        os.set_inheritable(w_fd, True)
        env = dict(os.environ)
        env["SABBA_RESULT_NONCE"] = nonce
        node_dir = os.path.dirname(shutil.which("node") or "")
        if node_dir:
            env["PATH"] = node_dir + os.pathsep + env.get("PATH", "")

        cmd = [node_bin(), "--stack-trace-limit=100000", f"--max-old-space-size={mem_mb}",
               "--report-on-fatalerror", "--report-uncaught-exception",
               f"--report-directory={reports}", "repro.js", str(poc_path), str(w_fd)]

        timed_out = False
        rc: int | None = None
        try:
            proc = subprocess.run(
                cmd, cwd=str(work), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                pass_fds=(w_fd,), timeout=timeout, env=env)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            os.close(w_fd)  # drop the parent's write end so the read end sees EOF

        raw = _read_pipe(r_fd)  # closes r_fd
        out = _from_pipe(raw, nonce, poc_bytes)
        if out is not None:
            return out
        return _from_report(reports, timed_out, rc, poc_bytes)
    finally:
        if own_work:
            shutil.rmtree(work, ignore_errors=True)


def _read_pipe(r_fd: int) -> bytes:
    """Drain the parent-held read end of the result pipe to EOF, then close it. EOF arrives once
    every write end is closed: the parent already dropped its copy, and the child's is gone when
    it exits or is killed."""
    chunks: list[bytes] = []
    try:
        while True:
            b = os.read(r_fd, 65536)
            if not b:
                break
            chunks.append(b)
    except OSError:
        pass
    finally:
        try:
            os.close(r_fd)
        except OSError:
            pass
    return b"".join(chunks)


def _authenticated(text: str, nonce: str) -> dict | None:
    """Return the one JSON object in the pipe whose nonce matches, ignoring everything else.

    The body never learns the nonce, so anything it could write (it cannot even reach this fd)
    is rejected here. We scan every object rather than json.loads the whole buffer so a stray
    write cannot knock out a genuine, correctly-nonced message."""
    dec = json.JSONDecoder()
    idx, n = 0, len(text)
    while idx < n:
        while idx < n and text[idx].isspace():
            idx += 1
        if idx >= n:
            break
        try:
            obj, end = dec.raw_decode(text, idx)
        except ValueError:
            break
        if isinstance(obj, dict) and obj.get("nonce") == nonce:
            return obj
        idx = end
    return None


def _from_pipe(raw: bytes, nonce: str, poc_bytes: bytes) -> Outcome | None:
    """Read the reproducer's nonce-authenticated JSON from the pipe, if it wrote one."""
    text = (raw or b"").decode("utf-8", "replace").strip()
    if not text:
        return None
    d = _authenticated(text, nonce)
    if d is None:
        return None
    kind = str(d.get("kind", ""))
    if kind not in ("exception", "none", "load_error"):
        return None
    files = [str(x) for x in (d.get("files") or [])]
    sample = [str(x) for x in (d.get("sample") or [])]
    return Outcome(
        kind=kind,
        error_class=str(d.get("error_class", "")),
        message=str(d.get("message", "")),
        frame_files=files,
        frame_sample=sample,
        raw=_evidence(kind, str(d.get("error_class", "")), str(d.get("message", "")), sample),
        poc_bytes=poc_bytes,
    )


def _from_report(reports: Path, timed_out: bool, rc: int | None,
                 poc_bytes: bytes) -> Outcome:
    """No fd-3 result means the child was killed or died in a fatal error. Read Node's own
    diagnostic report for the kind and frames; both are runtime-authored, not harness-authored.
    """
    report = _newest_report(reports)
    files, sample = _report_frames(report)
    trigger = ((report or {}).get("header") or {}).get("trigger") or ""
    event = ((report or {}).get("header") or {}).get("event") or ""
    low = (str(trigger) + " " + str(event)).lower()

    if timed_out:
        kind = "timeout"
    elif "oom" in low or "out of memory" in low or "allocation failed" in low:
        kind = "oom"
    elif report is not None:
        kind = "signal"
    else:
        # no result and no report: the child died before writing anything we can attribute.
        # Treat a wall-clock miss as timeout, otherwise a signal we could not dump.
        kind = "signal"
    signal = -rc if (rc is not None and rc < 0) else None
    return Outcome(kind=kind, frame_files=files, frame_sample=sample, signal=signal,
                   raw=_evidence(kind, str(trigger), str(event), sample), poc_bytes=poc_bytes)


def _newest_report(reports: Path) -> dict | None:
    try:
        files = sorted(reports.glob("report.*.json"))
    except OSError:
        return None
    for p in reversed(files):
        try:
            return json.loads(p.read_text())
        except Exception:
            continue
    return None


def _report_frames(report: dict | None) -> tuple[list[str], list[str]]:
    if not report:
        return [], []
    js = report.get("javascriptStack") or {}
    stack = js.get("stack") or []
    files: list[str] = []
    seen: set[str] = set()
    sample: list[str] = []
    for frame in stack:
        s = str(frame)
        # Node report frames read "at deep (/path/vuln.js:1:49)"; pull the file:line.
        m = _FRAME_RE.search(s)
        if not m:
            continue
        f = m.group(1)
        if f not in seen:
            seen.add(f)
            files.append(f)
        if len(sample) < 40:
            sample.append(f + ":" + m.group(2))
    return files, sample


def _evidence(kind: str, a: str, b: str, sample: list[str]) -> str:
    head = f"[reproducer] kind={kind} {a} {b}".strip()
    body = "\n".join(sample[:8])
    return (head + ("\n" + body if body else ""))[:1600]


_FRAME_RE = re.compile(r"([^\s()]+\.(?:js|mjs|cjs|ts|mts|cts)):(\d+)(?::\d+)?")
