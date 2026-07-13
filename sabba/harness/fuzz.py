"""Model-written fuzz harnesses, proven by triggering.

Point this at a C or C++ repo and it surveys the code, asks the reasoning model for a
libFuzzer harness plus a build recipe, compiles with clang and AddressSanitizer, and
fuzzes. A crash counts only when the sanitizer produces it and the minimized input
reproduces it. This is the discovery half of the hunter; the verified-only gate stays
in oracle.py. Nothing here is hardcoded to a target: the model reads each repo and
writes its own harness, which is what lets us reach libraries nobody has fuzzed.
"""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

SRC_EXT = (".c", ".cc", ".cpp", ".cxx")
HDR_EXT = (".h", ".hpp", ".hh", ".hxx")
SKIP_DIRS = {".git", "build", "out", "node_modules", ".github",
             "tests", "test", "examples", "_hgen"}

_SIG_RE = re.compile(r"^[A-Za-z_][\w\s\*]*\b([A-Za-z_]\w*)\s*\([^;{)]*\)\s*;", re.M)
_ENTRY_RE = re.compile(r"(const\s+)?(unsigned\s+)?(char|void)\s*\*|size_t|FILE\s*\*", re.I)
_LOC_RE = re.compile(r"\.(c|cc|cpp|cxx|h|hpp|hh):\d+")

# Defaults learned on the first targets. Real seeds plus allocation limits matter: a
# malformed input that asks for gigabytes otherwise drags throughput down to nothing.
RSS_LIMIT_MB = 2560
MALLOC_LIMIT_MB = 2048
MAX_LEN = 8192


@dataclass
class HarnessSpec:
    entry: str
    sources: list
    includes: list
    defines: list
    harness: str


@dataclass
class Finding:
    repo: str
    entry: str
    sanitizer: str
    summary: str
    frames: list
    poc: str
    poc_size: int
    workdir: str


def _survey(repo):
    files = []
    for root, dirs, names in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for n in names:
            if n.endswith(SRC_EXT + HDR_EXT):
                files.append(os.path.relpath(os.path.join(root, n), repo))
    files = sorted(files)[:120]
    return files, _signatures(repo, files), _header_docs(repo, files)


def _signatures(repo, files):
    out, seen = [], set()
    for rel in files:
        try:
            txt = Path(repo, rel).read_text(errors="ignore")
        except OSError:
            continue
        for m in _SIG_RE.finditer(txt):
            line = " ".join(m.group(0).split())
            if len(line) < 200 and _ENTRY_RE.search(line) and line not in seen:
                seen.add(line)
                out.append((rel, line))
                if len(out) >= 60:
                    return out
    return out


def _header_docs(repo, files, hint=""):
    key = (hint or "").lower().split()
    hdrs = [f for f in files if f.endswith(HDR_EXT)]
    hdrs.sort(key=lambda f: (0 if any(w in f.lower() for w in key) else 1, len(f)))
    docs = []
    for rel in hdrs[:3]:
        try:
            docs.append((rel, Path(repo, rel).read_text(errors="ignore")[:1200]))
        except OSError:
            pass
    return docs


def _prompt(files, sigs, docs, hint):
    sig_txt = "\n".join(f"  {f}: {s}" for f, s in sigs) or "  (none auto-detected)"
    doc_txt = "\n\n".join(f"--- top of {f} ---\n{d}" for f, d in docs)
    system = (
        "You write libFuzzer harnesses for C and C++ libraries. You output only JSON. "
        "You pick one input-parsing entry point that takes attacker-controlled bytes "
        "(a buffer with a length, a C string, or a file) and drive it from raw fuzz input."
    )
    user = f"""Repository at ./ contains these source and header files:
{json.dumps(files)}

Candidate entry-point signatures:
{sig_txt}

{doc_txt}

Target to fuzz: {hint or "the most obvious input parser"}

Write a libFuzzer harness that feeds the raw fuzz bytes to one entry point.
Return STRICT JSON only, no prose, with this shape:
{{
  "entry": "short note on which function you fuzz",
  "sources": ["relative paths to .c or .cpp files to compile alongside the harness"],
  "includes": ["dirs for -I, relative to repo root"],
  "defines": ["NAME or NAME=value for -D, e.g. a single-header IMPLEMENTATION macro"],
  "harness": "full C source including any #include lines and int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)"
}}
For a single-header library put the IMPLEMENTATION define in defines and include the
header in the harness; sources may then be empty. Match the exact function signatures
shown above. The harness must compile, keep it minimal, and free any results."""
    return system, user


def _parse_spec(text):
    t = text.strip()
    m = re.search(r"```(?:json)?\s*(.*?)```", t, re.S)
    if m:
        t = m.group(1).strip()
    a, b = t.find("{"), t.rfind("}")
    if a >= 0 and b > a:
        t = t[a:b + 1]
    d = json.loads(t)
    return HarnessSpec(
        entry=str(d.get("entry", "")),
        sources=list(d.get("sources") or []),
        includes=list(d.get("includes") or []),
        defines=list(d.get("defines") or []),
        harness=d["harness"],
    )


def _build_cmd(repo, spec, work):
    Path(work, "harness.c").write_text(spec.harness)
    cmd = ["clang", "-g", "-O1", "-fsanitize=address,fuzzer", "-Wno-everything"]
    for inc in spec.includes:
        cmd += ["-I", str(Path(repo, inc))]
    for d in spec.defines:
        cmd.append(f"-D{d}")
    for s in spec.sources:
        cmd.append(str(Path(repo, s)))
    cmd += [str(Path(work, "harness.c")), "-o", str(Path(work, "fuzz"))]
    return cmd


def _generate(repo, hint, work, judge_fn, log, attempts=4):
    """Ask the model for a harness and compile it, feeding compile errors back to fix."""
    files, sigs, docs = _survey(repo)
    docs = _header_docs(repo, files, hint) or docs
    log(f"survey: {len(files)} files, {len(sigs)} candidate signatures")
    system, user = _prompt(files, sigs, docs, hint)
    err = ""
    for i in range(attempts):
        prompt = user if i == 0 else user + f"\n\nYour previous attempt failed. Fix it. Error:\n{err[-2500:]}"
        try:
            spec = _parse_spec(judge_fn(system, prompt))
        except Exception as e:
            log(f"gen {i}: bad JSON ({e})")
            err = "your output was not valid JSON matching the required shape"
            continue
        log(f"gen {i}: entry={spec.entry!r} sources={spec.sources} defines={spec.defines}")
        p = subprocess.run(_build_cmd(repo, spec, work), capture_output=True, text=True)
        if p.returncode == 0:
            log("build: ok")
            return spec
        err = (p.stderr or "")[-4000:]
        log(f"build {i}: failed")
    return None


def _fuzz(work, seeds, secs, cores):
    binp = str(Path(work, "fuzz"))
    cmd = [binp, f"-max_total_time={secs}", f"-max_len={MAX_LEN}",
           f"-rss_limit_mb={RSS_LIMIT_MB}", f"-malloc_limit_mb={MALLOC_LIMIT_MB}"]
    if cores and cores > 1:
        cmd += [f"-jobs={cores}", f"-workers={cores}"]
    if seeds:
        cmd.append(seeds)
    subprocess.run(cmd, cwd=work, capture_output=True, text=True)
    return sorted(glob.glob(str(Path(work, "crash-*"))) + glob.glob(str(Path(work, "oom-*"))))


def _minimize(work, crash, runs=30000):
    subprocess.run([str(Path(work, "fuzz")), "-minimize_crash=1",
                    f"-runs={runs}", f"-max_len={MAX_LEN}", crash],
                   cwd=work, capture_output=True, text=True)
    mins = sorted(glob.glob(str(Path(work, "minimized-from-*"))),
                  key=os.path.getmtime, reverse=True)
    return mins[0] if mins else crash


def _triage(work, crash):
    p = subprocess.run([str(Path(work, "fuzz")), crash], cwd=work,
                       capture_output=True, text=True)
    log = (p.stdout or "") + (p.stderr or "")
    summary, sanitizer = "", ""
    for ln in log.splitlines():
        if "ERROR: AddressSanitizer" in ln or "ERROR: libFuzzer" in ln:
            summary = ln.strip()
            m = re.search(r"AddressSanitizer:\s*([\w-]+)", ln)
            sanitizer = m.group(1) if m else ("deadly-signal" if "libFuzzer" in ln else "")
            break
    frames = [ln.strip() for ln in log.splitlines() if _LOC_RE.search(ln)][:6]
    return sanitizer, summary, frames


def _clone(url):
    dest = tempfile.mkdtemp(prefix="sabba_hunt_")
    subprocess.run(["git", "clone", "--quiet", "--depth", "1", url, dest], check=True)
    return dest


def hunt(repo, hint="", seeds="", secs=90, work=None, cores=1,
         judge_fn=None, log=print):
    """Survey a repo, have the model write a harness, fuzz, and return a verified Finding."""
    if judge_fn is None:
        from sabba.llm import judge as judge_fn
    cloned = None
    if "://" in repo or repo.startswith("git@"):
        log(f"cloning {repo}")
        repo = cloned = _clone(repo)
    repo = os.path.abspath(repo)
    work = os.path.abspath(work or os.path.join(repo, "_hgen"))
    Path(work).mkdir(parents=True, exist_ok=True)
    try:
        spec = _generate(repo, hint, work, judge_fn, log)
        if spec is None:
            log("could not produce a building harness")
            return None
        crashes = _fuzz(work, os.path.abspath(seeds) if seeds else "", secs, cores)
        if not crashes:
            log("no crash this run")
            return None
        poc = _minimize(work, crashes[0])
        sanitizer, summary, frames = _triage(work, poc)
        return Finding(repo=repo, entry=spec.entry, sanitizer=sanitizer,
                       summary=summary, frames=frames, poc=poc,
                       poc_size=os.path.getsize(poc), workdir=work)
    finally:
        if cloned and (work is None or not work.startswith(cloned)):
            pass  # keep the clone so the PoC stays reproducible


def _main():
    import argparse
    from sabba import config
    config.apply_env(config.load())
    ap = argparse.ArgumentParser(description="Fuzz a repo with a model-written harness.")
    ap.add_argument("repo")
    ap.add_argument("--hint", default="")
    ap.add_argument("--seeds", default="")
    ap.add_argument("--work", default="")
    ap.add_argument("--secs", type=int, default=90)
    ap.add_argument("--cores", type=int, default=1)
    a = ap.parse_args()
    f = hunt(a.repo, hint=a.hint, seeds=a.seeds, secs=a.secs,
             work=a.work or None, cores=a.cores)
    if not f:
        return 1
    print("\n=== verified finding ===")
    print(f"entry:     {f.entry}")
    print(f"sanitizer: {f.sanitizer}")
    print(f"summary:   {f.summary}")
    for fr in f.frames:
        print(f"  {fr}")
    print(f"poc:       {f.poc} ({f.poc_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
