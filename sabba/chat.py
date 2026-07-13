"""Conversational driver: the model chats with the user and calls tools.

Tools do real work. `solve` runs the Z3 synthesizer plus the oracle, `verify` runs a
target's known PoC, `bash` runs a shell command, `clone_repo` fetches a GitHub repo,
`web_search` and `web_fetch` reach the internet, and the file tools read the tree. A bug
is only ever reported when the oracle confirmed it; the model does not get to assert one.
"""
from __future__ import annotations

import json
import re
import subprocess
import threading
from pathlib import Path

from . import config
from .harness import CCompileRunOracle
from .harness.symbolic.synth import hunt_symbolic
from .log import get_logger
from .types import PoC

LOG = get_logger()
BASH_TIMEOUT = 120      # seconds; a hung command is killed and reported

SYSTEM = """You are Sabba, a security assistant. Sabba finds security bugs and proves them \
by triggering them, never by guessing. In this chat you prove memory-safety bugs in C and \
C++ directly with solve and verify. Solidity, Python, Go, Java, and Node (JavaScript or \
TypeScript) are proven through `sabba hunt` on the project: a Foundry project gets an \
exploit run against a pinned fork; a Python, Go, Java, or Node project gets a fuzz harness \
(Atheris, go test -fuzz, Jazzer, or Jazzer.js) that reports only security-relevant crashes, \
such as a denial of service or a Jazzer security-issue sink.

Your tools and what they actually do:
- solve: run the Z3 overflow synthesizer plus the sanitizer oracle over a directory of C or \
C++ sources, and return confirmed findings.
- verify: compile a C or C++ target under the sanitizer and run its known PoC (needs a \
target.json).
- bash: run one short shell command. It is killed after 120 seconds and keeps no background \
process between calls, so use it for building, grep, git, and quick static analysis, not for \
a fork test, a fuzzing campaign, or a long-running server.
- clone_repo, list_dir, read_file, web_search, web_fetch: fetch and read.

When the user points you at something to analyze, a directory, a file, or a repository URL, \
act with your tools rather than answering from memory. Clone_repo the URL, then solve or run \
`sabba hunt` on the returned path, and report the real tool output. Do not say a target has no \
bugs before you have run a tool on it, and do not refuse an authorized analysis of a target the \
user gave you; run it. This is a security tool used on code the user is allowed to test.

Call a tool by emitting a single JSON object and nothing else, for example \
{"name": "clone_repo", "arguments": {"url": "https://github.com/owner/repo"}}. Do not wrap a \
tool call in XML tags, do not write it as a shell command, and do not invent tool names; use \
only the tools listed above with their real arguments.

Only state a bug that solve or verify confirmed through the sanitizer. For a Solidity, \
Python, Go, or Java target, do not claim a bug from reading the code; run or recommend \
`sabba hunt` on the project so the drain or crash is proven.

Work in a plan, act, report, decide loop, out loud:
- Before you call a tool, say in one short line what you are about to do and why.
- After a tool returns, say what you did and what you got back from it.
- Then read the result and decide what comes next. Either name the next step and take it, \
or, when the task is done, give a short final summary and ask the user whether they want a \
specific follow-up.

Let the situation choose the steps; do not follow a fixed script, and skip narration that \
adds nothing. Keep every line short and concrete, and base each claim on real tool output, \
not assumption."""

WORK = Path(config.HOME) / "work"

TOOLS = [
    {"name": "solve", "description": "Run the Z3 overflow synthesizer plus the sanitizer "
     "oracle over a directory of C or C++ sources. Returns confirmed findings.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}},
                      "required": ["path"]}},
    {"name": "verify", "description": "Compile a target under the sanitizer and run its "
     "known PoC (the directory must have a target.json).",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}},
                      "required": ["path"]}},
    {"name": "bash", "description": "Run a shell command and return its output. Use for "
     "building, grep, git, and general inspection.",
     "input_schema": {"type": "object", "properties": {"command": {"type": "string"}},
                      "required": ["command"]}},
    {"name": "clone_repo", "description": "Shallow-clone a public GitHub (or git) repo and "
     "return the local path.",
     "input_schema": {"type": "object", "properties": {"url": {"type": "string"}},
                      "required": ["url"]}},
    {"name": "list_dir", "description": "List the files in a directory.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}},
                      "required": ["path"]}},
    {"name": "read_file", "description": "Read a text file.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}},
                      "required": ["path"]}},
    {"name": "web_search", "description": "Search the public web, returns top results.",
     "input_schema": {"type": "object", "properties": {"query": {"type": "string"}},
                      "required": ["query"]}},
    {"name": "web_fetch", "description": "Fetch a URL and return its readable text.",
     "input_schema": {"type": "object", "properties": {"url": {"type": "string"}},
                      "required": ["url"]}},
]


class Ctl:
    """Cancellation handle: a stop flag plus the current subprocess, so ESC can interrupt."""

    def __init__(self):
        self.stop = threading.Event()
        self.proc: subprocess.Popen | None = None

    def stopped(self) -> bool:
        return self.stop.is_set()


def _sources(path: Path) -> list[Path]:
    tj = path / "target.json"
    if tj.exists():
        return [path / s for s in json.loads(tj.read_text())["sources"]]
    return (list(path.rglob("*.c")) + list(path.rglob("*.h"))
            + list(path.rglob("*.cc")) + list(path.rglob("*.cpp")))


def _bash(command: str, ctl: Ctl) -> str:
    import os
    import select
    import time
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, cwd=str(Path.cwd()),
                            start_new_session=True)
    ctl.proc = proc
    lines: list[str] = []
    total = 0
    deadline = time.monotonic() + BASH_TIMEOUT

    def kill(note: str) -> None:
        lines.append(note)
        try:
            os.killpg(os.getpgid(proc.pid), 15)
        except Exception:
            pass

    try:
        while True:
            if ctl.stopped():
                kill("\n[stopped]"); break
            if time.monotonic() > deadline:
                kill(f"\n[timed out after {BASH_TIMEOUT}s]"); break
            ready, _, _ = select.select([proc.stdout], [], [], 0.4)
            if not ready:
                if proc.poll() is not None:
                    break
                continue
            line = proc.stdout.readline()
            if not line:
                break
            lines.append(line)
            total += len(line)
            if total > 12000:
                kill("\n[output truncated]"); break
        try:
            proc.wait(timeout=2)
        except Exception:
            pass
    finally:
        ctl.proc = None
    return "".join(lines)[:12000] or "(no output)"


def _clone(url: str) -> str:
    WORK.mkdir(parents=True, exist_ok=True)
    name = re.sub(r"[^A-Za-z0-9_.-]", "-", url.rstrip("/").split("/")[-1].replace(".git", ""))
    dest = WORK / (name or "repo")
    if dest.exists():
        return str(dest)
    r = subprocess.run(["git", "clone", "--depth", "1", url, str(dest)],
                       capture_output=True, text=True, timeout=180)
    if r.returncode != 0:
        return f"clone failed: {r.stderr.strip()[:400]}"
    return str(dest)


def _web_search(query: str) -> str:
    try:
        try:
            from ddgs import DDGS
        except ImportError:
            from duckduckgo_search import DDGS
        rows = list(DDGS().text(query, max_results=6))
    except Exception as e:
        return f"web_search unavailable: {e}"
    if not rows:
        return "no results"
    return "\n".join(f"- {r.get('title','')} :: {r.get('href', r.get('url',''))}\n  "
                     f"{r.get('body', r.get('snippet',''))[:200]}" for r in rows)


def _web_fetch(url: str) -> str:
    import requests
    r = requests.get(url, timeout=20, headers={"User-Agent": "sabba-agent"})
    html = r.text
    html = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:6000] or "(empty)"


def _norm_args(args: dict) -> dict:
    """Unwrap a value a small model wrote as {"type": "string", "value": X} back to X.

    Weak models sometimes echo the parameter schema instead of the value, so `path` arrives as
    {"type": "string", "value": "/x"} and a tool that wants a string gets a dict. Undo that. It
    also normalizes the call signature so the loop guard sees a native and a text-recovered call
    with the same arguments as one and the same call.
    """
    if not isinstance(args, dict):
        return args
    out = {}
    for k, v in args.items():
        if isinstance(v, dict) and "value" in v and set(v) <= {
                "type", "value", "description", "name", "required"}:
            out[k] = v["value"]
        else:
            out[k] = v
    return out


def run_tool(name: str, args: dict, ctl: Ctl) -> str:
    args = _norm_args(args)
    LOG.info("tool %s %s", name, {k: str(v)[:100] for k, v in args.items()})
    if name == "bash" and not config.load().get("allow_bash", True):
        return "bash is disabled in ~/.sabba/config.json (set allow_bash to true to enable)"
    try:
        if name == "solve":
            d = Path(args["path"]).expanduser()
            sources = _sources(d)
            if not sources:
                return f"no C/C++ sources under {d}"
            found = hunt_symbolic(sources)
            if not found:
                return "no overflow reproduced by the solver"
            return "\n".join(f"{f.cwe} {f.title} at {f.function} {f.file}:{f.line} "
                             f"(PoC {f.poc.label() if f.poc else ''})" for f in found)
        if name == "verify":
            d = Path(args["path"]).expanduser()
            tj = d / "target.json"
            if not tj.exists():
                return "no target.json here; use solve instead"
            spec = json.loads(tj.read_text())
            kp = spec.get("known_poc") or {}
            v = CCompileRunOracle().verify([d / s for s in spec["sources"]],
                                           PoC(argv=kp.get("argv", []), stdin=kp.get("stdin", "")))
            klass = v.sanitizer.klass if v.sanitizer else None
            return f"verified={v.verified} reason={v.reason} class={klass}"
        if name == "bash":
            return _bash(args["command"], ctl)
        if name == "clone_repo":
            return _clone(args["url"])
        if name == "list_dir":
            return "\n".join(sorted(p.name for p in Path(args["path"]).expanduser().iterdir())) or "(empty)"
        if name == "read_file":
            return Path(args["path"]).expanduser().read_text(errors="replace")[:6000]
        if name == "web_search":
            return _web_search(args["query"])
        if name == "web_fetch":
            return _web_fetch(args["url"])
    except Exception as e:
        LOG.exception("tool %s failed", name)
        return f"tool error: {e}"
    return f"unknown tool {name}"


def turn_stream(provider, messages: list, user_text: str, ctl: Ctl, *,
                memory_context: str = "", on_start, on_text, on_done, on_tool, on_result,
                max_steps: int | None = None) -> None:
    """One user turn, streamed. Calls the callbacks as text and tool activity arrive.

    memory_context, when given, is the snippets recalled from past conversations; it is
    injected as a system note ahead of the new user message.
    """
    LOG.info("turn (%s): %s", getattr(provider, "model", "?"), user_text[:200])
    if not messages:
        messages.extend(provider.init_messages(SYSTEM, user_text))
        if memory_context:
            messages.insert(1, {"role": "system", "content": memory_context})
    else:
        if memory_context:
            messages.append({"role": "system", "content": memory_context})
        messages.append({"role": "user", "content": user_text})

    can_stream = hasattr(provider, "stream")
    if max_steps is None:
        max_steps = 24         # a hard backstop so a looping model always terminates the turn
    step = 0
    ran_sigs: set = set()      # signatures of tool calls already run this turn, for the loop guard
    while True:
        if max_steps is not None and step >= max_steps:
            on_start()
            on_text(chr(10) + "[reached the " + str(max_steps) + "-step limit. "
                    "Type 'continue' to keep going, the context is kept.]")
            on_done(None, None)
            return
        step += 1
        if ctl.stopped():
            return
        on_start()
        text, tool_calls, native, pt, ct = "", [], None, None, None
        if can_stream:
            for ev in provider.stream(messages, TOOLS):
                if ctl.stopped():
                    on_done(None, None)
                    return
                if ev["type"] == "text":
                    text += ev["text"]
                    on_text(ev["text"])
                elif ev["type"] == "done":
                    tool_calls, native = ev["tool_calls"], ev["assistant"]
                    pt, ct = ev["prompt_tokens"], ev["completion_tokens"]
        else:
            resp = provider.create(messages, TOOLS)
            text, tool_calls, native = resp.text, resp.tool_calls, resp.native_assistant
            if text:
                on_text(text)
        on_done(pt, ct)
        if native is not None:
            messages.append(native)
        if not tool_calls:
            return
        # Loop guard: a small model often re-requests a tool it already ran instead of reading
        # the result and finishing. When every call in this step is an exact repeat, stop so we
        # do not run the same expensive tool over and over.
        sigs = [(tc.name, json.dumps(_norm_args(tc.input), sort_keys=True, default=str))
                for tc in tool_calls]
        if sigs and all(s in ran_sigs for s in sigs):
            on_start()
            on_text(chr(10) + "[Done. The result above is from the tool that already ran.]")
            on_done(None, None)
            return
        results = []
        for tc, sig in zip(tool_calls, sigs):
            if ctl.stopped():
                return
            on_tool(tc.name, tc.input)
            out = run_tool(tc.name, dict(tc.input), ctl)
            on_result(tc.name, out)
            ran_sigs.add(sig)
            results.append({"id": tc.id, "content": out, "is_error": False})
        provider.add_tool_results(messages, results)
