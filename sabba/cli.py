"""Sabba command line.

Run `sabba` on its own for the overview, or one of the commands below.

  sabba hunt <dir>     retrieval, then z3, then the model; the oracle confirms all
  sabba fuzz <repo>    the model writes a fuzz harness, the oracle proves the crash
  sabba solve <dir>    z3 synthesizes overflow inputs, the oracle confirms (no model)
  sabba verify <dir>   run a target's known PoC through the oracle (no model)
  sabba scan <dir>     reasoning agent only (needs a model)
  sabba ask <task>     hand a task to the whole Claude Code agent (read, edit, bash)
  sabba try <dir> ...  run one candidate PoC by hand
  sabba doctor         show what the toolchain has available
  sabba update         pull the latest fixes, reinstall, show the new version
  sabba version        show the installed version and commit
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import typer
from rich.panel import Panel
from rich.text import Text

from . import ui
from .ui import console

app = typer.Typer(add_completion=False, no_args_is_help=False, rich_markup_mode=None,
                  help="Sabba security bug-finder")

_MODEL_HELP = ("reasoning model id, for example qwen/qwen-2.5-coder-32b-instruct on "
               "OpenRouter (set SABBA_LLM_BACKEND=openrouter and OPENROUTER_API_KEY)")


def _load(target: str):
    d = Path(target).resolve()
    spec = json.loads((d / "target.json").read_text())
    return d, spec, [d / s for s in spec["sources"]]


def _plain(msg: str) -> str:
    return " ".join(msg.split())


def _stream(title: str, fn):
    """Run fn(on_event) under a spinner, printing styled events as they arrive."""
    with console.status(Text(title, style="accent"), spinner="dots",
                        spinner_style="accent") as st:
        def on_event(m):
            line = ui.event(m)
            if line is not None:
                console.print(line)
            st.update(Text(_plain(m)[:72], style="accent"))
        return fn(on_event)


def _require_clang() -> None:
    """The native oracle compiles and runs the PoC with clang. Fail with a clear message
    instead of a traceback when it is missing."""
    if shutil.which("clang") is None:
        console.print(Text("clang not found. The oracle compiles and runs the PoC with clang, "
                           "so install it first:", style="warn"))
        console.print(Text("  Linux:  sudo apt-get install -y clang", style="muted"))
        console.print(Text("  macOS:  brew install llvm  (or xcode-select --install)", style="muted"))
        raise typer.Exit(3)


def _repl_main():
    """Import the REPL, or point the user at the tui extra if it is not installed."""
    try:
        from .repl import main
    except ImportError:
        console.print(Text("the interactive REPL needs the tui extra:  pip install 'sabba[tui]'",
                           style="warn"))
        console.print(Text("the tools work without it: sabba mcp, verify, prove, hunt, kali_run, ...",
                           style="muted"))
        raise typer.Exit(1)
    return main


@app.callback(invoke_without_command=True)
def _root(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        _repl_main()()
        raise typer.Exit()


@app.command()
def tui():
    """Open the interactive app (same as running sabba with no command). Needs sabba[tui]."""
    _repl_main()()


@app.command()
def dashboard():
    """Open the legacy boxed dashboard UI. Needs sabba[tui]."""
    try:
        from .tui import run
    except ImportError:
        console.print(Text("the dashboard needs the tui extra:  pip install 'sabba[tui]'", style="warn"))
        raise typer.Exit(1)
    run()


@app.command(hidden=True)
def studio(program: list[str] = typer.Argument(None, help="program to embed (default: claude)")):
    """EXPERIMENTAL: embed a live Claude Code session in a Sabba-framed full-screen pane.

    Hidden from the main help while the embedded TUI is still rough. Claude Code runs in a pty
    rendered live inside Sabba; ctrl-q detaches and returns.
    """
    try:
        from .studio import run as run_studio
    except ImportError:
        console.print(Text("studio needs the tui extra:  pip install 'sabba[tui]'", style="warn"))
        raise typer.Exit(1)
    raise typer.Exit(run_studio(program or None))


@app.command()
def mcp(
    http: bool = typer.Option(False, "--http", help="serve over streamable HTTP instead of stdio"),
    host: str = typer.Option("127.0.0.1", "--host", help="host for --http"),
    port: int = typer.Option(8765, "--port", help="port for --http"),
):
    """Run Sabba as an MCP server so other agents (Claude, Codex, OpenCode, ...) can call it."""
    from .mcp_server import run as run_mcp
    run_mcp(http=http, host=host, port=port)


@app.command()
def templates(
    action: str = typer.Argument("list", help="list or install"),
    dir: str = typer.Option(".claude", "--dir", "-d", help="Claude Code config dir to install into"),
):
    """Install Sabba's security command templates for coding agents.

    /pentest, /audit, /vet-skill, /prove-fix -- workflows that drive the Sabba MCP tools. Install
    them into a Claude Code config dir so an agent gets Sabba-driven security commands.
    """
    src = Path(__file__).resolve().parent / "templates" / "commands"
    files = sorted(src.glob("*.md"))
    ui.target_header("templates", action)
    if action == "list":
        for f in files:
            console.print(Text(f"  /{f.stem}", style="accent"))
        return
    if action == "install":
        dest = Path(dir).expanduser() / "commands"
        dest.mkdir(parents=True, exist_ok=True)
        for f in files:
            shutil.copy2(f, dest / f.name)
        console.print(Text(f"installed {len(files)} commands to {dest}", style="success"))
        return
    console.print(Text(f"unknown action {action!r}; use 'list' or 'install'", style="warn"))
    raise typer.Exit(1)


@app.command()
def ask(
    prompt: str = typer.Argument(..., help="the task to hand to Claude Code"),
    dir: str = typer.Option(None, "--dir", "-d", help="give Claude Code access to this directory"),
    edit: bool = typer.Option(False, "--edit", help="allow file edits (default is read-only)"),
    model: str = typer.Option(None, "--model", help="Claude model alias, e.g. opus, sonnet, haiku"),
    tool: list[str] = typer.Option(None, "--tool", help="restrict Claude Code to these tools (repeatable)"),
):
    """Hand a task to the whole Claude Code agent and print its answer.

    SABBA shells out to `claude -p`, so Claude Code runs its full toolchain (read, edit,
    bash, MCP) and returns a finished result. Read-only unless you pass --edit.
    """
    from rich.markdown import Markdown

    from .llm import claude_code
    ui.target_header("claude code", "ask")
    if not claude_code.available():
        console.print(Text("the `claude` CLI is not on PATH. install Claude Code first:",
                           style="warn"))
        console.print(Text("  https://docs.claude.com/claude-code", style="muted"))
        raise typer.Exit(1)
    with console.status("claude code working", spinner="dots"):
        res = claude_code.run(
            prompt,
            add_dirs=[dir] if dir else None,
            permission_mode="acceptEdits" if edit else "plan",
            model=model,
            allowed_tools=list(tool) if tool else None,
        )
    if not res.ok:
        console.print(Text(f"claude did not finish: {res.error}", style="warn"))
        raise typer.Exit(1)
    console.print(Markdown(res.text))
    meta = []
    if res.turns is not None:
        meta.append(f"{res.turns} turn{'s' if res.turns != 1 else ''}")
    if res.cost_usd is not None:
        meta.append(f"${res.cost_usd:.4f}")
    if res.duration_ms is not None:
        meta.append(f"{res.duration_ms / 1000:.1f}s")
    if meta:
        console.print(Text("  " + "  ".join(meta), style="muted"))


@app.command()
def mltrain(
    data: str = typer.Argument(None, help="JSONL of {\"code\":..., \"label\":0|1}; omit to use the bootstrap corpus"),
    out: str = typer.Option(None, "--out", "-o", help="where to save the model (default ~/.sabba/ranker.joblib)"),
    from_traces: bool = typer.Option(False, "--from-traces", help="train on execution-grounded traces from past hunts"),
):
    """Train the local risk ranker. It scores functions for bug likelihood so retrieval looks
    at the risky code first, on CPU, with no frontier model."""
    try:
        if from_traces:
            from .ml.train import train_from_traces
            report = train_from_traces(out=out)
        elif data:
            from .ml.train import train_from_jsonl
            report = train_from_jsonl(data, out=out)
        else:
            from .ml.train import train_bootstrap
            console.print(Text("no data given; training on the built-in bootstrap corpus",
                               style="muted"))
            report = train_bootstrap(out=out)
    except ImportError:
        console.print(Text("the ranker needs scikit-learn: pip install scikit-learn", style="warn"))
        raise typer.Exit(3)
    body = Text()
    body.append(f"held-out AUC   {report['auc']}\n", style="success")
    body.append(f"train / test   {report['n_train']} / {report['n_test']}\n", style="muted")
    if "real_traces" in report:
        body.append(f"real traces    {report['real_traces']} ({report['real_positives']} proven)\n",
                    style="muted")
    body.append(f"model          {report['model']}", style="key")
    console.print(Panel(body, title="[accent]risk ranker[/]", border_style="muted", expand=False))


@app.command()
def verify(target: str):
    """Compile the target under a sanitizer and run its known PoC."""
    from .harness import CCompileRunOracle
    from .types import PoC
    _require_clang()
    d, spec, sources = _load(target)
    ui.target_header(spec["name"], "verify")
    kp = spec.get("known_poc")
    if not kp:
        console.print(Text("this target has no known PoC; try `sabba solve`", style="warn"))
        raise typer.Exit(2)
    poc = PoC(argv=kp.get("argv", []), stdin=kp.get("stdin", ""))
    verdict = _stream("compiling and running", lambda _e: CCompileRunOracle().verify(sources, poc))
    klass = verdict.sanitizer.klass if verdict.sanitizer else None
    style = "success" if verdict.verified else "muted"
    body = Text()
    body.append(f"verified {verdict.verified}\n", style=style)
    body.append(f"reason   {verdict.reason}\n", style="muted")
    body.append(f"class    {klass}", style="key" if klass else "muted")
    console.print(Panel(body, border_style="danger" if verdict.verified else "muted",
                        expand=False, title=f"[accent]{poc.label()}[/]"))
    raise typer.Exit(0 if verdict.verified else 1)


@app.command()
def solve(target: str):
    """Let Z3 synthesize overflow inputs; the oracle confirms each one."""
    from .chat import _sources
    from .harness.symbolic.synth import hunt_symbolic
    d = Path(target).resolve()
    ui.target_header(d.name, "solve")
    from .provers import detect_domain
    dom = detect_domain(d, None)
    if dom == "native":
        _require_clang()
    if dom != "native":
        console.print(Text(f"solve is native C/C++ only. Use `sabba hunt` for {dom} targets.",
                           style="warn"))
        raise typer.Exit(2)
    sources = _sources(d)
    if not sources:
        console.print(Text("no C or C++ sources in this directory", style="warn"))
        raise typer.Exit(1)
    found = _stream("z3 synthesis", lambda ev: hunt_symbolic(sources, on_event=ev))
    ui.findings(found, d)
    raise typer.Exit(0 if found else 1)


@app.command()
def hunt(target: str,
         model: str = typer.Option(None, "--model", "-m", help=_MODEL_HELP),
         top_k: int = typer.Option(8, "--top-k", help="how many functions retrieval surfaces"),
         no_model: bool = typer.Option(False, "--no-model", help="skip the model, z3 and oracle only"),
         domain: str = typer.Option(None, "--domain", help="force the prover: native or evm")):
    """Full hunt: retrieval, Z3 and the agent for C/C++; the fork prover for Solidity."""
    from .harness.orchestrator import hunt as run_hunt
    d = Path(target).resolve()
    spec = {}
    tj = d / "target.json"
    if tj.exists():
        try:
            spec = json.loads(tj.read_text())
        except Exception:
            spec = {}
    ui.target_header(spec.get("name", d.name), "hunt")
    found = _stream("hunting", lambda ev: run_hunt(
        d, model=model, top_k=top_k, use_model=not no_model, on_event=ev, domain=domain))
    ui.findings(found, d)
    raise typer.Exit(0 if found else 1)


@app.command()
def scan(target: str, model: str = typer.Option(None, "--model", "-m", help=_MODEL_HELP)):
    """Reasoning agent only: the model finds, the oracle verifies."""
    from .harness.agent import run_scan
    from .llm import LLMUnavailable
    d, spec, _sources = _load(target)
    ui.target_header(spec["name"], "scan")
    try:
        found = _stream("reasoning", lambda ev: run_scan(d, model=model, on_event=ev))
    except LLMUnavailable as e:
        console.print(Panel(Text(str(e), style="warn"), title="[warn]no model[/]",
                            border_style="warn", expand=False))
        raise typer.Exit(3)
    ui.findings(found, d)
    raise typer.Exit(0 if found else 1)


@app.command()
def fuzz(repo: str,
         hint: str = typer.Option("", "--hint",
                                  help="what to fuzz, e.g. decode an image from a byte buffer"),
         seeds: str = typer.Option("", "--seeds", help="dir of seed inputs to start from"),
         secs: int = typer.Option(90, "--secs", help="fuzz time budget in seconds"),
         cores: int = typer.Option(1, "--cores", help="parallel fuzz jobs"),
         model: str = typer.Option(None, "--model", "-m", help=_MODEL_HELP)):
    """The model writes a libFuzzer harness for a repo, then the oracle proves the crash."""
    from .harness.fuzz import hunt as run_fuzz
    from .llm import judge, LLMUnavailable
    ui.target_header(Path(repo).name, "fuzz")
    try:
        finding = _stream("fuzzing", lambda ev: run_fuzz(
            repo, hint=hint, seeds=seeds, secs=secs, cores=cores,
            judge_fn=lambda s, u: judge(s, u, model), log=ev))
    except LLMUnavailable as e:
        console.print(Panel(Text(str(e), style="warn"), title="[warn]no model[/]",
                            border_style="warn", expand=False))
        raise typer.Exit(3)
    if finding is None:
        console.print(Text("no crash this run", style="muted"))
        raise typer.Exit(1)
    console.print(Text(f"entry:     {finding.entry}", style="accent"))
    console.print(Text(f"sanitizer: {finding.sanitizer}", style="success"))
    console.print(Text(finding.summary, style="muted"))
    for _fr in finding.frames:
        console.print(Text(f"  {_fr}", style="muted"))
    console.print(Text(f"poc:       {finding.poc} ({finding.poc_size} bytes)", style="accent"))
    raise typer.Exit(0)


@app.command(name="try")
def try_(target: str,
         argv: list[str] = typer.Argument(None, help="argv passed to the target"),
         stdin: str = typer.Option("", "--stdin", help="stdin bytes for the target")):
    """Run one candidate PoC by hand."""
    from .harness import CCompileRunOracle
    from .types import PoC
    d, spec, sources = _load(target)
    ui.target_header(spec["name"], "try")
    poc = PoC(argv=list(argv or []), stdin=stdin)
    verdict = _stream("running", lambda _e: CCompileRunOracle().verify(sources, poc))
    klass = verdict.sanitizer.klass if verdict.sanitizer else None
    mark = "success" if verdict.verified else "muted"
    console.print(Text(f"{poc.label()}  ->  verified={verdict.verified}  "
                       f"reason={verdict.reason}  class={klass}", style=mark))
    raise typer.Exit(0 if verdict.verified else 1)


@app.command()
def doctor():
    """Show what the toolchain has available."""
    ui.doctor()
    from .provers.evm import evm_doctor
    tools = evm_doctor()
    console.print(Text("\nEVM (Solidity) prover", style="accent"))
    for name in ("forge", "anvil", "cast"):
        path = tools.get(name)
        console.print(Text(f"  {name:13} {'found' if path else 'not found'}"
                           + (f"  {path}" if path else ""),
                           style="success" if path else "muted"))
    rpc = os.environ.get("SABBA_ETH_RPC")
    console.print(Text(f"  {'SABBA_ETH_RPC':13} {'set' if rpc else 'not set'}",
                       style="success" if rpc else "muted"))
    if not tools.get("forge"):
        console.print(Text("  install Foundry with foundryup to enable Solidity proofs",
                           style="muted"))
    from .provers.python import atheris_available
    ok = atheris_available()
    console.print(Text("\nPython fuzzing prover", style="accent"))
    console.print(Text(f"  {'atheris':13} {'found' if ok else 'not found'}",
                       style="success" if ok else "muted"))
    if not ok:
        console.print(Text("  pip install atheris to enable Python fuzzing proofs",
                           style="muted"))
    from .provers.golang import go_available, go_path
    go_ok = go_available()
    gp = go_path()
    console.print(Text("\nGo fuzzing prover", style="accent"))
    console.print(Text(f"  {'go':13} {'found' if go_ok else 'not found'}"
                       + (f"  {gp}" if gp else ""),
                       style="success" if go_ok else "muted"))
    if not go_ok:
        console.print(Text("  install Go 1.18+ (https://go.dev/dl) to enable Go fuzzing proofs",
                           style="muted"))
    from .provers.java import find_jazzer, javac_available
    jz = find_jazzer()
    console.print(Text("\nJava (Jazzer) fuzzing prover", style="accent"))
    console.print(Text(f"  {'javac':13} {'found' if javac_available() else 'not found'}",
                       style="success" if javac_available() else "muted"))
    console.print(Text(f"  {'jazzer':13} {'found' if jz else 'not found'}"
                       + (f"  {jz.launcher}" if jz else ""),
                       style="success" if jz else "muted"))
    jhome = os.environ.get("SABBA_JAZZER_HOME")
    console.print(Text(f"  {'SABBA_JAZZER_HOME':13} {'set' if jhome else 'not set'}",
                       style="success" if jhome else "muted"))
    if not (javac_available() and jz):
        console.print(Text("  install a JDK 17 and Jazzer (set SABBA_JAZZER_HOME or put "
                           "jazzer on PATH) to enable Java fuzzing proofs", style="muted"))
    from .provers.node import jazzerjs_available, node_available
    n_ok, jjs = node_available(), jazzerjs_available()
    console.print(Text("\nNode (Jazzer.js) fuzzing prover", style="accent"))
    console.print(Text(f"  {'node':13} {'found' if n_ok else 'not found'}",
                       style="success" if n_ok else "muted"))
    console.print(Text(f"  {'jazzer.js':13} {'found' if jjs else 'not found'}",
                       style="success" if jjs else "muted"))
    jjh = os.environ.get("SABBA_JAZZERJS_HOME")
    console.print(Text(f"  {'SABBA_JAZZERJS_HOME':13} {'set' if jjh else 'not set'}",
                       style="success" if jjh else "muted"))
    if not jjs:
        console.print(Text("  install Node and @jazzer.js/core (set SABBA_JAZZERJS_HOME) "
                           "to enable JavaScript/TypeScript fuzzing proofs", style="muted"))


@app.command()
def logs(lines: int = typer.Option(50, "--lines", "-n", help="how many trailing lines")):
    """Show the diagnostic log (~/.sabba/logs/sabba.log)."""
    from .log import LOG_PATH
    if not LOG_PATH.exists():
        console.print(Text("no log yet", style="warn"))
        raise typer.Exit()
    console.print(Text(str(LOG_PATH), style="muted"))
    console.print("\n".join(LOG_PATH.read_text(errors="replace").splitlines()[-lines:]))


def _git(root: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)
    return r.stdout.strip()


def _pyproject_version(root: Path) -> str:
    """Read the version straight off pyproject.toml on disk, so it reflects freshly pulled
    code rather than the metadata the running process was imported with."""
    import re
    try:
        text = (root / "pyproject.toml").read_text()
        m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
        if m:
            return m.group(1)
    except OSError:
        pass
    return ui._version()


def _version_line(root: Path) -> str:
    """A human version: the release plus the short commit and its date."""
    ver = _pyproject_version(root)
    sha = _git(root, "rev-parse", "--short", "HEAD")
    date = _git(root, "show", "-s", "--format=%cd", "--date=short", "HEAD")
    return f"{ver} ({sha}, {date})" if sha else ver


@app.command()
def version():
    """Show the installed version and commit."""
    root = Path(__file__).resolve().parent.parent
    console.print(Text(f"sabba {_version_line(root)}", style="accent"))


@app.command()
def update():
    """Pull the latest fixes, reinstall, and show the new version."""
    root = Path(__file__).resolve().parent.parent
    ui.target_header(str(root.name), "update")
    if not (root / ".git").exists():
        console.print(Text("not a git checkout; reinstall with the installer", style="warn"))
        raise typer.Exit(1)

    before = _git(root, "rev-parse", "HEAD")
    console.print(Text(f"  current  {_version_line(root)}", style="muted"))

    pull = subprocess.run(["git", "-C", str(root), "pull", "--ff-only"],
                          capture_output=True, text=True)
    if pull.returncode != 0:
        console.print(Text(pull.stderr.strip() or pull.stdout.strip(), style="warn"))
        console.print(Text("update failed; your checkout was left untouched", style="warn"))
        raise typer.Exit(1)

    after = _git(root, "rev-parse", "HEAD")
    if before == after:
        console.print(Text("already on the latest", style="success"))
        return

    console.print(Text("  reinstalling", style="muted"))
    reinstall = subprocess.run([sys.executable, "-m", "pip", "install", "-q", "-e", str(root)])
    if reinstall.returncode != 0:
        console.print(Text("pulled the latest but reinstall failed; run ./install.sh once by hand",
                           style="warn"))
        raise typer.Exit(1)

    console.print(Text(f"  updated  {_version_line(root)}", style="success"))
    console.print(Text("  restart sabba to pick up the new version", style="muted"))


@app.command()
def uninstall(yes: bool = typer.Option(False, "--yes", "-y", help="do not ask to confirm")):
    """Remove the sabba command and the ~/.sabba environment."""
    home = Path(os.environ.get("SABBA_HOME", Path.home() / ".sabba"))
    binlink = Path(os.environ.get("SABBA_BIN", Path.home() / ".local" / "bin")) / "sabba"
    ui.target_header("sabba", "uninstall")
    console.print(Text(f"remove  {home}\nremove  {binlink}", style="warn"))
    if not yes and not typer.confirm("continue"):
        raise typer.Exit(1)
    try:
        binlink.unlink()
    except FileNotFoundError:
        pass
    shutil.rmtree(home, ignore_errors=True)
    console.print(Text("sabba removed. your cloned repo was left in place.", style="success"))


def main():
    from . import config
    from .log import get_logger
    config.apply_env(config.load())
    try:
        app()
    except SystemExit:
        raise
    except BaseException:
        get_logger().exception("cli crashed")
        raise


if __name__ == "__main__":
    main()
