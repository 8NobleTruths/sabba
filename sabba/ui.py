"""Terminal presentation for the CLI.

All the colour, the banner, the spinners, and the finding panels live here so the command
functions in cli.py stay about behaviour. Rich handles non-interactive terminals on its
own, so piping the output to a file still reads cleanly.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

THEME = Theme({
    "accent": "bold cyan",
    "success": "bold green",
    "danger": "bold red",
    "warn": "yellow",
    "muted": "grey58",
    "info": "cyan",
    "key": "bold white",
})

console = Console(theme=THEME, highlight=False)

# The pixel logo, shared with the REPL so every surface shows the same mark.
_C1, _C2, _C3 = (206, 211, 220), (150, 157, 170), (104, 110, 124)
_GLYPH = {
    "S": ["#####", "#....", "#....", "#####", "....#", "....#", "#####"],
    "A": [".###.", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"],
    "B": ["####.", "#...#", "#...#", "####.", "#...#", "#...#", "####."],
}


def _lerp(a, b, t):
    return tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))


def _grad(t):
    c = _lerp(_C1, _C2, t * 2) if t < 0.5 else _lerp(_C2, _C3, (t - 0.5) * 2)
    return "#%02x%02x%02x" % c


def logo_text() -> Text:
    """The SABBA pixel logo as a rich Text, the same one the REPL shows."""
    glyphs = [_GLYPH[c] for c in "SABBA"]
    ncols = sum(len(g[0]) for g in glyphs) + (len(glyphs) - 1)
    grid = [[False] * ncols for _ in range(7)]
    x = 0
    for gi, g in enumerate(glyphs):
        w = len(g[0])
        for r in range(7):
            for c in range(w):
                if g[r][c] == "#":
                    grid[r][x + c] = True
        x += w + (1 if gi < len(glyphs) - 1 else 0)
    out = Text()
    for top in range(0, 7, 2):
        out.append("  ")
        for c in range(ncols):
            t = grid[top][c]
            b = top + 1 < 7 and grid[top + 1][c]
            ch = "█" if (t and b) else "▀" if t else "▄" if b else " "
            out.append(ch, style=_grad(c / (ncols - 1)))
        out.append("\n")
    return out


def _version() -> str:
    try:
        from importlib.metadata import version
        return version("sabba")
    except Exception:
        return "0.0.0"


def banner(compact: bool = False) -> None:
    console.print()
    console.print(logo_text(), end="")
    console.print(Text("  security bug-finder that proves every finding", style="muted"))
    if not compact:
        console.print(Text(f"  v{_version()}   github.com/8NobleTruths/sabba", style="muted"))
    console.print()


def _has(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def environment() -> list[tuple[str, bool, str]]:
    """(label, ok, detail) rows describing what the toolchain has available."""
    rows = []
    cc = _has("clang")
    rows.append(("compiler + sanitizers", cc, "clang" if cc else "install clang/llvm"))
    try:
        import z3  # noqa: F401
        rows.append(("z3 solver", True, "ready"))
    except Exception:
        rows.append(("z3 solver", False, "pip install z3-solver"))
    try:
        import tree_sitter_c  # noqa: F401
        rows.append(("c parser", True, "tree-sitter"))
    except Exception:
        rows.append(("c parser", False, "pip install tree-sitter-c"))
    backend = os.environ.get("SABBA_LLM_BACKEND", "glm")
    keyed = any(os.environ.get(k) for k in
                ("OPENROUTER_API_KEY", "SABBA_LLM_API_KEY", "ANTHROPIC_API_KEY"))
    rows.append((f"model ({backend})", keyed, "key set" if keyed else "no key, oracle still works"))
    return rows


def doctor() -> None:
    banner(compact=True)
    t = Table(box=None, pad_edge=False)
    t.add_column("", width=2)
    t.add_column("component", style="key")
    t.add_column("detail", style="muted")
    for label, ok, detail in environment():
        mark = Text("ok", style="success") if ok else Text("--", style="warn")
        t.add_row(mark, label, detail)
    console.print(Panel(t, title="[accent]environment[/]", border_style="muted", expand=False))
    console.print()


def welcome() -> None:
    banner()
    cmds = Table(box=None, pad_edge=False, show_header=False)
    cmds.add_column("cmd", style="accent", no_wrap=True)
    cmds.add_column("what it does", style="muted")
    cmds.add_row("sabba hunt <dir>", "retrieval, then z3, then the model; oracle confirms all")
    cmds.add_row("sabba solve <dir>", "z3 synthesizes overflow inputs, oracle confirms (no model)")
    cmds.add_row("sabba verify <dir>", "run a target's known PoC through the oracle (no model)")
    cmds.add_row("sabba scan <dir>", "reasoning agent only (needs a model)")
    cmds.add_row("sabba doctor", "show what the toolchain has available")
    cmds.add_row("sabba update", "pull the latest and reinstall")
    cmds.add_row("sabba uninstall", "remove the command and its environment")
    console.print(Panel(cmds, title="[accent]commands[/]", border_style="muted", expand=False))
    ready = sum(1 for _, ok, _ in environment() if ok)
    console.print(Text(f"  {ready}/4 ready   try:  sabba solve targets/cwe121_stack_overflow",
                       style="muted"))
    console.print()


def target_header(name: str, action: str) -> None:
    console.print(Rule(Text(f"{action}  {name}", style="accent"), style="muted"))


def event(msg: str):
    """Map an engine log line to a styled line, or None to suppress it."""
    low = msg.strip()
    if low.startswith("Retrieval surfaced") or low.startswith("  - ") or low.startswith("Already"):
        return None
    if low.startswith("[z3]"):
        return Text("  solving  ", style="info") + Text(low[4:].strip(), style="muted")
    if "confirmed" in low and "not confirmed" not in low:
        return Text("  confirmed  ", style="success") + Text(low.split("confirmed", 1)[1].strip(),
                                                             style="key")
    if "not confirmed" in low:
        return Text("  ruled out  ", style="muted") + Text(low.split("(", 1)[-1].rstrip(")"),
                                                           style="muted")
    if low.startswith("[stage]"):
        return Text("› ", style="accent") + Text(low[7:].strip(), style="key")
    return None


def _code_snippet(target_dir: Path, file_name: str, line: int | None):
    if not line:
        return None
    path = Path(target_dir) / file_name
    if not path.exists():
        return None
    try:
        text = path.read_text()
    except OSError:
        return None
    lo = max(1, line - 2)
    hi = line + 1
    return Syntax(text, "c", line_numbers=True, line_range=(lo, hi),
                  highlight_lines={line}, theme="ansi_dark", word_wrap=False)


def findings(items, target_dir) -> None:
    console.print()
    if not items:
        console.print(Panel(Text("no bug reproduced", style="muted"),
                            border_style="muted", expand=False))
        return
    for f in items:
        klass = f.verdict.sanitizer.klass if (f.verdict and f.verdict.sanitizer) else "buffer overflow"
        loc = f"{f.file}:{f.line}" if f.line else f.file
        body = Table(box=None, pad_edge=False, show_header=False)
        body.add_column(style="muted", no_wrap=True)
        body.add_column(style="key")
        body.add_row("where", f"{f.function}  {loc}")
        body.add_row("input", f.poc.label() if f.poc else "")
        if f.rationale:
            body.add_row("proof", f.rationale)
        parts = [body]
        snip = _code_snippet(target_dir, f.file, f.line)
        if snip is not None:
            parts.append(snip)
        console.print(Panel(Group(*parts),
                            title=f"[danger]● {f.cwe}  {klass}[/]",
                            border_style="danger", expand=False))
    console.print(Text(f"  {len(items)} confirmed finding(s)", style="success"))
    console.print()
