"""The interactive Sabba app.

A full-screen terminal interface with a pixel logo, a compact composer anchored at the
bottom, and a slash-command menu that rises from the bottom when you type "/". Set a model
and a key, then chat with the model in plain language. The model streams its reply and can
call tools (solve, verify, bash, clone_repo, web_search, web_fetch, and the file tools).
Press ESC to stop a running task. Launched by `sabba` with no arguments, or `sabba tui`.
"""
from __future__ import annotations

import os
import random
import signal
import time
from pathlib import Path

from rich.markdown import Markdown
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from textual import events, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.widgets import OptionList, Static, TextArea
from textual.widgets.option_list import Option

from . import chat, config, history, memory
from .llm import LLMUnavailable, get_provider
from .log import get_logger
from .ui import environment

LOG = get_logger()

MODELS = [
    "nvidia/nemotron-3-ultra-550b-a55b:free",
    "z-ai/glm-5.2",
    "deepseek/deepseek-v4-flash",
    "deepseek/deepseek-v4-pro",
    "moonshotai/kimi-k2.7-code",
    "qwen/qwen-2.5-coder-32b-instruct",
    "anthropic/claude-3.5-sonnet",
    "deepseek/deepseek-chat-v3-0324",
]
COMMANDS = [
    ("add-model-key", "add an OpenRouter API key"),
    ("add-memory-key", "add a Voyage key for long-term memory"),
    ("model", "choose the model"),
    ("resume", "reopen a saved conversation"),
    ("new", "start a fresh conversation"),
    ("solve", "z3 and the oracle over a directory"),
    ("hunt", "retrieval, z3, then the model"),
    ("verify", "run a target's known PoC"),
    ("doctor", "toolchain status"),
    ("clear", "clear the screen"),
    ("help", "show help"),
    ("quit", "exit"),
]
NOARG = {"new", "doctor", "clear", "help", "quit"}
PATHARG = {"solve", "hunt", "verify"}

_GLYPH = {
    "S": ["#####", "#....", "#....", "#####", "....#", "....#", "#####"],
    "A": [".###.", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"],
    "B": ["####.", "#...#", "#...#", "####.", "#...#", "#...#", "####."],
}
_C1, _C2, _C3 = (206, 211, 220), (150, 157, 170), (104, 110, 124)   # gray pixel gradient
_SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_VERBS = [
    "Thinking", "Pondering", "Reasoning", "Analyzing", "Cerebrating",
    "Cogitating", "Considering", "Contemplating", "Deciphering", "Deliberating",
    "Determining", "Percolating", "Reticulating", "Ruminating", "Mulling",
    "Noodling", "Puzzling", "Synthesizing", "Inferring", "Computing",
    "Crunching", "Processing", "Tracing", "Probing", "Auditing",
    "Fuzzing", "Sniffing", "Triaging", "Hunting", "Working",
]


def _lerp(a, b, t):
    return tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))


def _grad(t: float) -> str:
    c = _lerp(_C1, _C2, t * 2) if t < 0.5 else _lerp(_C2, _C3, (t - 0.5) * 2)
    return "#%02x%02x%02x" % c


def pixel_logo(word="SABBA", box_w=0):
    glyphs = [_GLYPH[c] for c in word]
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
    pad = max(0, (box_w - ncols) // 2) if box_w else 0
    out = Text()
    for top in range(0, 7, 2):
        out.append(" " * pad)
        for c in range(ncols):
            t = grid[top][c]
            b = top + 1 < 7 and grid[top + 1][c]
            ch = "█" if (t and b) else "▀" if t else "▄" if b else " "
            out.append(ch, style=_grad(c / (ncols - 1)))
        out.append(chr(10))
    return out


def _finding_panel(f, target_dir: Path) -> Panel:
    from rich.console import Group
    klass = f.verdict.sanitizer.klass if (f.verdict and f.verdict.sanitizer) else "buffer overflow"
    loc = f"{f.file}:{f.line}" if f.line else f.file
    body = Table(box=None, pad_edge=False, show_header=False)
    body.add_column(style="#8a7f74", no_wrap=True)
    body.add_column(style="white")
    body.add_row("where", f"{f.function}  {loc}")
    body.add_row("input", f.poc.label() if f.poc else "")
    if f.rationale:
        body.add_row("proof", f.rationale)
    parts = [body]
    src = target_dir / f.file
    if f.line and src.exists():
        try:
            lo, hi = max(1, f.line - 2), f.line + 1
            parts.append(Syntax(src.read_text(), "c", line_numbers=True, line_range=(lo, hi),
                                highlight_lines={f.line}, theme="ansi_dark"))
        except OSError:
            pass
    return Panel(Group(*parts), title=f"[bold #9aa1ad]{f.cwe}  {klass}[/]",
                 border_style="#9aa1ad", expand=False)


def _msg_text(content) -> str:
    """Best-effort text of a stored message content (a string or content blocks)."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(b.get("text", "") for b in content
                       if isinstance(b, dict) and b.get("type") == "text")
    return ""


class Composer(TextArea):
    """A soft-wrapping, auto-growing chat composer.

    Long text wraps onto as many rows as it needs and the box grows with it (up to MAX_ROWS,
    then it scrolls), so the whole message stays visible instead of only the last line. Enter
    submits; Ctrl+J inserts a newline. It keeps the small slice of the Input API the rest of
    the app relies on: .value, .cursor_position, .placeholder, and a .password mode for the
    hidden API-key paste, so nothing above it had to change.
    """

    MAX_ROWS = 10          # visual rows before the composer starts to scroll
    BULLET = "•"

    class Submitted(Message):
        """Posted when the user presses Enter. value is the composed text (or the real key
        in password mode)."""
        def __init__(self, value: str) -> None:
            self.value = value
            super().__init__()

    def __init__(self, placeholder: str = "", **kwargs) -> None:
        super().__init__(soft_wrap=True, show_line_numbers=False,
                         tab_behavior="focus", **kwargs)
        self._placeholder = placeholder
        self._password = False
        self._secret = ""

    # -- Input-compatible surface the app uses --------------------------------
    @property
    def value(self) -> str:
        return self._secret if self._password else self.text

    @value.setter
    def value(self, v: str) -> None:
        v = v or ""
        if self._password:
            self._secret = v
            self.text = self.BULLET * len(v)
        else:
            self.text = v
        self._to_end()
        self._autosize()
        self._sync_placeholder()

    @property
    def cursor_position(self) -> int:
        return len(self.value)

    @cursor_position.setter
    def cursor_position(self, _n: int) -> None:
        self._to_end()

    @property
    def password(self) -> bool:
        return self._password

    @password.setter
    def password(self, on: bool) -> None:
        # Switching mode always starts from an empty field: the bullets shown in password mode
        # are not real content, and a half-typed command must not become the key.
        self._password = bool(on)
        self._secret = ""
        try:
            self.text = ""
        except Exception:  # noqa: BLE001
            pass
        self._autosize()
        self._sync_placeholder()

    @property
    def placeholder(self) -> str:
        return self._placeholder

    @placeholder.setter
    def placeholder(self, text: str) -> None:
        self._placeholder = text or ""
        self._sync_placeholder()

    # -- growth and the placeholder hint --------------------------------------
    def _to_end(self) -> None:
        try:
            self.move_cursor(self.document.end)
        except Exception:  # noqa: BLE001
            pass

    def _autosize(self) -> None:
        """Grow to the number of wrapped rows the text needs, clamped to [1, MAX_ROWS]."""
        try:
            rows = self.wrapped_document.height
        except Exception:  # noqa: BLE001
            rows = self.text.count("\n") + 1
        self.styles.height = max(1, min(self.MAX_ROWS, rows))

    def _sync_placeholder(self) -> None:
        """Show the hint on the box border while the composer is empty."""
        try:
            box = self.screen.query_one("#composer-box")
        except Exception:  # noqa: BLE001
            return
        box.border_subtitle = self._placeholder if self.value == "" else ""

    def on_mount(self) -> None:
        self._autosize()
        self._sync_placeholder()

    def on_resize(self, event: events.Resize) -> None:
        self._autosize()

    def on_paste(self, event: events.Paste) -> None:
        # In password mode a pasted key must never be echoed: keep it in _secret and show
        # bullets. Otherwise let TextArea insert the text (Changed then grows the box).
        if self._password:
            self._secret += event.text
            self.text = self.BULLET * len(self._secret)
            self._to_end()
            event.prevent_default(); event.stop()

    def on_key(self, event: events.Key) -> None:
        app = self.app
        # the slash menu owns the arrows and enter while it is open
        if getattr(app, "menu_open", False):
            if event.key == "down":
                app.move_menu(1); event.prevent_default(); event.stop()
            elif event.key == "up":
                app.move_menu(-1); event.prevent_default(); event.stop()
            elif event.key == "enter":
                app.choose_menu(); event.prevent_default(); event.stop()
            elif event.key == "escape":
                app.close_menu(); event.prevent_default(); event.stop()
            return
        # recall a queued message with up/down only on an empty composer, so up/down still
        # move the cursor between rows once there is text to edit
        if getattr(app, "_queue", None) and self.value == "" and event.key in ("up", "down"):
            app.move_queue(-1 if event.key == "up" else 1)
            event.prevent_default(); event.stop(); return
        if getattr(app, "_queue_sel", -1) >= 0 and event.key == "enter":
            app.edit_queued(); event.prevent_default(); event.stop(); return
        if event.key == "escape":
            if getattr(app, "_queue_sel", -1) >= 0:
                app._queue_sel = -1
                app._render_queue()
                app._pump_queue()
            else:
                app.action_stop()
            event.prevent_default(); event.stop(); return
        # password entry: mask every character, submit the real key on enter
        if self._password:
            if event.key == "enter":
                self.post_message(self.Submitted(self._secret))
            elif event.key == "backspace":
                self._secret = self._secret[:-1]
                self.text = self.BULLET * len(self._secret); self._to_end()
            elif event.character and event.character.isprintable():
                self._secret += event.character
                self.text = self.BULLET * len(self._secret); self._to_end()
            event.prevent_default(); event.stop(); return
        # normal editing: Ctrl+J is a newline, Enter submits
        if event.key == "ctrl+j":
            self.insert("\n"); event.prevent_default(); event.stop(); return
        if event.key == "enter":
            self.post_message(self.Submitted(self.value))
            event.prevent_default(); event.stop(); return


class SabbaApp(App):
    CSS = """
    Screen { background: ansi_default; }
    #header { height: 9; background: ansi_default; }
    #brand { width: 3fr; padding: 1 1 0 1; background: ansi_default; }
    #overview {
        width: 2fr; height: 9; border: round #454b57; padding: 0 1; margin: 0 1 0 0;
        background: ansi_default; border-title-color: #9aa1ad; border-title-align: left;
    }
    #body { height: 1fr; background: ansi_default; }
    #leftcol { width: 3fr; background: ansi_default; }
    #rightcol { width: 2fr; background: ansi_default; }
    #log {
        height: 1fr; border: round #454b57; background: ansi_default; padding: 0 1; margin: 0 1 0 1;
        border-title-color: #9aa1ad; border-title-align: left;
    }
    #slash-menu {
        display: none; height: auto; max-height: 9; margin: 0 1 0 1;
        border: round #454b57; background: ansi_default; color: #cdd6e6;
    }
    #activity { height: 1; padding: 0 2; background: ansi_default; color: #9aa1ad; }
    #queue { display: none; height: auto; max-height: 6; background: ansi_default; padding: 0 1; margin: 0 1 0 1; }
    #composer-box {
        height: auto; min-height: 3; border: round #454b57; margin: 0 1 1 1;
        background: ansi_default; border-subtitle-color: #6b7280; border-subtitle-align: left;
    }
    #prompt { width: 3; content-align: center top; padding: 0; color: #8a91a0; text-style: bold; }
    #composer {
        border: none; background: ansi_default; color: #cdd6e6; height: auto; padding: 0;
        scrollbar-size-vertical: 1;
    }
    #context {
        height: auto; border: round #454b57; padding: 0 1; margin: 0 1 1 0;
        background: ansi_default; border-title-color: #9aa1ad; border-title-align: left;
    }
    #sessions {
        height: 1fr; border: round #454b57; padding: 0 1; margin: 0 1 1 0;
        background: ansi_default; border-title-color: #9aa1ad; border-title-align: left;
    }
    #status { height: 1; padding: 0 1; background: ansi_default; color: #7b8aa8; }
    .you { background: #2f333d; color: white; width: 1fr; padding: 0 1; }
    """
    BINDINGS = [("ctrl+q", "quit", "quit"),
                ("ctrl+l", "clear", "clear"), ("escape", "stop", "stop"),
                ("pageup", "log_up", "scroll up"), ("pagedown", "log_down", "scroll down")]

    def get_driver_class(self):
        # Do not capture the mouse, so the terminal keeps native drag to select
        # and copy. Scroll the console with PageUp / PageDown instead.
        base = super().get_driver_class()

        class _NoMouseDriver(base):
            def __init__(self, *args, **kwargs):
                kwargs["mouse"] = False
                super().__init__(*args, **kwargs)

        return _NoMouseDriver

    def __init__(self):
        super().__init__(ansi_color=True)
        self.cfg = config.load()
        self.messages: list = []
        self.awaiting = None            # None | "model" | "memory": which key we are collecting
        self.menu_open = False
        self.menu_items: list = []
        self.ctl = chat.Ctl()
        self.cur: Static | None = None
        self.buf = ""
        self.session_id: str | None = None
        self.session_title = ""
        self.last_assistant = ""
        self.n_repos = 0
        self.n_bugs = 0
        self.n_tasks = 0
        self._start = 0.0
        self._activity = ""
        self._spin_i = 0
        self._thinking = None
        self._status_verb = ""
        self._status_t0 = 0.0
        self._status_ticks = 0
        self._queue = []
        self._queue_sel = -1
        self._stream_dirty = False
        self._net_last = None

    def compose(self) -> ComposeResult:
        with Horizontal(id="header"):
            yield Static(self._brand(), id="brand")
            yield Static(self._overview(), id="overview")
        with Horizontal(id="body"):
            with Vertical(id="leftcol"):
                yield VerticalScroll(id="log")
                yield OptionList(id="slash-menu")
                yield Static("", id="activity")
                yield Static("", id="queue")
                with Horizontal(id="composer-box"):
                    yield Static(">", id="prompt")
                    yield Composer(placeholder="type a command, chat, or a GitHub URL", id="composer")
            with Vertical(id="rightcol"):
                yield Static(self._ctx_panel(), id="context")
                yield Static(self._sessions(), id="sessions")
        yield Static(self._status(), id="status")

    def on_mount(self) -> None:
        for wid, title in (("overview", "SYSTEM OVERVIEW"), ("log", "SABBA CONSOLE"),
                           ("context", "CONTEXT"), ("sessions", "SESSIONS")):
            self.query_one("#" + wid).border_title = title
        self._start = time.monotonic()
        self.set_interval(3.0, self._tick)
        self.set_interval(0.12, self._spin_tick)
        box = self.query_one("#composer", Composer)
        box.focus()
        box._sync_placeholder()
        self._sys("ready. type / for the menu, or /add-model-key then /model to chat. "
                  "Enter sends, Ctrl+J adds a newline.")

    def _status_line(self) -> Text:
        el = int(time.monotonic() - self._status_t0)
        return (Text(f"  {_SPIN[self._spin_i]} ", style="#9aa1ad")
                + Text(f"{self._status_verb}… ", style="#9aa1ad")
                + Text(f"({el}s · esc to interrupt)", style="#6b6259"))

    def _spin_tick(self) -> None:
        self._spin_i = (self._spin_i + 1) % len(_SPIN)
        if self._thinking is not None:
            self._status_ticks += 1
            if self._status_ticks % 26 == 0:
                self._status_verb = random.choice(_VERBS)
            self._thinking.update(self._status_line())
        if self.cur is not None and self._stream_dirty:
            self._stream_dirty = False
            try:
                self.cur.update(Markdown(self.buf))
            except Exception:
                self.cur.update(Text(self.buf, style="white"))
            self.query_one("#log", VerticalScroll).scroll_end(animate=False)
        try:
            w = self.query_one("#activity", Static)
        except Exception:
            return
        if self._activity:
            w.display = True
            w.update(Text(f"  {_SPIN[self._spin_i]} {self._activity}", style="#9aa1ad"))
        else:
            w.display = False
            w.update("")

    def _set_activity(self, text: str) -> None:
        self._activity = text

    def on_unmount(self) -> None:
        self._persist()

    # rendering --------------------------------------------------------------
    def on_resize(self, event) -> None:
        try:
            self.query_one("#brand", Static).update(self._brand())
        except Exception:
            pass

    def _brand_width(self) -> int:
        w = self.size.width if (self.size and self.size.width) else 120
        return max(12, int(w * 3 / 5) - 3)

    def _brand(self) -> Text:
        box = self._brand_width()
        t = Text()
        t.append_text(pixel_logo(box_w=box))
        def ctr(txt):
            return " " * max(0, (box - len(txt)) // 2)
        sub = "security bug-finder that proves every finding"
        t.append(ctr(sub) + sub + "\n", style="#7b8aa8")
        segs = [("type ", "#7b8aa8"), ("/", "#9aa1ad"), ("  ·  ", "#7b8aa8"),
                ("/add-model-key", "#9aa1ad"), (" then ", "#7b8aa8"), ("/model", "#9aa1ad"),
                ("  ·  ", "#7b8aa8"), ("esc", "#9aa1ad"), (" to stop", "#7b8aa8")]
        t.append(ctr("".join(x for x, _ in segs)), style="#7b8aa8")
        for txt, st in segs:
            t.append(txt, style=st)
        return t

    def _bar(self, pct) -> str:
        pct = max(0, min(100, int(pct)))
        fill = pct // 10
        return f"[{'|' * fill}{'.' * (10 - fill)}] {pct:3d}%"

    def _sysbars(self):
        try:
            import psutil
            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory().percent
            disk = psutil.disk_usage(str(Path.cwd())).percent
            return (self._bar(cpu), self._bar(mem), self._bar(disk), self._bar(self._net_pct()))
        except Exception:
            return ("[..........]  n/a",) * 4

    def _net_pct(self) -> float:
        try:
            import psutil
            now = time.monotonic()
            io = psutil.net_io_counters()
            total = io.bytes_sent + io.bytes_recv
            if self._net_last is None:
                self._net_last = (now, total)
                return 0.0
            lt, lb = self._net_last
            self._net_last = (now, total)
            rate = (total - lb) / max(0.001, now - lt)   # bytes/sec
            return min(100.0, rate / 5_000_000 * 100)     # 5 MB/s reference = full bar
        except Exception:
            return 0.0

    def _overview(self) -> Table:
        up = int(time.monotonic() - (self._start or time.monotonic()))
        h, m, s = up // 3600, (up % 3600) // 60, up % 60
        cpu, mem, disk, net = self._sysbars()
        t = Table(box=None, pad_edge=False, show_header=False)
        t.add_column(style="#7b8aa8", no_wrap=True)
        t.add_column(justify="right", style="#4ade80", no_wrap=True)
        t.add_column(width=3)
        t.add_column(style="#7b8aa8", no_wrap=True)
        t.add_column(style="#4ade80", no_wrap=True)
        t.add_row("REPOS SCANNED", str(self.n_repos), "", "CPU", cpu)
        t.add_row("BUGS CONFIRMED", str(self.n_bugs), "", "MEM", mem)
        t.add_row("TASKS DONE", str(self.n_tasks), "", "DISK", disk)
        t.add_row("UPTIME", f"{h}h {m:02d}m {s:02d}s", "", "NET", net)
        return t

    def _ctx_panel(self) -> Table:
        t = Table(box=None, pad_edge=False, show_header=False)
        t.add_column(style="#7b8aa8", no_wrap=True)
        t.add_column(style="#9fe8b0")
        t.add_row("MODEL", self.cfg.get("model", "not set"))
        t.add_row("CONTEXT", "128k")
        t.add_row("MEMORY", "on" if self.cfg.get("voyage_key") else "off")
        t.add_row("ASAN", "on")
        t.add_row("SOLVER", "Z3")
        t.add_row("WORKSPACE", str(Path.cwd()))
        t.add_row("SESSION", self.session_id or "(none)")
        return t

    def _sessions(self) -> Text:
        rows = history.sessions()
        t = Text()
        if not rows:
            t.append("no saved sessions yet\n", style="#7b8aa8")
        for s in rows[:6]:
            active = s["id"] == self.session_id
            t.append(("> " if active else "  ") + s["id"],
                     style="#4ade80" if active else "#8fa0bd")
            if active:
                t.append("  (active)", style="#4ade80")
            t.append("\n")
        t.append("\nuse /resume <session>", style="#5b6b88")
        return t

    def _status(self) -> Text:
        mem = "on" if self.cfg.get("voyage_key") else "off"
        return Text(f" MODEL: {self.cfg.get('model','not set')}   |   "
                    f"KEY: {config.masked(self.cfg.get('api_key',''))}   |   "
                    f"MEMORY: {mem}        ESC: stop   |   drag select + Cmd/Ctrl+C copy  ·  PgUp/PgDn scroll   |   CTRL+Q: quit",
                    style="#7b8aa8")

    def _refresh_status(self) -> None:
        self._refresh_panels()

    def _refresh_panels(self) -> None:
        try:
            self.query_one("#overview", Static).update(self._overview())
            self.query_one("#context", Static).update(self._ctx_panel())
            self.query_one("#sessions", Static).update(self._sessions())
            self.query_one("#status", Static).update(self._status())
        except Exception:
            pass

    def _tick(self) -> None:
        try:
            self.query_one("#overview", Static).update(self._overview())
        except Exception:
            pass

    def _emit(self, renderable, classes: str = "") -> None:
        log = self.query_one("#log", VerticalScroll)
        log.mount(Static(renderable, classes=classes))
        log.scroll_end(animate=False)

    def _sys(self, t): self._emit(Text("  " + t, style="#8f96a3"))
    def _err(self, t): self._emit(Text("  " + t, style="bold red"))
    def _you(self, t):
        self._emit(Text("› ", style="#8a91a0") + Text(t, style="bold white"), classes="you")

    async def _assistant_start(self) -> None:
        log = self.query_one("#log", VerticalScroll)
        self._status_verb = random.choice(_VERBS)
        self._status_t0 = time.monotonic()
        self._status_ticks = 0
        self._thinking = Static(self._status_line())
        await log.mount(self._thinking)
        self.cur = Static(Text(""))
        await log.mount(self.cur)
        self.buf = ""
        log.scroll_end(animate=False)

    def _grow(self, chunk: str) -> None:
        if self._thinking is not None:
            self._thinking.display = False
            self._thinking = None
        self.buf += chunk
        self._stream_dirty = True

    def _assistant_end(self, pt, ct) -> None:
        self._stream_dirty = False
        if self._thinking is not None:
            self._thinking.display = False
            self._thinking = None
        if self.cur is not None and self.buf:
            self.cur.update(Markdown(self.buf))
        if self.buf:
            self.last_assistant = self.buf
        if pt is not None or ct is not None:
            self._emit(Text(f"  {pt or 0} in  ·  {ct or 0} out", style="#6b6259"))
        self.cur = None

    def _tool_render(self, name, args):
        return Text(f"  · {name}(" + ", ".join(f"{k}={str(v)[:60]}" for k, v in args.items()) + ")",
                    style="#8a7f74")

    def _result_render(self, name, out):
        return Panel(Text(out[:2000], style="white"), title=f"[#8a7f74]{name}[/]",
                     border_style="#454b57", expand=False)

    # slash menu -------------------------------------------------------------
    def _menu_items(self, value: str):
        body = value[1:]
        tokens = body.split(" ")
        if len(tokens) > 1:
            if tokens[0] == "model":
                q = " ".join(tokens[1:]).lower()
                return [("model", m, m) for m in MODELS if q in m.lower()]
            if tokens[0] == "resume":
                q = " ".join(tokens[1:]).lower()
                return [("session", s["id"], f"{s['title']}  ({s['updated'][:16]})")
                        for s in history.sessions() if q in s["title"].lower()]
            return []
        q = tokens[0].lower()
        return [("cmd", name, dict(COMMANDS).get(name, "")) for name, _ in COMMANDS
                if name.startswith(q)]

    def _fill_menu(self, items):
        ol = self.query_one("#slash-menu", OptionList)
        ol.clear_options()
        for kind, val, label in items:
            if kind == "cmd":
                ol.add_option(Option(Text(f"/{val}", style="#9aa1ad") + Text(f"   {label}", style="#8a7f74")))
            else:
                ol.add_option(Option(label))
        self.menu_items = items
        if items:
            ol.highlighted = 0

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        box = self.query_one("#composer", Composer)
        box._autosize()
        box._sync_placeholder()
        if self.awaiting:
            return
        v = box.value
        if v.startswith("/"):
            items = self._menu_items(v)
            self._fill_menu(items)
            self.menu_open = bool(items)
            self.query_one("#slash-menu", OptionList).display = self.menu_open
        else:
            self.close_menu()

    def move_menu(self, delta: int) -> None:
        ol = self.query_one("#slash-menu", OptionList)
        if ol.option_count == 0:
            return
        ol.highlighted = max(0, min(ol.option_count - 1, (ol.highlighted or 0) + delta))

    def close_menu(self) -> None:
        self.menu_open = False
        self.query_one("#slash-menu", OptionList).display = False

    def _set_input(self, value: str) -> None:
        box = self.query_one("#composer", Composer)
        box.value = value
        box.cursor_position = len(value)

    def choose_menu(self) -> None:
        ol = self.query_one("#slash-menu", OptionList)
        idx = ol.highlighted
        if idx is None or idx >= len(self.menu_items):
            return
        kind, val, _label = self.menu_items[idx]
        if kind == "model":
            self.close_menu(); self._set_input(""); self._apply_model(val)
        elif kind == "session":
            self.close_menu(); self._set_input(""); self._resume(val)
        elif val in ("model", "resume"):
            self._set_input(f"/{val} ")
        elif val == "add-model-key":
            self.close_menu(); self._set_input(""); self._start_key_entry("model")
        elif val == "add-memory-key":
            self.close_menu(); self._set_input(""); self._start_key_entry("memory")
        elif val in PATHARG:
            self.close_menu(); self._set_input(f"/{val} ")
        else:
            self.close_menu(); self._set_input(""); self._slash(f"/{val}")

    # input ------------------------------------------------------------------
    def on_composer_submitted(self, event: Composer.Submitted) -> None:
        text = event.value.strip()
        self._set_input("")
        if self.awaiting:
            kind, self.awaiting = self.awaiting, None
            box = self.query_one("#composer", Composer)
            box.password = False
            box.placeholder = "Type a message, a /command, or a GitHub URL"
            self._save_key(kind, text)
            return
        if not text:
            return
        self.close_menu()
        if text.startswith("/"):
            self._you(text)
            self._slash(text)
        elif self._busy():
            self._queue.append(text)
            self._queue_sel = -1
            self._render_queue()
        else:
            self._you(text)
            self._worker = self._chat(text)

    def action_clear(self) -> None:
        self.query_one("#log", VerticalScroll).remove_children()

    def action_log_up(self) -> None:
        self.query_one("#log", VerticalScroll).scroll_page_up()

    def action_log_down(self) -> None:
        self.query_one("#log", VerticalScroll).scroll_page_down()

    def action_stop(self) -> None:
        running = [w for w in self.workers if getattr(w, "group", "") == "task"]
        if not running:
            return
        self.ctl.stop.set()
        if self.ctl.proc:
            try:
                os.killpg(os.getpgid(self.ctl.proc.pid), signal.SIGTERM)
            except Exception:
                pass
        for w in running:
            w.cancel()

    # message queue ----------------------------------------------------------
    def _busy(self) -> bool:
        from textual.worker import WorkerState
        return any(getattr(w, "group", "") == "task" and w.state == WorkerState.RUNNING
                   for w in self.workers)

    def _render_queue(self) -> None:
        w = self.query_one("#queue", Static)
        if not self._queue:
            w.display = False
            w.update("")
            return
        w.display = True
        t = Text()
        for i, msg in enumerate(self._queue):
            one = msg if len(msg) <= 68 else msg[:65] + "…"
            if i == self._queue_sel:
                t.append(f"  ▸ {one}\n", style="bold #cdd6e6")
            else:
                t.append(f"  ⧗ {one}\n", style="#8a91a0")
        t.append(f"  queued {len(self._queue)} · ↑↓ select · enter to edit", style="#6b6259")
        w.update(t)

    def _pump_queue(self) -> None:
        if self._busy() or self._queue_sel != -1 or not self._queue:
            return
        text = self._queue.pop(0)
        self._render_queue()
        self._you(text)
        self._worker = self._chat(text)

    def on_worker_state_changed(self, event) -> None:
        from textual.worker import WorkerState
        if getattr(event.worker, "group", "") == "task" and event.state in (
                WorkerState.SUCCESS, WorkerState.CANCELLED, WorkerState.ERROR):
            self.call_later(self._pump_queue)

    def move_queue(self, delta: int) -> None:
        if not self._queue:
            return
        if self._queue_sel == -1:
            self._queue_sel = len(self._queue) - 1 if delta < 0 else -1
        else:
            self._queue_sel += delta
            if self._queue_sel < 0:
                self._queue_sel = 0
            elif self._queue_sel >= len(self._queue):
                self._queue_sel = -1
        self._render_queue()

    def edit_queued(self) -> None:
        if not (0 <= self._queue_sel < len(self._queue)):
            return
        text = self._queue.pop(self._queue_sel)
        self._queue_sel = -1
        box = self.query_one("#composer", Composer)
        box.value = text
        box.cursor_position = len(text)
        box.focus()
        self._render_queue()
        self._activity = ""
        self._sys("stopped")

    def _slash(self, text: str) -> None:
        parts = text[1:].split()
        cmd = parts[0].lower() if parts else ""
        arg = " ".join(parts[1:]).strip()
        if cmd in ("help", "h"):
            self._help()
        elif cmd in ("model", "m"):
            self._apply_model(arg) if arg else self._sys("usage: /model <id> (or type / and pick)")
        elif cmd in ("add-model-key", "key"):
            self._save_key("model", arg) if arg else self._start_key_entry("model")
        elif cmd == "add-memory-key":
            self._save_key("memory", arg) if arg else self._start_key_entry("memory")
        elif cmd == "resume":
            self._resume(arg) if arg else self._resume_list()
        elif cmd == "new":
            self._new_session()
        elif cmd in PATHARG:
            (self._op(cmd, arg)) if arg else self._sys(f"usage: /{cmd} <directory>")
        elif cmd == "doctor":
            self._doctor()
        elif cmd in ("clear", "cls"):
            self.action_clear()
        elif cmd in ("quit", "q", "exit"):
            self.exit()
        else:
            self._sys(f"unknown command /{cmd}  (type / for the menu)")

    def _help(self) -> None:
        t = Table(box=None, pad_edge=False, show_header=False)
        t.add_column(style="#9aa1ad", no_wrap=True)
        t.add_column(style="#8a7f74")
        for name, help_txt in COMMANDS:
            t.add_row(f"/{name}", help_txt)
        t.add_row("just type", "chat; the model can clone repos, run bash, search the web")
        self._emit(Panel(t, title="[bold #9aa1ad]commands[/]", border_style="#454b57", expand=False))

    def _doctor(self) -> None:
        t = Table(box=None, pad_edge=False, show_header=False)
        t.add_column(width=3); t.add_column(style="white"); t.add_column(style="#8a7f74")
        for label, ok, detail in environment():
            t.add_row(Text("ok" if ok else "--", style="green" if ok else "#8f96a3"), label, detail)
        self._emit(Panel(t, title="[bold #9aa1ad]environment[/]", border_style="#454b57", expand=False))

    def _apply_model(self, model: str) -> None:
        self.cfg["model"] = model
        self.cfg.setdefault("backend", "openrouter")
        config.save(self.cfg); config.apply_env(self.cfg); self._reset_provider()
        self._sys(f"model set to {model}"); self._refresh_status()

    def _start_key_entry(self, kind: str) -> None:
        self.awaiting = kind
        box = self.query_one("#composer", Composer)
        box.password = True
        which = "OpenRouter" if kind == "model" else "Voyage"
        box.placeholder = f"paste your {which} key and press Enter"
        self._sys(f"paste your {which} key (hidden, saved to ~/.sabba/config.json)")

    def _save_key(self, kind: str, key: str) -> None:
        key = key.strip()
        if not key:
            self._sys("no key entered"); return
        field = "api_key" if kind == "model" else "voyage_key"
        self.cfg[field] = key
        self.cfg.setdefault("backend", "openrouter")
        config.save(self.cfg); config.apply_env(self.cfg); self._reset_provider()
        if kind == "memory":
            self._sys(f"memory key saved ({config.masked(key)}); long-term memory is on")
        else:
            self._sys(f"key saved ({config.masked(key)})")
        self._refresh_status()

    def _resume_list(self) -> None:
        rows = history.sessions()
        if not rows:
            self._sys("no saved conversations yet"); return
        t = Table(box=None, pad_edge=False, show_header=False)
        t.add_column(style="#9aa1ad", no_wrap=True); t.add_column(style="#8a7f74")
        for s in rows[:12]:
            t.add_row(s["id"], f"{s['title']}  ({s['updated'][:16]})")
        self._emit(Panel(t, title="[bold #9aa1ad]/resume <id>  (or type /resume and pick)[/]",
                         border_style="#454b57", expand=False))

    def _resume(self, session_id: str) -> None:
        try:
            data = history.load(session_id)
        except (OSError, ValueError):
            self._sys(f"no conversation {session_id}"); return
        self.messages = data.get("messages", [])
        self.session_id = data["id"]
        self.session_title = data.get("title", "")
        self.action_clear()
        self._sys(f"resumed {self.session_id}: {self.session_title}")
        names = {}
        for m in self.messages:
            role = m.get("role")
            text = _msg_text(m.get("content"))
            if role == "user":
                if text:
                    self._you(text)
            elif role == "assistant":
                if text:
                    self._emit(Markdown(text))
                for tc in (m.get("tool_calls") or []):
                    fn = tc.get("function") or {}
                    nm = fn.get("name", "tool")
                    names[tc.get("id")] = nm
                    try:
                        args = json.loads(fn.get("arguments") or "{}")
                    except Exception:
                        args = {}
                    self._emit(self._tool_render(nm, args))
            elif role == "tool":
                self._emit(self._result_render(names.get(m.get("tool_call_id"), "tool"), text))
        self._refresh_panels()

    def _new_session(self) -> None:
        self._persist()
        self.messages = []
        self.session_id = None
        self.session_title = ""
        self.action_clear()
        self._sys("started a new conversation")
        self._refresh_panels()

    def _persist(self) -> None:
        if self.session_id and self.messages:
            history.save(self.session_id, self.session_title, self.cfg.get("model", ""), self.messages)

    def _reset_provider(self) -> None:
        import sabba.llm as L
        L._PROVIDER_CACHE.clear()

    # workers ----------------------------------------------------------------
    @work(thread=True, group="task")
    def _op(self, kind: str, arg: str) -> None:
        self.ctl = chat.Ctl()
        self._activity = ""
        d = Path(arg).expanduser().resolve()
        if kind in ("hunt", "verify") and not (d / "target.json").exists():
            self._activity = ""
            self.call_from_thread(self._sys, f"{d} has no target.json"); return
        try:
            if kind == "solve":
                from .chat import _sources
                from .harness.symbolic.synth import hunt_symbolic
                found = hunt_symbolic(_sources(d),
                                      on_event=lambda m: self.call_from_thread(self._tool_line, m))
            elif kind == "hunt":
                from .harness.orchestrator import hunt
                found = hunt(d, model=self.cfg.get("model"), use_model=bool(self.cfg.get("api_key")),
                             on_event=lambda m: self.call_from_thread(self._tool_line, m))
            else:
                import json as _j
                from .harness import CCompileRunOracle
                from .types import PoC
                spec = _j.loads((d / "target.json").read_text())
                kp = spec.get("known_poc") or {}
                v = CCompileRunOracle().verify([d / s for s in spec["sources"]],
                                               PoC(argv=kp.get("argv", []), stdin=kp.get("stdin", "")))
                self.call_from_thread(self._sys,
                                      f"verified={v.verified} class={v.sanitizer.klass if v.sanitizer else None}")
                self._activity = ""
                return
        except Exception as e:
            LOG.exception("%s failed", kind)
            self._activity = ""
            self.call_from_thread(self._err, f"{kind} failed: {e}"); return
        self.n_repos += 1
        self.n_tasks += 1
        if found:
            self.n_bugs += len(found)
            for f in found:
                self.call_from_thread(self._emit, _finding_panel(f, d))
            self.call_from_thread(self._sys, f"{len(found)} confirmed finding(s)")
        else:
            self.call_from_thread(self._sys, "no bug reproduced")
        self._activity = ""
        self.call_from_thread(self._refresh_panels)

    def _tool_line(self, msg: str) -> None:
        from .ui import event
        line = event(msg)
        if line is not None:
            self._emit(line)

    def _on_text(self, chunk: str) -> None:
        self._activity = ""
        self.call_from_thread(self._grow, chunk)

    def _on_tool(self, name, args) -> None:
        self._activity = ""
        self.call_from_thread(self._emit, self._tool_render(name, args))

    def _on_result(self, name, out) -> None:
        self._activity = ""
        if name == "solve":
            self.n_repos += 1
            self.n_bugs += sum(1 for ln in out.splitlines() if ln.strip().startswith("CWE-"))
        elif name == "verify" and "verified=True" in out:
            self.n_bugs += 1
        elif name == "clone_repo" and out and "clone failed" not in out:
            self.n_repos += 1
        self.call_from_thread(self._emit, self._result_render(name, out))

    @work(thread=True, exclusive=True, group="task")
    def _chat(self, text: str) -> None:
        self.ctl = chat.Ctl()
        self._activity = ""
        if not self.session_id:
            self.session_id = history.new_id()
            self.session_title = text
        config.apply_env(self.cfg); self._reset_provider()
        try:
            provider = get_provider(self.cfg.get("model"))
        except LLMUnavailable as e:
            self.call_from_thread(self._sys, str(e)); return
        context = ""
        hits = memory.search(text, exclude_session=self.session_id) if memory.enabled() else []
        if hits:
            context = "Relevant memory from past conversations:\n" + "\n".join(hits)
            self.call_from_thread(self._sys, f"recalled {len(hits)} memory snippet(s)")
        try:
            chat.turn_stream(
                provider, self.messages, text, self.ctl, memory_context=context,
                on_start=lambda: self.call_from_thread(self._assistant_start),
                on_text=self._on_text,
                on_done=lambda pt, ct: self.call_from_thread(self._assistant_end, pt, ct),
                on_tool=self._on_tool,
                on_result=self._on_result)
        except Exception as e:
            LOG.exception("chat turn failed")
            self._activity = ""
            self.call_from_thread(self._err, f"model error: {e}")
            return
        self._activity = ""
        self.n_tasks += 1
        self.call_from_thread(self._refresh_panels)
        history.save(self.session_id, self.session_title, self.cfg.get("model", ""), self.messages)
        if memory.enabled():
            memory.add(self.session_id, "user", text)
            if self.last_assistant:
                memory.add(self.session_id, "assistant", self.last_assistant)


def run() -> None:
    SabbaApp().run()


if __name__ == "__main__":
    run()
