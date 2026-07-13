"""Sabba as an inline REPL, in the spirit of Claude Code.

The conversation prints straight into the terminal, so scrolling, selecting, and
copying are the terminal's own and just work, and the background stays whatever the
terminal is. The composer stays pinned at the bottom the whole time: the turn runs in
a background thread and prints above it (prompt_toolkit patch_stdout), so you can keep
typing while the model works. A message sent mid-turn is queued and shown above the
composer; press up on an empty line to pull the last queued message back to edit.
"""
from __future__ import annotations

import json
import os
import random
import signal
import threading
import time
from pathlib import Path

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

from prompt_toolkit import prompt as ptk_prompt
from prompt_toolkit.application import Application
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.filters import Condition
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, Layout, Window, ConditionalContainer
from prompt_toolkit.layout.controls import BufferControl, FormattedTextControl
from prompt_toolkit.layout.dimension import Dimension
from prompt_toolkit.layout.processors import BeforeInput
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.styles import Style as PTStyle

from . import chat, config, history, memory
from .llm import LLMUnavailable, get_provider
from .log import get_logger
from .ui import environment

LOG = get_logger()

_C1, _C2, _C3 = (206, 211, 220), (150, 157, 170), (104, 110, 124)
_GLYPH = {
    "S": ["#####", "#....", "#....", "#####", "....#", "....#", "#####"],
    "A": [".###.", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"],
    "B": ["####.", "#...#", "#...#", "####.", "#...#", "#...#", "####."],
}
_VERBS = [
    "Thinking", "Pondering", "Reasoning", "Analyzing", "Cerebrating", "Cogitating",
    "Considering", "Deciphering", "Deliberating", "Percolating", "Reticulating",
    "Ruminating", "Mulling", "Noodling", "Puzzling", "Synthesizing", "Inferring",
    "Crunching", "Tracing", "Probing", "Auditing", "Fuzzing", "Sniffing", "Triaging",
    "Hunting", "Working",
]
COMMANDS = [
    ("setup", "guided first-time setup (start here)"),
    ("local-llm-config", "set up a local model (device, catalog, quantization)"),
    ("select-local-model", "browse and install a local model of your choice"),
    ("add-model-key", "add a cloud model key (OpenRouter)"),
    ("model", "choose the cloud model"),
    ("ml-config", "train the local risk ranker"),
    ("add-memory-key", "add a Voyage key for long-term memory"),
    ("resume", "reopen a saved conversation"),
    ("new", "start a fresh conversation"),
    ("solve", "z3 and the oracle over a directory"),
    ("hunt", "retrieval, z3, then the model"),
    ("verify", "run a target's known PoC"),
    ("ask", "hand a one-shot task to the Claude Code agent"),
    ("doctor", "toolchain status"),
    ("clear", "clear the screen"),
    ("help", "show help"),
    ("quit", "exit"),
]
MODELS = [
    "nvidia/nemotron-3-ultra-550b-a55b:free", "z-ai/glm-5.2",
    "deepseek/deepseek-v4-flash", "deepseek/deepseek-v4-pro",
    "moonshotai/kimi-k2.7-code", "qwen/qwen-2.5-coder-32b-instruct",
    "anthropic/claude-3.5-sonnet", "deepseek/deepseek-chat-v3-0324",
]
_ARG_CMDS = {"model", "resume", "solve", "hunt", "verify", "select-local-model"}
# these are long jobs, so they run in the background with a spinner like a chat turn;
# every other slash command is instant and runs synchronously in the main loop
_BG_CMDS = {"solve", "hunt", "verify"}
_SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def _lerp(a, b, t):
    return tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))


def _grad(t):
    c = _lerp(_C1, _C2, t * 2) if t < 0.5 else _lerp(_C2, _C3, (t - 0.5) * 2)
    return "#%02x%02x%02x" % c


def logo_text() -> Text:
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


def _msg_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(b.get("text", "") for b in content
                       if isinstance(b, dict) and b.get("type") == "text")
    return ""


class SlashCompleter(Completer):
    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        if not text.startswith("/"):
            return
        parts = text[1:].split(" ")
        if len(parts) <= 1:
            word = parts[0] if parts else ""
            for name, desc in COMMANDS:
                if name.startswith(word):
                    yield Completion(name, start_position=-len(word),
                                     display="/" + name, display_meta=desc)
        elif parts[0] in ("model", "m"):
            word = parts[-1].lower()
            for m in MODELS:
                if word in m.lower():
                    yield Completion(m, start_position=-len(parts[-1]), display=m)
        elif parts[0] == "resume":
            word = parts[-1].lower()
            for s in history.sessions():
                if word in s["id"].lower() or word in s.get("title", "").lower():
                    yield Completion(s["id"], start_position=-len(parts[-1]),
                                     display=s["id"], display_meta=s.get("title", ""))


def _input_app(completer, style, repl, inp=None, out=None):
    """The composer: a spinner, a queue strip, a rule-framed input, then the / menu.

    inp and out are only passed by tests, to drive the app headless; in normal use they are
    None and prompt_toolkit uses the real terminal.
    """
    pending = repl._pending
    # multiline so a long or pasted message keeps its newlines and can wrap; Enter still
    # submits (the enter binding below), and Ctrl+J inserts a newline.
    buf = Buffer(completer=completer, complete_while_typing=True, multiline=True)

    def menu_open():
        return bool(buf.complete_state and buf.complete_state.completions)

    def waiting():
        return repl._active and repl._waiting

    def status_frags():
        if not waiting():
            return []
        frame = _SPIN[int(time.time() * 10) % len(_SPIN)]
        el = int(time.time() - repl._t0)
        out = getattr(repl, "_out_count", 0)
        tok = f" · {out} tok" if out else ""      # live progress so a slow model is not silent
        return [("class:spin", f"  {frame} "),
                ("class:verb", f"{repl._verb}… "),
                ("class:status.dim", f"({el}s{tok} · esc to interrupt)")]

    def menu_frags():
        cs = buf.complete_state
        if not cs or not cs.completions:
            return []
        w = max((len(c.display_text) for c in cs.completions), default=0)
        cur = cs.complete_index if cs.complete_index is not None else -1
        frags = []
        for i, c in enumerate(cs.completions):
            name = c.display_text
            meta = c.display_meta_text or ""
            sel = (i == cur)
            frags.append(("class:menu.sel.name" if sel else "class:menu.name",
                          f"  {name:<{w + 3}}"))
            frags.append(("class:menu.sel.meta" if sel else "class:menu.meta",
                          f"{meta}\n"))
        return frags

    def queue_frags():
        if not pending:
            return []
        out = []
        for m in pending:
            one = m if len(m) <= 72 else m[:69] + "…"
            out.append(("class:queue", f"  ⧗ {one}\n"))
        out.append(("class:queue.hint", "  queued · up to pull the last one back to edit\n"))
        return out

    # Grow with the text instead of clipping to one row: the window sizes to the number of
    # wrapped rows the message needs, from 1 up to 10, then scrolls. A long line used to wrap
    # internally while the fixed height=1 showed only the last row.
    input_win = Window(
        BufferControl(buffer=buf,
                      input_processors=[BeforeInput([("class:prompt", "› ")])]),
        height=Dimension(min=1, max=10), wrap_lines=True, dont_extend_height=True)
    top_rule = Window(height=1, char="─", style="class:rule")
    bot_rule = Window(height=1, char="─", style="class:rule")
    queue_win = ConditionalContainer(
        Window(FormattedTextControl(queue_frags), dont_extend_height=True),
        filter=Condition(lambda: bool(pending)))
    status_win = ConditionalContainer(
        Window(FormattedTextControl(status_frags), height=1, style="bg:default"),
        filter=Condition(waiting))
    menu_win = ConditionalContainer(
        Window(FormattedTextControl(menu_frags), dont_extend_height=True, style="bg:default"),
        filter=Condition(menu_open))
    root = HSplit([status_win, queue_win, top_rule, input_win, bot_rule, menu_win])

    kb = KeyBindings()

    @kb.add("enter")
    def _(e):
        b = e.app.current_buffer
        cs = b.complete_state
        if cs and cs.current_completion:
            b.apply_completion(cs.current_completion)
            head = b.text[1:].strip() if b.text.startswith("/") else ""
            if head in _ARG_CMDS:
                b.insert_text(" ")
                return
        e.app.exit(result=b.text)

    @kb.add("c-j")
    def _(e):
        # Ctrl+J adds a newline; Enter still submits.
        e.app.current_buffer.insert_text("\n")

    @kb.add("up")
    def _(e):
        b = e.app.current_buffer
        if b.complete_state:
            b.complete_previous()
        elif not b.text and pending:
            b.text = pending.pop()
            b.cursor_position = len(b.text)
        elif "\n" in b.text:
            b.cursor_up()

    @kb.add("down")
    def _(e):
        b = e.app.current_buffer
        if b.complete_state:
            b.complete_next()
        elif "\n" in b.text:
            b.cursor_down()

    @kb.add("escape")
    def _(e):
        if e.app.current_buffer.complete_state:
            e.app.current_buffer.cancel_completion()
        elif repl._busy():
            repl._stop()

    @kb.add("c-c")
    def _(e):
        e.app.exit(result="\x03")

    @kb.add("c-d")
    def _(e):
        if not e.app.current_buffer.text:
            e.app.exit(exception=EOFError)

    @kb.add("c-q")
    def _(e):
        e.app.exit(exception=EOFError)

    app = Application(layout=Layout(root, focused_element=input_win),
                      key_bindings=kb, style=style, full_screen=False,
                      erase_when_done=True,  # animation is driven by Repl._tick
                      input=inp, output=out)
    app.sabba_input_win = input_win       # exposed for the headless composer test
    app.sabba_buf = buf
    return app


class Repl:
    def __init__(self):
        self.cfg = config.load()
        config.apply_env(self.cfg)
        self.console = Console(highlight=False, force_terminal=True, color_system="truecolor")
        self.messages: list = []
        self.session_id = None
        self.session_title = ""
        self.last_assistant = ""
        self.ctl = chat.Ctl()
        self._buf = ""
        self._pending: list = []
        self._gen = None
        self._app = None            # the live composer, for the ticker to redraw
        self._active = False        # a turn (or its queue) is running
        self._waiting = False       # waiting on the model, no output yet -> spinner on
        self._verb = ""
        self._t0 = 0.0

    def _busy(self) -> bool:
        return self._gen is not None and self._gen.is_alive()

    # ---- output ----
    def sys(self, msg: str) -> None:
        self.console.print(Text("  " + msg, style="#8f96a3"))

    def _you(self, text: str) -> None:
        # the user's own message, echoed with a full-width gray highlight bar
        bar = Text(style="on #2b2f38")
        bar.append("› ", style="bold #cdd3de")
        bar.append(text, style="bold white")
        pad = self.console.width - bar.cell_len
        if pad > 0:
            bar.append(" " * pad)
        self.console.print(bar)

    def header(self) -> None:
        from . import onboarding
        c = self.console
        c.print()
        c.print(logo_text(), end="")
        c.print(Text("  security bug-finder that proves every finding", style="#7b8aa8"))
        if self.cfg.get("backend") == "local" and self.cfg.get("local_model"):
            model = f"local:{self.cfg['local_model']}"
        else:
            model = self.cfg.get("model", "not set")
        mem = "on" if memory.enabled() else "off"
        sid = self.session_id or "new"
        c.print(Text(f"  model {model}   ·   memory {mem}   ·   session {sid}", style="#6b7280"))
        c.print(Text("  type / for commands  ·  ctrl-c stops a task  ·  ctrl-q quits",
                     style="#565d6d"))
        if not onboarding.can_chat(self.cfg):
            c.print(Text("  not set up for chat yet, type /setup to configure a model "
                         "(cloud key or local)", style="#d0864f"))

    # ---- streaming ----
    # The reply is buffered and rendered as Markdown when the turn's message finishes, so
    # headers, tables, and code blocks come out formatted rather than as raw ## and | text.
    # During generation the spinner shows a live token count (see status_frags), so a slow model
    # is not a silent wait: you can watch it produce and interrupt with esc.
    def on_start(self) -> None:
        self._buf = ""
        self._out_count = 0             # rough streamed-token count, shown live in the spinner
        self._verb = random.choice(_VERBS)
        self._waiting = True

    def on_text(self, chunk: str) -> None:
        if not chunk:
            return
        self._buf += chunk
        self._out_count += 1

    def on_done(self, pt, ct) -> None:
        self._waiting = False
        if self._buf:
            self.console.print(Markdown(self._buf))
            self.last_assistant = self._buf
        if pt is not None or ct is not None:
            self.console.print(Text(f"  {pt or 0} in · {ct or 0} out", style="#565d6d"))

    def on_tool(self, name, args) -> None:
        self._waiting = False
        argstr = ", ".join(f"{k}={str(v)[:60]}" for k, v in args.items())
        self.console.print(Text(f"  · {name}({argstr})", style="#8a7f74"))

    def on_result(self, name, out) -> None:
        self.console.print(Panel(Text((out or "")[:2000], style="white"),
                                 title=f"[#8a7f74]{name}[/]", border_style="#454b57",
                                 expand=False))

    # ---- one turn (runs in a background thread) ----
    def _reset_provider(self) -> None:
        import sabba.llm as L
        L._PROVIDER_CACHE.clear()

    def turn(self, text: str) -> None:
        self._you(text)
        if not self.session_id:
            self.session_id = history.new_id()
            self.session_title = text
        config.apply_env(self.cfg)
        self._reset_provider()
        # pick the model for the active backend: the local model id for the local endpoint,
        # the cloud model id otherwise. Passing the cloud id to a local endpoint 404s.
        if self.cfg.get("backend") == "local":
            model_id = self.cfg.get("local_model")
        else:
            model_id = self.cfg.get("model")
        try:
            provider = get_provider(model_id)
        except LLMUnavailable as e:
            self.sys(str(e))
            return
        context = ""
        if memory.enabled():
            hits = memory.search(text, exclude_session=self.session_id)
            if hits:
                context = "Relevant memory from past conversations:\n" + "\n".join(hits)
                self.sys(f"recalled {len(hits)} memory snippet(s)")
        try:
            chat.turn_stream(provider, self.messages, text, self.ctl,
                             memory_context=context, on_start=self.on_start,
                             on_text=self.on_text, on_done=self.on_done,
                             on_tool=self.on_tool, on_result=self.on_result)
        except Exception as e:
            LOG.exception("turn failed")
            self.console.print(Text(f"  model error: {e}", style="bold red"))
        history.save(self.session_id, self.session_title, self.cfg.get("model", ""),
                     self.messages)
        if memory.enabled():
            memory.add(self.session_id, "user", text)
            if self.last_assistant:
                memory.add(self.session_id, "assistant", self.last_assistant)

    def _run_one(self, text: str) -> None:
        if text.startswith("/"):
            self.slash(text)
        else:
            self.turn(text)

    def _invalidate(self) -> None:
        app = self._app
        if app is not None:
            try:
                app.invalidate()
            except Exception:
                pass

    def _tick(self) -> None:
        # redraw the composer ~10x/s ONLY while a turn runs, so the spinner
        # animates without touching the terminal while the user sits idle
        while self._active:
            self._invalidate()
            time.sleep(0.1)

    def _start(self, text: str) -> None:
        self.ctl = chat.Ctl()
        self._active = True
        self._waiting = True
        self._verb = random.choice(_VERBS)
        self._t0 = time.time()

        def work():
            try:
                self._run_one(text)
                while self._pending and not self.ctl.stopped():
                    self.ctl = chat.Ctl()
                    self._waiting = True
                    self._run_one(self._pending.pop(0))
            finally:
                self._active = False
                self._waiting = False
                self._invalidate()

        self._gen = threading.Thread(target=work, daemon=True)
        self._gen.start()
        threading.Thread(target=self._tick, daemon=True).start()

    def _stop(self) -> None:
        self.ctl.stop.set()
        if self.ctl.proc:
            try:
                os.killpg(os.getpgid(self.ctl.proc.pid), signal.SIGTERM)
            except Exception:
                pass

    # ---- slash commands ----
    def slash(self, text: str) -> None:
        parts = text[1:].split()
        cmd = parts[0].lower() if parts else ""
        arg = " ".join(parts[1:]).strip()
        if not cmd:                       # a bare "/" is not a command
            return
        if cmd in ("help", "h", "?"):
            self.help()
        elif cmd in ("setup", "start"):
            self.setup()
        elif cmd in ("local-llm-config", "local", "local-llm"):
            self.local_llm_config()
        elif cmd in ("select-local-model", "select-model", "models"):
            self.select_local_model(arg)
        elif cmd in ("ml-config", "ml"):
            self.ml_config()
        elif cmd in ("model", "m"):
            self.choose_model(arg)
        elif cmd in ("add-model-key", "key"):
            self.explain("model-key")
            self.set_key("model", arg)
        elif cmd == "add-memory-key":
            self.explain("memory-key")
            self.set_key("memory", arg)
        elif cmd == "resume":
            self.resume(arg) if arg else self.resume_list()
        elif cmd == "new":
            self.new_session()
        elif cmd in ("clear", "cls"):
            self.console.clear()
            self.header()
        elif cmd in ("solve", "hunt", "verify"):
            self.op(cmd, arg) if arg else self.sys(f"usage: /{cmd} <directory>")
        elif cmd == "ask":
            self.ask(arg)
        elif cmd in ("claude-code", "claude", "cc"):
            self.claude_session(arg)
        elif cmd == "doctor":
            self.doctor()
        elif cmd in ("quit", "q", "exit"):
            raise EOFError
        else:
            self.sys(f"unknown command /{cmd}")

    def help(self) -> None:
        t = Table(box=None, pad_edge=False, show_header=False)
        t.add_column(style="#9aa1ad", no_wrap=True)
        t.add_column(style="#8a7f74")
        for name, desc in COMMANDS:
            t.add_row(f"/{name}", desc)
        t.add_row("just type", "chat; the model can clone repos, run bash, search the web")
        self.console.print(Panel(t, title="[bold #9aa1ad]commands[/]",
                                 border_style="#454b57", expand=False))

    def apply_model(self, model: str) -> None:
        self.cfg["model"] = model
        # choosing a cloud model switches the backend to the cloud; setdefault would leave a
        # previously set "local" backend in place, so the cloud model was never actually used
        self.cfg["backend"] = "openrouter"
        config.save(self.cfg)
        config.apply_env(self.cfg)
        self._reset_provider()
        self.sys(f"model set to {model} (cloud)")

    def set_key(self, kind: str, key: str) -> None:
        key = key.strip()
        if not key:
            which = "OpenRouter" if kind == "model" else "Voyage"
            try:
                key = ptk_prompt(f"  paste your {which} key: ", is_password=True).strip()
            except (EOFError, KeyboardInterrupt):
                return
        if not key:
            self.sys("no key entered")
            return
        field = "api_key" if kind == "model" else "voyage_key"
        self.cfg[field] = key
        if kind == "model":
            # an OpenRouter key means the user wants the cloud backend; switch to it (setdefault
            # would leave a previously set "local" backend in place)
            self.cfg["backend"] = "openrouter"
        else:
            self.cfg.setdefault("backend", "openrouter")
        config.save(self.cfg)
        config.apply_env(self.cfg)
        self._reset_provider()
        if kind == "memory":
            self.sys(f"memory key saved ({config.masked(key)}); long-term memory is on")
        else:
            self.sys(f"key saved ({config.masked(key)}); backend is now cloud (openrouter)")

    # ---- guided onboarding ----
    def explain(self, key: str) -> None:
        """Print the why / skip / do explanation for a setup step."""
        from . import onboarding
        e = onboarding.EXPLAIN.get(key)
        if not e:
            return
        t = Table(box=None, pad_edge=False, show_header=False)
        t.add_column(style="#8a7f74", no_wrap=True, width=6)
        t.add_column(style="#cdd6e6")
        t.add_row("why", e["why"])
        t.add_row("skip", e["skip"])
        t.add_row("do", e["do"])
        self.console.print(Panel(t, title=f"[bold #9aa1ad]{e['title']}[/]",
                                 border_style="#454b57", expand=False))

    def setup(self) -> None:
        """The onboarding checklist: what is done, what is left, and the command for each."""
        from . import onboarding
        t = Table(box=None, pad_edge=False, show_header=False)
        t.add_column(width=2)
        t.add_column(style="#cdd6e6", no_wrap=True)
        t.add_column(style="#8a7f74")
        for s in onboarding.setup_status(self.cfg):
            mark = (Text("ok", style="#7ec699") if s["done"]
                    else Text("--", style="#8f96a3" if s["optional"] else "#d0864f"))
            tag = "  (optional)" if s["optional"] else "  (needed for chat)"
            t.add_row(mark, s["label"] + tag, s["hint"])
        ready = onboarding.can_chat(self.cfg)
        head = ("You are set up to chat." if ready else
                "Not ready to chat. Do the first row: /add-model-key (cloud) or /local-llm-config (local).")
        self.console.print(Panel(t, title="[bold #9aa1ad]setup[/]",
                                 subtitle=f"[#8a7f74]{head}[/]",
                                 border_style="#454b57", expand=False))
        self.console.print(Text("  /solve and /verify need no model and work right now.",
                                style="#6b7280"))

    def choose_model(self, arg: str) -> None:
        self.explain("model")
        if arg:
            self.apply_model(arg)
            return
        t = Table(box=None, pad_edge=False, show_header=False)
        t.add_column(style="#8a91a0", no_wrap=True)
        for m in MODELS:
            t.add_row(f"/model {m}")
        self.console.print(Panel(t, title="[bold #9aa1ad]pick a model (Tab completes)[/]",
                                 border_style="#454b57", expand=False))

    def ml_config(self) -> None:
        self.explain("ml")
        self.sys("training the risk ranker on the built-in corpus...")
        try:
            from .ml.train import train_bootstrap
            r = train_bootstrap()
        except ImportError:
            self.sys("the ranker needs scikit-learn: pip install scikit-learn")
            return
        except Exception as e:  # noqa: BLE001
            self.sys(f"training failed: {e}")
            return
        self.sys(f"ranker trained (held-out AUC {r['auc']}), saved to {r['model']}. Retrieval "
                 f"uses it automatically; re-run after hunts or `sabba mltrain --from-traces`.")

    def local_llm_config(self) -> None:
        """Explain the local option, detect the device, and show the catalog. Installing a model
        is a separate, explicit step so you choose what to run, not a forced default."""
        from . import onboarding
        self.explain("local-llm")
        d = onboarding.detect_device()
        rec = onboarding.recommend_local_model(d)
        self.sys(f"device: {d['cores']} cores, {d['ram_gb'] or '?'} GB RAM"
                 + (", Apple Silicon" if d["apple_silicon"] else ""))
        self.sys(f"recommended for you: {rec['model']}  ({rec['reason']})")
        self._model_catalog_panel(rec["model"], d.get("ram_gb", 0.0))
        self.console.print(Text("  " + onboarding.QUANT_EXPLAIN, style="#8a7f74"))
        self.console.print(Text("  " + onboarding.AGENTIC_NOTE, style="#8a7f74"))
        self.sys(f"install the recommended one:  /select-local-model {rec['model']}")
        self.sys("or browse and pick another:  /select-local-model")

    def select_local_model(self, arg: str) -> None:
        """No argument shows the catalog; an argument (number, Ollama tag, or hf.co reference)
        downloads that model and switches the backend to it."""
        from . import onboarding
        if not arg:
            self.explain("select-model")
            d = onboarding.detect_device()
            self._model_catalog_panel(onboarding.recommend_local_model(d)["model"], d.get("ram_gb", 0.0))
            self.console.print(Text("  " + onboarding.QUANT_EXPLAIN, style="#8a7f74"))
            self.console.print(Text("  " + onboarding.AGENTIC_NOTE, style="#8a7f74"))
            self.sys("pick one:  /select-local-model <number or tag>   "
                     "(or any Ollama tag, or hf.co/<repo>:<quant>)")
            return
        model = onboarding.resolve_choice(arg)
        if not model:
            self.sys(f"no catalog entry {arg!r}; run /select-local-model to see the list")
            return
        self._pull_and_apply(model)

    def _model_catalog_panel(self, recommended: str, ram_gb: float) -> None:
        from . import onboarding
        t = Table(box=None, pad_edge=False, show_header=True, header_style="#8a7f74")
        for col in ("#", "model", "params", "quant", "~size", "RAM"):
            t.add_column(col, no_wrap=True, style="#8f96a3" if col not in ("#", "model") else "#cdd6e6")
        t.add_column("", style="#8a7f74")
        for i, m in enumerate(onboarding.LOCAL_MODELS, 1):
            fits = ram_gb == 0.0 or m["ram_gb"] <= ram_gb
            star = " *" if m["tag"] == recommended else ""
            note = m["note"] + ("" if fits else "  (needs more RAM)")
            t.add_row(str(i), m["tag"] + star, m["params"], m["quant"],
                      f"{m['size_gb']}G", f"{m['ram_gb']}G+", note,
                      style=None if fits else "#6b7280")
        self.console.print(Panel(
            t, title="[bold #9aa1ad]local model catalog  (* recommended for you)[/]",
            border_style="#454b57", expand=False))

    def _pull_and_apply(self, model: str) -> None:
        """Ensure Ollama has the model (pulling if needed), then switch the backend to it."""
        from . import onboarding
        st = onboarding.ollama_status()
        if not st["installed"]:
            self.sys("Ollama is not installed. Install it, then run /select-local-model again:")
            self.console.print(Text("    " + onboarding.install_hint(), style="#8a91a0"))
            return
        if not st["running"]:
            self.sys("Ollama is installed but its server is not running. In another terminal run:")
            self.console.print(Text("    ollama serve", style="#8a91a0"))
            return
        if model not in st["models"]:
            self.sys(f"pulling {model} with Ollama (this can take a few minutes)...")
            if not self._ollama_pull(model):
                self.sys("pull did not finish. Run it yourself, then /select-local-model again:")
                self.console.print(Text(f"    ollama pull {model}", style="#8a91a0"))
                return
        self.cfg["backend"] = "local"
        self.cfg["local_model"] = model
        self.cfg["local_base_url"] = "http://localhost:11434/v1"
        config.save(self.cfg)
        config.apply_env(self.cfg)
        self._reset_provider()
        self.sys(f"local model ready: {model}. The backend is now local and offline. You can chat.")

    def _ollama_pull(self, model: str) -> bool:
        """Run `ollama pull` and echo its stage lines through the console. Never raises."""
        import subprocess
        try:
            p = subprocess.Popen(["ollama", "pull", model], stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True, bufsize=1)
            for line in p.stdout:
                line = line.strip()
                if line:
                    self.console.print(Text("    " + line[:100], style="#6b7280"))
            return p.wait() == 0
        except Exception as e:  # noqa: BLE001
            self.console.print(Text(f"    {e}", style="warn"))
            return False

    def resume_list(self) -> None:
        rows = history.sessions()
        if not rows:
            self.sys("no saved conversations yet")
            return
        t = Table(box=None, pad_edge=False, show_header=False)
        t.add_column(style="#9aa1ad", no_wrap=True)
        t.add_column(style="#8a7f74")
        for s in rows[:15]:
            t.add_row(s["id"], f"{s['title']}  ({s['updated'][:16]})")
        self.console.print(Panel(t, title="[bold #9aa1ad]/resume <id>[/]",
                                 border_style="#454b57", expand=False))

    def resume(self, sid: str) -> None:
        try:
            data = history.load(sid)
        except (OSError, ValueError):
            self.sys(f"no conversation {sid}")
            return
        self.messages = data.get("messages", [])
        self.session_id = data["id"]
        self.session_title = data.get("title", "")
        self.console.clear()
        self.header()
        self.sys(f"resumed {self.session_id}: {self.session_title}")
        names = {}
        for m in self.messages:
            role = m.get("role")
            txt = _msg_text(m.get("content"))
            if role == "user":
                if txt:
                    self._you(txt)
            elif role == "assistant":
                if txt:
                    self.console.print(Markdown(txt))
                for tc in (m.get("tool_calls") or []):
                    fn = tc.get("function") or {}
                    nm = fn.get("name", "tool")
                    names[tc.get("id")] = nm
                    try:
                        a = json.loads(fn.get("arguments") or "{}")
                    except Exception:
                        a = {}
                    self.on_tool(nm, a)
            elif role == "tool":
                self.on_result(names.get(m.get("tool_call_id"), "tool"), txt)

    def new_session(self) -> None:
        self.messages = []
        self.session_id = None
        self.session_title = ""
        self.last_assistant = ""
        self.console.clear()
        self.header()
        self.sys("new conversation")

    def op(self, kind: str, arg: str) -> None:
        d = Path(arg).expanduser().resolve()
        ev = lambda m: self.console.print(Text("  " + m, style="#8a7f74"))
        self.ctl = chat.Ctl()
        if kind in ("hunt", "verify") and not (d / "target.json").exists():
            self.sys(f"{d} has no target.json; use /solve")
            return
        try:
            if kind == "solve":
                from .chat import _sources
                from .harness.symbolic.synth import hunt_symbolic
                found = hunt_symbolic(_sources(d), on_event=ev)
            elif kind == "hunt":
                from .harness.orchestrator import hunt as run_hunt
                found = run_hunt(d, model=self.cfg.get("model"),
                                 use_model=bool(self.cfg.get("api_key")), on_event=ev)
            else:
                from .harness import CCompileRunOracle
                from .types import PoC
                spec = json.loads((d / "target.json").read_text())
                kp = spec.get("known_poc") or {}
                v = CCompileRunOracle().verify([d / s for s in spec["sources"]],
                                               PoC(argv=kp.get("argv", []), stdin=kp.get("stdin", "")))
                self.sys(f"verified={v.verified} "
                         f"class={v.sanitizer.klass if v.sanitizer else None}")
                return
        except Exception as e:
            self.sys(f"error: {e}")
            return
        if found:
            for f in found:
                self.console.print(Text(
                    f"  {getattr(f, 'cwe', '')} {getattr(f, 'title', '')} "
                    f"at {getattr(f, 'file', '')}:{getattr(f, 'line', '')}", style="white"))
        else:
            self.sys("no bugs confirmed")

    def ask(self, arg: str) -> None:
        """Hand a task to the whole Claude Code agent (read-only) and render its answer."""
        from .llm import claude_code
        if not arg:
            self.sys("usage: /ask <task>   (hands it to the whole Claude Code agent)")
            return
        if not claude_code.available():
            self.sys("the `claude` CLI is not on PATH here; install Claude Code to use /ask")
            return
        self.console.print(Text("  claude code working...", style="#8a7f74"))
        try:
            res = claude_code.run(arg, add_dirs=[str(Path.cwd())], permission_mode="plan")
        except Exception as e:
            self.sys(f"error: {e}")
            return
        if not res.ok:
            self.sys(f"claude did not finish: {res.error}")
            return
        self.console.print(Markdown(res.text))
        meta = []
        if res.turns is not None:
            meta.append(f"{res.turns} turn{'s' if res.turns != 1 else ''}")
        if res.cost_usd is not None:
            meta.append(f"${res.cost_usd:.4f}")
        if res.duration_ms is not None:
            meta.append(f"{res.duration_ms / 1000:.1f}s")
        if meta:
            self.console.print(Text("  " + "  ".join(meta), style="#565d6d"))

    def claude_session(self, arg: str) -> None:
        """Open the embedded Claude Code pane (Sabba Studio) from inside the REPL.

        Runs `sabba studio` as a child so the two full-screen apps do not nest: the studio
        child takes the terminal, renders a live Claude Code session in a Sabba-framed pane,
        and ctrl-q returns here. An optional arg becomes Claude Code's first message.
        """
        import shutil
        import subprocess
        import sys

        from .llm import claude_code
        if not claude_code.available():
            self.sys("the `claude` CLI is not on PATH here; install Claude Code first")
            return
        sabba_bin = shutil.which("sabba")
        base = [sabba_bin, "studio"] if sabba_bin else [sys.executable, "-m", "sabba", "studio"]
        cmd = base + (["claude", arg] if arg else [])
        self.console.clear()
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            pass
        self.console.clear()
        self.header()

    def doctor(self) -> None:
        t = Table(box=None, pad_edge=False, show_header=False)
        t.add_column(width=3)
        t.add_column(style="white")
        t.add_column(style="#8a7f74")
        for label, ok, detail in environment():
            t.add_row("ok" if ok else "--", label, detail)
        self.console.print(Panel(t, title="[bold #9aa1ad]toolchain[/]",
                                 border_style="#454b57", expand=False))

    # ---- main loop ----
    def run(self) -> None:
        self.header()
        style = PTStyle.from_dict({
            "prompt": "#9aa1ad bold",
            "rule": "#3a4150",
            "menu.name": "#8a91a0 bg:default",
            "menu.meta": "#565d6d bg:default",
            "menu.sel.name": "#ece7f2 bold bg:default",
            "menu.sel.meta": "#9aa1ad bg:default",
            "queue": "#8a91a0 bg:default",
            "queue.hint": "#565d6d bg:default",
            "spin": "#c9b8f0 bg:default",
            "verb": "#b8bec9 bg:default",
            "status.dim": "#565d6d bg:default",
            # kill prompt_toolkit's built-in completion-menu grays, belt and suspenders
            "completion-menu": "bg:default",
            "completion-menu.completion": "bg:default",
            "completion-menu.completion.current": "bg:default noinherit",
            "completion-menu.meta.completion": "bg:default",
            "completion-menu.meta.completion.current": "bg:default",
        })
        completer = SlashCompleter()
        with patch_stdout(raw=True):
            while True:
                app = _input_app(completer, style, self)
                self._app = app
                try:
                    text = app.run()
                except EOFError:
                    self._stop()
                    break
                finally:
                    self._app = None
                text = (text or "").strip()
                if text == "\x03":                       # ctrl-c
                    if self._busy():
                        self._stop()
                        self.sys("[stopped]")
                    continue
                if not text:
                    continue
                if text.startswith("/"):
                    parts = text[1:].split()
                    cmd = parts[0].lower() if parts else ""
                    if cmd in _BG_CMDS:                   # long jobs behave like a turn
                        if self._busy():
                            self._pending.append(text)
                        else:
                            self._start(text)
                    else:                                # instant control commands
                        try:
                            self.slash(text)
                        except EOFError:                 # /quit
                            self._stop()
                            break
                        except KeyboardInterrupt:
                            self.sys("[stopped]")
                    continue
                if self._busy():
                    self._pending.append(text)
                else:
                    self._start(text)
        self.console.print(Text("bye", style="#565d6d"))


def main() -> None:
    Repl().run()
