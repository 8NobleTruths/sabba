"""Sabba Studio: a full-screen TUI that embeds a live Claude Code session as a pane.

Claude Code (or any command) runs in a pseudo-terminal. pyte turns its byte output into a
screen buffer, and a prompt_toolkit window renders that buffer live, so the whole embedded
program is visible and interactive inside Sabba. Keys typed while the pane is focused are
translated back to terminal byte sequences and written to the pty. ctrl-q detaches and
returns to Sabba.

This module keeps the emulator core (PtyTerminal, render_screen) free of prompt_toolkit so
it can be unit-tested headlessly; run() does the full-screen wiring.
"""
from __future__ import annotations

import fcntl
import os
import pty
import struct
import termios

import pyte

# ---- emulator core (no prompt_toolkit; unit-testable) ----


class PtyTerminal:
    """A child process on a pty, with its output emulated by a pyte screen."""

    def __init__(self, argv: list[str], rows: int = 24, cols: int = 80):
        self.argv = argv
        self.rows = rows
        self.cols = cols
        self.screen = pyte.Screen(cols, rows)
        self.stream = pyte.ByteStream(self.screen)
        self.master_fd: int | None = None
        self.pid: int | None = None

    def spawn(self) -> None:
        pid, fd = pty.fork()
        if pid == 0:                                   # child: become the program
            os.environ["TERM"] = "xterm-256color"
            try:
                os.execvp(self.argv[0], self.argv)
            except OSError:
                os._exit(127)
        self.pid, self.master_fd = pid, fd
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        self._set_winsize(self.rows, self.cols)

    def _set_winsize(self, rows: int, cols: int) -> None:
        if self.master_fd is not None:
            fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ,
                        struct.pack("HHHH", rows, cols, 0, 0))

    def read(self, n: int = 65536) -> bytes | None:
        """Read available output and feed it to the emulator.

        Returns the bytes read, b'' at end of file, or None when nothing is ready."""
        if self.master_fd is None:
            return b""
        try:
            data = os.read(self.master_fd, n)
        except BlockingIOError:
            return None
        except OSError:
            return b""
        if data:
            self.stream.feed(data)
        return data

    def write(self, data: bytes) -> None:
        if self.master_fd is not None:
            try:
                os.write(self.master_fd, data)
            except OSError:
                pass

    def resize(self, rows: int, cols: int) -> None:
        if rows <= 0 or cols <= 0 or (rows == self.rows and cols == self.cols):
            return
        self.rows, self.cols = rows, cols
        self.screen.resize(rows, cols)
        self._set_winsize(rows, cols)

    def is_alive(self) -> bool:
        if self.pid is None:
            return False
        try:
            wpid, _ = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            return False
        return wpid == 0

    def close(self) -> None:
        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None


# ---- pyte screen -> prompt_toolkit FormattedText ----

_ANSI = {
    "black": "ansiblack", "red": "ansired", "green": "ansigreen",
    "brown": "ansiyellow", "yellow": "ansiyellow", "blue": "ansiblue",
    "magenta": "ansimagenta", "cyan": "ansicyan", "white": "ansiwhite",
    "default": "",
}


def _color(name: str) -> str:
    if not name or name == "default":
        return ""
    if name in _ANSI:
        return _ANSI[name]
    if len(name) == 6 and all(c in "0123456789abcdefABCDEF" for c in name):
        return "#" + name
    return ""


def _cell_style(ch, cursor: bool = False) -> str:
    parts = []
    fg = _color(ch.fg)
    bg = _color(ch.bg)
    if fg:
        parts.append("fg:" + fg)
    if bg:
        parts.append("bg:" + bg)
    if ch.bold:
        parts.append("bold")
    if ch.underscore:
        parts.append("underline")
    if ch.reverse ^ cursor:            # cursor cell is drawn reversed
        parts.append("reverse")
    return " ".join(parts)


def render_screen(screen) -> list[tuple[str, str]]:
    """Turn a pyte screen into prompt_toolkit FormattedText, grouping same-style runs."""
    ft: list[tuple[str, str]] = []
    cx, cy = screen.cursor.x, screen.cursor.y
    show_cursor = not screen.cursor.hidden
    for y in range(screen.lines):
        row = screen.buffer[y]
        x = 0
        while x < screen.columns:
            at_cursor = show_cursor and y == cy and x == cx
            style = _cell_style(row[x], at_cursor)
            run = row[x].data or " "
            x2 = x + 1
            while x2 < screen.columns:
                nxt_cursor = show_cursor and y == cy and x2 == cx
                if _cell_style(row[x2], nxt_cursor) != style:
                    break
                run += row[x2].data or " "
                x2 += 1
            ft.append((style, run))
            x = x2
        ft.append(("", "\n"))
    if ft and ft[-1] == ("", "\n"):
        ft.pop()
    return ft


# ---- key -> terminal bytes ----

def _key_bytes_map():
    from prompt_toolkit.keys import Keys
    return {
        Keys.Enter: b"\r", Keys.Escape: b"\x1b", Keys.Backspace: b"\x7f",
        Keys.Tab: b"\t", Keys.BackTab: b"\x1b[Z",
        Keys.Up: b"\x1b[A", Keys.Down: b"\x1b[B",
        Keys.Right: b"\x1b[C", Keys.Left: b"\x1b[D",
        Keys.Home: b"\x1b[H", Keys.End: b"\x1b[F",
        Keys.PageUp: b"\x1b[5~", Keys.PageDown: b"\x1b[6~",
        Keys.Delete: b"\x1b[3~", Keys.Insert: b"\x1b[2~",
        Keys.ControlA: b"\x01", Keys.ControlB: b"\x02", Keys.ControlC: b"\x03",
        Keys.ControlD: b"\x04", Keys.ControlE: b"\x05", Keys.ControlF: b"\x06",
        Keys.ControlG: b"\x07", Keys.ControlK: b"\x0b",
        Keys.ControlL: b"\x0c", Keys.ControlN: b"\x0e", Keys.ControlP: b"\x10",
        Keys.ControlR: b"\x12", Keys.ControlT: b"\x14", Keys.ControlU: b"\x15",
        Keys.ControlV: b"\x16", Keys.ControlW: b"\x17", Keys.ControlY: b"\x19",
        Keys.ControlZ: b"\x1a",
    }


# ---- chrome (gray theme, matches the approved mockup) ----

def _pad_line(left, right, width):
    """Left segments, then a gap, then right segments, filling `width`."""
    used = sum(len(t) for _, t in left) + sum(len(t) for _, t in right)
    gap = max(1, width - used)
    return list(left) + [("", " " * gap)] + list(right)


def _footer_ft(mode):
    return [
        ("class:footer", " "),
        ("class:footer.key", "[tab]"), ("class:footer", " sabba ⇄ claude-code    "),
        ("class:footer.key", "[ctrl-q]"), ("class:footer", " exit    "),
        ("class:live", "● live"),
        ("class:footer", "     mode "),
        ("class:mode.on", mode),
    ]


def _run_sabba_line(sabba_bin, line, timeout=120, max_lines=8):
    """Run `sabba <line>` and return an `$ sabba <line>` header plus the tail of its output.

    Unit-testable; the studio shows the returned string in its result strip."""
    import shlex
    import subprocess
    try:
        proc = subprocess.run([sabba_bin, *shlex.split(line)],
                              capture_output=True, text=True, timeout=timeout)
    except Exception as e:                       # noqa: BLE001
        return f"$ sabba {line}\nerror: {e}"
    out = [ln.rstrip() for ln in (proc.stdout or proc.stderr or "").splitlines() if ln.strip()]
    body = "\n".join(out[-max_lines:]) if out else "done"
    return f"$ sabba {line}\n{body}"


# ---- full-screen app ----

def run(argv: list[str] | None = None) -> int:
    """Embed `argv` (default: claude) in the gray Sabba Studio chrome and run it live.

    One composer at the bottom. Tab flips it between claude-code (the line you type is sent
    to the embedded session) and sabba (the line runs as a sabba command and its output shows
    in the result strip). ctrl-q detaches. Returns 0, or 127 if the program is missing."""
    import shutil
    import threading
    import time

    from prompt_toolkit.application import Application, get_app
    from prompt_toolkit.buffer import Buffer
    from prompt_toolkit.formatted_text import FormattedText
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.layout import Layout
    from prompt_toolkit.layout.containers import HSplit, VSplit, Window
    from prompt_toolkit.layout.controls import BufferControl, FormattedTextControl
    from prompt_toolkit.layout.dimension import Dimension
    from prompt_toolkit.styles import Style
    from prompt_toolkit.widgets import Frame

    argv = argv or ["claude"]
    if not shutil.which(argv[0]):
        print(f"the `{argv[0]}` CLI is not on PATH; install it first")
        return 127
    sabba_bin = shutil.which("sabba")
    start = time.monotonic()

    size = None
    try:
        from prompt_toolkit.output.defaults import create_output
        size = create_output().get_size()
    except Exception:
        pass
    cols = size.columns if size else 80
    rows = (size.rows - 10) if size else 20        # header, boot, frame, status, composer, footer

    term = PtyTerminal(argv, rows=max(rows, 4), cols=max(cols - 2, 20))
    term.spawn()
    state = {"mode": "claude-code", "status": ""}

    def _uptime():
        s = int(time.monotonic() - start)
        return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"

    def brand_meta():
        try:
            w = get_app().output.get_size().columns
        except Exception:
            w = cols
        left = [("class:brand", "SABBA"),
                ("class:tag", "   security bug-finder that proves every finding")]
        right = [("class:meta.v", "v0.2.0"), ("class:meta.k", "  ·  mode "),
                 ("class:meta.v", "claude-code"), ("class:meta.k", "  ·  session "),
                 ("class:meta.v", "new"), ("class:meta.k", "  ·  uptime "),
                 ("class:meta.v", _uptime()), ("", " ")]
        return FormattedText(_pad_line(left, right, w))

    def tags_line():
        return FormattedText([("class:tag2",
            " execution-oracle-anchored · multi-agent · always-proving · no-false-positives")])

    def pane():
        try:
            s = get_app().output.get_size()
            term.resize(max(s.rows - 10, 4), max(s.columns - 2, 20))
        except Exception:
            pass
        return FormattedText(render_screen(term.screen))

    def status_line():
        if not state["status"]:
            return FormattedText([])
        segs = []
        for ln in state["status"].splitlines():
            segs.append(("class:status", "  " + ln))
            segs.append(("", "\n"))
        return FormattedText(segs[:-1])

    def prompt_text():
        label = "sabba" if state["mode"] == "sabba" else "claude"
        return FormattedText([("class:prompt.on", f" {label} › ")])

    def footer():
        return FormattedText(_footer_ft(state["mode"]))

    # one composer for both targets; Tab flips where its input goes
    composer_buffer = Buffer(multiline=False)

    def accept(buff):
        text = buff.text
        buff.text = ""
        if state["mode"] == "claude-code":
            term.write(text.encode("utf-8") + b"\r")      # send the whole line to claude
            return None
        line = text.strip()
        if not line:
            return None
        if not sabba_bin:
            state["status"] = "sabba is not on PATH"
            return None
        state["status"] = f"$ sabba {line}\nrunning ..."
        get_app().invalidate()

        def work():
            state["status"] = _run_sabba_line(sabba_bin, line)
            try:
                get_app().invalidate()
            except Exception:
                pass
        threading.Thread(target=work, daemon=True).start()
        return None

    composer_buffer.accept_handler = accept

    pane_window = Window(FormattedTextControl(pane), wrap_lines=False)          # display only
    prompt_window = Window(FormattedTextControl(prompt_text), dont_extend_width=True, height=1)
    composer_window = Window(BufferControl(buffer=composer_buffer), height=1)
    status_window = Window(FormattedTextControl(status_line),
                           height=Dimension(min=0, max=8), dont_extend_height=True)

    body = HSplit([
        Window(FormattedTextControl(brand_meta), height=1),
        Window(FormattedTextControl(tags_line), height=1),
        Frame(pane_window, title="CLAUDE CODE (EMBEDDED WIDGET)"),
        status_window,
        VSplit([prompt_window, composer_window]),
        Window(FormattedTextControl(footer), height=1),
    ])

    kb = KeyBindings()

    @kb.add("c-q", eager=True)
    def _detach(event):
        event.app.exit()

    @kb.add("tab", eager=True)
    def _toggle(event):
        state["mode"] = "sabba" if state["mode"] == "claude-code" else "claude-code"

    style = Style.from_dict({
        "brand": "bold #dbe0e8",
        "tag": "#9aa1ad",
        "tag2": "#565d6d",
        "meta.k": "#838b98",
        "meta.v": "#b9c0cb",
        "boot": "#838b98",
        "boot.hi": "#dbe0e8",
        "boot.v": "#b9c0cb",
        "boot.dot": "#8a7f74",
        "frame.border": "#3b444f",
        "frame.label": "#9aa1ad",
        "status": "#8a7f74",
        "prompt.on": "bold #dbe0e8",
        "prompt.off": "#565d6d",
        "mode.sw": "#565d6d",
        "mode.on": "#dbe0e8",
        "footer": "#565d6d",
        "footer.key": "#838b98",
        "live": "#8a7f74",
    })

    app: Application = Application(
        layout=Layout(body, focused_element=composer_window),
        key_bindings=kb, style=style, full_screen=True, mouse_support=False)

    def _attach_reader():
        import asyncio
        loop = asyncio.get_event_loop()

        def on_output():
            data = term.read()
            if data is None:
                return
            if data == b"":
                try:
                    loop.remove_reader(term.master_fd)
                except Exception:
                    pass
                app.exit()
                return
            app.invalidate()

        if term.master_fd is not None:
            loop.add_reader(term.master_fd, on_output)

    try:
        app.run(pre_run=_attach_reader)
    finally:
        term.close()
    return 0
