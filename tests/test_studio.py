"""Sabba Studio embeds a live pty (Claude Code) and renders it with pyte.

These cover the emulator core headlessly, without an interactive terminal or claude: a real
child runs on a pty and its coloured output is captured, and the pyte -> prompt_toolkit
render keeps text, colour, bold, and the cursor cell."""
import time

import pyte

from sabba import studio
from sabba.studio import PtyTerminal, _color, render_screen


def test_color_mapping():
    assert _color("green") == "ansigreen"
    assert _color("red") == "ansired"
    assert _color("default") == ""
    assert _color("ff8800") == "#ff8800"
    assert _color("") == ""


def test_render_screen_captures_text_and_style():
    screen = pyte.Screen(20, 3)
    pyte.ByteStream(screen).feed(b"\x1b[1;32mHI\x1b[0m ok\r\nline2")
    ft = render_screen(screen)
    text = "".join(t for _, t in ft)
    assert "HI ok" in text and "line2" in text
    green_run = next((s for s, t in ft if t.startswith("HI")), "")
    assert "ansigreen" in green_run and "bold" in green_run


def test_render_screen_marks_cursor():
    screen = pyte.Screen(10, 2)
    pyte.ByteStream(screen).feed(b"ab")            # cursor now at col 2, row 0
    ft = render_screen(screen)
    assert any("reverse" in s for s, _ in ft)


def test_pty_terminal_runs_a_command():
    term = PtyTerminal(["bash", "-c", "printf '\\033[32mSABBA-PTY\\033[0m\\n'"], rows=4, cols=40)
    term.spawn()
    got_eof = False
    deadline = time.time() + 5
    while time.time() < deadline:
        data = term.read()
        if data == b"":
            got_eof = True
            break
        time.sleep(0.02)
    display = "".join(term.screen.display)
    term.close()
    assert got_eof
    assert "SABBA-PTY" in display


def test_pty_terminal_missing_program_dies():
    term = PtyTerminal(["definitely-not-a-real-cmd-xyz-123"], rows=4, cols=20)
    term.spawn()
    dead = False
    for _ in range(50):
        if not term.is_alive():
            dead = True
            break
        time.sleep(0.02)
    term.close()
    assert dead


def test_pty_terminal_resize():
    term = PtyTerminal(["bash", "-c", "sleep 0.3"], rows=10, cols=40)
    term.spawn()
    term.resize(20, 80)
    assert term.rows == 20 and term.cols == 80
    assert term.screen.lines == 20 and term.screen.columns == 80
    term.close()


def test_key_bytes_map_has_essentials():
    from prompt_toolkit.keys import Keys
    m = studio._key_bytes_map()
    assert m[Keys.Enter] == b"\r"
    assert m[Keys.ControlC] == b"\x03"
    assert m[Keys.Up] == b"\x1b[A"
    assert m[Keys.Backspace] == b"\x7f"


# ---- v2 chrome + dual-mode composer ----

def test_pad_line_fills_width_and_keeps_ends():
    out = studio._pad_line([("", "abc")], [("", "xy")], 10)
    text = "".join(t for _, t in out)
    assert len(text) == 10
    assert text.startswith("abc") and text.endswith("xy")


def test_footer_shows_mode_and_keys():
    text = "".join(t for _, t in studio._footer_ft("sabba"))
    assert "tab" in text and "sabba" in text and "ctrl-q" in text


def test_run_sabba_line_summarizes(monkeypatch):
    import subprocess

    class P:
        stdout = "first\nlast line"
        stderr = ""
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: P())
    out = studio._run_sabba_line("/usr/bin/sabba", "doctor")
    assert "sabba doctor" in out and "last line" in out


def test_run_sabba_line_reports_error(monkeypatch):
    import subprocess

    def boom(*a, **k):
        raise subprocess.TimeoutExpired("sabba", 1)
    monkeypatch.setattr(subprocess, "run", boom)
    out = studio._run_sabba_line("/usr/bin/sabba", "hunt /x", timeout=1)
    assert "error" in out


def test_run_missing_program_returns_127():
    assert studio.run(["definitely-not-a-real-cmd-xyz-123"]) == 127


def test_prompt_toolkit_symbols_used_by_run_exist():
    # catch API drift in the version installed, since run() can't be driven headlessly
    from prompt_toolkit.application import Application, get_app  # noqa: F401
    from prompt_toolkit.buffer import Buffer  # noqa: F401
    from prompt_toolkit.filters import has_focus  # noqa: F401
    from prompt_toolkit.layout import Layout  # noqa: F401
    from prompt_toolkit.layout.containers import HSplit, VSplit, Window  # noqa: F401
    from prompt_toolkit.layout.controls import BufferControl, FormattedTextControl  # noqa: F401
    from prompt_toolkit.widgets import Frame  # noqa: F401


def test_run_builds_the_full_layout(monkeypatch):
    # the whole gray chrome (header, boot, Frame pane, composer, footer, key bindings)
    # is constructed here without a terminal; only app.run is stubbed out.
    from prompt_toolkit.application import Application

    built = {}
    monkeypatch.setattr(Application, "run", lambda self, *a, **k: built.setdefault("ok", True))
    rc = studio.run(["cat"])          # cat waits on stdin in the pty; app.run is stubbed
    assert built.get("ok") is True
    assert rc == 0
