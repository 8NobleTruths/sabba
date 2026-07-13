"""The REPL composer grows to fit long and multi-line messages.

The input window used to be pinned at height=1 with wrap_lines on, so a long message wrapped
internally but only the last row was visible. This runs the real prompt_toolkit app headless
(a pipe input and a dummy output) and checks the input window now sizes to the wrapped text.
"""
import asyncio
import types

from prompt_toolkit.input.defaults import create_pipe_input
from prompt_toolkit.output import DummyOutput
from prompt_toolkit.styles import Style as PTStyle

from sabba.repl import SlashCompleter, _input_app


def _fake_repl():
    r = types.SimpleNamespace()
    r._pending = []
    r._active = False
    r._waiting = False
    r._t0 = 0.0
    r._verb = "working"
    r._busy = lambda: False
    r._stop = lambda: None
    return r


def test_repl_composer_grows_with_wrapped_and_multiline_text():
    async def check():
        with create_pipe_input() as inp:
            app = _input_app(SlashCompleter(), PTStyle([]), _fake_repl(), inp, DummyOutput())
            win, buf = app.sabba_input_win, app.sabba_buf
            rows = {}

            async def drive():
                await asyncio.sleep(0.25)              # let the app render once
                width = 60
                buf.text = ""
                rows["empty"] = win.preferred_height(width, 100).preferred
                buf.text = "x" * 300                    # long single line, must wrap
                rows["long"] = win.preferred_height(width, 100).preferred
                buf.text = "one\ntwo\nthree\nfour"       # explicit newlines
                rows["multiline"] = win.preferred_height(width, 100).preferred
                buf.text = "z" * 4000                    # very long, clamps at the max
                rows["huge"] = win.preferred_height(width, 100).preferred
                app.exit()

            asyncio.ensure_future(drive())
            await app.run_async()
            return rows

    rows = asyncio.run(check())
    assert rows["empty"] == 1
    assert rows["long"] > 1
    assert rows["multiline"] >= 4
    assert rows["huge"] == 10
