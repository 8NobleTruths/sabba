"""The REPL buffers a reply and renders it as Markdown at the end, so headers, tables, and code
come out formatted rather than as raw ## and | text. The spinner shows a live token count during
generation (status_frags) so a slow model is not a silent wait."""
import io

from rich.console import Console

from sabba.repl import Repl


def _stub():
    class S:
        pass
    s = S()
    s.console = Console(file=io.StringIO(), force_terminal=False, width=120)
    s.last_assistant = ""
    return s


def test_reply_is_buffered_then_rendered_as_markdown():
    s = _stub()
    Repl.on_start(s)
    assert s._out_count == 0
    Repl.on_text(s, "# Title\n")
    Repl.on_text(s, "some **bold** words")
    assert s._out_count == 2                       # deltas counted for the spinner
    assert s.console.file.getvalue() == ""         # nothing printed yet: it is buffered
    Repl.on_done(s, 100, 20)
    out = s.console.file.getvalue()
    assert "Title" in out and "some" in out and "bold" in out
    assert "##" not in out and "**bold**" not in out   # rendered, not raw markdown
    assert "100 in" in out and "20 out" in out
    assert s.last_assistant == "# Title\nsome **bold** words"


def test_empty_chunks_do_not_count():
    s = _stub()
    Repl.on_start(s)
    Repl.on_text(s, "")
    assert s._out_count == 0
    Repl.on_text(s, "x")
    assert s._out_count == 1
