"""The bottom composer grows to fit long and multi-line messages.

It used to be a single-line Input, so a long message scrolled sideways and only the tail was
visible. These checks run the real Textual app headless (a Pilot) and assert the composer now
wraps and grows, still submits on Enter, and keeps a working hidden mode for the API-key paste.
"""
import asyncio

from textual.events import Paste

from sabba.tui import Composer, SabbaApp


def _run(coro):
    asyncio.run(coro)


def test_composer_grows_with_wrapped_and_multiline_text():
    async def check():
        app = SabbaApp()
        async with app.run_test(size=(80, 30)) as pilot:
            box = app.query_one("#composer", Composer)
            cbox = app.query_one("#composer-box")
            await pilot.pause()

            # empty: one row, placeholder shown on the border
            assert box.styles.height.value == 1
            assert cbox.border_subtitle

            # a long line wraps onto several rows and the box grows to match
            box.value = "prove this finding by triggering it " * 8
            await pilot.pause()
            assert box.value == "prove this finding by triggering it " * 8
            assert box.styles.height.value > 1
            assert cbox.border_subtitle == ""   # hint hidden once there is text

            # explicit newlines grow it too, and clearing collapses it back to one row
            box.value = "one\ntwo\nthree"
            await pilot.pause()
            assert box.styles.height.value >= 3
            box.value = ""
            await pilot.pause()
            assert box.styles.height.value == 1
            assert cbox.border_subtitle

    _run(check())


def test_enter_submits_and_ctrl_j_inserts_a_newline():
    async def check():
        app = SabbaApp()
        async with app.run_test(size=(80, 30)) as pilot:
            box = app.query_one("#composer", Composer)
            box.focus()
            await pilot.pause()

            n_before = len(app.query_one("#log").children)
            box.value = "hello there"
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            assert box.value == ""                              # cleared by the submit path
            assert len(app.query_one("#log").children) > n_before  # line posted to the log

            box.value = "first"
            box.focus()
            await pilot.pause()
            await pilot.press("ctrl+j")
            await pilot.pause()
            assert "\n" in box.value                            # newline, not a submit

    _run(check())


def test_password_mode_masks_the_key_but_keeps_the_real_value():
    async def check():
        app = SabbaApp()
        async with app.run_test(size=(80, 30)) as pilot:
            box = app.query_one("#composer", Composer)
            await pilot.pause()
            box.password = True
            box.post_message(Paste("sk-secret-123"))
            await pilot.pause()
            assert set(box.text) == {"•"}            # only bullets on screen
            assert len(box.text) == len("sk-secret-123")
            assert box.value == "sk-secret-123"           # real key preserved for saving
            box.password = False
            assert box.value == ""                        # leaving the mode wipes the field

    _run(check())
