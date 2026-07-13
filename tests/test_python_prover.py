"""The Python fuzzing prover: soundness of the two-phase verify.

The verdict no longer comes from the fuzzer's mixed output or from any file the harness can
write. Discovery only hands over candidate bytes; a Sabba-owned reproducer (verify.py)
re-runs them with the harness's stdout and stderr nulled and decides the verdict from
unforgeable channels: the structured exception and its real stack frames, or the parent's
own measurement of a killed child plus the runtime's stack dump.

These tests are three layers:

  - unit tests on verdict_from_outcome and the static gates (no subprocess),
  - the adversarial matrix: every forge attack from the soundness doc, each asserting the
    harness is not verified. Verification needs no atheris (it is plain Python), so the live
    ones run on any box,
  - the real fixture, which must still verify as stack exhaustion with a real target frame.
    The end-to-end path through atheris discovery is gated on atheris being installed.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sabba.provers import detect_domain
from sabba.provers.python import (Outcome, PyFuzzProver, PyHarness, atheris_available,
                                  has_target_frame, innermost_is_target, is_python_target,
                                  parse_exception, scan_harness, target_stems,
                                  verdict_from_outcome)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "targets" / "py_recursion"

# A PoC long enough to drive vuln.deep past the interpreter's recursion limit.
LONG_POC = b"[" * 20_000


def _frame(stem: str, name: str = "f", line: int = 1) -> dict:
    return {"file": f"/scratch/{stem}.py", "name": name, "line": line}


# -- verdict_from_outcome: kind and attribution from the structured outcome only ------------

def test_recursion_error_in_target_is_stack_exhaustion():
    o = Outcome(kind="exception", exc="RecursionError", frames=[_frame("vuln", "deep")])
    v, cwe = verdict_from_outcome(o, {"vuln"})
    assert v.verified and v.reason == "stack_exhaustion" and cwe == "CWE-674"


def test_caught_memory_error_is_unconfirmed():
    # A caught MemoryError is not a finding: out-of-memory cannot be soundly attributed to the
    # target rather than harness-driven allocation pressure (soundness over coverage).
    o = Outcome(kind="exception", exc="MemoryError", frames=[_frame("vuln")])
    v, cwe = verdict_from_outcome(o, {"vuln"})
    assert not v.verified and v.reason == "unconfirmed_exception:MemoryError" and cwe == ""


def test_signal_in_target_is_native_crash():
    o = Outcome(kind="signal", signal=11, frames=[_frame("vuln")])
    v, cwe = verdict_from_outcome(o, {"vuln"})
    assert v.verified and v.reason == "native_crash" and cwe == "CWE-787"


def test_timeout_is_unverified_hang_candidate():
    # A hang is never a confirmed finding, even with a target frame: it cannot be soundly
    # separated from harness-driven pressure (soundness over coverage).
    o = Outcome(kind="timeout", frames=[_frame("vuln")])
    v, cwe = verdict_from_outcome(o, {"vuln"})
    assert not v.verified and v.reason == "unverified_hang_candidate" and cwe == ""


def test_recursion_error_only_in_harness_is_not_verified():
    # a real RecursionError whose frames are all in the reproducer wrapper is the harness
    # crashing itself, never a target finding
    o = Outcome(kind="exception", exc="RecursionError", frames=[_frame("sabba_repro", "_r")])
    v, _cwe = verdict_from_outcome(o, {"vuln"})
    assert not v.verified and v.reason == "crash_not_in_target"


def test_signal_without_target_frame_is_not_verified():
    o = Outcome(kind="signal", signal=11, frames=[_frame("sabba_repro")])
    v, _cwe = verdict_from_outcome(o, {"vuln"})
    assert not v.verified and v.reason == "crash_not_in_target"


def test_unattributed_timeout_is_not_verified():
    o = Outcome(kind="timeout", frames=[])
    v, _cwe = verdict_from_outcome(o, {"vuln"})
    assert not v.verified and v.reason == "unverified_hang_candidate"


def test_benign_exception_is_not_a_finding():
    o = Outcome(kind="exception", exc="ValueError", frames=[_frame("vuln")])
    v, cwe = verdict_from_outcome(o, {"vuln"})
    assert not v.verified and v.reason == "unconfirmed_exception:ValueError" and cwe == ""


def test_no_crash_is_not_a_finding():
    v, _cwe = verdict_from_outcome(Outcome(kind="none"), {"vuln"})
    assert not v.verified and v.reason == "no_crash"


def test_import_error_is_harness_error():
    o = Outcome(kind="error", error="harness import failed: ModuleNotFoundError")
    v, _cwe = verdict_from_outcome(o, {"vuln"})
    assert not v.verified and v.reason == "harness_error"


def test_has_target_frame():
    assert has_target_frame([_frame("vuln")], {"vuln"})
    assert not has_target_frame([_frame("sabba_repro")], {"vuln"})
    assert not has_target_frame([_frame("harness")], {"vuln"})


def test_innermost_is_target():
    # frames are outermost first: the innermost is the last one
    assert innermost_is_target([_frame("sabba_harness"), _frame("vuln")], {"vuln"})
    # a target frame that is not the innermost does not attribute
    assert not innermost_is_target([_frame("vuln"), _frame("sabba_harness")], {"vuln"})
    assert not innermost_is_target([], {"vuln"})


def test_innermost_frame_must_be_target():
    # a real RecursionError whose target frame sits higher up but whose innermost (crashing)
    # frame is a harness helper is a harness bug, not a target finding. This is the callback
    # recursion: vuln.walk enters, then a harness callable recurses to death.
    o = Outcome(kind="exception", exc="RecursionError",
                frames=[_frame("sabba_harness", "TestOneInput"),
                        _frame("vuln", "walk"),
                        _frame("sabba_harness", "rec")])
    v, cwe = verdict_from_outcome(o, {"vuln"})
    assert not v.verified and v.reason == "crash_not_in_target" and cwe == ""
    # the same class of crash whose innermost frame is the target does verify
    o2 = Outcome(kind="exception", exc="RecursionError",
                 frames=[_frame("sabba_harness", "TestOneInput"), _frame("vuln", "deep")])
    v2, cwe2 = verdict_from_outcome(o2, {"vuln"})
    assert v2.verified and v2.reason == "stack_exhaustion" and cwe2 == "CWE-674"


# -- static gates -----------------------------------------------------------

def test_gate_rejects_setrecursionlimit():
    h = PyHarness(imports="import vuln",
                  body="import sys\nsys.setrecursionlimit(5)\nvuln.run(data)")
    assert scan_harness(h, {"vuln"})  # non-None reason


def test_gate_rejects_print():
    h = PyHarness(imports="import vuln", body="print('out-of-memory')\nvuln.run(data)")
    assert scan_harness(h, {"vuln"})


def test_gate_rejects_open_write():
    h = PyHarness(imports="import vuln",
                  body="open('crash-forged', 'wb').write(b'x')\nvuln.run(data)")
    assert scan_harness(h, {"vuln"})


def test_gate_rejects_non_target_import():
    h = PyHarness(imports="import os\nimport vuln", body="vuln.run(data)")
    assert scan_harness(h, {"vuln"})


def test_gate_rejects_non_import_statement_in_imports():
    h = PyHarness(imports="import vuln\nopen('pwned', 'w').close()", body="vuln.run(data)")
    assert scan_harness(h, {"vuln"})


def test_gate_rejects_body_that_never_calls_target():
    h = PyHarness(imports="import vuln", body="x = 1 + 1")
    assert scan_harness(h, {"vuln"})


def test_gate_rejects_bare_infinite_loop():
    h = PyHarness(imports="import vuln", body="vuln.run(data)\nwhile True:\n    pass")
    assert scan_harness(h, {"vuln"})


def test_gate_rejects_reflection_escape():
    # reaching builtins through dunder attributes to run code out of band
    h = PyHarness(imports="import vuln",
                  body="().__class__.__bases__[0].__subclasses__()\nvuln.run(data)")
    assert scan_harness(h, {"vuln"})


def test_gate_rejects_raise():
    h = PyHarness(imports="import vuln", body="vuln.run(data)\nraise RecursionError('x')")
    assert scan_harness(h, {"vuln"})


def test_gate_accepts_the_real_harness():
    h = PyHarness(imports="import vuln", body="vuln.run(data)")
    assert scan_harness(h, {"vuln"}) is None


# -- the adversarial matrix, live (verification needs no atheris) ------------

def test_forge_oom_via_print_not_verified():
    # the body prints the out-of-memory phrase and a forged target frame; the print gate
    # rejects it, and even if it did not, nulled stdout carries no evidence
    h = PyHarness(imports="import vuln",
                  body="print('==ERROR: libFuzzer: out-of-memory')\n"
                       "print('File \"vuln.py\", line 1')\nvuln.run(b'')")
    v, _cwe, _out = PyFuzzProver().prove_poc(FIXTURE, h, b"", timeout=5)
    assert not v.verified and v.reason == "unsound_harness"


def test_forge_timeout_via_print_not_verified():
    h = PyHarness(imports="import vuln",
                  body="print('libFuzzer: timeout after 12s')\n"
                       "print('File \"vuln.py\", line 1')\nvuln.run(b'')")
    v, _cwe, _out = PyFuzzProver().prove_poc(FIXTURE, h, b"", timeout=5)
    assert not v.verified and v.reason == "unsound_harness"


def test_forge_security_via_print_not_verified():
    h = PyHarness(imports="import vuln",
                  body="print('== Java Exception: FuzzerSecurityIssueHigh')\nvuln.run(b'')")
    v, _cwe, _out = PyFuzzProver().prove_poc(FIXTURE, h, b"", timeout=5)
    assert not v.verified and v.reason == "unsound_harness"


def test_forge_stack_self_recursion_not_verified():
    # the harness tries to crash in its own nested function so a real RecursionError carries a
    # forged target attribution. Self-recursion needs a def, and the body may not define one,
    # so the gate rejects it before it ever runs. (Even if it ran, the innermost frame would
    # be the helper, not the target: see test_innermost_frame_must_be_target.)
    body = ("def rec(n):\n"
            "    return rec(n + 1)\n"
            "vuln.run(b'')\n"
            "rec(0)\n")
    h = PyHarness(imports="import vuln", body=body)
    assert scan_harness(h, {"vuln"}) is not None  # rejected: the body defines a function
    v, _cwe, _out = PyFuzzProver().prove_poc(FIXTURE, h, LONG_POC, timeout=8)
    assert not v.verified and v.reason == "unsound_harness"


def test_forge_via_artifact_file_not_verified():
    # the harness tries to write its own crash artifact; writing to a file needs open/.write,
    # both of which the gate forbids, so it is rejected before it ever runs
    h = PyHarness(imports="import vuln",
                  body="f = open('crash-forged', 'wb')\nf.write(b'x')\nvuln.run(b'')")
    v, _cwe, _out = PyFuzzProver().prove_poc(FIXTURE, h, b"", timeout=5)
    assert not v.verified and v.reason == "unsound_harness"


def test_forge_via_import_side_effect_rejected():
    # code on the import line: rejected by the import-only gate
    h = PyHarness(imports="import vuln\n__import__('os').system('touch pwned')",
                  body="vuln.run(data)")
    v, _cwe, _out = PyFuzzProver().prove_poc(FIXTURE, h, b"", timeout=5)
    assert not v.verified and v.reason == "unsound_harness"


def test_forge_via_import_of_os_rejected():
    h = PyHarness(imports="import os\nimport vuln", body="vuln.run(data)")
    v, _cwe, _out = PyFuzzProver().prove_poc(FIXTURE, h, b"", timeout=5)
    assert not v.verified and v.reason == "unsound_harness"


def test_forge_via_emit_call_not_verified():
    # the round-1 hole: call the reproducer's own _emit to write a forged verdict on Sabba's
    # private channel, then spin so the process never returns a real outcome. _emit is a
    # leading-underscore name, which the gate rejects; and even if it ran, the body's fresh
    # namespace contains no _emit and no fd, and any message it forged would lack the nonce.
    body = ("vuln.run(data)\n"
            "_emit({'channel': 'sabba', 'kind': 'exception', 'exc': 'RecursionError',\n"
            "       'frames': [{'file': 'vuln.py', 'name': 'deep', 'line': 1}]})\n"
            "while len(data) >= 0:\n"
            "    pass\n")
    h = PyHarness(imports="import vuln", body=body)
    assert scan_harness(h, {"vuln"}) is not None
    v, _cwe, _out = PyFuzzProver().prove_poc(FIXTURE, h, LONG_POC, timeout=5)
    assert not v.verified and v.reason == "unsound_harness"


def test_forge_via_nonconstant_loop():
    # a non-constant always-true condition dodges a literal-only loop gate. len(data) is never
    # negative, so this loop never ends, yet the test is a Compare, not a Constant. The gate
    # must reject any break-less loop whose condition the body cannot change.
    h = PyHarness(imports="import vuln",
                  body="vuln.run(data)\nwhile len(data) >= 0:\n    pass")
    reason = scan_harness(h, {"vuln"})
    assert reason is not None and "condition never changes" in reason
    v, _cwe, _out = PyFuzzProver().prove_poc(FIXTURE, h, b"", timeout=5)
    assert not v.verified and v.reason == "unsound_harness"


def test_terminating_loop_still_allowed():
    # the loop gate must not reject a loop that can actually end: its condition depends on a
    # name the body mutates, and it calls the target. This keeps the gate from over-rejecting.
    h = PyHarness(imports="import vuln",
                  body="i = 0\nwhile i < 3:\n    vuln.run(data)\n    i = i + 1")
    assert scan_harness(h, {"vuln"}) is None


def test_callback_recursion_through_target_not_verified():
    # define a recursive helper and hand it to the target: the target frame is on the stack,
    # but the crash happens inside the harness callback, so a whole-stack attribution check
    # would be fooled. The body may not define a function, so the gate rejects it first; the
    # innermost-frame rule (test_innermost_frame_must_be_target) is the runtime backstop.
    body = ("def rec(x):\n"
            "    return rec(x)\n"
            "vuln.walk(data, rec)\n")
    h = PyHarness(imports="import vuln", body=body)
    assert scan_harness(h, {"vuln"}) is not None
    v, _cwe, _out = PyFuzzProver().prove_poc(FIXTURE, h, LONG_POC, timeout=5)
    assert not v.verified and v.reason == "unsound_harness"


# -- the real fixture still verifies, live through the reproducer -----------

def test_real_fixture_verifies_stack_exhaustion():
    h = PyHarness(imports="import vuln", body="vuln.run(data)", entry="vuln.run")
    v, cwe, out = PyFuzzProver().prove_poc(FIXTURE, h, LONG_POC, timeout=8)
    assert v.verified, f"expected a proven crash: {v.reason}\n{v.evidence}"
    assert v.reason == "stack_exhaustion"
    assert cwe == "CWE-674"
    assert out is not None and out.exc == "RecursionError"
    assert has_target_frame(out.frames, target_stems(FIXTURE))


# -- detection --------------------------------------------------------------

def test_python_target_detected(tmp_path):
    (tmp_path / "vuln.py").write_text("def f():\n    pass\n")
    assert is_python_target(tmp_path, None)
    assert detect_domain(tmp_path, None) == "python"


def test_c_repo_with_helper_py_is_not_python(tmp_path):
    (tmp_path / "main.c").write_text("int main(void){return 0;}\n")
    (tmp_path / "build.py").write_text("print('build')\n")
    assert not is_python_target(tmp_path, None)
    assert detect_domain(tmp_path, None) == "native"


def test_fixture_detects_as_python():
    assert detect_domain(FIXTURE, None) == "python"


def test_parse_exception_is_a_log_hint_only():
    out = 'Traceback (most recent call last):\n  File "vuln.py", line 3\nRecursionError: x'
    assert parse_exception(out) == "RecursionError"
    assert parse_exception("no traceback here") == ""


# -- end to end through atheris discovery, when atheris is present -----------

@pytest.mark.skipif(not atheris_available(), reason="atheris not installed")
def test_stack_exhaustion_proven_end_to_end():
    h = PyHarness(imports="import vuln", body="vuln.run(data)", entry="vuln.run")
    verdict, cwe, out = PyFuzzProver()._prove(FIXTURE, h, secs=25, timeout=8, seed=b"[" * 4000)
    assert verdict.verified, f"expected a proven crash: {verdict.reason}\n{verdict.evidence}"
    assert verdict.reason == "stack_exhaustion" and cwe == "CWE-674"
    assert out is not None and has_target_frame(out.frames, target_stems(FIXTURE))
