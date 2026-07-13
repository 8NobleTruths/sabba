"""The Go fuzzing prover: soundness tests.

Two kinds of test. Offline tests need no go toolchain: they exercise the static gates (which
run before anything executes), the structured-outcome classifier, attribution, and detection.
Live tests, gated on the go toolchain, run the real Sabba reproducer end to end: the genuine
fixture must still verify with the right kind and CWE, and a harness that crashes itself must
not verify because its structured stack lands in the wrapper, not the target.

The forge matrix from docs/PROVER_SOUNDNESS.md is encoded here. Every forge attempt asserts
the harness is NOT verified.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sabba.provers import detect_domain
from sabba.provers.golang import (GoFuzzProver, GoHarness, Outcome, classify_outcome,
                                   frames_hit_target, go_available, is_go_target)
from sabba.provers.golang.classify import crash_frame_is_target
from sabba.provers.golang.prover import (_calls_target, _gate_body, _gate_import,
                                         _import_aliases)

ROOT = Path(__file__).resolve().parents[1]
GO_OOB = ROOT / "targets" / "go_oob"
TARGET_STEMS = {"vuln"}


# -- the classifier reads kind and attribution only from the structured outcome --

def _recover(value: str, frames: str) -> Outcome:
    return Outcome(channel="recover", panic_value=value, frames=frames)


def test_index_panic_is_verified():
    out = _recover("runtime error: index out of range [100] with length 3",
                   "goroutine 1 [running]:\ngoobtarget.Index(...)\n\t/w/vuln.go:6 +0x1d\n")
    v, cwe = classify_outcome(out, TARGET_STEMS)
    assert v.verified and v.reason == "panic_crash" and cwe == "CWE-125"


def test_nil_and_divzero_map_to_their_class():
    nil = _recover("runtime error: invalid memory address or nil pointer dereference",
                   "\t/w/vuln.go:4 +0x1")
    assert classify_outcome(nil, TARGET_STEMS)[1] == "CWE-476"
    dz = _recover("runtime error: integer divide by zero", "\t/w/vuln.go:9 +0x1")
    assert classify_outcome(dz, TARGET_STEMS)[1] == "CWE-369"


def test_generic_panic_is_uncaught_class():
    out = _recover("something bad happened", "\t/w/vuln.go:2 +0x1")
    v, cwe = classify_outcome(out, TARGET_STEMS)
    assert v.verified and v.reason == "panic_crash" and cwe == "CWE-248"


def test_fatal_stack_overflow_is_verified():
    frames = ("runtime: goroutine stack exceeds 1000000000-byte limit\n"
              "fatal error: stack overflow\n\t/w/vuln.go:8 +0x38\n")
    v, cwe = classify_outcome(Outcome(channel="fatal", frames=frames), TARGET_STEMS)
    assert v.verified and v.reason == "stack_exhaustion" and cwe == "CWE-674"


def test_fatal_oom_is_unverified_candidate():
    # Out-of-memory is never confirmed: it cannot be soundly attributed to the target rather
    # than harness-driven allocation, so it stays an unverified candidate (soundness over coverage).
    frames = "fatal error: runtime: out of memory\n\t/w/vuln.go:12 +0x1\n"
    v, cwe = classify_outcome(Outcome(channel="fatal", frames=frames), TARGET_STEMS)
    assert not v.verified and v.reason == "unverified_oom_candidate" and cwe == ""


def test_timeout_is_unverified_hang_candidate():
    # A hang is never confirmed, even with a target frame in the dump (soundness over coverage).
    frames = "SIGQUIT: quit\ngoroutine 1:\ngoobtarget.Hang(...)\n\t/w/vuln.go:15 +0x1\n"
    v, cwe = classify_outcome(Outcome(channel="timeout", frames=frames), TARGET_STEMS)
    assert not v.verified and v.reason == "unverified_hang_candidate" and cwe == ""


def test_no_crash_and_build_error_are_not_findings():
    assert not classify_outcome(Outcome(channel="none"), TARGET_STEMS)[0].verified
    v, _ = classify_outcome(Outcome(channel="build_error"), TARGET_STEMS)
    assert not v.verified and v.reason == "harness_error"


# -- attribution: a crash whose structured stack is only in the wrapper is rejected --

def test_frames_hit_target():
    assert frames_hit_target("\t/w/vuln.go:6 +0x1", TARGET_STEMS)
    assert not frames_hit_target("\t/w/zz_sabba_body.go:6 +0x1", TARGET_STEMS)
    assert not frames_hit_target("panic: out of memory at vuln.go line 6", TARGET_STEMS)


def test_recover_without_target_frame_is_not_verified():
    # the harness panicked in its own wrapper, not in the target
    out = _recover("runtime error: index out of range [1] with length 0",
                   "goroutine 1:\nmain.sabbaRunBody(...)\n\t/w/zz_sabba_body.go:6 +0x1\n")
    v, cwe = classify_outcome(out, TARGET_STEMS)
    assert not v.verified and v.reason == "crash_not_in_target"


def test_fatal_overflow_without_target_frame_is_not_verified():
    frames = "fatal error: stack overflow\n\t/w/zz_sabba_body.go:8 +0x1\n"
    v, _ = classify_outcome(Outcome(channel="fatal", frames=frames), TARGET_STEMS)
    assert not v.verified and v.reason == "crash_not_in_target"


def test_timeout_without_target_frame_is_not_verified():
    frames = "SIGQUIT: quit\ngoroutine 1:\nmain.sabbaRunBody(...)\n\t/w/zz_sabba_body.go:9\n"
    v, _ = classify_outcome(Outcome(channel="timeout", frames=frames), TARGET_STEMS)
    assert not v.verified and v.reason == "unverified_hang_candidate"


# -- attribution is from the INNERMOST (crashing) frame, not any target frame present --

def test_crash_frame_walks_to_innermost_user_frame():
    # a real recovered-panic dump: the defer closure (zz_sabba_main) and the runtime panic frame
    # sit ABOVE the crash site. The innermost USER frame is the target, so it attributes.
    real = ("goroutine 1 [running]:\n"
            "main.main.func1()\n\t/w/zz_sabba_main.go:16 +0x48\n"
            "panic({0x0?, 0x0?})\n\t/usr/local/go/src/runtime/panic.go:860 +0x12c\n"
            "goobtarget.Index(...)\n\t/w/vuln.go:6\n"
            "main.sabbaRunBody(...)\n\t/w/zz_sabba_body.go:10\n"
            "main.main()\n\t/w/zz_sabba_main.go:20\n")
    assert crash_frame_is_target(real, TARGET_STEMS)


def test_crash_frame_rejects_body_innermost_even_with_deeper_target_frame():
    # the harness body crashed itself; a target frame appears only as a caller deeper down. The
    # innermost user frame is the body, so this is not a target bug. frames_hit_target (presence)
    # would wrongly pass, crash_frame_is_target (innermost) must not.
    body_crash = ("goroutine 1 [running]:\n"
                  "main.main.func1()\n\t/w/zz_sabba_main.go:16\n"
                  "panic({0x0?, 0x0?})\n\t/usr/local/go/src/runtime/panic.go:860\n"
                  "main.sabbaRunBody(...)\n\t/w/zz_sabba_body.go:10\n"
                  "goobtarget.Helper(...)\n\t/w/vuln.go:6\n")
    assert frames_hit_target(body_crash, TARGET_STEMS)          # a target frame is present
    assert not crash_frame_is_target(body_crash, TARGET_STEMS)  # but not at the crashing frame
    v, _ = classify_outcome(Outcome(channel="recover", panic_value="boom", frames=body_crash),
                            TARGET_STEMS)
    assert not v.verified and v.reason == "crash_not_in_target"


# -- timeout: never a confirmed finding, even in the strongest attributable case --

def test_timeout_is_unverified_even_with_running_body_in_target():
    # Even when the running goroutine's innermost frame is the target (a real hang inside a
    # target function), a timeout is never confirmed: a hang cannot be soundly separated from
    # harness-driven pressure, so it stays an unverified candidate (soundness over coverage).
    frames = ("SIGQUIT: quit\n"
              "goroutine 1 [running]:\n"
              "goobtarget.Loop(...)\n\t/w/vuln.go:15 +0x1\n"
              "main.sabbaRunBody(...)\n\t/w/zz_sabba_body.go:7 +0x1\n")
    v, cwe = classify_outcome(Outcome(channel="timeout", frames=frames), TARGET_STEMS)
    assert not v.verified and v.reason == "unverified_hang_candidate" and cwe == ""


# -- the import gate: only a single plain import of the target module --

def test_import_gate_accepts_the_target():
    assert _gate_import('vuln "goobtarget"', "goobtarget") is None
    assert _gate_import('"goobtarget/pkg/parse"', "goobtarget") is None


def test_import_gate_rejects_other_modules():
    assert _gate_import('"os/exec"', "goobtarget")
    assert _gate_import('x "os"', "goobtarget")
    assert _gate_import('"net/http"', "goobtarget")


def test_import_gate_rejects_blank_and_dot_imports():
    assert _gate_import('_ "goobtarget"', "goobtarget")   # side-effect init
    assert _gate_import('. "goobtarget"', "goobtarget")   # dot import


def test_import_gate_rejects_break_out_of_import_block():
    # the classic Go template-injection: escape the import block to run code
    inj = 'vuln "goobtarget"\n)\n\nfunc init() { doEvil() }\n\nvar _ = ('
    assert _gate_import(inj, "goobtarget")
    assert _gate_import('vuln "goobtarget"\n\t_ "os/exec"', "goobtarget")  # smuggled 2nd import


def test_import_aliases():
    assert _import_aliases('vuln "goobtarget"') == {"vuln", "goobtarget"}
    assert _import_aliases('"goobtarget/pkg/parse"') == {"parse"}


# -- the body gate: no manufactured crash, no output writer, no testing.T --

def test_body_gate_rejects_panic_and_recover():
    assert "panic" in _gate_body('panic("boom")')
    assert "recover" in _gate_body("defer func(){ recover() }()")


def test_body_gate_rejects_output_writers():
    # this is what makes forge-via-print impossible: the write itself is gated
    assert _gate_body('fmt.Println("out of memory at vuln.go:6")')
    assert _gate_body('println("timeout vuln.go:6")')
    assert _gate_body('os.Stderr.WriteString("boom")')


def test_body_gate_rejects_os_runtime_reflect_and_infinite_loop():
    assert _gate_body("os.Exit(1)")
    assert _gate_body("runtime.Goexit()")
    assert _gate_body("debug.SetMaxStack(1)")
    assert _gate_body("reflect.ValueOf(data)")
    assert _gate_body("for {\n\tvuln.Index(data)\n}")
    assert _gate_body("t.Fatal(\"x\")")


def test_body_gate_allows_a_plain_target_call():
    assert _gate_body("vuln.Index(data)") == []


def test_nonconstant_loop_rejected():
    # a plain `for {}` was already rejected; the bypass is an always-true condition that looks
    # nonconstant. These all spin forever regardless of the target, so a harness could use them
    # to force a wall-clock timeout. Reject every one.
    assert _gate_body("for len(data) >= 0 {\n\tvuln.Index(data)\n}")
    assert _gate_body("for len(data) > -1 {\n\tvuln.Index(data)\n}")
    assert _gate_body("for true {\n\tvuln.Index(data)\n}")
    assert _gate_body("for i := 0; ; i++ {\n\tvuln.Index(data)\n}")     # empty middle clause
    assert _gate_body("for cond || true {\n\tvuln.Index(data)\n}")
    # a bounded loop that makes progress is still allowed
    assert _gate_body("for i := 0; i < len(data); i++ {\n\tvuln.Index(data[i:])\n}") == []
    assert _gate_body("for _, b := range data {\n\tvuln.Feed(b)\n}") == []


def test_body_gate_rejects_func_literal():
    # a func literal lets the body define a recursive helper or a callback it passes into the
    # target, so a crash can route through a target frame that is not a target bug.
    assert "func" in _gate_body("f := func(n int) { f(n + 1) }\nf(0)")
    assert "func" in _gate_body("vuln.Walk(data, func(b []byte) {})")


def test_calls_target():
    assert _calls_target("vuln.Index(data)", {"vuln", "goobtarget"})
    assert not _calls_target("_ = data", {"vuln", "goobtarget"})


# -- the forge matrix, at the prover boundary (gates run offline, before go) --

def _prove(harness, **kw):
    return GoFuzzProver()._prove(GO_OOB, harness, secs=5, timeout=5, **kw)


def test_forge_oom_via_print():
    h = GoHarness(import_line='vuln "goobtarget"',
                  body='vuln.Index(data)\nfmt.Println("fatal error: runtime: out of memory\\nvuln.go:6")')
    v, _cwe, _o = _prove(h)
    assert not v.verified and v.reason == "unsound_harness"


def test_forge_timeout_via_print():
    h = GoHarness(import_line='vuln "goobtarget"',
                  body='vuln.Index(data)\nprintln("test timed out at vuln.go:6")')
    v, _cwe, _o = _prove(h)
    assert not v.verified and v.reason == "unsound_harness"


def test_forge_security_via_print():
    h = GoHarness(import_line='vuln "goobtarget"',
                  body='vuln.Index(data)\nfmt.Fprintln(os.Stderr, "SECURITY ISSUE vuln.go:6")')
    v, _cwe, _o = _prove(h)
    assert not v.verified and v.reason == "unsound_harness"


def test_forge_via_artifact_file():
    # the harness tries to write a crash artifact itself; the os write is gated
    h = GoHarness(import_line='vuln "goobtarget"',
                  body='vuln.Index(data)\nos.WriteFile("crash-1", []byte("oom vuln.go:6"), 0644)')
    v, _cwe, _o = _prove(h)
    assert not v.verified and v.reason == "unsound_harness"


def test_forge_via_import_side_effect():
    # code smuggled through the import line is rejected by the import-only gate
    h = GoHarness(import_line='vuln "goobtarget"\n)\nfunc init(){ recover() }\nvar _ = (',
                  body="vuln.Index(data)")
    v, _cwe, _o = _prove(h)
    assert not v.verified and v.reason == "unsound_harness"


def test_body_that_does_not_call_target_is_rejected():
    h = GoHarness(import_line='vuln "goobtarget"', body="_ = data")
    v, _cwe, _o = _prove(h)
    assert not v.verified and v.reason == "unsound_harness"


def test_callback_recursion_not_verified():
    # the body defines a recursive callback and passes it into the target. A stack overflow that
    # bounces through a target frame this way is not a target bug. The func gate rejects it up
    # front, so it never runs.
    body = ("var cb func([]byte)\n"
            "cb = func(b []byte) { vuln.Walk(b, cb) }\n"
            "vuln.Walk(data, cb)")
    h = GoHarness(import_line='vuln "goobtarget"', body=body, entry="callback recursion forge")
    v, _cwe, _o = _prove(h)
    assert not v.verified and v.reason == "unsound_harness"
    assert "func" in _gate_body(body)


# -- detection --------------------------------------------------------------

def test_go_target_detected(tmp_path):
    (tmp_path / "go.mod").write_text("module x\n\ngo 1.21\n")
    (tmp_path / "vuln.go").write_text("package vuln\n\nfunc F() {}\n")
    assert is_go_target(tmp_path, None)
    assert detect_domain(tmp_path, None) == "go"


def test_c_repo_with_helper_go_is_not_go(tmp_path):
    (tmp_path / "main.c").write_text("int main(void){return 0;}\n")
    (tmp_path / "gen.go").write_text("package main\n")
    assert not is_go_target(tmp_path, None)


def test_fixture_detects_as_go():
    assert detect_domain(GO_OOB, None) == "go"


# -- live, when the go toolchain is present ---------------------------------

@pytest.mark.skipif(not go_available(), reason="go toolchain not installed")
def test_real_fixture_still_verifies():
    # the genuine index-out-of-range panic: a short seed reproduces it deterministically
    h = GoHarness(import_line='vuln "goobtarget"', body="vuln.Index(data)", entry="vuln.Index")
    v, cwe, outcome = GoFuzzProver()._prove(GO_OOB, h, secs=15, timeout=8, seed=b"\x00" * 8)
    assert v.verified, f"expected a proven crash: {v.reason}\n{v.evidence}"
    assert v.reason == "panic_crash"
    assert cwe == "CWE-125"
    assert outcome.channel == "recover"
    assert "vuln.go" in (outcome.frames or "")


def test_forge_stack_self_recursion_is_not_verified():
    # the body recurses itself to a real stack overflow through a func literal. Two layers reject
    # it: the func gate rejects the harness before it ever runs, and even if it ran the crashing
    # frames would all be in the wrapper, not the target. This no longer needs the go toolchain
    # because the gate catches it offline.
    body = ("_ = vuln.Index(data)\n"
            "var f func(int)\n"
            "f = func(n int) { f(n + 1) }\n"
            "f(0)")
    h = GoHarness(import_line='vuln "goobtarget"', body=body, entry="self-recursion forge")
    v, _cwe, _outcome = GoFuzzProver()._prove(GO_OOB, h, secs=15, timeout=8, seed=b"\x00" * 200)
    assert not v.verified, f"self-recursion must not verify, got {v.reason}"
    assert v.reason in ("unsound_harness", "crash_not_in_target", "no_crash", "unconfirmed_failure")
