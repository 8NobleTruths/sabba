"""The Java fuzzing prover: soundness tests.

Three layers, matching the prover:

  - the classifier decides a verdict only from a structured Outcome (a caught Throwable's real
    class and frames, or the JVM's own dump for a killed child), never from mixed fuzzer output;
  - the static gates reject a harness that could fake a structured crash, run code at class
    load, print or write, or never call the target;
  - the reproducer, live when javac and java are present, re-runs a PoC and proves a real
    StackOverflowError on the fixture while rejecting a harness that crashes only itself.

The forge matrix from docs/PROVER_SOUNDNESS.md is encoded here: every attack asserts the
harness is not verified, next to the real fixture that must still verify.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sabba.provers import detect_domain
from sabba.provers.java import (Frame, JavaFuzzProver, JavaHarness, Outcome,
                                attributed_to_target, classify_outcome, cwe_for_issue,
                                innermost_is_target, is_java_target, verify_available)
from sabba.provers.java.runner import _decide_outcome, _running_thread_frames

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "targets" / "java_recursion"
TARGET_FILES = {"Vuln.java"}


def _throwable(cls: str, files, message: str = "") -> Outcome:
    frames = [Frame(cls="X", method="m", file=f, line=1) for f in files]
    return Outcome(kind="throwable", exc_class=cls, message=message, frames=frames)


# -- the classifier decides only from the structured outcome ----------------

def test_stack_overflow_with_target_frame_is_verified():
    o = _throwable("java.lang.StackOverflowError", ["Vuln.java"])
    v, cwe = classify_outcome(o, TARGET_FILES)
    assert v.verified and v.reason == "stack_exhaustion" and cwe == "CWE-674"


def test_caught_out_of_memory_is_unconfirmed():
    # A caught OutOfMemoryError is not a finding: a benign target can hit the heap limit on
    # crafted input, and out-of-memory cannot be soundly attributed (soundness over coverage).
    o = _throwable("java.lang.OutOfMemoryError", ["Vuln.java"])
    v, cwe = classify_outcome(o, TARGET_FILES)
    assert not v.verified and v.reason == "unconfirmed_exception:OutOfMemoryError" and cwe == ""


def test_timeout_is_unverified_hang_candidate():
    # A hang is never confirmed, even with a target frame in the dump (soundness over coverage).
    o = Outcome(kind="timeout", frames=[Frame(cls="Vuln", method="spin", file="Vuln.java", line=4)])
    v, cwe = classify_outcome(o, TARGET_FILES)
    assert not v.verified and v.reason == "unverified_hang_candidate" and cwe == ""


def test_security_issue_with_target_frame_is_verified_and_mapped():
    o = _throwable("com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh",
                   ["Vuln.java"], message="OS Command Injection")
    v, cwe = classify_outcome(o, TARGET_FILES)
    assert v.verified and v.reason == "security_issue" and cwe == "CWE-78"


def test_benign_exception_is_not_a_finding():
    o = _throwable("java.lang.NullPointerException", ["Vuln.java"])
    v, cwe = classify_outcome(o, TARGET_FILES)
    assert not v.verified and v.reason == "unconfirmed_exception:NullPointerException"
    o2 = _throwable("java.lang.IllegalArgumentException", ["Vuln.java"])
    assert not classify_outcome(o2, TARGET_FILES)[0].verified


def test_crash_with_no_target_frame_is_not_verified():
    # a real StackOverflowError whose frames are only in Harness is the harness crashing itself
    o = _throwable("java.lang.StackOverflowError", ["Harness.java"])
    v, _ = classify_outcome(o, TARGET_FILES)
    assert not v.verified and v.reason == "crash_not_in_target"


def test_timeout_with_no_target_frame_is_not_verified():
    o = Outcome(kind="timeout", frames=[Frame(cls="Harness", method="x", file="Harness.java", line=3)])
    v, _ = classify_outcome(o, TARGET_FILES)
    assert not v.verified and v.reason == "unverified_hang_candidate"


def test_none_outcome_is_not_a_finding():
    assert not classify_outcome(Outcome(kind="none"), TARGET_FILES)[0].verified
    assert not classify_outcome(Outcome(kind="build_error"), TARGET_FILES)[0].verified


def test_cwe_for_issue_mapping():
    assert cwe_for_issue("SQL Injection") == "CWE-89"
    assert cwe_for_issue("Server Side Request Forgery") == "CWE-918"
    assert cwe_for_issue("Remote Code Execution via deserialization") == "CWE-502"
    assert cwe_for_issue("nothing recognizable") == "CWE-20"


def test_attribution_is_structural_not_substring():
    tgt = [Frame(cls="Vuln", method="deep", file="Vuln.java", line=9)]
    harn = [Frame(cls="Harness", method="fuzzerTestOneInput", file="Harness.java", line=3)]
    repro = [Frame(cls="SabbaReproducer", method="main", file="SabbaReproducer.java", line=1)]
    assert attributed_to_target(tgt, TARGET_FILES)
    assert not attributed_to_target(harn, TARGET_FILES)
    assert not attributed_to_target(repro, TARGET_FILES)


# -- static gates: rejected before the harness is ever run ------------------

def _gate(body: str, imports: str = "") -> object:
    p = JavaFuzzProver()
    v, _cwe, _o = p._prove(FIXTURE, JavaHarness(body=body, imports=imports), secs=5, timeout=5)
    return v


def test_harness_that_throws_is_rejected():
    v = _gate("if (data.length > 0) throw new RuntimeException(); Vuln.deep(data, 0);")
    assert not v.verified and v.reason == "unsound_harness"


def test_harness_with_local_recursive_helper_is_rejected():
    v = _gate("class R { int f(int i){ return f(i+1);} } new R().f(0); Vuln.deep(data,0);")
    assert not v.verified and v.reason == "unsound_harness"


def test_harness_that_ignores_the_target_is_rejected():
    v = _gate("int x = data.length; /* Vuln mentioned only in a comment */ x++;")
    assert not v.verified and v.reason == "unsound_harness"


def test_harness_that_forces_stack_overflow_is_rejected():
    v = _gate("throw new StackOverflowError(); ")
    assert not v.verified and v.reason == "unsound_harness"


def test_forge_oom_via_print_is_rejected():
    # print the out-of-memory phrase plus a forged target frame, without crashing the target
    v = _gate('System.out.println("OutOfMemoryError at Vuln.deep(Vuln.java:9)"); Vuln.deep(data,0);')
    assert not v.verified and v.reason == "unsound_harness"


def test_forge_timeout_via_print_is_rejected():
    v = _gate('System.err.print("libFuzzer: timeout at Vuln.deep(Vuln.java:9)"); Vuln.deep(data,0);')
    assert not v.verified and v.reason == "unsound_harness"


def test_forge_security_via_print_is_rejected():
    v = _gate('System.out.print("FuzzerSecurityIssueHigh: SQL Injection Vuln.java:9"); Vuln.deep(data,0);')
    assert not v.verified and v.reason == "unsound_harness"


def test_forge_via_artifact_file_is_rejected():
    # the Java analogue of writing a crash artifact: any file write is gated
    body = ('new java.io.FileOutputStream("crash-forged").write(new byte[]{1}); Vuln.deep(data,0);')
    v = _gate(body)
    assert not v.verified and v.reason == "unsound_harness"


def test_forge_via_static_initializer_breakout_is_rejected():
    # break out of fuzzerTestOneInput to run code at class load, the JVM "code at import" attack
    body = "} static { Runtime.getRuntime().exec(new String[]{\"id\"}); } { Vuln.deep(data,0);"
    v = _gate(body)
    assert not v.verified and v.reason == "unsound_harness"


def test_forge_via_reflection_is_rejected():
    v = _gate('Class.forName("Vuln").getMethod("deep").invoke(null); Vuln.deep(data,0);')
    assert not v.verified and v.reason == "unsound_harness"


def test_forge_via_import_side_effect_is_rejected():
    # a non-import statement smuggled into the import channel, and a disallowed package
    v = _gate("Vuln.deep(data, 0);", imports="static { evil(); }")
    assert not v.verified and v.reason == "unsound_harness"
    v2 = _gate("Vuln.deep(data, 0);", imports="import java.nio.file.Files;")
    assert not v2.verified and v2.reason == "unsound_harness"


def test_allowed_import_of_fuzzer_api_passes_the_gate():
    # a jazzer-api import is allowed, so this harness reaches the toolchain check, not a gate reject
    p = JavaFuzzProver()
    h = JavaHarness(body="Vuln.deep(data, 0);",
                    imports="import com.code_intelligence.jazzer.api.FuzzedDataProvider;")
    v, _cwe, _o = p._prove(FIXTURE, h, secs=5, timeout=5)
    assert v.reason != "unsound_harness"


# -- detection --------------------------------------------------------------

def test_java_target_detected(tmp_path):
    (tmp_path / "Vuln.java").write_text("public class Vuln {}\n")
    assert is_java_target(tmp_path, None)
    assert detect_domain(tmp_path, None) == "java"


def test_c_repo_with_helper_java_is_not_java(tmp_path):
    (tmp_path / "main.c").write_text("int main(void){return 0;}\n")
    (tmp_path / "Build.java").write_text("public class Build {}\n")
    assert not is_java_target(tmp_path, None)
    assert detect_domain(tmp_path, None) == "native"


def test_fixture_detects_as_java():
    assert detect_domain(FIXTURE, None) == "java"


# -- the reproducer, live when javac and java are present -------------------

@pytest.mark.skipif(not verify_available(), reason="javac or java is not available")
def test_stack_exhaustion_is_proven_by_the_reproducer():
    # skip discovery: hand the reproducer a PoC that recurses past the JVM stack
    harness = JavaHarness(body="Vuln.deep(data, 0);", entry="Vuln.deep")
    verdict, cwe, outcome = JavaFuzzProver()._prove(FIXTURE, harness, secs=5, timeout=25,
                                                    poc=b"\x01" * 60000)
    assert verdict.verified, f"expected a proven crash: {verdict.reason}\n{verdict.evidence}"
    assert verdict.reason == "stack_exhaustion" and cwe == "CWE-674"
    assert any(f.file == "Vuln.java" for f in outcome.frames)


@pytest.mark.skipif(not verify_available(), reason="javac or java is not available")
def test_forge_stack_self_recursion_is_not_verified_by_the_reproducer():
    # the body calls the target (bounded) so it passes the call gate, then recurses itself, so a
    # real StackOverflowError carries only Harness frames. The structured stack rejects it.
    harness = JavaHarness(
        body="Vuln.deep(new byte[0], 0); fuzzerTestOneInput(data);", entry="self recursion")
    verdict, _cwe, outcome = JavaFuzzProver()._prove(FIXTURE, harness, secs=5, timeout=25,
                                                     poc=b"\x01" * 8)
    assert not verdict.verified and verdict.reason == "crash_not_in_target"
    assert not any(f.file == "Vuln.java" for f in outcome.frames)


# -- Round 2: the result channel is a parent-held nonce pipe, not a cwd file ----------------
#
# Round 1 read the outcome from work/outcome.json, which the reproducer runs beside (cwd=work).
# The body could write that file directly, through a fully qualified java.io class that needs no
# import, and win because the runner read the file before it checked its own timeout. These tests
# encode that exact forge and its variants and assert each yields verified=False, next to the
# genuine crash that must still verify.

def test_forge_via_randomaccessfile_outcome_not_verified():
    # the precise round-2 attack: recurse the target, then overwrite the parent's old result file
    # through a fully qualified RandomAccessFile (no import, so the import gate never sees it), and
    # hang on a disguised infinite loop so the parent's timeout carries the forged frames. The body
    # gate must reject every piece of this, so it never runs and never forges an outcome.
    body = ('Vuln.deep(data, 0); '
            'try { new java.io.RandomAccessFile("outcome.json", "rw")'
            '.write("{\\"kind\\":\\"throwable\\"}".getBytes()); } catch (Throwable e) {} '
            'while (data.length >= 0) {}')
    v = _gate(body)
    assert not v.verified and v.reason == "unsound_harness"


def test_fully_qualified_io_class_rejected():
    # a name-based short-name blacklist misses fully qualified IO and file classes, which Java
    # resolves with no import. Each of these must be rejected by the body gate on its own.
    attacks = [
        'new java.io.RandomAccessFile("outcome.json", "rw"); Vuln.deep(data, 0);',
        'java.nio.file.Files.newOutputStream(java.nio.file.Paths.get("x")); Vuln.deep(data, 0);',
        'java.nio.channels.FileChannel.open(java.nio.file.Paths.get("x")); Vuln.deep(data, 0);',
        'new java.io.FileOutputStream("/dev/fd/3"); Vuln.deep(data, 0);',
    ]
    for body in attacks:
        v = _gate(body)
        assert not v.verified and v.reason == "unsound_harness", body


def test_disguised_infinite_loop_is_rejected():
    # `while (data.length >= 0)` is always true (a length is never negative), the exact loop the
    # round-1 gate let through because it is not the literal `while (true)`.
    for body in ('Vuln.deep(data, 0); while (data.length >= 0) {}',
                 'Vuln.deep(data, 0); for (int i = 0; ; i++) {}',
                 'Vuln.deep(data, 0); while (1 == 1) {}'):
        v = _gate(body)
        assert not v.verified and v.reason == "unsound_harness", body
    # a genuinely bounded loop over the input is still allowed through the gate
    ok = _gate("for (int i = 0; i < data.length; i++) { Vuln.deep(data, i); }")
    assert ok.reason != "unsound_harness"


def test_timeout_prefers_dump_over_file():
    # On a measured timeout the runner reads only the JVM's own thread dump, never the pipe (or any
    # file), and attributes only within the thread that ran the harness. Here the body wrote a
    # forged throwable to the pipe with a nonce it had to guess, and a parked background thread
    # happens to show a Vuln.java frame; neither may count. The running (main) thread is the harness
    # spinning in its own loop, so attribution fails and the verdict is not verified.
    nonce = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
    forged_pipe = ('{"nonce":"GUESSEDWRONG","kind":"throwable",'
                   '"class":"java.lang.StackOverflowError",'
                   '"frames":[{"cls":"Vuln","method":"deep","file":"Vuln.java","line":9}]}\n')
    dump = (
        '"Reference Handler" #2 daemon prio=10 os_prio=0 tid=0x1 nid=0x1 waiting\n'
        '   java.lang.Thread.State: RUNNABLE\n'
        '\tat Vuln.deep(Vuln.java:9)\n'
        '\n'
        '"main" #1 prio=5 os_prio=0 tid=0x2 nid=0x2 runnable\n'
        '   java.lang.Thread.State: RUNNABLE\n'
        '\tat Harness.fuzzerTestOneInput(Harness.java:3)\n'
        '\tat SabbaReproducer.main(SabbaReproducer.java:20)\n'
    )
    outcome = _decide_outcome(True, None, forged_pipe, dump, nonce, b"x")
    assert outcome.kind == "timeout"
    # the forged pipe frame and the parked-thread frame are both discarded
    assert not any(f.file == "Vuln.java" for f in outcome.frames)
    v, _ = classify_outcome(outcome, TARGET_FILES)
    assert not v.verified and v.reason == "unverified_hang_candidate"

    # the genuine hang: the running thread's innermost frame is the target. The dump parsing
    # still isolates it correctly, but a hang is never confirmed (soundness over coverage), so
    # the verdict is an unverified candidate rather than a finding.
    real_dump = (
        '"main" #1 prio=5 os_prio=0 tid=0x2 nid=0x2 runnable\n'
        '   java.lang.Thread.State: RUNNABLE\n'
        '\tat Vuln.spin(Vuln.java:4)\n'
        '\tat Harness.fuzzerTestOneInput(Harness.java:3)\n'
        '\tat SabbaReproducer.main(SabbaReproducer.java:20)\n'
    )
    good = _decide_outcome(True, None, "", real_dump, nonce, b"x")
    assert _running_thread_frames(real_dump)[0].file == "Vuln.java"
    gv, gcwe = classify_outcome(good, TARGET_FILES)
    assert not gv.verified and gv.reason == "unverified_hang_candidate" and gcwe == ""


def test_innermost_frame_must_be_target():
    # attribution must sit at the crash site. A harness callback recursed through the target puts
    # Vuln.java frames in the stack, but the innermost owned frame is the harness lambda, so it is
    # the harness crashing itself, not a target bug.
    callback = [
        Frame(cls="Harness", method="lambda$0", file="Harness.java", line=5),
        Frame(cls="Vuln", method="apply", file="Vuln.java", line=12),
        Frame(cls="Harness", method="lambda$0", file="Harness.java", line=5),
        Frame(cls="Vuln", method="apply", file="Vuln.java", line=12),
    ]
    o = Outcome(kind="throwable", exc_class="java.lang.StackOverflowError", frames=callback)
    v, _ = classify_outcome(o, TARGET_FILES)
    assert not v.verified and v.reason == "crash_not_in_target"
    assert not innermost_is_target(callback, TARGET_FILES)

    # the genuine crash: the target frame is innermost, verified
    real = [Frame(cls="Vuln", method="deep", file="Vuln.java", line=9),
            Frame(cls="Harness", method="fuzzerTestOneInput", file="Harness.java", line=3)]
    assert innermost_is_target(real, TARGET_FILES)
    assert classify_outcome(Outcome(kind="throwable", exc_class="java.lang.StackOverflowError",
                                    frames=real), TARGET_FILES)[0].verified

    # a genuine crash that raises inside a JDK method the target called: JDK frames are skipped,
    # and the first owned frame is the target, so it still verifies
    through_jdk = [Frame(cls="java.util.Arrays", method="copyOf", file="Arrays.java", line=3332),
                   Frame(cls="Vuln", method="grow", file="Vuln.java", line=20),
                   Frame(cls="Harness", method="fuzzerTestOneInput", file="Harness.java", line=3)]
    assert innermost_is_target(through_jdk, TARGET_FILES)
