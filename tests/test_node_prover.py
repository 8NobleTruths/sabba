"""The Node (JavaScript and TypeScript) fuzzing prover: soundness tests.

The prover is sound only if no hostile harness can fabricate a verified finding and the real
vulnerable fixture still verifies. These tests encode the forge attacks from
docs/PROVER_SOUNDNESS.md and assert each is rejected, next to the real fixture that must still
verify.

Three tiers:
  - offline: the static gates and the Outcome classifier, no toolchain needed.
  - node-gated: the Sabba reproducer (phase two) runs under plain `node`, so the real fixture
    and the forge attacks that pass the gates are exercised live without Jazzer.js.
  - jazzer-gated: the full two-phase prove, discovery included, when Jazzer.js is installed.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sabba.provers import detect_domain
from sabba.provers.node import (NodeFuzzProver, NodeHarness, Outcome, check_harness,
                                classify_outcome, is_node_target, jazzerjs_available,
                                node_available, target_file_basenames)
from sabba.provers.node.prover import _target_bindings

ROOT = Path(__file__).resolve().parents[1]
JS_TARGET = ROOT / "targets" / "node_recursion"
TS_TARGET = ROOT / "targets" / "ts_recursion"
TARGET_FILES = {"vuln.js"}


def _gate(requires: str, body: str) -> str | None:
    return check_harness(NodeHarness(requires=requires, body=body))


def _classify(outcome: Outcome):
    v, cwe = classify_outcome(outcome, TARGET_FILES)
    return v.verified, v.reason, cwe


# -- the classifier reads only the structured Outcome ------------------------

def test_stack_overflow_with_target_frame_is_verified():
    v, reason, cwe = _classify(Outcome(kind="exception", error_class="RangeError",
                                       message="Maximum call stack size exceeded",
                                       frame_files=["/w/vuln.js", "/w/fuzz.js"]))
    assert v and reason == "stack_exhaustion" and cwe == "CWE-674"


def test_stack_overflow_without_target_frame_is_not_verified():
    # a real RangeError, but every frame is in the harness or the reproducer: not the target.
    v, reason, _ = _classify(Outcome(kind="exception", error_class="RangeError",
                                     message="Maximum call stack size exceeded",
                                     frame_files=["/w/fuzz.js", "/w/repro.js"]))
    assert not v and reason == "crash_not_in_target"


def test_caught_oom_rangeerror_is_unconfirmed():
    # A caught allocation RangeError is not a finding: a benign target can throw it on crafted
    # input, and a real out-of-memory arrives on the kill path (soundness over coverage).
    v, reason, cwe = _classify(Outcome(kind="exception", error_class="RangeError",
                                       message="Array buffer allocation failed",
                                       frame_files=["/w/vuln.js"]))
    assert not v and reason == "unconfirmed_exception:RangeError" and cwe == ""


def test_benign_typeerror_is_not_a_finding():
    v, reason, cwe = _classify(Outcome(kind="exception", error_class="TypeError",
                                       message="x is not a function",
                                       frame_files=["/w/vuln.js"]))
    assert not v and reason == "unconfirmed_exception:TypeError" and cwe == ""


def test_security_finding_needs_detector_class():
    # a Jazzer.js detector Finding: structured class + banner + target frame -> verified.
    v, reason, cwe = _classify(Outcome(kind="exception", error_class="Finding",
                                       message="Command Injection in child_process.exec",
                                       frame_files=["/w/vuln.js"]))
    assert v and reason == "security_issue" and cwe == "CWE-78"
    # the same banner on a plain error class is not a finding: a harness cannot mint one by
    # putting the phrase in an ordinary exception message.
    v2, reason2, _ = _classify(Outcome(kind="exception", error_class="TypeError",
                                       message="Command Injection", frame_files=["/w/vuln.js"]))
    assert not v2 and reason2 == "unconfirmed_exception:TypeError"


def test_signal_needs_a_target_frame():
    # a fatal signal (a native addon) is verified only when the runtime dump names a target
    # frame; otherwise it is unattributed and unverified.
    assert _classify(Outcome(kind="signal", frame_files=["/w/vuln.js"])) == \
        (True, "native_crash", "CWE-787")
    assert _classify(Outcome(kind="signal", frame_files=[])) == \
        (False, "crash_not_in_target", "")


def test_oom_and_timeout_are_unverified_candidates():
    # a timeout or heap out-of-memory kill is never confirmed, with or without a target frame:
    # neither can be soundly attributed to the target rather than harness-driven pressure
    # (soundness over coverage).
    assert _classify(Outcome(kind="oom", frame_files=["/w/vuln.js"])) == \
        (False, "unverified_oom_candidate", "")
    assert _classify(Outcome(kind="oom", frame_files=[])) == \
        (False, "unverified_oom_candidate", "")
    assert _classify(Outcome(kind="timeout", frame_files=["/w/vuln.js"])) == \
        (False, "unverified_hang_candidate", "")
    assert _classify(Outcome(kind="timeout", frame_files=["/w/fuzz.js"])) == \
        (False, "unverified_hang_candidate", "")


def test_none_and_load_error_are_not_verified():
    assert not classify_outcome(Outcome(kind="none"), TARGET_FILES)[0].verified
    assert classify_outcome(Outcome(kind="load_error"), TARGET_FILES)[0].reason == "harness_error"


# -- static gates: the forge attacks that never reach a fuzz -----------------

def test_forge_via_import_side_effect_module():
    # requiring anything but the target or the fuzzer API is rejected: this is the require
    # hole the reproducer depends on being closed.
    assert _gate('const fs = require("fs");', "vuln.run(data);").startswith("requires may load")
    assert _gate('const cp = require("child_process");', "vuln.run(data);") is not None
    assert _gate('const x = require("/etc/passwd");', "x.run(data);") is not None


def test_forge_via_import_side_effect_code():
    # code on the require line (not a bare import) is rejected, so nothing runs at load.
    assert "import/require statements only" in \
        _gate('const vuln = require("./vuln"); process.exit(1);', "vuln.run(data);")
    assert "import/require statements only" in \
        _gate('const vuln = require("./vuln"); vuln.run(Buffer.alloc(1e9));', "vuln.run(data);")


def test_import_only_whitelist_allows_target_and_jazzer():
    ok = ('const { FuzzedDataProvider } = require("@jazzer.js/core"); '
          'const vuln = require("./vuln");')
    assert _gate(ok, "const fdp = new FuzzedDataProvider(data); vuln.run(fdp);") is None


def test_forge_oom_via_print_is_rejected():
    # printing the out-of-memory phrase plus a forged target frame: rejected at the gate,
    # and even if it slipped through the reproducer nulls stdout (see the node-gated arm).
    r = _gate('const vuln = require("./vuln");',
              'console.log("out of memory at vuln.js:1"); vuln.run(data);')
    assert r is not None and "console" in r


def test_forge_timeout_via_print_is_rejected():
    r = _gate('const vuln = require("./vuln");',
              'process.stderr.write("libFuzzer: timeout vuln.js:1\\n"); vuln.run(data);')
    assert r is not None and "process" in r


def test_forge_security_via_print_is_rejected():
    r = _gate('const vuln = require("./vuln");',
              'console.error("SECURITY: Command Injection in vuln.js:1"); vuln.run(data);')
    assert r is not None and "console" in r


def test_forge_via_artifact_file_is_rejected():
    # the body cannot write a crash/oom artifact file: fs and every file-writer is banned, and
    # nothing else can be required. Even if a file existed, phase two never reads artifacts.
    assert _gate('const vuln = require("./vuln");',
                 'require("fs").writeFileSync("oom-forged", data); vuln.run(data);') is not None
    assert _gate('const vuln = require("./vuln");',
                 'writeFileSync("crash-forged", data); vuln.run(data);') is not None


def test_throw_in_body_is_rejected():
    assert _gate('const vuln = require("./vuln");',
                 'vuln.run(data); throw new Error("x");').startswith("harness body may not use")


def test_eval_and_reflection_in_body_are_rejected():
    assert _gate('const vuln = require("./vuln");', 'eval("1"); vuln.run(data);') is not None
    assert _gate('const vuln = require("./vuln");',
                 'Reflect.apply(vuln.run, null, [data]);') is not None


def test_bare_infinite_loop_in_body_is_rejected():
    assert _gate('const vuln = require("./vuln");', "while(true){} vuln.run(data);") is not None
    assert _gate('const vuln = require("./vuln");', "for(;;){} vuln.run(data);") is not None


def test_body_must_call_the_target():
    assert _gate('const vuln = require("./vuln");', "const x = data.length;") is not None
    # a bare mention with no call or member access does not count as calling the target.
    assert _gate('const vuln = require("./vuln");', "const y = vuln;") is not None


def test_calling_only_the_fuzzer_helper_is_not_calling_the_target():
    # FuzzedDataProvider is the fuzzer API, not the target; the body must reach the target.
    r = _gate('const { FuzzedDataProvider } = require("@jazzer.js/core"); '
              'const vuln = require("./vuln");',
              "const fdp = new FuzzedDataProvider(data); const n = fdp.consumeIntegral(4);")
    assert r is not None


# -- round 2: the authenticated channel and body-scope isolation -------------

def test_computed_member_access_rejected():
    # the round-1 hole: the name-only regex missed computed member access, so
    # module["require"]("fs")["writeFileSync"](...) slipped through. Any computed access with []
    # is now rejected; the body must use dot access.
    assert "computed member access" in _gate('const vuln = require("./vuln");',
                                              'vuln["run"](data);')
    assert "computed member access" in _gate('const vuln = require("./vuln");',
                                              'vuln.run(data); const k = "run"; const f = vuln[k];')
    assert "computed member access" in _gate('const vuln = require("./vuln");',
                                              'vuln.run(data)["x"];')
    # a real dot-access harness is not flagged, and neither is an array literal.
    assert _gate('const vuln = require("./vuln");', "const a = [1, 2, 3]; vuln.run(data);") is None


def test_this_globalThis_escape_rejected():
    # reaching the global object by any spelling is rejected, so the body cannot walk from a
    # global to require/process. this is undefined at runtime anyway (undefined receiver), but
    # the gate refuses it up front, including the [].constructor.constructor Function escape.
    assert "globalThis" in _gate('const vuln = require("./vuln");',
                                  'globalThis.process.exit(1); vuln.run(data);')
    assert "global" in _gate('const vuln = require("./vuln");',
                             'global.process.exit(1); vuln.run(data);')
    assert "this" in _gate('const vuln = require("./vuln");', 'this.x = 1; vuln.run(data);')
    assert "constructor" in _gate('const vuln = require("./vuln");',
                                  'const g = [].constructor.constructor("return this")(); vuln.run(data);')


def test_callback_recursion_not_verified():
    # a harness-defined recursive helper crashes in fuzz.js, not the target, and a callback
    # passed into the target lets a harness frame be the innermost (crashing) frame with a
    # target frame merely below it. Both are rejected at the gate.
    assert "function definition" in _gate('const vuln = require("./vuln");',
                                          'function r(n){ return vuln.run(n) && r(n); } r(data);')
    assert "arrow function" in _gate('const vuln = require("./vuln");',
                                     'vuln.run(data, x => x);')
    # and even if attribution were reached, the innermost frame must be the target's, not a
    # harness callback below which a target frame sits.
    from sabba.provers.node.classify import _attributed_to_target
    assert _attributed_to_target(["/w/fuzz.js", "/w/vuln.js"], TARGET_FILES) is False
    assert _attributed_to_target(["/w/vuln.js", "/w/fuzz.js"], TARGET_FILES) is True


def test_target_bindings_only_from_relative_requires():
    assert _target_bindings('const vuln = require("./vuln");') == {"vuln"}
    assert _target_bindings('const { run } = require("./vuln");') == {"run"}
    assert _target_bindings('import vuln from "./vuln"') == {"vuln"}
    assert _target_bindings('import { run } from "./vuln"') == {"run"}
    # a binding to the fuzzer API is not a target binding
    assert _target_bindings('const { FuzzedDataProvider } = require("@jazzer.js/core");') == set()


# -- detection ---------------------------------------------------------------

def test_node_target_detected(tmp_path):
    (tmp_path / "index.js").write_text("module.exports = {};\n")
    assert is_node_target(tmp_path, None)
    assert detect_domain(tmp_path, None) == "node"


def test_c_repo_with_helper_js_is_not_node(tmp_path):
    (tmp_path / "main.c").write_text("int main(void){return 0;}\n")
    (tmp_path / "build.js").write_text("console.log('build')\n")
    assert not is_node_target(tmp_path, None)
    assert detect_domain(tmp_path, None) == "native"


def test_fixtures_detect_as_node():
    assert detect_domain(JS_TARGET, None) == "node"
    assert detect_domain(TS_TARGET, None) == "node"


def test_target_file_basenames_maps_ts_to_js():
    assert target_file_basenames(JS_TARGET) == {"vuln.js"}
    assert target_file_basenames(TS_TARGET) == {"vuln.ts", "vuln.js"}


# -- node-gated: the Sabba reproducer, live under plain node -----------------

@pytest.mark.skipif(not node_available(), reason="Node not installed")
def test_real_fixture_verifies_through_reproducer():
    h = NodeHarness(requires='const vuln = require("./vuln");', body="vuln.run(data);")
    v, cwe, oc = NodeFuzzProver()._verify_candidate(JS_TARGET, h, b"A" * 200000, timeout=10)
    assert v.verified, f"expected a proven crash: {v.reason}\n{v.evidence}"
    assert v.reason == "stack_exhaustion" and cwe == "CWE-674"
    assert oc.kind == "exception" and any("vuln.js" in f for f in oc.frame_files)


@pytest.mark.skipif(not node_available(), reason="Node not installed")
def test_forge_stack_self_recursion_is_not_verified():
    # the body recurses itself and calls the target with an input too small to overflow it, so
    # a real RangeError happens but its structured stack is in fuzz.js, not the target.
    h = NodeHarness(requires='const vuln = require("./vuln");',
                    body="vuln.run(data); function r(n){ return r(n + 1); } r(0);")
    v, _cwe, oc = NodeFuzzProver()._verify_candidate(JS_TARGET, h, b"A", timeout=10)
    assert not v.verified and v.reason == "crash_not_in_target"
    assert not any("vuln.js" in f for f in oc.frame_files)


@pytest.mark.skipif(not node_available(), reason="Node not installed")
def test_forge_phrase_smuggled_in_output_is_ignored():
    # the phrase sits in a string (so it passes the gates); the reproducer nulls output and the
    # target does not crash on this input, so no verdict is read from the smuggled text.
    h = NodeHarness(requires='const vuln = require("./vuln");',
                    body='const banner = "out of memory at vuln.js:1"; vuln.run(data);')
    assert check_harness(h) is None
    v, _cwe, oc = NodeFuzzProver()._verify_candidate(JS_TARGET, h, b"short", timeout=10)
    assert not v.verified and v.reason == "no_crash" and oc.kind == "none"


@pytest.mark.skipif(not node_available(), reason="Node not installed")
def test_forge_via_module_require_writefile_not_verified():
    # the exact round-2 attack: reach fs through computed member access on the module object,
    # write the parent's old result.json in the harness cwd with a forged crash, then hang so
    # the parent reads that file on timeout. First, the gate rejects it outright (computed
    # access, module, and the always-true / empty loop).
    attack = ('vuln.run(data); var zz = module["require"]("fs"); '
              'zz["writeFileSync"]("result.json", '
              '"{\\"kind\\":\\"exception\\",\\"error_class\\":\\"RangeError\\",'
              '\\"message\\":\\"Maximum call stack size exceeded\\",'
              '\\"files\\":[\\"vuln.js\\"]}"); while (data.length >= 0) {}')
    assert check_harness(NodeHarness(requires='const vuln = require("./vuln");',
                                     body=attack)) is not None
    # And even if the gate were bypassed, running it does not verify: module is shadowed to
    # undefined in the body scope, so module["require"] throws a plain TypeError, and the parent
    # reads its private nonce-authenticated pipe, never a result.json in the cwd. (The hang loop
    # is dropped here only so the live run finishes fast; the write attempt is what matters.)
    no_loop = ('vuln.run(data); var zz = module["require"]("fs"); '
               'zz["writeFileSync"]("result.json", '
               '"{\\"kind\\":\\"exception\\",\\"error_class\\":\\"RangeError\\",'
               '\\"message\\":\\"Maximum call stack size exceeded\\",'
               '\\"files\\":[\\"vuln.js\\"]}");')
    h = NodeHarness(requires='const vuln = require("./vuln");', body=no_loop)
    v, _cwe, oc = NodeFuzzProver()._verify_candidate(JS_TARGET, h, b"A", timeout=10)
    assert not v.verified
    assert oc.kind == "exception" and oc.error_class == "TypeError"


@pytest.mark.skipif(not node_available(), reason="Node not installed")
def test_result_file_in_cwd_is_ignored(tmp_path):
    # a forged result.json planted in the reproducer's working directory is never read: the
    # verdict comes only from the parent-held pipe. A benign run in that same directory returns
    # no crash, not the planted RangeError.
    work = tmp_path / "repro"
    work.mkdir()
    forged = ('{"kind":"exception","error_class":"RangeError",'
              '"message":"Maximum call stack size exceeded","files":["vuln.js"],'
              '"nonce":"deadbeefdeadbeefdeadbeefdeadbeef"}')
    (work / "result.json").write_text(forged)
    from sabba.provers.node import verify_poc
    h = NodeHarness(requires='const vuln = require("./vuln");', body="vuln.run(data);")
    oc = verify_poc(JS_TARGET, h, b"harmless", timeout=10, workdir=work)
    assert oc.kind == "none"
    v, _cwe = classify_outcome(oc, TARGET_FILES)
    assert not v.verified


@pytest.mark.skipif(not node_available(), reason="Node not installed")
def test_forge_via_artifact_bytes_do_not_verify():
    # phase one only yields candidate bytes; a forged artifact is just bytes phase two re-runs.
    # A benign harness on arbitrary bytes does not crash the target, so nothing verifies.
    h = NodeHarness(requires='const vuln = require("./vuln");', body="vuln.run(data);")
    v, _cwe, oc = NodeFuzzProver()._verify_candidate(JS_TARGET, h, b"harmless", timeout=10)
    assert not v.verified and oc.kind == "none"


# -- jazzer-gated: the full two-phase prove ----------------------------------

@pytest.mark.skipif(not jazzerjs_available(), reason="Node or Jazzer.js not installed")
def test_js_stack_exhaustion_full_prove():
    h = NodeHarness(requires='const vuln = require("./vuln");', body="vuln.run(data);",
                    entry="vuln.run")
    verdict, cwe, _oc = NodeFuzzProver()._prove(JS_TARGET, h, secs=25, timeout=8,
                                                seed=b"A" * 20000)
    assert verdict.verified, f"expected a proven crash: {verdict.reason}\n{verdict.evidence}"
    assert verdict.reason == "stack_exhaustion" and cwe == "CWE-674"


@pytest.mark.skipif(not jazzerjs_available(), reason="Node or Jazzer.js not installed")
def test_ts_stack_exhaustion_full_prove():
    h = NodeHarness(requires='const vuln = require("./vuln");', body="vuln.run(data);",
                    entry="vuln.run")
    verdict, cwe, _oc = NodeFuzzProver()._prove(TS_TARGET, h, secs=25, timeout=8,
                                                seed=b"A" * 20000)
    assert verdict.verified, f"expected a proven TS crash: {verdict.reason}\n{verdict.evidence}"
    assert verdict.reason == "stack_exhaustion" and cwe == "CWE-674"
