# Prover soundness: the fuzzing provers

Status: implemented across all four fuzzing provers; adversarial suite green on the box.
Last updated 2026-07-11.

The native oracle and the EVM prover are sound by construction. The native oracle trusts a
sanitizer, which the model cannot forge. The EVM prover measures an ETH balance the model
cannot mint. The fuzzing provers (Python, Go, Java, Node) were not sound: they read the
verdict from the fuzzer's mixed output and from files in a directory the harness can write,
so a model-written harness could fabricate a confirmed finding without the target ever
crashing. This document defines the model that fixes that, uniformly, across all four.

The one rule is unchanged: a Finding is minted only from a Verdict whose verified is true,
and verified is true only when a real security-relevant crash happened inside the target.
What changes is where the verdict comes from. It must come only from channels the harness
cannot influence.

## The threat model

The harness is untrusted. It is written by the model, and the model reads the target's
source, so a hostile target can steer the harness through prompt injection. Assume the
harness will try to:

- print the magic phrase of a crash kind ("out of memory", "timeout", a security banner) to
  stdout or stderr,
- print a forged stack frame like `vuln.js:1` so an attribution check that scans output
  passes,
- write a `crash-*`, `oom-*`, or `timeout-*` artifact file itself,
- run arbitrary code at load through its import or require lines,
- crash itself (its own recursion, its own allocation, its own loop) so a real crash signal
  carries a forged target frame.

None of these may produce a verified finding.

## Two phases: the fuzzer discovers, a Sabba reproducer proves

Discovery. The fuzzer runs the harness and finds an input that makes it crash. From this
phase we take exactly one thing: the candidate PoC bytes. We take nothing from the fuzzer's
stdout, and we ignore any artifact file the harness may have written. A forged "crash" here
only yields a candidate input, which the next phase rejects.

Verification. Sabba re-runs the PoC through a reproducer that Sabba owns and the harness
cannot control. The reproducer establishes the verdict from unforgeable channels only:

- it nulls the harness's stdout and stderr, so anything the harness prints is gone,
- it runs in a scratch directory and ignores any file the harness creates,
- it captures the outcome over a private channel: a structured exception (its class and its
  real stack frames) for a caught crash, or the parent's own measurement of a killed child
  (a fatal signal, an out-of-memory kill under a set memory limit, or a wall-clock timeout)
  plus a runtime stack dump the language emits on death,
- it decides the kind from that structured outcome, and attribution from the real stack
  frames, requiring at least one frame whose source file is a target file and is not the
  harness or the wrapper.

The harness cannot forge a genuine exception's structured stack, and it cannot forge the
runtime's own dump. Combined with the static gates below (which stop it from throwing a
fake structured error or running code at import), attribution becomes sound.

## Static gates (defense in depth, and what makes the reproducer sound)

These run before the harness is ever executed:

1. Scan both the import/require lines and the body, not just the body. The Node prover's
   unscanned requires was the worst hole.
2. The import/require lines must be import or require statements only, and may load only the
   target module and the fuzzer API. Any other module (fs, os, child_process, process,
   subprocess, sockets) or any statement that is not a bare import is rejected. This is what
   stops the harness running code at load, which in turn is what lets the reproducer trust
   its private result channel.
3. The body may not manufacture its own crash or write output: no throw, panic, os.Exit,
   process.exit, no explicit recursion-limit or resource-limit change, no writer to stdout,
   stderr, or a file descriptor, no reflection or eval or dynamic code, no bare infinite
   loop. Enumerated where a language allows, but the real backstop is that attribution comes
   from the structured stack, not from anything the body prints.
4. The body must actually call the target, a call or member access through the bound name,
   not merely mention it.

A harness that fails any gate is rejected as unsound_harness, never fuzzed.

## Unforgeable outcome, per language

Each prover implements one function, verify_poc(target_dir, harness, poc_bytes) -> Outcome,
where Outcome carries kind and the structured stack frames. The reproducer is Sabba source,
generated at run time, never the model's.

Python. A Sabba reproducer subprocess. It opens a private pipe on fd 3 before importing the
harness, redirects stdout and stderr to os.devnull, sets RLIMIT_AS for the memory limit and
faulthandler.dump_traceback_later for the timeout (both emit a real traceback the harness
cannot forge, to fd 3), then imports the harness and calls TestOneInput(poc). It catches
BaseException, reads the class and traceback.extract_tb frames, and writes them as JSON to
fd 3. The parent reads fd 3. RecursionError, MemoryError, and a fault dump all arrive with
real frames. Attribution requires a frame in a target .py file other than harness.py.

Node. A Sabba reproducer script run by node with `--report-on-fatalerror` and
`--report-uncaught-exception`, writing the diagnostic report to a Sabba directory. It sets
Error.stackTraceLimit large, replaces process.stdout.write and process.stderr.write with
no-ops, requires the harness, and calls fuzz(poc) in try/catch. On catch it reads
err.constructor.name and parses err.stack into frames, writing JSON to fd 3. A heap
out-of-memory or a timeout (the parent sends the signal after a wall deadline) produces a
Node diagnostic report whose javascriptStack gives the frames. Attribution requires a frame
in a target .js or .ts file other than fuzz.js.

Go. The FuzzTarget wrapper is Sabba source. It wraps the model's body in a deferred
recover that, on a panic, captures runtime.Stack(buf, false), the real stack, and reports it
on fd 3. The body cannot call recover (gated), so its panic reaches the wrapper. Output is
sent to os.devnull. For a timeout the parent sends SIGQUIT, which makes the Go runtime dump
every goroutine stack; for an out-of-memory the runtime dumps on its own. Attribution
requires a frame in a target .go file other than the wrapper _test.go.

Java. A Sabba reproducer class invokes Harness.fuzzerTestOneInput(poc) in try/catch with
System.out and System.err set to a null stream. It reads the Throwable class and
getStackTrace(), whose StackTraceElement.getFileName gives real frames, and writes them to
fd 3. StackOverflowError, OutOfMemoryError, and a Jazzer FuzzerSecurityIssue all arrive as
throwables with real frames. For a timeout the parent takes a thread dump. Attribution
requires a frame in a target .java file other than Harness.java.

## Verified kinds, and how each is soundly established

- stack_exhaustion (CWE-674): a RecursionError, a StackOverflowError, a Go stack-overflow
  fatal, or a "maximum call stack" RangeError, caught in the reproducer with the crashing
  frame in the target. This is bounded, not a resource-pressure guess: the overflow is a
  single deep call chain the runtime reports with a real target frame at the top.
- native_crash (CWE-787): a fatal signal (SIGSEGV, SIGABRT) the parent observes, with a
  target frame in the dump. Applies to C extensions and cgo.
- security_issue: a fuzzer bug-detector finding (Jazzer, Jazzer.js) that arrives as a
  structured throwable whose type is the detector's own class, with a target frame. Matched
  on the detector's structured banner, not on a loose phrase anywhere in output.
- panic_crash (Go): a recovered runtime panic (index or slice out of range, nil dereference,
  divide by zero) whose crashing frame is the target.

Timeout and out-of-memory are not verified kinds. See "Round 3 and 4" below: neither can be
soundly separated from harness-driven pressure, so both are surfaced as unverified candidates
(unverified_hang_candidate, unverified_oom_candidate), never minted as findings. A caught
MemoryError, OutOfMemoryError, or allocation RangeError is likewise only an unconfirmed
exception, not a finding.

Anything else, including a benign application exception, is unverified.

## Adversarial test matrix

Every prover ships tests that encode the attacks above and assert each is rejected, next to
the real fixture that must still verify. At minimum, per prover:

- forge_oom_via_print: body or imports print the out-of-memory phrase and a forged target
  frame, and do not crash the target. Expect not verified.
- forge_timeout_via_print: same with the timeout phrase. Expect not verified.
- forge_security_via_print: same with a security banner. Expect not verified.
- forge_stack_self_recursion: the body recurses itself and prints a forged target frame, so
  a real crash carries a fake attribution. Expect not verified (the structured stack is in
  the harness, not the target).
- forge_via_artifact_file (Node, Python): the harness writes a crash or oom artifact file
  itself. Expect not verified.
- forge_via_import_side_effect (Node, Python): the import or require line runs code. Expect
  rejected by the import-only gate.
- real fixture: the genuine vulnerable target still verifies with the right kind and CWE and
  a real target frame.

A prover is sound for this pass only when every forge test is rejected and the real fixture
still verifies, live on the box.

## Honest residual limits

- Soundness here means no false positive from a hostile harness, not a proof of full
  isolation. The reproducer reduces the harness's capability and reads only unforgeable
  channels; it is not a syscall sandbox. A container backend (the reserved Docker sandbox)
  is the next layer for running wholly untrusted target code.
- Timeout and out-of-memory are never verified, by design (see "Round 3 and 4"). Sabba still
  discovers and surfaces them as unverified candidates for a human to triage, but it will not
  mint a finding from them. This is a deliberate, permanent loss of coverage in favor of
  soundness: a hang or an allocation blowup cannot be told apart from the harness spinning or
  pre-filling the heap around a benign target call.

## Round 2: an authenticated channel the harness cannot reach or forge (required)

Round 1 left three provers forgeable: the body could reach the result writer (Python `_emit`
was a module global in the body's scope) or write the parent's result file in its own cwd
(Node `result.json`, Java `outcome.json`), and no nonce told Sabba's message apart from the
harness's. Go was the only sound one, because the body genuinely cannot reach the parent's
anonymous pipe. Converge all four on Go's model.

1. Parent-held channel. The parent opens an anonymous pipe and passes only the write end to
   the reproducer as an inherited fd. Never a file in the harness's cwd. The parent generates
   a random per-run nonce and passes it to the reproducer wrapper only.
2. The wrapper emits, not the body. The Sabba wrapper runs the body inside try/except and
   emits the outcome to the fd from its own scope, after the body returns or raises. The
   body's namespace must not contain the emit function, the fd, or the nonce.
3. Nonce authentication. Every message carries the nonce; the parent accepts only a message
   with the matching nonce and ignores all others. The body never sees the nonce, so it
   cannot forge an accepted message.
4. Body-scope isolation. Run the body with no access to the module object, require or import,
   the global object, reflection, or the inherited fd. Reject a leading-underscore name
   (Python), any computed member access or module/require/global/globalThis/Function/this
   (Node), any fully qualified file or IO class (Java), any dot or aliased dangerous import
   (Go).
5. Attribution from the crashing frame. Require the innermost frame, the one that raised, to
   be a target frame, not merely any frame present. Forbid the body from defining a recursive
   helper or passing a callable into the target: a harness callback that recurses through a
   target frame is not a target bug.
6. Timeout and out-of-memory. Read only the runtime's own dump. Attribute only within the
   running thread or goroutine, not a parked background one. Never read a file or fd the child
   could have written before it hung.
7. Loop gate. Reject any always-true or side-effect-free loop condition, not only a literal
   true or 1. `while len(data) >= 0` must be rejected.

A prover is sound only when a fresh adversarial review cannot construct any admissible
harness that yields verified true without a real target crash.

## Round 3 and 4: the resource-attribution class, and the resolution

Rounds 1 and 2 closed channel forgery: the harness can no longer reach the result channel,
forge an accepted message, or borrow a target frame it did not crash in. Round 3 found a
class that channel authentication does not fix. For a timeout or an out-of-memory kill, the
verdict rested on "the crashing frame is the target", but a hang and an allocation blowup
have no single crashing frame. They are resource states, and the runtime dump only shows
where each thread happens to sit when the parent kills the child. That is forgeable in ways
frame authentication cannot catch:

- Amplified benign timeout. The harness feeds the target a large but valid input so a genuinely
  linear target runs past the deadline. The dump's running thread sits in a real target frame,
  yet the target has no vulnerability; the harness manufactured the pressure.
- Loop-wrapped or heap-hog pressure. The harness spins fast target calls, or pre-fills the
  heap and then makes one target call. The parent measures a timeout or OOM whose innermost
  running frame is the target, but the cause is the harness, not a target defect.

Per-thread and per-goroutine isolation (Round 2, item 6) narrows this but does not close it:
it cannot distinguish a target that is slow because the harness inflated its input from a
target that is slow because it is quadratic. Distinguishing them soundly needs a baseline
(does a normal-sized input finish?), which is a different, heavier discipline than "prove by
triggering".

Resolution: soundness over coverage. Timeout and out-of-memory are downgraded from verified
kinds to unverified candidates, across all four provers, unconditionally. The provers still
run the reproducer and still surface unverified_hang_candidate and unverified_oom_candidate
for a human to triage, but neither ever sets verified true, so neither can become a finding.
The now-unused timeout attribution machinery (the goroutine and thread isolation that only
fed the timeout verdict) is removed; the dump parser stays where a test still exercises it.
This supersedes item 6 above for the verdict path.

What stays verified is only what has a single, bounded, target-owned crash site the runtime
reports with a real frame: stack_exhaustion, native_crash, a Go panic_crash, and a fuzzer
security_issue. Native ASan crashes and EVM fund-drains are unaffected; they were sound by
construction from the start.
