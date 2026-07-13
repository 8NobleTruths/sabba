# Hunting fresh zero days

This is the method Sabba uses to find real, previously unknown memory bugs in
released software, not to rediscover ones a fuzzer already reported. It was written
after a run that produced both outcomes: a known bug in a heavily fuzzed target, and
a genuinely unreported heap out of bounds read in a target nobody was fuzzing. The
difference between the two came down almost entirely to target choice and to honest
triage, so those are the parts this document spends the most time on.

## The one lever that matters most: target selection

A coverage guided fuzzer with a sanitizer finds bugs. Whether those bugs are new is
decided before the fuzzer starts, by what you point it at.

Avoid:

- Anything on OSS-Fuzz. Google fuzzes those around the clock, so the shallow bugs are
  already filed and fixed. You will spend your run rediscovering issue numbers.
- Anything with a fuzz driven issue tracker. If the last ten issues are all "heap
  overflow in X" and "out of bounds read in Y", someone is already running the exact
  campaign you are about to run. A known bug will surface first and waste the run.
- The most popular library in a category. Popular means scrutinized.

Prefer:

- A real, used parser of untrusted input that is maintained but under fuzzed: no
  `fuzz/` directory in the repo, no OSS-Fuzz integration, few or no security issues in
  the tracker. Maintained matters for disclosure value; under fuzzed matters for
  novelty. That intersection is where new bugs live.
- Complex binary formats over simple text ones. More state, more length fields, more
  chances for a size to be computed one way at allocation and another way at use.
- Single file or small libraries, so a correct harness is quick to write.

A blunt but effective filter: clone the candidate, grep for a function that takes a
buffer and a length and returns a parsed structure, then check the issue tracker for
the words "overflow", "out of bounds", and "asan". A target with the parse entry and
no such issues is a good target.

## Write the harness against the real contract

The fastest way to produce a fake finding is to call the API wrong. Two real examples
from the run this document is based on:

- A TOML parser whose entry is `toml_parse(const char *src, int len)`. It reads
  `src[len]` to confirm the string is NUL terminated, because its documented contract
  requires that. A harness that passes the raw fuzzer buffer, which is not NUL
  terminated, triggers a one byte over read inside the library's own validation. That
  is the harness violating the contract, not a bug. The fix is to copy the input into a
  `len + 1` buffer and set the last byte to zero.
- A decoder called with a zero length input segfaults. That is usually the harness
  handing over something the caller is expected to screen, not a defect worth
  reporting. Skip trivially small inputs unless the format genuinely allows them.

So: read the header comment and the first few lines of the entry function before
writing the harness. Answer three questions. Does it require NUL termination. Does it
respect the length or scan for a terminator. What is the minimum sensible input. Encode
the answers in the harness. A harness that obeys the contract turns every sanitizer
stop into a real defect in the library.

## Build and run

- Sanitizer: AddressSanitizer as the workhorse, because its reports are precise and
  almost never false. Add UndefinedBehaviorSanitizer for a second, cheaper pass when
  ASan is dry, since it catches the integer overflows that later become out of bounds
  accesses. Keep them in separate builds so a benign signed overflow does not stop the
  memory campaign.
- Seeds: give the fuzzer one valid input so it gets past magic bytes and header checks
  immediately. For a binary format, craft a minimal valid file by hand or generate one
  with a real encoder. A seedless run on a binary format spends its whole budget
  failing the first length check.
- Coverage guided, one target per core, a wall clock cap, a per input timeout, and a
  memory cap so a claimed huge dimension does not turn into an out of memory instead of
  a clean overflow.

## Triage is where a finding is earned or discarded

A sanitizer stop is a candidate, not a finding. Before it counts:

1. Reproduce it. Re run the artifact through the binary and confirm the same stop at
   the same line. Non deterministic stops usually mean the harness has state.
2. Locate the fault. The top frames must be inside the library, and the frame just
   below must be the harness calling the documented public entry. If the top frame is
   the harness, or a system header the harness dragged in, it is not a library bug.
3. Rule out a contract violation. Ask whether a correct caller could have produced this.
   If the crash needs a non NUL terminated buffer for a NUL terminated API, or a zero
   length input for a format with a fixed header, it is the harness.
4. Root cause it. Read the faulting line and the allocation it overran. A real report
   names the mismatch: a size computed as `w * bpp` at one place and `(1 + linebytes) *
   h` at another, an off by one between the allocated extent and the read extent, a
   length field trusted without bound.
5. Minimize it. libFuzzer's crash minimizer shrinks the reproducer to the bytes that
   matter, which both confirms determinism and makes the disclosure legible.
6. Verify novelty, and be willing to lose. Search the issue tracker, the CVE list, and
   the recent commits for the same function and the same class. In the run this is based
   on, a macroblock over read in a popular video decoder looked like a find until the
   tracker showed it was already filed. The out of bounds read in the unfilter step of
   an obscure, unmaintained PNG decoder had no issue anywhere, so it was new. Same
   sanitizer, same harness discipline, opposite verdict, decided by the tracker.

A finding that survives all six is real. Anything that fails one is dropped, out loud.
The discipline is the product: Sabba would rather report nothing than report a harness
artifact as a zero day.

## How this feeds the rest of Sabba

The oracle already decides whether a native crash is a real, security relevant defect.
This document is the front half that keeps the oracle pointed at fresh ground: choose an
under fuzzed but maintained parser, write a contract correct harness, run ASan with a
valid seed, then run the six step triage before anything is minted as a finding. The
target selection heuristic and the triage checklist are the parts worth automating next,
because they are what turned a run into a new bug rather than a rediscovered one.

## JavaScript, TypeScript, and Node

The language is memory safe, so there is no AddressSanitizer signal and no heap
overflow to find. The bug classes move to logic and to the runtime:

- Prototype pollution: a write to `__proto__` or `constructor.prototype` through an
  attacker controlled key, which changes every object in the process.
- ReDoS: a regular expression with catastrophic backtracking, where a crafted string
  turns a linear parse into an exponential one and hangs the event loop.
- Stack exhaustion (CWE-674): a recursive descent parser with no depth limit that a
  deeply nested input drives into V8's "maximum call stack size exceeded".
- Path traversal and command or template injection, when the parsed value reaches a
  filesystem, shell, or template sink.

Tooling. Jazzer.js is the coverage guided fuzzer; Sabba's node prover already wraps it.
The signal is different from ASan and needs three things bolted onto the harness so the
run means something:

- A self contained prototype pollution oracle. Snapshot the own property names of
  `Object.prototype` at load, and after every fuzz call assert that no new name appeared.
  This does not depend on any detector being configured, and it catches pollution through
  any path the target takes. Delete the injected key before rethrowing so the next input
  starts clean.
- A benign error filter. Parsers throw on bad input constantly, so an uncaught exception
  is not a finding. Catch, then rethrow only the two that are real: a `RangeError` whose
  message is "maximum call stack size exceeded" (stack exhaustion) and the pollution
  signal. Everything else is swallowed.
- A per input timeout. A hang with no exception is the ReDoS signal; the fuzzer's timeout
  turns it into a reported crash. Keep it short.

What this run taught about target choice. Six fresh, real npm parsers were fuzzed for ten
minutes each, about sixteen million executions total, and every one came back clean. The
validation step explains why, and it is the lesson: modern object manipulation libraries
are now hardened against the textbook prototype pollution vectors. `dotty` and `nestie`
silently refuse a `__proto__` or `constructor.prototype` segment, and `js-ini` throws
`Unsupported section name "__proto__"` outright. The guard that used to be missing is now
standard. So the yield in maintained JavaScript has shifted away from prototype pollution
toward ReDoS, stack exhaustion, and logic bugs, and toward libraries old or obscure enough
to predate the hardening. The prototype pollution oracle is still worth running, because it
costs nothing and the long tail of unmaintained packages still has the bug, but it should
not be the reason a target is chosen. Choose for a regex heavy parse or an unbounded
recursion, and keep the same triage and novelty discipline as the native side.
