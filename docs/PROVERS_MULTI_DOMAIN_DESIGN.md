# Sabba across languages and Web3

Status: design, in progress. Last updated 2026-07-10.

Sabba today finds memory-safety bugs in C and C++ and proves each one by triggering it
under a sanitizer. This document extends that same discipline to any programming language
and to smart contracts, Solidity first. The rule does not change. What changes is the set
of ways a finding can be proven, and the machinery that materializes a target so an exploit
can be run against it.

Read `SABBA_AGENT_DESIGN.md` first. This document assumes the oracle-anchored pipeline it
describes and generalizes the oracle.

## The one rule that does not change

A finding is reported only after Sabba has run an exploit and a checker has confirmed that a
security property was violated. No sanitizer firing, no callback received, no invariant
broken, no report. Asking a model "is this vulnerable" is close to a coin flip and buries
maintainers in false positives, so Sabba never emits a finding it has not demonstrated.

The consequence is the same across every language and chain: the output is trustworthy
because a bug you can trigger is a bug you have shown, not one you have guessed. The cost is
also the same: Sabba proves what it can build a checker for, and stays quiet about what it
cannot yet demonstrate. That is a deliberate trade of coverage for trust.

## From one oracle to a registry of provers

The C and C++ oracle is one instance of a general shape:

> a finding is a target, a witness that drives it, and a checker that deterministically
> decides whether a security property broke when the witness ran.

For memory safety the witness is an input and the checker is a sanitizer. For a web app the
witness is a request sequence and the checker watches for a leaked canary or an out-of-band
callback. For a smart contract the witness is a transaction sequence and the checker is an
invariant on balances. Same shape, different parts.

So the oracle becomes a **registry of provers**. A prover is:

- the languages and runtimes it applies to,
- the vulnerability class it targets,
- an environment builder that makes the target runnable in a sandbox,
- an exploit runner that drives the witness,
- a checker that turns the run into a yes or no verdict,
- a proof-bundle writer.

Every prover obeys the same contract as the current oracle: it is deterministic, it runs in
a sandbox, and it emits a bundle anyone can re-run. There is still one definition of a real
finding, shared by the agent, by any future training reward, and by serving. Provers are
added, never forked.

Given a target, the registry selects the provers whose language and available candidate
sources apply, and runs the cheap ones before the expensive ones, exactly as the native
pipeline does today.

## The proof bundle

Every confirmed finding ships a bundle that reproduces it with one command. The format is
uniform across domains so a maintainer or a bounty triager learns it once:

- the target, pinned: a source tree and build, a container image, or a chain fork block,
- the witness: the input, the request sequence, or the exploit transactions,
- the checker: the sanitizer flags, the canary or callback definition, or the invariant,
- a single re-run script that rebuilds the environment, drives the witness, and prints the
  verdict.

This is the deliverable. It is what makes a report trustworthy and what makes it shareable.

## Provers by domain

### Native memory safety, existing

Languages: C, C++, and the unsafe surface of Rust, Zig, Objective-C, and similar.

Environment: compile with clang and a sanitizer. Witness: an input. Checker: AddressSanitizer,
UBSan, MemorySanitizer, or ThreadSanitizer fires and the crash reproduces. Candidate sources:
dangerous-sink retrieval, the Z3 shape synthesizer, and coverage-guided fuzzing with libFuzzer
or AFL++. This is the pipeline that exists now.

### Managed languages and web applications

Languages: Python, JavaScript and TypeScript, Java and the JVM, Go, Ruby, PHP, C#, and
others. Here memory safety is not the bug class. The classes are injection, server-side
request forgery, path traversal, deserialization, template injection, prototype pollution,
authentication and authorization bypass, and insecure direct object references.

A sanitizer crash does not prove these. The checker is effect-based instead:

- Injection and command execution: the exploit runs a marker. Command injection is proven
  when a nonce command executes, seen as the nonce in the response, a canary file written,
  or an out-of-band callback carrying the nonce. SQL injection is proven by exfiltrating a
  seeded canary row, by a time-based delay measured across repeated trials, or by an
  out-of-band callback.
- Server-side request forgery: the exploit forces the target to fetch an attacker URL, and
  a callback with the matching nonce arrives at a listener inside the sandbox.
- Path traversal and file read: the harness plants a canary file outside the intended
  directory, and its contents appear in the response.
- Template injection: a payload the server evaluates returns a computed marker.
- Authorization bypass and insecure direct object reference: two accounts are seeded, and an
  attacker session retrieves the victim's canary resource.
- Client-side, such as reflected or DOM cross-site scripting: a headless browser loads the
  page, the injected script runs, and it beacons the nonce to the sandbox listener.

The shared infrastructure for this track is a contained out-of-band interaction listener, a
set of canary tokens and seeded records, and a headless browser for client-side classes.
The sandbox network is closed so a payload cannot reach a real external system. Candidate
sources: taint analysis from sources to sinks with Semgrep or CodeQL, model reasoning over
the routes and handlers, and per-language fuzzing (Atheris for Python, Jazzer for the JVM,
native Go fuzzing, cargo-fuzz for Rust, jsfuzz for JavaScript) for library targets that have
no HTTP surface.

The hard engineering here is the environment builder: getting an arbitrary application to
boot in a sandbox with its services and a seeded database. Start where that is tractable,
single-service apps and libraries, before sprawling multi-service systems.

### Web3 and Solidity

This is the cleanest oracle after native crashes, because decentralized finance has crisp
invariants. Money is conserved or it is not.

Environment: a local EVM fork of a real chain at a fixed block, with Foundry's anvil and
forge or an equivalent. Pinning the fork block makes the run deterministic. Witness: a
sequence of transactions, usually an attacker contract plus calls, written as a Foundry
test. Checker: an invariant or a profit condition.

The gold-standard proof is economic. The attacker starts with no capital, or only a flash
loan that is repaid within the transaction, and ends with a strictly larger token or ETH
balance at the victim contract's expense. A net profit that came from nowhere legitimate is
an exploit that has been shown, not argued. Other checkers cover classes where profit is not
the direct signal:

- Solvency and conservation invariants: the sum of balances equals total supply, or the
  contract can always cover its liabilities. The exploit makes one fail.
- Access control: a privileged function that should reject an unauthorized caller accepts
  one, proven by the state change it was not allowed to make.
- Reentrancy: a callback re-enters and withdraws more than the balance allowed, drained on
  the fork.
- Price and oracle manipulation: a flash loan skews an automated market maker or a spot
  oracle, and a dependent contract misprices, letting the attacker extract value.
- Integer overflow and underflow in unchecked arithmetic, proxy and delegatecall storage
  collisions, uninitialized proxies, signature replay with a missing nonce, unchecked
  external call returns, tx.origin authentication, first-depositor share inflation, and
  rounding and precision abuse. Each has a concrete post-condition the run must exhibit.

Candidate sources for the EVM track: Slither and Aderyn for static findings, Mythril for
symbolic exploration, Echidna and Medusa for property and assertion fuzzing, and Halmos or
Kontrol for symbolic and formal checking of specific properties. The model reasons about the
economic intent and the invariants, which static tools do not understand, and proposes the
transaction sequence. Whatever the source, the candidate becomes a Foundry proof: a test
that passes only when the exploit works, that anyone can re-run with forge test against an
archive node.

Non-EVM chains, such as Solana with Rust and Anchor, and Move on Aptos and Sui, follow the
same shape with their own runners and invariants. They come after EVM.

## Candidate sources, generalized

The cheap-before-expensive ordering holds in every domain. Static filters and pattern rules
run first and are free. Symbolic and property tools run next where they fit. The model runs
where the cheaper stages left something unresolved, because it reasons about intent and
economic invariants that pattern tools cannot express. Fuzzing runs last where a harness
exists. Every candidate, whatever produced it, goes through a prover and is reported only if
the checker confirms it.

## Environment materialization

The sandbox package grows from one compile step into a set of environment builders:

- native: detect the build, compile with the sanitizer,
- managed library: install dependencies, build a fuzz harness for the language,
- web application: build a container, seed a database with canaries and a victim account,
  boot the services, health-check,
- EVM: create a fork at a block, deploy or attach to the target, load Foundry.

The builder is the main cost outside the native track. It is also where determinism is won
or lost, so each builder pins versions, seeds, and fork blocks.

## How this fits the Water Layer

The prover registry is the verifier the Water Layer already depends on. Two things follow.

First, a prover for a new vulnerability class is itself a skill the agent can learn and
compile. The genome accumulates provers the way it accumulates any other skill, and the
same oracle discipline gates them: a new prover is trusted only after it correctly confirms
known-true and known-false cases. The agent gets better at proving new classes over time.

Second, the tiered reasoning applies directly. Reflex runs the static and symbolic provers
and the compiled exploit templates with no model. The Resident handles moderate cases
offline. The Teacher is consulted for novel economic logic or an unfamiliar framework, and
what it works out is distilled down so the next similar target stays local.

## What is crisp and what is not

Being honest about oracle strength matters, because it bounds what Sabba will claim.

- Strong and direct: native memory safety under a sanitizer, decentralized-finance fund
  drains and conservation invariants, command and template injection proven by marker
  execution, injection and request forgery proven by an out-of-band callback.
- Workable with setup: authorization bypass and insecure direct object references, which
  need seeded accounts and canary resources; reentrancy and access control, which need the
  invariant stated; client-side scripting, which needs a headless browser oracle.
- Out of scope for now: business-logic flaws with no checkable invariant, severity
  judgments that depend on context rather than a triggerable effect, and design weaknesses
  that cannot be run. Sabba does not report these, rather than guess at them.

## Responsible use

An exploit that drains a live protocol is a live weapon. The discipline is fixed. Prove on a
fork or a local environment, never against funds or systems you are not authorized to touch,
contain the sandbox network so payloads cannot reach real systems, and disclose through the
proper channel, an Immunefi program or a maintainer, with the re-runnable bundle. The bundle
that makes a finding trustworthy is the same bundle a defender uses to confirm the fix.

## Roadmap

Order the domains by how tractable the oracle and the environment builder are.

- **First, Web3 and Solidity.** The environment is standardized with Foundry forks and the
  invariants are crisp. Ship a prover that emits a re-runnable forge PoC for reentrancy,
  access control, and a flash-loan price manipulation, checked by an attacker-profit or a
  solvency invariant.
- **Second, managed libraries.** Reuse per-language fuzzers feeding a sanitizer or assertion
  oracle. No web environment needed, so the builder stays simple.
- **Third, web applications.** Add the container-plus-seed environment builder and the
  effect and callback oracle for injection, request forgery, traversal, and authorization.
- **Throughout, register each prover as a skill** so the Water Layer accumulates them and the
  shared verifier stays single.
