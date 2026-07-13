# Sabba Agent design

Status: early, in active development. Last updated 2026-07-10.

Sabba is a system for finding memory-safety bugs, not a single model. The model is one
component. Most of the useful work is done by retrieval, static and symbolic analysis, and
an execution oracle that decides what is real. This document describes how those pieces fit
together and what gets built next.

Scope. This document describes the C and C++ memory-safety pipeline that exists today. The
same discipline, prove a finding by triggering it, extends to any language and to smart
contracts. The oracle stays the anchor and becomes a registry of provers, one per
vulnerability class and runtime, including an EVM fork that checks fund-drain and solvency
invariants for Solidity. See `PROVERS_MULTI_DOMAIN_DESIGN.md` for that generalization.

## Principles

The oracle is the anchor. Every other component proposes candidates. The oracle compiles
the target under a sanitizer, runs the candidate input, and decides. Nothing is reported
unless a sanitizer fires and the crash reproduces. This is the whole reason the output is
trustworthy: a bug you can trigger is a bug you have shown, not one you have guessed.

Formal methods help, but they do not replace execution. The Z3 layer generates candidate
inputs and prunes impossible paths. It does not try to prove real C correct, because that
does not scale and because a model turning code into a formula can produce the wrong
formula. The run under a sanitizer is what checks the formula.

The model is a swappable part. The backend is chosen at runtime (GLM, OpenRouter,
Anthropic, or a self-hosted endpoint later). Self-hosting matters for a security tool
because client code stays on your own machine and there are no third-party refusals or
terms getting in the way of legitimate work. It does not make the tool more capable on its
own; capability comes from the system around the model.

Cheap before expensive. Static filters run before symbolic synthesis, which runs before
the model, which runs before fuzzing. Spend the expensive steps only where the cheap ones
left something unresolved.

One verifier, shared. The same oracle is used by the agent, by any future training reward,
and by serving. It is never forked, so what counts as a real bug is the same everywhere.

## How a hunt runs

Given a target, the driver (`harness/orchestrator.py`) does this:

1. Rank functions by dangerous-sink presence and call-graph reachability
   (`harness/retrieval.py`), so attention goes to the risky code first.
2. Run the Z3 synthesizer (`harness/symbolic/synth.py`) over the sources. It resolves the
   common overflow shapes outright and needs no model.
3. If a model is configured, run the reasoning agent (`harness/agent.py`) over what is
   left, seeded with the retrieval hints, for the bugs the synthesizer cannot express yet.

Whatever the source of a candidate, it goes through the oracle (`harness/oracle.py`) and is
reported only if the sanitizer confirms it.

## The symbolic layer

The first version of the synthesizer models the arithmetic that relates a buffer's size to
how many bytes get written into it, then asks Z3 for an input length that makes the write
exceed the buffer. It covers two shapes to start with:

- `strcpy` and friends into a fixed-size stack array. Overflow when the input length
  reaches the array size.
- `strcpy` into a heap buffer sized from `strlen` without the `+1` for the terminator. The
  write is one byte past the allocation.

The source of the copy is traced one hop back to `argv[i]` through the enclosing function's
parameter, so the input Z3 solves for actually reaches the sink. The size model is written
out explicitly rather than hidden, so harder cases (integer overflow in the size
expression, signed and unsigned truncation) can be added later without changing the rest of
the pipeline. Those harder cases are where an SMT solver earns its place; the current
constraints are simple on purpose.

## Modes

Offensive hunt. `sabba hunt <target>` runs the full driver and reports reproducible PoCs.
`sabba solve <target>` runs the Z3 path alone.

Defensive verify. Planned. Take a finding, have a separate gated agent write a patch, and
re-check that the patch removes the crash, the tests still pass, and coverage is preserved.
Attach a bundle that anyone can re-run to reproduce the verdict.

## What ships next

- `harness/patch/`: the defensive patch agent and the reproducible verification bundle.
- A broader symbolic-execution front end (angr or KLEE) feeding the same oracle.
- Static discovery through Semgrep and Joern as additional candidate sources.
- A self-hosted reasoning endpoint behind the existing backend switch.

The verifier stays constant across all of this. It is the same oracle a future training
reward would use.
