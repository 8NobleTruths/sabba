# Sabba Agent: the Water Layer

Status: design, not yet built. Last updated 2026-07-10.

This document describes the next layer on top of the current Sabba agent. The agent today
finds memory-safety bugs and proves them with an execution oracle. The Water Layer turns
that same machinery into a general agent that learns skills, keeps them as runnable code,
runs without a frontier model when it has to, and can be rebuilt from a seed after it is
deleted.

The name comes from a simple picture. Water takes the shape of whatever holds it, flows
around what blocks it, and cannot be destroyed by removing one part of it. The agent should
behave the same way: shape itself to the user's work, keep working when the network or the
model is gone, and come back after the process or the machine dies.

Nothing here throws away the current design. It reuses the oracle, the sandbox, the model
backend switch, and the agent loop. It generalizes them.

## The idea in one page

The agent is not the running process, and it is not the model. Those are temporary. The
lasting thing is a **genome**: the skills it has learned, the memory it has kept, the small
models it has trained, and the rules it must not break. A running process is a **body** the
genome grows on a machine. A frontier model is a **teacher** the body consults when it hits
something it cannot do yet.

One mechanism ties the whole thing together: **when the teacher solves something, the agent
compiles that solution into a standalone, verified skill.** A skill is ordinary code plus a
verification harness. Once compiled and checked by the oracle, it runs with no model at
all. This is how a slow, model-driven solution becomes a fast reflex, the same way a person
turns effort into habit.

That single mechanism gives two properties that sound separate but are not:

- **Survives without a model.** Everything the agent has already learned is code, so it
  runs offline, with no API key, on a machine with a weak CPU. It cannot learn something
  genuinely new without a teacher, but it does not stop working.
- **Can be reborn.** The genome is a signed, versioned seed kept in more than one place.
  Kill the process, delete the files, lose the machine: as long as one genome copy
  survives, a new body reconstitutes with every skill intact.

## Three parts of the agent

**Genome, the seed that does not die.** A signed, versioned directory (a git repo) holding
compiled skills and their tests, memory, trained small models and adapters, the router
policies, the constitution, and a trust ledger. Portable and backed up to more than one
location. This is the self that carries forward.

**Body, the process that runs and can die.** On birth it loads the genome, registers the
skills, loads the resident model, connects a teacher if one is available, and starts the
agent loop. On death a supervisor verifies the latest genome signature and grows a new
body from it. Bodies are disposable. The genome is not.

**Teacher, the organ that is optional.** A frontier model reached through the existing
backend switch (OpenRouter, Anthropic, a self-hosted endpoint). It is consulted for
genuinely novel work and, more importantly, it teaches: it produces new skill code,
training data for the resident model, and labels for the routers. If it is absent the body
still runs on what it has learned.

## Three tiers of reasoning

This is the existing "cheap before expensive" principle extended to reasoning. A task is
tried at the cheapest tier that can handle it, and only escalated when the tier is not
confident or the verifier rejects the result.

1. **Reflex.** Compiled skills (deterministic code) and small machine-learning models
   (classifiers, retrievers, policies). No model call. Milliseconds. Runs on a weak CPU.
   This is the learned repertoire.
2. **Resident.** A small local language model, quantized, run through llama.cpp or a
   similar CPU runtime. Handles moderate reasoning and the cases Reflex does not cover.
   Always available, no network. It gets better over time by learning from the teacher.
3. **Teacher.** The frontier model. Slowest and most expensive. Consulted only for what the
   lower tiers cannot resolve, and used to teach the lower tiers so that next time the work
   stays local.

The point of the ladder is that it moves work downward over time. What the Teacher solves
today becomes a Resident that can solve it tomorrow, and a Reflex skill the day after. Cost
falls, speed rises, and the fraction of work that needs the network shrinks.

## The mechanism: compile reasoning into verified skills

The current code already has a small version of this. In `harness/fuzz.py` the model writes
a fuzzing harness and the oracle proves the crash. The Water Layer generalizes that exact
move from "model writes a harness, oracle proves a crash" to "model writes a skill, oracle
proves the skill works."

A skill is:

- a function with declared inputs and outputs,
- a declaration of the capabilities it needs (files, network, processes),
- a verification harness: generated tests, including property tests, that decide whether
  the skill does what it claims,
- fitness metadata: how often it has run, how often it passed, when it was last used.

The compile step:

1. The Teacher (or Resident) solves a task and produces a concrete procedure.
2. The compiler extracts a reusable skill and its verification harness.
3. The oracle runs the skill in the sandbox against the harness and decides. This is the
   same oracle the bug-finder uses. It is never forked.
4. Only a skill the oracle confirms enters the genome, committed with its tests and its
   fitness record.

Later, when a similar task arrives, Reflex runs the compiled skill with no model call.

## Components

Each component below says what it does and where it plugs into the current code.

**Genome (`water/genome.py`, new).** Reads and writes the genome directory: a manifest,
`skills/`, `memory/`, `models/` (resident adapters and the machine-learning models),
`constitution.md`, and `ledger/`. Every change is a git commit and is signed. Provides
birth (load into a body) and export (push to backups and peers). Grows out of the current
`memory.py` and `history.py`.

**Body and Supervisor (`water/body.py`, `water/supervisor.py`, new).** The body is the
running agent loop, which is today `harness/agent.py` and `harness/orchestrator.py` with
the tier cascade added in front. The supervisor is a tiny watchdog (a systemd user unit in
practice) that restarts a dead body from the last good, signature-verified genome. A
`sabba resurrect` command reconstitutes on a fresh machine from the genome repo alone.

**Teacher (existing `llm/`).** No new interface needed. The frontier backends already
exist. The Water Layer adds the teaching outputs: skill code, distillation pairs, router
labels.

**Resident (`water/resident.py`, new).** A local, quantized small model behind the same
`llm/base.py` interface, so the rest of the system does not care which brain answered. Runs
inference only on the end device. Its weights and LoRA adapters live in the genome. It is
improved offline, not on the low-CPU device.

**Reflex (`water/reflex.py`, new).** Runs compiled skills and the small machine-learning
models. Selects a skill for a task by retrieval over skill descriptions, checks the
capability declaration, and hands execution to the sandbox and oracle.

**Router (`water/router.py`, new).** A small, CPU-cheap classifier that decides, per task
or subtask, which tier should handle it: Reflex, Resident, or Teacher. It starts naive
(escalate almost everything to the Teacher) and is trained on outcomes (which tier actually
succeeded). A well-calibrated router is what keeps the Resident from being trusted past its
ability. When unsure, it escalates.

**Skill Compiler (`water/compiler.py`, new).** The generalization of `harness/fuzz.py`.
Turns a solved task into a skill plus a verification harness, submits it to the oracle, and
on success writes it to the genome.

**Distiller (`water/distiller.py`, new).** The continual-learning loop. It collects
`(task, teacher solution)` pairs into an append-only dataset in the genome, and on a
schedule it fine-tunes the Resident (LoRA or QLoRA) and retrains the machine-learning
routers on the same labels. A new resident adapter or a new router is promoted only if it
does at least as well as the current one on a held-out replay set of past tasks. This is
the same fitness-gated discipline the skills use. The Teacher's dataset is append-only so
distillation cannot quietly erase what was learned.

**Verifier and Guard (existing `harness/oracle.py`, `sandbox/`).** Every action and every
self-modification passes the guard: a capability check against the constitution, execution
in the sandbox, an oracle verdict on the outcome, and a signed line in the trust ledger.
This is what keeps a self-modifying, self-restoring agent from behaving like a worm. The
oracle is the anchor here exactly as it is for the bug-finder.

**Constitution (`water/constitution.py` and `constitution.md` in the genome, new).** A
small set of rules the agent cannot modify from inside a normal run: capability ceilings,
actions that always require a human, and the requirement that the genome stay signed.
Changing the constitution is a separate, human-in-the-loop act.

## Running without a model

There are three availability states, and the router degrades across them without the agent
stopping.

- **Full: Teacher, Resident, and Reflex.** Best quality. Can learn genuinely new skills.
- **Local: Resident and Reflex, no Teacher.** Offline, no key, or out of budget. Handles
  the known repertoire and moderately novel work through the local model. It cannot compile
  a truly new skill, so it records "teach me this later" items and continues.
- **Reflex only: compiled skills and machine-learning models, no model at all.** Lowest
  power, fully deterministic. Survival mode. The learned repertoire still runs.

## The life of a task

1. A task arrives. The router picks a tier.
2. Reflex tries a compiled skill or a small model. If it is confident and the oracle
   confirms the result, the task is done with no model call.
3. Otherwise the Resident reasons locally. If confident and confirmed, done. The exchange
   is logged as a candidate for skill compilation and distillation.
4. Otherwise the task escalates to the Teacher. It solves. The oracle confirms.
5. The Teacher's solution feeds the Skill Compiler (make a Reflex skill when the procedure
   is deterministic) and the Distiller dataset (teach the Resident and the routers).
6. Every step is verified by the guard, recorded in the trust ledger, and any change is
   committed to the genome.
7. Over weeks, more tasks resolve at the Reflex and Resident tiers. The agent gets cheaper,
   faster, and more able to work offline.

## Mapping onto the current code

| Water Layer role | Where it comes from today |
| --- | --- |
| Verifier and guard | `harness/oracle.py`, run in `sandbox/` |
| Teacher, pluggable brain | `llm/base.py` and the OpenRouter, Anthropic, GLM providers |
| Agent loop, the body | `harness/agent.py`, `harness/orchestrator.py` |
| Seed of the genome | `memory.py`, `history.py` |
| Model writes code, oracle proves it | `harness/fuzz.py` (auto harness generation) |
| Cheap before expensive | the existing static, symbolic, model, fuzz ordering |

## New modules to add

```
water/
  genome.py        seed: skills, memory, models, constitution, ledger; git backed and signed
  body.py          the running agent, wraps the existing loop with the tier cascade
  supervisor.py    watchdog and rebirth; sabba resurrect
  resident.py      local quantized model behind the llm/base.py interface
  reflex.py        run compiled skills and the small ML models
  router.py        escalation classifier: Reflex, Resident, or Teacher
  compiler.py      turn a solved task into a verified skill (generalizes fuzz.py)
  distiller.py     continual learning: fine-tune Resident and retrain routers, gated by replay
  constitution.py  load and enforce the immutable rules
```

## Hard problems, stated honestly

- **General skills are harder to verify than crashes.** A sanitizer firing is a crisp
  ground truth. "Did this skill do what it claimed" is not. The compiler must generate
  strong tests, lean on property-based checks, keep a human spot-check in the loop, and be
  conservative about what it is willing to compile.
- **The genome will rot.** Thousands of skills means conflicts, dead code, and drift.
  Needs garbage collection, deduplication, fitness decay, and skill-health checks.
- **Rebirth resembles malware persistence.** A self-restoring, self-modifying agent is
  dual-use. The defenses are non-negotiable: the genome is signed, the constitution is
  enforced, capabilities are bounded, and constitution changes need a human. This is a
  benevolent immortal only because the guard makes it one.
- **Distillation can collapse or drift.** A new resident that trained on its own outputs
  can get worse. The replay gate before promotion and the append-only teacher dataset are
  what prevent silent regression.
- **A small local model is weak.** The Resident handles routine and narrow work, not
  everything. The router must be calibrated to escalate when unsure rather than trust the
  Resident past its ability.
- **Fine-tuning does not belong on a weak CPU.** The end device runs inference only.
  Distillation runs offline, batched, on the dev box or a GPU, and ships adapters back into
  the genome.

## Roadmap, thin slices with a demo each

- **Phase 0, skeleton.** The `water/` package, the genome format (git backed), the
  constitution file, wired into the current agent loop. No learning yet.
- **Phase 1, skill compile.** Generalize `fuzz.py`: the agent writes a skill, the oracle
  verifies it, it goes in the genome, Reflex reuses it. Demo: it teaches itself a skill,
  then does the task again with no model.
- **Phase 2, cascade and local.** Add the Resident (a small local model) and the router.
  Demo: unplug the network, the agent keeps working on Resident and Reflex.
- **Phase 3, distill.** Collect teacher pairs, fine-tune the Resident offline, promote only
  through the replay gate. Demo: the local model measurably improves over a week.
- **Phase 4, rebirth.** The supervisor, the signed genome, and `sabba resurrect`. Demo:
  delete the install, it comes back with every skill.
- **Phase 5, guard and ledger.** The full attestation trust ledger and its view.

## Open questions for the next session

- Which small model to start the Resident with, and which CPU runtime.
- The exact genome manifest schema and the signing scheme.
- Where the router's features come from, and its first training signal.
- How much of `harness/agent.py` to reuse as the body versus rewrite around the cascade.
- The safest default constitution.
