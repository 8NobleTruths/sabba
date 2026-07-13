# Local models: run offline, and learn where to look

Sabba's oracle and provers never needed a model. This layer adds two small local pieces so the
model-driven parts can run on your own machine and get cheaper over time: a CPU risk ranker
that learns which functions to look at first, and a cascade that keeps work at the cheapest
tier that can do it. Together with the local LLM backend (see AGENT_INTEGRATION.md) the whole
loop can run with no frontier model.

## The risk ranker

The ranker scores a function for how likely it holds a memory-safety bug, so retrieval
surfaces the risky code before any reasoning budget is spent. The shipped model is a TF-IDF
over the function source (word tokens catch dangerous identifiers like `strcpy`; character
n-grams catch patterns and survive unseen tokens) into a logistic classifier. It trains in
seconds, the artifact is a few megabytes, and it runs on CPU.

It is wired into `harness/retrieval.py`: the ranking blends the structural score (dangerous
sinks, the classic off-by-one shape, call-graph reachability) with the learned risk. When no
model is trained the ranker returns a transparent heuristic, so the ranking is never worse
than the structural score alone, and nothing breaks if you never train it.

Train it:

```bash
sabba mltrain                     # train on the built-in bootstrap corpus, save ~/.sabba/ranker.joblib
sabba mltrain data.jsonl          # train on your own labeled corpus
sabba mltrain data.jsonl -o m.joblib
```

The corpus is JSONL, one object per line:

```json
{"code": "void f(const char *s){ char b[16]; strcpy(b, s); }", "label": 1}
{"code": "void f(const char *s){ char b[16]; strncpy(b, s, 15); b[15]=0; }", "label": 0}
```

`label` is 1 for a function that holds a bug, 0 for one that does not. The built-in bootstrap
corpus (`sabba/ml/bootstrap.py`) is only for bring-up and tests; point production training at a
real labeled corpus in the same format. A trained model overrides the heuristic automatically;
set `SABBA_RANKER_PATH` to load one from a custom location.

### The flywheel: learn from proven runs

The oracle already decides truth by running the exploit, so that verdict is the training signal
we keep. After a native hunt, each function retrieval surfaced is written to a trace with a
label: 1 when the oracle proved a bug in it, 0 otherwise. Over time these real, execution-
grounded examples replace the synthetic bootstrap corpus, and they are the same reward signal a
later RLVR pass uses to improve the local reasoning model.

Collection is on by default and fail-safe (it never breaks a hunt). Turn it off with
`SABBA_TRACES=0`; relocate it with `SABBA_TRACE_DIR`. Retrain the ranker on what you have
collected:

```bash
sabba mltrain --from-traces
```

Honest caveat: a positive is rock solid (the oracle reproduced a crash), but a negative is
weak, a function that did not yield a proven finding this run may still be buggy. The trainer
keeps that in mind, dedupes to the strongest label per function, and tops up with the bootstrap
corpus when a class is thin, reporting how much real data went in.

### Upgrading to an embedding model

The classical model is the recommended start. For more semantic power, freeze a code embedder
(for example `jinaai/jina-embeddings-v2-base-code`, ~161M, Apache-2.0, ONNX-exportable, CPU)
and train a small head on the same corpus. The `RiskRanker` interface does not change (fit on
code strings, score to a probability); only `build_pipeline` in `sabba/ml/ranker.py` does.

## The cascade: Reflex, Resident, Teacher

`sabba/water/cascade.py` routes a task to the cheapest tier that can do it:

- **Reflex** runs no model at all: the ranker, Z3, and the oracle. Verifying a PoC, running
  Z3, or ranking is always Reflex.
- **Resident** is a local model (`SABBA_LLM_BACKEND=local`) for the common reasoning cases.
- **Teacher** is a frontier model for the hard or high-value cases.

A reasoning hunt goes to Resident when a local model is present and the task looks tractable,
and to Teacher when it is hard or when Resident came up empty. The verdict discipline is
unchanged across tiers: whatever proposes a candidate, the oracle still runs it before it
becomes a finding, so a cheaper tier can only ever cost coverage, never soundness.

## Where this is going

The ranker and the cascade are the Resident-tier machinery of the Water Layer: knowledge kept
as small runnable models, learned from data, usable with no frontier model. The next step is
execution-grounded learning, using the oracle's verdict as a hard reward to improve the local
model on the cases the Teacher solved. See WATER_LAYER_DESIGN.md.
