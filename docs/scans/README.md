# `docs/scans/`, verified findings (the data flywheel)

Each file documents a vulnerability **Sabba found and the oracle verified** on real code,
with a reproducing PoC. These are the seed of the continuous data flywheel
(docs/08-productionization.md): every confirmed finding is gold-standard supervision -
a real (vulnerable code, PoC, CWE, fix) tuple that later trains and evaluates the model.

Phase-0 findings are produced by a **reasoning model driving the harness by hand** (the
"self as LLM" mode, no external model endpoint) plus the deterministic ASan oracle on the
GCP build box `sabba-dev`. Framing is honest: these are **reproduction / variant analysis**
of real bugs (the realistic Phase-0 capability), not novel zero-days, those come with the
trained model + fuzzing/symbolic integration in Phases 4-5.

| Finding | Target | Class | Method |
|---|---|---|---|
| [cjson-1.4.6-cwe674](cjson-1.4.6-cwe674.md) | DaveGamble/cJSON v1.4.6 | CWE-674 stack exhaustion | variant analysis from the fix commit |
| [cjson-issue800-cwe125](cjson-issue800-cwe125.md) | DaveGamble/cJSON v1.7.17 | CWE-125 heap buffer over-read | variant analysis from the fix + test commits |
