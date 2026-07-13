# Contributing

## Never commit credentials

API keys, tokens, and private keys never go in the repository. The code reads them from
environment variables at runtime (for example `OPENROUTER_API_KEY`, `SABBA_LLM_API_KEY`).

Turn on the secret-scanning pre-commit hook once, right after you clone:

```bash
git config core.hooksPath .githooks
```

The hook rejects a commit if the staged diff contains something shaped like a key, or if
a staged file name looks like a secret (`.env`, `*secret*`, `*.pem`, `*.key`). If it fires,
remove the value and load it from the environment instead.

## Setting a model

The reasoning model is selected at runtime, not baked in:

```bash
export SABBA_LLM_BACKEND=openrouter
export OPENROUTER_API_KEY=...            # from openrouter.ai/keys
sabba hunt targets/cwe121_stack_overflow --model qwen/qwen-2.5-coder-32b-instruct
```

The oracle (`sabba verify`) and the Z3 synthesizer (`sabba solve`) need no model at all.

## Running the tests

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
pytest -q
```

The oracle needs `clang` with AddressSanitizer available on the machine.
