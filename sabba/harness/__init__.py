"""The agentic harness, the 70%.

Phase 0 ships the two load-bearing pieces:
  - `oracle`  : the deterministic verification oracle (compile + sanitizer + run PoC)
  - `agent`   : the LLM-driven find -> verify -> report loop (needs an API key)

The oracle is usable on its own with no model. A Finding is only ever produced
from a confirmed Verdict (ADR 0001).
"""
from .oracle import CCompileRunOracle

__all__ = ["CCompileRunOracle"]
