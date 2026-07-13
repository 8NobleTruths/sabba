"""Local ML: small CPU models that make Sabba cheaper before any LLM is called.

The first model here is the risk ranker: it scores a function for how likely it is to hold a
memory-safety bug, so retrieval surfaces the risky code first and the expensive reasoning
budget is spent where it matters. It runs on CPU, trains in seconds, and degrades to a
heuristic when no model is present, so nothing breaks if it was never trained.

This is the Resident-tier machinery of the Water Layer: knowledge kept as a small runnable
model, learned from data, usable with no frontier model in the loop. See docs/WATER_LAYER_DESIGN.md.
"""
from .ranker import RiskRanker, heuristic_score

__all__ = ["RiskRanker", "heuristic_score"]
