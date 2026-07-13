"""Wave 3.2, graph-structured retrieval.

Surfaces the functions a reasoner should look at FIRST, instead of dumping a whole
repo into context (ADR 0002: reachability/taint are graph properties flat-embedding RAG
can't capture). Ranks functions by dangerous-sink presence, classic-bug patterns, and
call-graph reachability. The agent then focuses its hypothesize->verify budget on the
top candidates.
"""
from __future__ import annotations

import re
from pathlib import Path

from .cpg import build, _c_files

# Sink risk weights (memory-safety severity-ish).
_W = {"strcpy": 3, "strcat": 3, "sprintf": 3, "vsprintf": 3, "gets": 4, "memcpy": 2,
      "memmove": 2, "alloca": 2, "scanf": 2, "sscanf": 2, "system": 2, "realloc": 1}

# how much the learned risk (0..1) counts against the structural sink score
_ML_WEIGHT = 5.0
_RANKER = None


def _ranker():
    """Load the risk ranker once. It returns a heuristic-only ranker when no model was
    trained, so retrieval never depends on the model being present."""
    global _RANKER
    if _RANKER is None:
        from ..ml.ranker import RiskRanker
        _RANKER = RiskRanker.load()
    return _RANKER


def rank_candidates(target: str | Path, top_k: int = 10) -> list[dict]:
    """Return functions ranked by vulnerability-candidate score (highest first).

    The score blends two signals: the structural one (dangerous sinks, the classic off-by-one
    shape, call-graph reachability) and a learned one from the ML risk ranker over the function
    source. When no model is trained the ranker contributes a transparent heuristic, so the
    ranking is never worse than the structural score alone.
    """
    rows = build(_c_files(Path(target).expanduser()))
    ranker = _ranker()
    scored = []
    for r in rows:
        if not r.get("function") or r.get("parse_quality") != "ok":
            continue
        score = sum(_W.get(s, 1) for s in r.get("sinks", []))
        # classic off-by-one: malloc sized by strlen feeding a copy
        text_sinks = set(r.get("sinks", []))
        if {"malloc"} & text_sinks and {"strcpy", "memcpy", "sprintf"} & set(r.get("calls", [])):
            score += 3
        # reachability: functions with many callers are more exercised (untrusted input flows in)
        score += min(len(r.get("callers", [])), 5) * 0.5
        # learned risk from the function source
        risk = ranker.score(r.get("code", "") or "")
        score += risk * _ML_WEIGHT
        if score <= 0:
            continue
        scored.append({"function": r["function"], "file": r.get("file", ""),
                       "line": r.get("line"), "sinks": r.get("sinks", []),
                       "callers": r.get("callers", [])[:6], "risk": round(risk, 3),
                       "score": round(score, 1), "code": r.get("code", "")})
    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored[:top_k]


def format_hints(candidates: list[dict]) -> str:
    """A compact hint block to prepend to the agent's task (focuses its search)."""
    if not candidates:
        return ""
    lines = ["Retrieval surfaced these high-risk functions (investigate first):"]
    for c in candidates:
        loc = f"{Path(c['file']).name}:{c['line']}"
        risk = f"  risk={c['risk']}" if "risk" in c else ""
        lines.append(f"  - {c['function']} @ {loc}  sinks={c['sinks']}  score={c['score']}{risk}")
    return "\n".join(lines)
