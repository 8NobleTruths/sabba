"""The risk ranker: score a function for memory-safety-bug likelihood, on CPU.

The shipped model is a TF-IDF over the function source (word tokens catch dangerous identifiers
like strcpy and memcpy, character n-grams catch patterns and survive unseen tokens) into a
logistic classifier. It trains in seconds and the artifact is a few megabytes, so it runs
anywhere. Train it with `sabba mltrain` (see train.py); point production training at the real
labeled corpus, the format is one JSON object per line, {"code": ..., "label": 0 or 1}.

When no model is loaded, score() falls back to a transparent heuristic (a weighted count of
dangerous calls), so retrieval keeps working and never depends on the ranker being trained.

An embedding backend is a drop-in upgrade: freeze a code embedder (for example
jinaai/jina-embeddings-v2-base-code) and train a small head on the same corpus. The interface
here (fit on code strings, score to a probability) does not change; only build_pipeline does.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

# a dangerous call -> its weight, for the no-model heuristic fallback
_DANGER = {
    "gets": 4, "strcpy": 3, "strcat": 3, "sprintf": 3, "vsprintf": 3, "scanf": 2,
    "sscanf": 2, "memcpy": 2, "memmove": 2, "alloca": 2, "system": 2, "realloc": 1,
    "malloc": 1, "strncpy": 1, "snprintf": 0,
}
_CALL_RE = {name: re.compile(r"\b" + re.escape(name) + r"\s*\(") for name in _DANGER}

DEFAULT_PATH = Path(os.environ.get(
    "SABBA_RANKER_PATH", str(Path.home() / ".sabba" / "ranker.joblib")))


def heuristic_score(code: str) -> float:
    """A transparent risk score in [0, 1] from a weighted count of dangerous calls. Used when
    no trained model is available, so the ranker always returns something sensible."""
    if not code:
        return 0.0
    s = sum(w for name, w in _DANGER.items() if _CALL_RE[name].search(code))
    return min(1.0, s / 8.0)


def build_pipeline():
    """A TF-IDF (word + character n-gram) to logistic-regression pipeline. Kept small on
    purpose: fast to train, tiny to ship, runs on CPU."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import FeatureUnion, Pipeline

    word = TfidfVectorizer(analyzer="word", token_pattern=r"[A-Za-z_][A-Za-z0-9_]*",
                           ngram_range=(1, 2), min_df=1, max_features=8000, sublinear_tf=True)
    char = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1, max_features=8000)
    feats = FeatureUnion([("word", word), ("char", char)])
    clf = LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced")
    return Pipeline([("feats", feats), ("clf", clf)])


class RiskRanker:
    """Score and rank functions by bug likelihood. A trained model gives calibrated
    probabilities; with no model, a heuristic keeps the ranker usable."""

    def __init__(self, model=None):
        self.model = model

    @property
    def trained(self) -> bool:
        return self.model is not None

    @classmethod
    def load(cls, path: str | Path | None = None) -> "RiskRanker":
        """Load a trained model if one exists, else return a heuristic-only ranker. Never
        raises for a missing model or a missing joblib, so callers can use it unconditionally."""
        p = Path(path) if path else DEFAULT_PATH
        if not p.exists():
            return cls(None)
        try:
            import joblib
            return cls(joblib.load(p))
        except Exception:  # noqa: BLE001 - a broken/absent artifact must not break retrieval
            return cls(None)

    def save(self, path: str | Path | None = None) -> Path:
        import joblib
        p = Path(path) if path else DEFAULT_PATH
        p.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, p)
        return p

    def score(self, code: str) -> float:
        """Probability in [0, 1] that this function holds a memory-safety bug."""
        if not code:
            return 0.0
        if self.model is None:
            return heuristic_score(code)
        try:
            return float(self.model.predict_proba([code])[0][1])
        except Exception:  # noqa: BLE001
            return heuristic_score(code)

    def score_many(self, codes: list[str]) -> list[float]:
        if self.model is None:
            return [heuristic_score(c) for c in codes]
        try:
            return [float(p[1]) for p in self.model.predict_proba(codes)]
        except Exception:  # noqa: BLE001
            return [heuristic_score(c) for c in codes]

    def rank(self, items: list[dict], code_key: str = "code") -> list[dict]:
        """Return items sorted by risk (highest first), each annotated with 'risk'."""
        scores = self.score_many([it.get(code_key, "") or "" for it in items])
        out = [{**it, "risk": round(s, 4)} for it, s in zip(items, scores)]
        out.sort(key=lambda x: x["risk"], reverse=True)
        return out
