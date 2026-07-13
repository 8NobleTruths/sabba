"""Train the risk ranker from a labeled corpus and report held-out AUC.

Input is JSONL, one {"code": ..., "label": 0 or 1} per line. The same trainer serves the
bootstrap corpus (for bring-up and tests) and the real labeled corpus (for production); only
the data changes.
"""
from __future__ import annotations

import json
from pathlib import Path

from .ranker import DEFAULT_PATH, RiskRanker, build_pipeline


def _load_jsonl(path: str | Path) -> tuple[list[str], list[int]]:
    codes, labels = [], []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        codes.append(r["code"])
        labels.append(int(r["label"]))
    return codes, labels


def train(codes: list[str], labels: list[int], out: str | Path | None = None,
          test_size: float = 0.2, seed: int = 0) -> dict:
    """Fit the pipeline, measure AUC on a held-out split, save the model. Returns a report."""
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import train_test_split

    x_tr, x_te, y_tr, y_te = train_test_split(
        codes, labels, test_size=test_size, random_state=seed, stratify=labels)
    pipe = build_pipeline()
    pipe.fit(x_tr, y_tr)
    proba = [p[1] for p in pipe.predict_proba(x_te)]
    auc = float(roc_auc_score(y_te, proba))
    path = RiskRanker(pipe).save(out)
    return {"auc": round(auc, 4), "n_train": len(x_tr), "n_test": len(x_te),
            "positives": int(sum(labels)), "model": str(path)}


def train_from_jsonl(jsonl: str | Path, out: str | Path | None = None,
                     test_size: float = 0.2, seed: int = 0) -> dict:
    codes, labels = _load_jsonl(jsonl)
    return train(codes, labels, out=out, test_size=test_size, seed=seed)


def train_bootstrap(out: str | Path | None = None, n_per_class: int = 300, seed: int = 0) -> dict:
    """Train on the built-in bootstrap corpus (no external data). Good for a first model and
    for tests; retrain on the real corpus for production."""
    from .bootstrap import make_corpus
    rows = make_corpus(n_per_class=n_per_class, seed=seed)
    codes = [r["code"] for r in rows]
    labels = [r["label"] for r in rows]
    report = train(codes, labels, out=out or DEFAULT_PATH, test_size=test_size_for(len(rows)), seed=seed)
    report["corpus"] = "bootstrap"
    return report


def test_size_for(n: int) -> float:
    return 0.2 if n >= 50 else 0.4


def train_from_traces(store: str | None = None, out: str | Path | None = None,
                      seed: int = 0, min_per_class: int = 20) -> dict:
    """Train on execution-grounded traces collected from real hunts (oracle verdicts as labels).

    Positives are oracle-proven; negatives are weak (a function with no proven finding this run).
    When a class is thin or missing, top up with the bootstrap corpus so training still works,
    and report how much real data went in.
    """
    from ..water.traces import TraceStore
    rows = TraceStore(store).load_labeled()
    pos = [r for r in rows if r["label"] == 1]
    neg = [r for r in rows if r["label"] == 0]
    topped_up = False
    if len(pos) < min_per_class or len(neg) < min_per_class:
        from .bootstrap import make_corpus
        need = max(min_per_class, len(pos), len(neg))
        boot = make_corpus(n_per_class=need, seed=seed)
        pos += [r for r in boot if r["label"] == 1][:max(0, need - len(pos))]
        neg += [r for r in boot if r["label"] == 0][:max(0, need - len(neg))]
        topped_up = True
    data = pos + neg
    codes = [r["code"] for r in data]
    labels = [r["label"] for r in data]
    report = train(codes, labels, out=out or DEFAULT_PATH,
                   test_size=test_size_for(len(data)), seed=seed)
    report.update({"corpus": "traces", "real_traces": len(rows),
                   "real_positives": len([r for r in rows if r["label"] == 1]),
                   "bootstrap_topup": topped_up})
    return report
