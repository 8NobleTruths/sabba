"""The local ML risk ranker: it learns to score risky functions above safe ones, and it
degrades to a heuristic when no model was trained so retrieval never depends on it."""
from sabba.ml import train as T
from sabba.ml.bootstrap import make_corpus
from sabba.ml.ranker import RiskRanker, heuristic_score

RISKY = "void f(const char *s) {\n    char b[16];\n    strcpy(b, s);\n}"
SAFE = "void f(const char *s) {\n    char b[16];\n    strncpy(b, s, 15);\n    b[15] = 0;\n}"


def test_heuristic_scores_risky_above_safe():
    assert heuristic_score(RISKY) > heuristic_score(SAFE)
    assert heuristic_score("") == 0.0


def test_untrained_ranker_falls_back_and_still_ranks():
    r = RiskRanker(None)
    assert not r.trained
    ranked = r.rank([{"code": SAFE}, {"code": RISKY}])
    assert ranked[0]["code"] == RISKY          # the risky one is first
    assert "risk" in ranked[0]


def test_bootstrap_corpus_is_balanced_and_deterministic():
    a = make_corpus(n_per_class=50, seed=1)
    b = make_corpus(n_per_class=50, seed=1)
    assert len(a) == 100 and sum(r["label"] for r in a) == 50
    assert [r["code"] for r in a] == [r["code"] for r in b]   # deterministic for a seed


def test_train_bootstrap_learns_then_ranks(tmp_path):
    out = tmp_path / "ranker.joblib"
    report = T.train_bootstrap(out=out, n_per_class=300, seed=0)
    assert report["auc"] >= 0.85            # the risky/safe shapes are clearly separable
    assert out.exists()
    r = RiskRanker.load(out)
    assert r.trained
    assert r.score(RISKY) > r.score(SAFE)


def test_load_missing_model_is_heuristic_only(tmp_path):
    r = RiskRanker.load(tmp_path / "nope.joblib")
    assert not r.trained
    assert r.score(RISKY) > r.score(SAFE)
