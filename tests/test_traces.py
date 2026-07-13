"""The execution-grounded flywheel: hunts leave labeled traces, the ranker retrains on them."""
import types

from sabba.water.traces import TraceStore, enabled


def test_record_and_load_roundtrip(tmp_path):
    ts = TraceStore(tmp_path)
    n = ts.record([{"code": "void a(){}", "label": 1}, {"code": "int b(){}", "label": 0}])
    assert n == 2
    codes = {r["code"] for r in ts.load_labeled()}
    assert codes == {"void a(){}", "int b(){}"}


def test_record_hunt_labels_by_proven_finding(tmp_path):
    ts = TraceStore(tmp_path)
    cands = [
        {"function": "greet", "code": "void greet(char*s){char b[8];strcpy(b,s);}", "file": "v.c", "line": 1},
        {"function": "main", "code": "int main(){return 0;}", "file": "v.c", "line": 9},
        {"function": "nocode", "code": ""},                       # no source -> skipped
    ]
    findings = [types.SimpleNamespace(function="greet")]           # the oracle proved greet
    n = ts.record_hunt("target", cands, findings)
    assert n == 2
    labels = {r["code"]: r["label"] for r in ts.load_labeled()}
    assert labels["void greet(char*s){char b[8];strcpy(b,s);}"] == 1
    assert labels["int main(){return 0;}"] == 0


def test_load_keeps_the_strongest_label(tmp_path):
    ts = TraceStore(tmp_path)
    ts.record([{"code": "X", "label": 0}])
    ts.record([{"code": "X", "label": 1}])                        # later proven a bug
    labels = {r["code"]: r["label"] for r in ts.load_labeled()}
    assert labels["X"] == 1


def test_record_skips_empty_code(tmp_path):
    assert TraceStore(tmp_path).record([{"code": "", "label": 1}]) == 0


def test_enabled_honours_the_env(monkeypatch):
    monkeypatch.setenv("SABBA_TRACES", "0")
    assert not enabled()
    monkeypatch.setenv("SABBA_TRACES", "1")
    assert enabled()
    monkeypatch.delenv("SABBA_TRACES", raising=False)
    assert enabled()                                              # on by default


def test_train_from_traces_tops_up_and_learns(tmp_path):
    from sabba.ml.ranker import RiskRanker
    from sabba.ml.train import train_from_traces
    store = tmp_path / "traces"
    TraceStore(store).record([
        {"code": "void f(char *s){ char b[8]; strcpy(b, s); }", "label": 1},
    ])
    out = tmp_path / "r.joblib"
    rep = train_from_traces(store=str(store), out=str(out))
    assert rep["corpus"] == "traces"
    assert rep["real_positives"] >= 1
    assert rep["bootstrap_topup"] is True                         # only one class of real data
    assert out.exists() and RiskRanker.load(out).trained
