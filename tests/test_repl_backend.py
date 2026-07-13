"""Switching to a cloud model must actually switch the backend.

The bug: after /select-local-model set backend=local, /add-model-key and /model used
setdefault, which does not override, so the cloud model was chosen but the local endpoint kept
being used (and produced the weak local model's output). These check the backend really flips.
"""
from sabba import config, repl


def _stub(monkeypatch):
    monkeypatch.setattr(config, "save", lambda cfg: None)
    monkeypatch.setattr(config, "apply_env", lambda cfg: None)

    class S:
        pass
    s = S()
    s._reset_provider = lambda: None
    s.sys = lambda m: None
    return s


def test_choosing_a_cloud_model_switches_backend_from_local(monkeypatch):
    s = _stub(monkeypatch)
    s.cfg = {"backend": "local", "local_model": "qwen2.5-coder:1.5b"}
    repl.Repl.apply_model(s, "deepseek/deepseek-chat")
    assert s.cfg["backend"] == "openrouter"
    assert s.cfg["model"] == "deepseek/deepseek-chat"


def test_adding_a_model_key_switches_backend_from_local(monkeypatch):
    s = _stub(monkeypatch)
    s.cfg = {"backend": "local", "local_model": "qwen2.5-coder:1.5b"}
    repl.Repl.set_key(s, "model", "sk-or-test-key")
    assert s.cfg["backend"] == "openrouter"
    assert s.cfg["api_key"] == "sk-or-test-key"


def test_a_memory_key_does_not_change_the_backend(monkeypatch):
    s = _stub(monkeypatch)
    s.cfg = {"backend": "local", "local_model": "qwen2.5-coder:1.5b"}
    repl.Repl.set_key(s, "memory", "voyage-test-key")
    assert s.cfg["backend"] == "local"          # memory key must not steal the backend
    assert s.cfg["voyage_key"] == "voyage-test-key"
