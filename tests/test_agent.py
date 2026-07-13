"""Agent-side tests: config, history, memory, the synthesizer, and the tools.

Each test isolates its own storage by patching the module path, so a run never touches the
user's real ~/.sabba. No network: memory uses a stubbed embedder.
"""
import pathlib

from sabba import chat, config, history, memory
from sabba.harness.symbolic import synth


def test_cint_parses_c_literals():
    assert synth._cint("1000000LL") == 1000000
    assert synth._cint("0x1F") == 31
    assert synth._cint("42u") == 42
    assert synth._cint("1'000") == 1000
    assert synth._cint("not-a-number") is None


def test_find_overflow_sinks_on_demo():
    src = pathlib.Path("targets/cwe121_stack_overflow/vuln.c").read_bytes()
    specs = synth.find_overflow_sinks(src)
    assert any(s.sink == "strcpy" and s.buffer == "buf" for s in specs)


def test_config_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "PATH", tmp_path / "config.json")
    config.save({"model": "m", "api_key": "k"})
    assert config.load()["model"] == "m"
    assert config.masked("sk-1234567890abcd").startswith("sk-1234")


def test_history_save_load_list(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "DIR", tmp_path / "hist")
    sid = history.new_id()
    history.save(sid, "cjson hunt", "m", [{"role": "user", "content": "hi"}])
    assert any(s["id"] == sid for s in history.sessions())
    assert history.load(sid)["messages"][0]["content"] == "hi"


def test_memory_off_without_key(monkeypatch):
    monkeypatch.delenv("VOYAGE_API_KEY", raising=False)
    assert memory.enabled() is False
    assert memory.search("anything") == []


def test_memory_store_and_recall(tmp_path, monkeypatch):
    monkeypatch.setattr(memory, "STORE", tmp_path / "store.jsonl")
    monkeypatch.setenv("VOYAGE_API_KEY", "dummy")

    def fake_embed(texts, input_type):
        out = []
        for t in texts:
            v = [0.0] * memory.DIM
            for ch in t.lower():
                v[ord(ch) % memory.DIM] += 1.0
            out.append(v)
        return out

    monkeypatch.setattr(memory, "_embed", fake_embed)
    memory.add("s1", "user", "heap buffer overflow in the cjson parser")
    memory.add("s2", "user", "how to bake sourdough bread")
    hits = memory.search("cjson heap memory bug", exclude_session="other")
    assert hits and "cjson" in hits[0]


def test_tool_bash():
    assert "hi" in chat.run_tool("bash", {"command": "echo hi"}, chat.Ctl())


def test_tool_list_and_read(tmp_path):
    (tmp_path / "a.txt").write_text("hello world")
    assert "a.txt" in chat.run_tool("list_dir", {"path": str(tmp_path)}, chat.Ctl())
    assert "hello world" in chat.run_tool("read_file", {"path": str(tmp_path / "a.txt")}, chat.Ctl())


def test_tool_unknown():
    assert "unknown tool" in chat.run_tool("nope", {}, chat.Ctl())


def test_direct_argv_sink():
    src = b'#include <string.h>\nint main(int c, char **argv){ char b[16]; strcpy(b, argv[1]); return 0; }\n'
    specs = synth.find_overflow_sinks(src)
    assert any(s.sink == "strcpy" and s.argv_index == 1 and s.source_kind == "argv" for s in specs)


def test_local_var_sink():
    src = (b'#include <string.h>\nint main(int c, char **argv){ char b[16]; char *s = argv[1];'
           b' strcpy(b, s); return 0; }\n')
    specs = synth.find_overflow_sinks(src)
    assert any(s.sink == "strcpy" and s.argv_index == 1 for s in specs)


def test_stdin_scanf_sink():
    src = b'#include <stdio.h>\nint main(void){ char n[16]; scanf("%s", n); return 0; }\n'
    specs = synth.find_overflow_sinks(src)
    assert any(s.source_kind == "stdin" and s.sink == "scanf" for s in specs)
