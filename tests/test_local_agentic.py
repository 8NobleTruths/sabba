"""The local backend drives the agentic loop.

Against an OpenAI-compatible endpoint that emits a tool call, the local provider must parse it
and the turn loop must run the tool. This isolates Sabba's code from model quality: a small
local model that will not emit tool calls is a model limit, not a bug here.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from sabba import chat, llm
from sabba.llm.openrouter_provider import extract_text_tool_calls


def test_norm_args_unwraps_schema_wrapped_values():
    from sabba.chat import _norm_args
    # a weak model wraps the value as {"type": "string", "value": X}; undo it
    assert _norm_args({"path": {"type": "string", "value": "/x"}}) == {"path": "/x"}
    assert _norm_args({"command": {"type": "string", "value": "ls"}}) == {"command": "ls"}
    # a real dict argument (not a schema wrapper) is left alone
    assert _norm_args({"opts": {"a": 1, "b": 2}}) == {"opts": {"a": 1, "b": 2}}
    assert _norm_args({"path": "/plain"}) == {"path": "/plain"}


def test_recovers_tool_calls_written_as_json_text():
    """Small and Ollama-served models write the call as ```json text instead of the native
    field; Sabba must recover it. A non-tool JSON object must be ignored."""
    names = {"solve", "verify", "read_file", "clone_repo"}
    fenced = 'Sure, let me run it.\n```json\n{"name": "solve", "arguments": {"path": "t/x"}}\n```'
    assert extract_text_tool_calls(fenced, names) == [("solve", {"path": "t/x"})]
    assert extract_text_tool_calls('{"name":"verify","arguments":{"target":"t"}}', names) == \
        [("verify", {"target": "t"})]
    # "parameters" is accepted as an alias for "arguments"
    assert extract_text_tool_calls('{"name":"read_file","parameters":{"path":"a"}}', names) == \
        [("read_file", {"path": "a"})]
    # a JSON object that is not a known tool call is left alone
    assert extract_text_tool_calls('the config is {"foo": 1, "bar": 2}', names) == []
    assert extract_text_tool_calls("just chatting, no tools here", names) == []


def _make_server():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            # stateless: emit a tool call until a tool result comes back, then a final answer
            has_result = any(m.get("role") == "tool" for m in body.get("messages", []))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            if not has_result:
                delta = {"tool_calls": [{"index": 0, "id": "call_1", "type": "function",
                         "function": {"name": "web_fetch",
                                      "arguments": json.dumps({"url": "https://example.com"})}}]}
            else:
                delta = {"content": "Done, I fetched it and found nothing."}
            for chunk in [{"choices": [{"delta": delta}]},
                          {"choices": [{"delta": {}}],
                           "usage": {"prompt_tokens": 10, "completion_tokens": 5}}]:
                self.wfile.write(("data: " + json.dumps(chunk) + "\n\n").encode())
            self.wfile.write(b"data: [DONE]\n\n")

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _make_looping_server():
    """Always returns the same tool call, never a final answer, to exercise the loop guard."""
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            delta = {"tool_calls": [{"index": 0, "id": "c", "type": "function",
                     "function": {"name": "web_fetch",
                                  "arguments": json.dumps({"url": "https://example.com"})}}]}
            for chunk in [{"choices": [{"delta": delta}]}, {"choices": [{"delta": {}}]}]:
                self.wfile.write(("data: " + json.dumps(chunk) + "\n\n").encode())
            self.wfile.write(b"data: [DONE]\n\n")

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_loop_guard_stops_a_repeated_tool_call(monkeypatch):
    srv = _make_looping_server()
    monkeypatch.setenv("SABBA_LLM_BACKEND", "local")
    monkeypatch.setenv("SABBA_LOCAL_BASE_URL", f"http://127.0.0.1:{srv.server_address[1]}/v1")
    monkeypatch.setenv("SABBA_LOCAL_MODEL", "mock")
    llm._PROVIDER_CACHE.clear()
    provider = llm.get_provider()
    ran = []
    monkeypatch.setattr(chat, "_web_fetch", lambda url: ran.append(url) or "TEXT")
    noop = lambda *a, **k: None
    try:
        chat.turn_stream(provider, [], "fetch it", chat.Ctl(),
                         on_start=noop, on_text=noop, on_done=noop, on_tool=noop, on_result=noop)
        # the model repeats the same call forever; the guard runs the tool once, then stops
        assert len(ran) == 1
    finally:
        srv.shutdown()
        llm._PROVIDER_CACHE.clear()


def test_local_backend_parses_and_runs_a_tool_call(monkeypatch):
    srv = _make_server()
    port = srv.server_address[1]
    monkeypatch.setenv("SABBA_LLM_BACKEND", "local")
    monkeypatch.setenv("SABBA_LOCAL_BASE_URL", f"http://127.0.0.1:{port}/v1")
    monkeypatch.setenv("SABBA_LOCAL_MODEL", "mock")
    llm._PROVIDER_CACHE.clear()
    provider = llm.get_provider()
    try:
        # the provider parses a streamed tool call
        done = None
        for ev in provider.stream(provider.init_messages("s", "find bugs in https://example.com"),
                                  chat.TOOLS):
            if ev["type"] == "done":
                done = ev
        assert done and [tc.name for tc in done["tool_calls"]] == ["web_fetch"]

        # the turn loop actually runs the tool
        ran = {}
        monkeypatch.setattr(chat, "_web_fetch", lambda url: ran.setdefault("hit", True) or "TEXT")
        noop = lambda *a, **k: None
        chat.turn_stream(provider, [], "find bugs in https://example.com", chat.Ctl(),
                         on_start=noop, on_text=noop, on_done=noop, on_tool=noop, on_result=noop)
        assert ran.get("hit") is True
    finally:
        srv.shutdown()
        llm._PROVIDER_CACHE.clear()
