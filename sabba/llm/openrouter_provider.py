"""OpenRouter provider (OpenAI-compatible), with streaming.

OpenRouter proxies many models behind one OpenAI-style endpoint, so you can pick the
reasoning model by id (for example "z-ai/glm-5.2", "deepseek/deepseek-v4-flash",
"anthropic/claude-3.5-sonnet"). See https://openrouter.ai/docs.

The API key is read from the environment (OPENROUTER_API_KEY, or SABBA_LLM_API_KEY as a
fallback). Nothing is ever hardcoded here.
"""
from __future__ import annotations

import json
import os

from .base import LLMUnavailable, Resp, ToolCall

DEFAULT_MODEL = "deepseek/deepseek-chat-v3-0324"
BASE_URL = "https://openrouter.ai/api/v1"


def _openai_tools(tools: list[dict]) -> list[dict]:
    return [
        {"type": "function",
         "function": {"name": t["name"], "description": t.get("description", ""),
                      "parameters": t["input_schema"]}}
        for t in tools
    ]


def _json_objects(text: str) -> list[str]:
    """Every top-level {...} block in the text, by brace matching (handles nested braces)."""
    out, depth, start = [], 0, None
    for i, ch in enumerate(text or ""):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth > 0:
            depth -= 1
            if depth == 0 and start is not None:
                out.append(text[start:i + 1])
                start = None
    return out


def extract_text_tool_calls(text: str, tool_names: set) -> list[tuple[str, dict]]:
    """Recover tool calls a model wrote as JSON text instead of the native tool_calls field.

    Smaller and Ollama-served models often answer with a ```json {"name": ..., "arguments":
    {...}}``` block rather than a structured tool call. We only accept a JSON object whose name
    is a real tool, so a model showing example JSON in prose is not mistaken for a call.
    """
    calls: list[tuple[str, dict]] = []
    for blob in _json_objects(text):
        try:
            obj = json.loads(blob)
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(obj, dict):
            continue
        fn = obj.get("function") if isinstance(obj.get("function"), dict) else {}
        name = obj.get("name") or obj.get("tool") or fn.get("name")
        if name not in tool_names:
            continue
        args = obj.get("arguments")
        if args is None:
            args = obj.get("parameters")
        if args is None:
            args = fn.get("arguments")
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except Exception:  # noqa: BLE001
                args = {}
        calls.append((name, args if isinstance(args, dict) else {}))
    return calls


def _fallback_resp(text: str, tools: list[dict]):
    """Build a tool_use Resp from JSON-text tool calls, or None if the text has none."""
    extracted = extract_text_tool_calls(text, {t["name"] for t in tools})
    if not extracted:
        return None
    tool_calls = [ToolCall(id=f"call_{i}", name=n, input=a) for i, (n, a) in enumerate(extracted)]
    native = {"role": "assistant", "content": "",
              "tool_calls": [{"id": f"call_{i}", "type": "function",
                              "function": {"name": n, "arguments": json.dumps(a)}}
                             for i, (n, a) in enumerate(extracted)]}
    return Resp(text="", tool_calls=tool_calls, stop="tool_use", native_assistant=native)


class OpenRouterProvider:
    name = "openrouter"

    def __init__(self, model: str | None = None):
        try:
            from openai import OpenAI
        except ImportError as e:  # pragma: no cover
            raise LLMUnavailable("OpenRouter backend needs: pip install openai") from e
        self.model = model or os.environ.get("OPENROUTER_MODEL") \
            or os.environ.get("SABBA_MODEL", DEFAULT_MODEL)
        api_key = os.environ.get("OPENROUTER_API_KEY") or os.environ.get("SABBA_LLM_API_KEY")
        if not api_key:
            raise LLMUnavailable(
                "No OpenRouter key. Set it with /add-model-key (openrouter.ai/keys). "
                "The oracle and /solve need no model.")
        headers = {
            "HTTP-Referer": os.environ.get("OPENROUTER_REFERER", "https://github.com/8NobleTruths/sabba"),
            "X-Title": os.environ.get("OPENROUTER_TITLE", "Sabba Agent"),
        }
        self.client = OpenAI(base_url=BASE_URL, api_key=api_key, default_headers=headers,
                             max_retries=3, timeout=90.0)

    def init_messages(self, system: str, user: str) -> list:
        return [{"role": "system", "content": system}, {"role": "user", "content": user}]

    def create(self, messages: list, tools: list[dict]) -> Resp:
        kwargs = dict(model=self.model, messages=messages, temperature=0.2, max_tokens=4096)
        if tools:
            kwargs["tools"] = _openai_tools(tools)
        r = self.client.chat.completions.create(**kwargs)
        msg = r.choices[0].message
        tool_calls = []
        for tc in (msg.tool_calls or []):
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            tool_calls.append(ToolCall(id=tc.id, name=tc.function.name, input=args))
        text = msg.content or ""
        # Some models (small, or Ollama-served) write the tool call as JSON text instead of the
        # native field. Recover it so the agentic loop still runs the tool.
        if not tool_calls and tools:
            fb = _fallback_resp(text, tools)
            if fb is not None:
                return fb
        native = {"role": "assistant", "content": text}
        if msg.tool_calls:
            native["tool_calls"] = [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in msg.tool_calls]
        return Resp(text=text, tool_calls=tool_calls,
                    stop="tool_use" if tool_calls else "end", native_assistant=native)

    def stream(self, messages: list, tools: list[dict]):
        """Yield {'type':'text','text':...} deltas, then one {'type':'done',...} with the
        accumulated tool calls, the native assistant message, and token usage."""
        kwargs = dict(model=self.model, messages=messages, temperature=0.2, max_tokens=4096,
                      stream=True, stream_options={"include_usage": True})
        if tools:
            kwargs["tools"] = _openai_tools(tools)
        acc: dict = {}
        usage = None
        parts: list[str] = []
        for chunk in self.client.chat.completions.create(**kwargs):
            if getattr(chunk, "usage", None):
                usage = chunk.usage
            if not chunk.choices:
                continue
            delta = chunk.choices[0].delta
            text = getattr(delta, "content", None)
            if text:
                parts.append(text)
                yield {"type": "text", "text": text}
            for tc in (getattr(delta, "tool_calls", None) or []):
                slot = acc.setdefault(tc.index, {"id": "", "name": "", "args": ""})
                if tc.id:
                    slot["id"] = tc.id
                fn = getattr(tc, "function", None)
                if fn and fn.name:
                    slot["name"] = fn.name
                if fn and fn.arguments:
                    slot["args"] += fn.arguments
        tool_calls = []
        for i in sorted(acc):
            s = acc[i]
            try:
                args = json.loads(s["args"] or "{}")
            except json.JSONDecodeError:
                args = {}
            tool_calls.append(ToolCall(id=s["id"] or f"call_{i}", name=s["name"], input=args))
        text = "".join(parts)
        pt = getattr(usage, "prompt_tokens", None) if usage else None
        ct = getattr(usage, "completion_tokens", None) if usage else None
        # recover a tool call the model wrote as JSON text rather than the native field
        if not tool_calls and tools:
            fb = _fallback_resp(text, tools)
            if fb is not None:
                yield {"type": "done", "tool_calls": fb.tool_calls,
                       "assistant": fb.native_assistant, "prompt_tokens": pt, "completion_tokens": ct}
                return
        native = {"role": "assistant", "content": text}
        if tool_calls:
            native["tool_calls"] = [
                {"id": t.id, "type": "function",
                 "function": {"name": t.name, "arguments": json.dumps(t.input)}} for t in tool_calls]
        yield {"type": "done", "tool_calls": tool_calls, "assistant": native,
               "prompt_tokens": pt, "completion_tokens": ct}

    def add_assistant(self, messages: list, resp: Resp) -> None:
        messages.append(resp.native_assistant)

    def add_tool_results(self, messages: list, results: list[dict]) -> None:
        for r in results:
            messages.append({"role": "tool", "tool_call_id": r["id"], "content": r["content"]})
