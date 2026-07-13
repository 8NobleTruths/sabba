"""GLM-5.2 provider via BigModel/Zhipu (OpenAI-compatible).

base: https://open.bigmodel.cn/api/paas/v4 · model: glm-5.2 · auth: Bearer key.
Credentials come from the environment (SABBA_LLM_API_KEY), never hardcode/commit.
The same OpenAI-compatible path serves a self-hosted Sabba-R1 endpoint later.
"""
from __future__ import annotations

import json
import os

from .base import LLMUnavailable, Resp, ToolCall


def _openai_tools(tools: list[dict]) -> list[dict]:
    """Convert our Anthropic-style tools to OpenAI function-tool format."""
    return [
        {"type": "function",
         "function": {"name": t["name"], "description": t.get("description", ""),
                      "parameters": t["input_schema"]}}
        for t in tools
    ]


class GLMProvider:
    name = "glm"

    def __init__(self, model: str | None = None):
        try:
            from openai import OpenAI
        except ImportError as e:  # pragma: no cover
            raise LLMUnavailable("GLM backend needs: pip install openai") from e
        self.model = model or os.environ.get("SABBA_MODEL", "glm-5.2")
        base_url = os.environ.get("SABBA_LLM_BASE_URL", "https://open.bigmodel.cn/api/paas/v4")
        api_key = os.environ.get("SABBA_LLM_API_KEY")
        if not api_key:
            raise LLMUnavailable(
                "No GLM key. Set SABBA_LLM_API_KEY (BigModel/Zhipu key). On sabba-dev: "
                "`source ~/.config/sabba/env`. The oracle (`sabba verify`) needs no model."
            )
        self.client = OpenAI(base_url=base_url, api_key=api_key)

    def init_messages(self, system: str, user: str) -> list:
        return [{"role": "system", "content": system}, {"role": "user", "content": user}]

    def create(self, messages: list, tools: list[dict]) -> Resp:
        kwargs = dict(model=self.model, messages=messages, temperature=0.2, max_tokens=4096)
        if tools:
            kwargs["tools"] = _openai_tools(tools)
        if os.environ.get("SABBA_DISABLE_THINKING"):
            kwargs["extra_body"] = {"enable_thinking": False}
        r = self.client.chat.completions.create(**kwargs)
        msg = r.choices[0].message
        tool_calls = []
        for tc in (msg.tool_calls or []):
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            tool_calls.append(ToolCall(id=tc.id, name=tc.function.name, input=args))
        native = {"role": "assistant", "content": msg.content or ""}
        if msg.tool_calls:
            native["tool_calls"] = [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in msg.tool_calls
            ]
        return Resp(text=msg.content or "", tool_calls=tool_calls,
                    stop="tool_use" if tool_calls else "end", native_assistant=native)

    def add_assistant(self, messages: list, resp: Resp) -> None:
        messages.append(resp.native_assistant)

    def add_tool_results(self, messages: list, results: list[dict]) -> None:
        for r in results:
            messages.append({"role": "tool", "tool_call_id": r["id"], "content": r["content"]})
