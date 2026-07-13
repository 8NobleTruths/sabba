"""Anthropic (Claude) provider, kept for the self-as-LLM / Claude path.

Not the default endpoint (the project uses GLM-5.2 via BigModel, see glm_provider.py),
but retained so the harness can run on Claude (first-party API or Vertex on sabba-lab)
when wanted. Conforms to the same LLMProvider interface (base.py).
"""
from __future__ import annotations

import os

from .base import LLMUnavailable, Resp, ToolCall


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str | None = None, vertex: bool = False):
        try:
            import anthropic
        except ImportError as e:  # pragma: no cover
            raise LLMUnavailable("Claude backend needs: pip install anthropic") from e
        self.model = model or os.environ.get("SABBA_MODEL", "claude-opus-4-8")
        self._system = ""
        if vertex:
            try:
                from anthropic import AnthropicVertex
            except ImportError as e:  # pragma: no cover
                raise LLMUnavailable('Vertex needs: pip install "anthropic[vertex]"') from e
            self.client = AnthropicVertex(
                project_id=os.environ.get("SABBA_GCP_PROJECT", "sabba-lab"),
                region=os.environ.get("SABBA_GCP_REGION", "global"))
        else:
            if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")
                    or os.path.isdir(os.path.expanduser("~/.config/anthropic/credentials"))):
                raise LLMUnavailable("No Claude credentials (ANTHROPIC_API_KEY / ant login).")
            self.client = anthropic.Anthropic()

    def init_messages(self, system: str, user: str) -> list:
        self._system = system
        return [{"role": "user", "content": user}]

    def create(self, messages: list, tools: list[dict]) -> Resp:
        r = self.client.messages.create(
            model=self.model, max_tokens=8000, system=self._system,
            tools=tools, messages=messages, thinking={"type": "adaptive"})
        text = "".join(b.text for b in r.content if b.type == "text")
        tool_calls = [ToolCall(id=b.id, name=b.name, input=dict(b.input))
                      for b in r.content if b.type == "tool_use"]
        return Resp(text=text, tool_calls=tool_calls,
                    stop="tool_use" if r.stop_reason == "tool_use" else "end",
                    native_assistant={"role": "assistant", "content": r.content})

    def add_assistant(self, messages: list, resp: Resp) -> None:
        messages.append(resp.native_assistant)

    def add_tool_results(self, messages: list, results: list[dict]) -> None:
        messages.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": r["id"], "content": r["content"],
             "is_error": r["is_error"]} for r in results]})
