"""Provider-agnostic LLM interface for the agent loop.

The agent (`harness/agent.py`) drives the find->verify->report loop through these
primitives; each provider hides its own wire shape (OpenAI chat messages vs
Anthropic content-blocks). Our tool definitions are written once in Anthropic style
({name, description, input_schema}); each provider converts as needed.

Swap the reasoning model by setting SABBA_LLM_BACKEND (glm-5.2 now via BigModel,
Sabba-R1 later via a self-hosted OpenAI-compatible endpoint), agent.py never changes.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


class LLMUnavailable(RuntimeError):
    """Raised when no usable LLM endpoint/credentials are configured."""


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict


@dataclass
class Resp:
    text: str                 # assistant visible text
    tool_calls: list[ToolCall]
    stop: str                 # "tool_use" | "end"
    native_assistant: Any     # provider-native assistant message, appended verbatim


class LLMProvider(Protocol):
    name: str
    model: str

    def init_messages(self, system: str, user: str) -> list: ...
    def create(self, messages: list, tools: list[dict]) -> Resp: ...
    def add_assistant(self, messages: list, resp: Resp) -> None: ...
    # results: list of {"id": str, "content": str, "is_error": bool}
    def add_tool_results(self, messages: list, results: list[dict]) -> None: ...
