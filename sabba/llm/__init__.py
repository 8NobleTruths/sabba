"""LLM provider selection.

`get_provider()` returns a provider-agnostic LLM (base.LLMProvider) chosen by the
SABBA_LLM_BACKEND environment variable:

  "glm" (default)     GLM-5.2 via BigModel/Zhipu, OpenAI-compatible
  "openrouter"        any model on OpenRouter, picked with --model or OPENROUTER_MODEL
  "local"             a local OpenAI-compatible endpoint (Ollama, llama.cpp, vLLM)
  "api" / "anthropic" Claude first-party API
  "vertex"            Claude via Vertex AI

The agent depends only on the interface, so the reasoning model can move to a self-hosted
endpoint later without touching agent code.
"""
from __future__ import annotations

import os

from .base import LLMProvider, LLMUnavailable, Resp, ToolCall

__all__ = ["get_provider", "judge", "LLMProvider", "LLMUnavailable", "Resp", "ToolCall"]


def judge(system: str, user: str, model: str | None = None) -> str:
    """Single-turn chat with no tools. Returns the assistant text."""
    p = get_provider(model)
    msgs = p.init_messages(system, user)
    return p.create(msgs, []).text


_PROVIDER_CACHE: dict = {}


def get_provider(model: str | None = None) -> LLMProvider:
    backend = os.environ.get("SABBA_LLM_BACKEND", "glm").lower()
    key = (backend, model)
    if key in _PROVIDER_CACHE:               # reuse one client across threads (bounded FDs)
        return _PROVIDER_CACHE[key]
    if backend == "glm":
        from .glm_provider import GLMProvider
        p = GLMProvider(model=model)
    elif backend == "openrouter":
        from .openrouter_provider import OpenRouterProvider
        p = OpenRouterProvider(model=model)
    elif backend == "local":
        from .local_provider import LocalProvider
        p = LocalProvider(model=model)
    elif backend in ("api", "anthropic"):
        from .anthropic_provider import AnthropicProvider
        p = AnthropicProvider(model=model)
    elif backend == "vertex":
        from .anthropic_provider import AnthropicProvider
        p = AnthropicProvider(model=model, vertex=True)
    else:
        raise LLMUnavailable(
            f"unknown SABBA_LLM_BACKEND={backend!r} (use glm|openrouter|local|api|vertex)")
    _PROVIDER_CACHE[key] = p
    return p
