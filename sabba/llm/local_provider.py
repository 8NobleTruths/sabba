"""Local model provider: run the reasoning model on your own machine.

Any OpenAI-compatible local server works, because it speaks the same wire shape as the
OpenRouter provider we already have. Point Sabba at it and the agent loop does not change:

  Ollama        SABBA_LOCAL_BASE_URL=http://localhost:11434/v1   (the default)
  llama.cpp     SABBA_LOCAL_BASE_URL=http://localhost:8080/v1
  vLLM / LM Studio / any other OpenAI-compatible endpoint

Select it with SABBA_LLM_BACKEND=local. Pick the model with SABBA_LOCAL_MODEL (or --model).
No API key is required for a local server; SABBA_LOCAL_API_KEY is sent only if you set it.

This is the Resident tier of the Water Layer: a small model that runs on modest hardware and
handles the common cases, with a frontier Teacher reachable through the openrouter backend for
the hard ones. Because it reuses the OpenRouter provider's request and streaming code, only the
endpoint and credentials differ.
"""
from __future__ import annotations

import os

from .base import LLMUnavailable
from .openrouter_provider import OpenRouterProvider

DEFAULT_BASE_URL = "http://localhost:11434/v1"   # Ollama's OpenAI-compatible endpoint
DEFAULT_MODEL = "qwen2.5-coder:7b"


class LocalProvider(OpenRouterProvider):
    """OpenAI-compatible client aimed at a local endpoint. Inherits create/stream and the
    message helpers from OpenRouterProvider; only the endpoint and credentials change."""

    name = "local"

    def __init__(self, model: str | None = None):
        try:
            from openai import OpenAI
        except ImportError as e:  # pragma: no cover
            raise LLMUnavailable("local backend needs: pip install openai") from e
        self.model = model or os.environ.get("SABBA_LOCAL_MODEL") \
            or os.environ.get("SABBA_MODEL", DEFAULT_MODEL)
        base_url = os.environ.get("SABBA_LOCAL_BASE_URL", DEFAULT_BASE_URL)
        # A local server usually needs no key; send a placeholder so the OpenAI client is happy,
        # and the real one only if the user set it (some gateways check it).
        api_key = os.environ.get("SABBA_LOCAL_API_KEY", "local")
        self.client = OpenAI(base_url=base_url, api_key=api_key, max_retries=2, timeout=180.0)
