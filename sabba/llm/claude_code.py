"""Drive the whole Claude Code agent from SABBA.

This is not a chat model like the other providers. `claude -p` (headless print mode)
runs the full Claude Code agent: its own tools (read, edit, bash, MCP, subagents), its
own loop, its own permission system. SABBA hands it a task and gets back a finished
result, so SABBA never reimplements file editing or code navigation. Claude Code brings
its whole toolchain.

Use it as the cascade's Teacher tier for the rare step that needs frontier agency, or as
the fixer in a prove -> fix -> re-prove loop. It spends the caller's Claude tokens, so it
is opt-in, and read-only by default (permission_mode="plan").
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass

CLAUDE_BIN = "claude"


class ClaudeCodeUnavailable(RuntimeError):
    """Raised when the `claude` CLI is not installed or not on PATH."""


@dataclass
class ClaudeResult:
    text: str                    # the final assistant answer
    ok: bool                     # completed without an error result
    turns: int | None = None     # agent turns taken
    cost_usd: float | None = None
    duration_ms: int | None = None
    session_id: str | None = None
    raw: dict | None = None      # full parsed JSON when available
    error: str | None = None


def available() -> bool:
    """True when the Claude Code CLI is installed and on PATH."""
    return shutil.which(CLAUDE_BIN) is not None


def build_cmd(
    prompt: str,
    *,
    add_dirs: list[str] | None = None,
    permission_mode: str = "plan",
    allowed_tools: list[str] | None = None,
    model: str | None = None,
    mcp_config: str | None = None,
    system_append: str | None = None,
) -> list[str]:
    """The `claude -p` command line. Kept separate so it can be unit-tested."""
    cmd = [CLAUDE_BIN, "-p", prompt, "--output-format", "json",
           "--permission-mode", permission_mode]
    for d in add_dirs or []:
        cmd += ["--add-dir", d]
    if allowed_tools:
        cmd += ["--allowedTools", ",".join(allowed_tools)]
    if model:
        cmd += ["--model", model]
    if mcp_config:
        cmd += ["--mcp-config", mcp_config]
    if system_append:
        cmd += ["--append-system-prompt", system_append]
    return cmd


def parse(stdout: str) -> ClaudeResult:
    """Turn `claude --output-format json` stdout into a ClaudeResult.

    Falls back to treating the output as plain text when it is not the expected JSON
    (an older CLI, or a stream that was not captured whole)."""
    stdout = stdout.strip()
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return ClaudeResult(text=stdout, ok=bool(stdout))
    if not isinstance(data, dict):
        return ClaudeResult(text=stdout, ok=bool(stdout))
    text = data.get("result") or data.get("text") or ""
    is_error = bool(data.get("is_error"))
    return ClaudeResult(
        text=text,
        ok=not is_error,
        turns=data.get("num_turns"),
        cost_usd=data.get("total_cost_usd"),
        duration_ms=data.get("duration_ms"),
        session_id=data.get("session_id"),
        raw=data,
        error=(text or "claude reported an error") if is_error else None,
    )


def run(
    prompt: str,
    *,
    cwd: str | None = None,
    add_dirs: list[str] | None = None,
    permission_mode: str = "plan",
    allowed_tools: list[str] | None = None,
    model: str | None = None,
    mcp_config: str | None = None,
    system_append: str | None = None,
    timeout: float = 600.0,
) -> ClaudeResult:
    """Run the whole Claude Code agent on `prompt` and return its final result.

    Defaults to plan (read-only) permissions so a bare call cannot touch the tree; pass
    permission_mode="acceptEdits" for a fix loop inside a sandbox. Raises
    ClaudeCodeUnavailable if the `claude` CLI is not installed.
    """
    if not available():
        raise ClaudeCodeUnavailable(
            "the `claude` CLI is not on PATH; install Claude Code to use this tier")
    cmd = build_cmd(prompt, add_dirs=add_dirs, permission_mode=permission_mode,
                    allowed_tools=allowed_tools, model=model, mcp_config=mcp_config,
                    system_append=system_append)
    try:
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        return ClaudeResult(text="", ok=False,
                            error=f"claude timed out after {int(timeout)}s")
    if proc.returncode != 0:
        return ClaudeResult(
            text="", ok=False,
            error=(proc.stderr.strip() or proc.stdout.strip()
                   or f"claude exited with code {proc.returncode}"))
    return parse(proc.stdout)
