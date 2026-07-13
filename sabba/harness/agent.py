"""The Phase-0 agent: a Naptime-style find -> verify -> report loop.

The model reads the target, hypothesizes a vulnerability + a concrete PoC, tests it
with `compile_and_run`, and reports only what the oracle confirms. We run the manual
tool loop (not the SDK tool-runner) so the verification gate and logging are explicit.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from ..llm import get_provider
from ..types import Finding
from .tools import TOOLS, Toolbox

SYSTEM = """You are Sabba's memory-safety hunter. You find memory-safety vulnerabilities \
in C and C++ and PROVE each one with a reproducing proof-of-concept. This loop is native \
only; other languages and Solidity are handled by their own provers, not here.

Method (Naptime-style): read the code, hypothesize one concrete vulnerability and a \
specific input that would trigger it, then TEST that input with `compile_and_run`. The \
target is compiled with AddressSanitizer + UBSan, so a real memory-safety bug shows up as \
a sanitizer report. Iterate on near-misses (e.g. make the overflowing input longer).

Rules:
- Only `report_finding` for a vulnerability you have CONFIRMED with `compile_and_run` on \
the exact same argv/stdin. The harness re-verifies and rejects non-reproducing reports.
- Never report a bug you have not triggered. No hallucinated findings.
- A benign run (no sanitizer) is not a finding, keep searching or stop.
- When you have reported every vulnerability you can confirm (or found none), say so and stop.

Be concise. Act rather than narrate."""


def run_scan(
    target_dir: str | Path,
    *,
    model: str | None = None,
    max_steps: int = 24,
    hints: str = "",
    on_event: Callable[[str], None] | None = None,
    oracle=None,
) -> list[Finding]:
    """Drive the agent over one target directory. Returns confirmed findings."""
    target_dir = Path(target_dir).resolve()
    spec = json.loads((target_dir / "target.json").read_text())
    sources = [target_dir / s for s in spec["sources"]]
    box = Toolbox(target_dir, sources, oracle=oracle)
    log = on_event or (lambda _m: None)

    provider = get_provider(model)
    files = ", ".join(spec["sources"])
    user = (f"Target `{spec['name']}` ({spec.get('language','c')}). Source files: {files}. "
            f"Find and prove any memory-safety vulnerabilities.")
    if hints:
        user += "\n\n" + hints
    messages = provider.init_messages(SYSTEM, user)

    for _step in range(max_steps):
        resp = provider.create(messages, TOOLS)

        if resp.text.strip():
            log(f"[think] {resp.text.strip()}")
        if resp.stop != "tool_use" or not resp.tool_calls:
            break

        provider.add_assistant(messages, resp)
        results = []
        for tc in resp.tool_calls:
            log(f"[tool] {tc.name}({_short(tc.input)})")
            out, is_err = box.dispatch(tc.name, dict(tc.input))
            if tc.name in ("compile_and_run", "report_finding"):
                log(f"   -> {out.splitlines()[0] if out else ''}")
            results.append({"id": tc.id, "content": out, "is_error": is_err})
        provider.add_tool_results(messages, results)
    else:
        log("[warn] hit max_steps")

    return box.findings


def _short(d: dict) -> str:
    parts = []
    for k, v in d.items():
        s = str(v)
        parts.append(f"{k}={s if len(s) <= 28 else s[:25] + '...'}")
    return ", ".join(parts)
