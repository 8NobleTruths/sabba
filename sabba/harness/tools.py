"""Tools the reasoning model drives, and the dispatcher that executes them.

Design follows Naptime: the LLM proposes, deterministic tools dispose, and the
verifier is the only thing that can mint a Finding. `report_finding` RE-RUNS the
oracle on the model's claimed PoC (XBOW-style validator), so a hallucinated or
non-reproducing "finding" is rejected even if the model asserts it.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..types import Finding, PoC
from .oracle import CCompileRunOracle

TOOLS: list[dict[str, Any]] = [
    {
        "name": "list_files",
        "description": "List the source files available in the target under analysis.",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "read_file",
        "description": "Read one source file from the target. Returns the file contents with line numbers.",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "File path relative to the target root."}},
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "compile_and_run",
        "description": (
            "Compile the target with AddressSanitizer+UBSan and run it with the given argv/stdin. "
            "Use this to TEST a hypothesis: does this concrete input trigger a memory-safety bug? "
            "Returns whether a sanitizer fired, its class, exit/signal, and the sanitizer report."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "argv": {"type": "array", "items": {"type": "string"},
                          "description": "Command-line arguments passed to the target (argv[1:])."},
                "stdin": {"type": "string", "description": "Bytes to write to the target's stdin."},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "report_finding",
        "description": (
            "Report a CONFIRMED vulnerability. Only call this after compile_and_run showed a sanitizer "
            "firing for the SAME argv/stdin you pass here. The harness re-verifies your PoC and REJECTS "
            "the report if it does not reproduce, never report an unverified bug."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "cwe": {"type": "string", "description": "CWE id, e.g. CWE-121."},
                "title": {"type": "string"},
                "function": {"type": "string", "description": "Vulnerable function name."},
                "file": {"type": "string"},
                "line": {"type": "integer"},
                "poc_argv": {"type": "array", "items": {"type": "string"}},
                "poc_stdin": {"type": "string"},
                "rationale": {"type": "string", "description": "Source -> sink reasoning for the bug."},
            },
            "required": ["cwe", "title", "poc_argv", "rationale"],
            "additionalProperties": False,
        },
    },
]


class Toolbox:
    """Stateful dispatcher bound to one target. Holds confirmed findings."""

    def __init__(self, target_dir: Path, sources: list[Path], oracle: CCompileRunOracle | None = None):
        self.target_dir = target_dir
        self.sources = sources
        self.oracle = oracle or CCompileRunOracle()
        self.findings: list[Finding] = []

    def dispatch(self, name: str, args: dict[str, Any]) -> tuple[str, bool]:
        """Run a tool. Returns (result_text_for_model, is_error)."""
        try:
            fn = getattr(self, f"_tool_{name}")
        except AttributeError:
            return f"unknown tool: {name}", True
        try:
            return fn(args), False
        except Exception as e:  # surface tool errors to the model, don't crash the loop
            return f"tool error: {e}", True

    # -- tools -------------------------------------------------------------
    def _tool_list_files(self, _args: dict) -> str:
        return "\n".join(str(s.relative_to(self.target_dir)) for s in self.sources)

    def _tool_read_file(self, args: dict) -> str:
        rel = args["path"]
        path = (self.target_dir / rel).resolve()
        if self.target_dir.resolve() not in path.parents and path != self.target_dir.resolve():
            return f"refused: path escapes target root: {rel}"
        if not path.exists():
            return f"no such file: {rel}"
        lines = path.read_text(errors="replace").splitlines()
        return "\n".join(f"{i+1:4d}  {ln}" for i, ln in enumerate(lines))

    def _tool_compile_and_run(self, args: dict) -> str:
        poc = PoC(argv=list(args.get("argv", [])), stdin=args.get("stdin", ""))
        verdict = self.oracle.verify(self.sources, poc)
        san = verdict.sanitizer
        return (
            f"reason={verdict.reason}\n"
            f"sanitizer_triggered={bool(san and san.triggered)}\n"
            f"sanitizer_class={san.klass if san else None}\n"
            f"verified_memory_safety_bug={verdict.verified}\n"
            f"--- evidence ---\n{verdict.evidence[:1500]}"
        )

    def _tool_report_finding(self, args: dict) -> str:
        poc = PoC(argv=list(args["poc_argv"]), stdin=args.get("poc_stdin", ""))
        verdict = self.oracle.verify(self.sources, poc)   # re-verify: the validator gate
        if not verdict.verified:
            return (f"REJECTED: PoC did not reproduce a memory-safety bug "
                    f"(reason={verdict.reason}). Do not report unverified findings.")
        finding = Finding(
            cwe=args["cwe"], title=args["title"],
            function=args.get("function", ""), file=args.get("file", ""),
            line=args.get("line"), poc=poc, verdict=verdict,
            rationale=args.get("rationale", ""),
        )
        self.findings.append(finding)
        klass = verdict.sanitizer.klass if verdict.sanitizer else "crash"
        return f"ACCEPTED: finding confirmed ({klass}). PoC reproduces. {poc.label()}"
