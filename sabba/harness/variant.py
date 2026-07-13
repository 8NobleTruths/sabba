"""Wave 3.4, variant-analysis driver: retrieval -> reasoning -> verification.

The full Phase-5 loop in the constrained regime that actually works: graph-retrieval
surfaces high-risk functions, the agent (GLM-5.2) hypothesizes + tests PoCs against
them, and only oracle-verified findings are emitted. This is the path to M5.

  python -m sabba.harness.variant <target_dir>
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .agent import run_scan
from .retrieval import format_hints, rank_candidates
from ..types import Finding


def scan_with_retrieval(target_dir, *, model=None, top_k: int = 8, on_event=None
                        ) -> tuple[list[Finding], list[dict]]:
    log = on_event or (lambda _m: None)
    candidates = rank_candidates(target_dir, top_k=top_k)
    hints = format_hints(candidates)
    if hints:
        log(hints)
    findings = run_scan(target_dir, model=model, hints=hints, on_event=log)
    return findings, candidates


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sabba.harness.variant")
    p.add_argument("target")
    p.add_argument("--model", default=None)
    p.add_argument("--top-k", type=int, default=8)
    args = p.parse_args(argv)
    findings, cands = scan_with_retrieval(args.target, model=args.model, top_k=args.top_k,
                                          on_event=lambda m: print(m))
    print(f"\n== retrieval surfaced {len(cands)} candidate(s); {len(findings)} verified finding(s) ==")
    for i, f in enumerate(findings, 1):
        loc = f"{f.file}:{f.line}" if f.line else f.file
        print(f"  {i}. {f.cwe} {f.title}  [{f.function} @ {loc}]")
    return 0 if findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
