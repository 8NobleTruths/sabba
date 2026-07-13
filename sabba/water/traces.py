"""The execution-grounded flywheel: every hunt leaves labeled data behind.

The oracle already decides truth by running the exploit. That verdict is the perfect training
signal, so we keep it. After a hunt, each function retrieval surfaced is written to a trace with
a label: 1 when the oracle proved a bug in it, 0 otherwise. Over time this replaces the
synthetic bootstrap corpus with real, execution-grounded examples the ranker learns from, and
it is the same reward signal a later RLVR pass uses to improve the local reasoning model.

Honest caveat: a positive is rock solid (the oracle reproduced a crash), but a negative is
weak. A function that did not yield a proven finding this run may still be buggy; we just did
not prove it. So negatives are noisy, positives are not. The trainer keeps that in mind and
falls back to the bootstrap corpus when a class is missing.

Collection is on by default and fail-safe: it never raises into a hunt. Turn it off with
SABBA_TRACES=0, and point it somewhere else with SABBA_TRACE_DIR.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def enabled() -> bool:
    return os.environ.get("SABBA_TRACES", "1").lower() not in ("0", "off", "false", "no")


def _default_dir() -> Path:
    return Path(os.environ.get("SABBA_TRACE_DIR", str(Path.home() / ".sabba" / "traces")))


class TraceStore:
    """Append-only JSONL of labeled functions from real runs."""

    def __init__(self, path: str | Path | None = None):
        base = Path(path) if path else _default_dir()
        # a directory means the default file inside it; a file path is used as is
        self.path = base / "traces.jsonl" if base.suffix == "" else base

    def record(self, records: list[dict]) -> int:
        """Append records as JSONL. Never raises; returns how many were written."""
        recs = [r for r in records if r.get("code")]
        if not recs:
            return 0
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a") as f:
                for r in recs:
                    f.write(json.dumps(r) + "\n")
            return len(recs)
        except Exception:  # noqa: BLE001 - collection must never break a hunt
            return 0

    def record_hunt(self, target: Any, candidates: list[dict], findings: list) -> int:
        """Label each surfaced candidate by whether the oracle proved a bug in it, and store."""
        proven = {getattr(f, "function", None) for f in findings}
        proven.discard(None)
        recs = []
        for c in candidates:
            code = c.get("code")
            if not code:
                continue
            label = 1 if c.get("function") in proven else 0
            recs.append({"kind": "hunt", "target": str(target), "function": c.get("function"),
                         "file": c.get("file", ""), "line": c.get("line"),
                         "code": code, "label": label, "verified": bool(label)})
        return self.record(recs)

    def load_labeled(self) -> list[dict]:
        """Read all traces as {code, label}, keeping the strongest label per unique code (a
        proven positive always wins over a weak negative for the same function body)."""
        if not self.path.exists():
            return []
        best: dict[str, int] = {}
        for line in self.path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:  # noqa: BLE001
                continue
            code = r.get("code")
            if not code:
                continue
            best[code] = max(best.get(code, 0), int(r.get("label", 0)))
        return [{"code": c, "label": lbl} for c, lbl in best.items()]
