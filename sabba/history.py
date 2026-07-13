"""Saved conversations on the local device, for /resume.

Each session is a JSON file under ~/.sabba/history/ holding the full message list, so a
conversation can be reopened later exactly where it left off.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from . import config

DIR = Path(config.HOME) / "history"


def new_id() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def save(session_id: str, title: str, model: str, messages: list) -> None:
    DIR.mkdir(parents=True, exist_ok=True)
    (DIR / f"{session_id}.json").write_text(json.dumps({
        "id": session_id, "title": (title or "conversation")[:80], "model": model,
        "updated": datetime.now().isoformat(timespec="seconds"), "messages": messages}, indent=1))


def load(session_id: str) -> dict:
    return json.loads((DIR / f"{session_id}.json").read_text())


def sessions() -> list[dict]:
    if not DIR.exists():
        return []
    out = []
    for p in DIR.glob("*.json"):
        try:
            d = json.loads(p.read_text())
            out.append({"id": d["id"], "title": d.get("title", "conversation"),
                        "updated": d.get("updated", "")})
        except (ValueError, KeyError):
            continue
    out.sort(key=lambda x: x["updated"], reverse=True)
    return out
