"""Long-term memory with Voyage embeddings and a small local vector store.

Each message is embedded with voyage-4-lite and appended to ~/.sabba/memory/store.jsonl on
the user's own device. Before a new turn, the user's text is embedded as a query and the
most similar snippets from earlier conversations are pulled back, so the model recalls the
past. The Voyage key comes from the environment (VOYAGE_API_KEY, set from the saved config);
memory is simply off when no key is present. Retrieval is a brute-force cosine scan, which
is plenty for a personal store.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path

from . import config

MODEL = "voyage-4-lite"
DIM = 512  # voyage-4 supports 2048/1024/512/256; 512 halves on-device storage and scan cost
URL = "https://api.voyageai.com/v1/embeddings"
STORE = Path(config.HOME) / "memory" / "store.jsonl"


def enabled() -> bool:
    return bool(os.environ.get("VOYAGE_API_KEY"))


def _embed(texts: list[str], input_type: str):
    import requests
    key = os.environ.get("VOYAGE_API_KEY")
    if not key:
        return None
    r = requests.post(URL, timeout=30,
                      headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                      json={"model": MODEL, "input": texts, "input_type": input_type,
                            "output_dimension": DIM})
    r.raise_for_status()
    return [d["embedding"] for d in r.json()["data"]]


def add(session_id: str, role: str, text: str) -> None:
    text = (text or "").strip()
    if not text or not enabled():
        return
    try:
        vecs = _embed([text[:8000]], "document")
        if not vecs:
            return
        STORE.parent.mkdir(parents=True, exist_ok=True)
        with STORE.open("a") as f:
            f.write(json.dumps({"session": session_id, "role": role,
                                "text": text[:2000], "vec": vecs[0]}) + "\n")
    except Exception:
        pass


def _cos(a, b) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def search(query: str, k: int = 6, exclude_session: str | None = None) -> list[str]:
    if not enabled() or not STORE.exists():
        return []
    try:
        qv = _embed([query[:8000]], "query")
        if not qv:
            return []
        qv = qv[0]
    except Exception:
        return []
    scored = []
    with STORE.open() as f:
        for line in f:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if exclude_session and rec.get("session") == exclude_session:
                continue
            scored.append((_cos(qv, rec["vec"]), rec))
    scored.sort(key=lambda x: x[0], reverse=True)
    out = []
    for score, rec in scored[:k]:
        if score < 0.35:
            continue
        out.append(f"[{rec.get('role','')}] {rec['text'][:300]}")
    return out
