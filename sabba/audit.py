"""An append-only audit log of security-relevant actions.

Offensive tooling needs a record: what tool ran, against what target, whether scope allowed it.
Every kali_run, security_scan, and run_sandboxed is logged (allowed and blocked alike) as one
JSON line to $SABBA_AUDIT_LOG (default ~/.sabba/audit.log). Logging never raises.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

_PATH = Path(os.environ.get("SABBA_AUDIT_LOG", Path.home() / ".sabba" / "audit.log"))


def record(action: str, **fields) -> None:
    try:
        _PATH.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps({"ts": int(time.time()), "action": action, **fields})
        with _PATH.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:  # noqa: BLE001 - auditing must never break the action
        pass
