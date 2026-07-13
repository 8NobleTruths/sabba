"""What security tools are available on this host, from the curated catalog."""
from __future__ import annotations

import shutil

from .catalog import CATALOG


def list_security_tools() -> dict:
    installed, missing = [], []
    for name in sorted(CATALOG):
        meta = CATALOG[name]
        row = {"name": name, "category": meta["category"], "network": meta["network"]}
        if shutil.which(name):
            installed.append(row)
        else:
            missing.append(name)
    return {"installed": installed, "count_installed": len(installed), "missing": missing}
