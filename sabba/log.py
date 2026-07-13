"""File logging for diagnosis.

Turns, tool calls, and errors with tracebacks go to a rotating log at ~/.sabba/logs/sabba.log
so a failure can be understood after the fact. The console stays clean; this file is the
record you check when something breaks. `sabba logs` tails it.
"""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from . import config

LOG_DIR = Path(config.HOME) / "logs"
LOG_PATH = LOG_DIR / "sabba.log"
_configured = False


def get_logger() -> logging.Logger:
    global _configured
    logger = logging.getLogger("sabba")
    if not _configured:
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(LOG_PATH, maxBytes=2_000_000, backupCount=3)
            handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s"))
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            logger.propagate = False
        except OSError:
            logger.addHandler(logging.NullHandler())
        _configured = True
    return logger
