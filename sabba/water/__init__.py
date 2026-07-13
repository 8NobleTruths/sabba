"""The Water Layer: knowledge kept as runnable skills, usable without a frontier model.

The first piece here is the cascade router (cascade.py): it decides which tier handles a task,
so cheap, local work stays local and the frontier model is called only when it is worth it.
See docs/WATER_LAYER_DESIGN.md for the full design (genome, skill compile, rebirth).
"""
from .cascade import Cascade, Tier, choose_tier
from .traces import TraceStore

__all__ = ["Cascade", "Tier", "choose_tier", "TraceStore"]
