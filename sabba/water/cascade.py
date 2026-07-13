"""The three-tier cascade: Reflex, Resident, Teacher.

  Reflex    no LLM at all: the ranker, Z3, and the oracle. Deterministic and free.
  Resident  a local model (SABBA_LLM_BACKEND=local) for the common reasoning cases.
  Teacher   a frontier model (openrouter and friends) for the hard or high-value cases.

The point is to keep work at the cheapest tier that can do it, and to escalate only when the
cheaper tier comes up empty. Verifying a PoC, running Z3, or ranking functions never needs a
model, so those are always Reflex. A reasoning hunt goes to Resident when a local model is
present and the task looks tractable, and to Teacher when it is hard, or when Resident found
nothing and a Teacher is available.

The verdict discipline is unchanged across tiers: whatever proposes a candidate, the oracle
still runs it before it becomes a finding. A cheaper tier can only ever cost coverage, never
soundness.
"""
from __future__ import annotations

from enum import Enum
from typing import Callable

# tasks that are pure execution or search, with no model in the loop
_REFLEX_KINDS = frozenset({"verify", "solve", "rank"})

# at or above this difficulty a reasoning task prefers the Teacher (when one is available)
_HARD = 0.66


class Tier(str, Enum):
    REFLEX = "reflex"
    RESIDENT = "resident"
    TEACHER = "teacher"


def choose_tier(kind: str, difficulty: float = 0.0,
                have_resident: bool = False, have_teacher: bool = False) -> Tier:
    """Pick the tier for a task.

    kind is the operation ("verify", "solve", "rank", "hunt", "scan"). difficulty is a 0..1
    estimate (for a hunt, for example 1 minus the ranker's confidence in a clear top candidate).
    have_resident / have_teacher say which model tiers are configured.
    """
    if kind in _REFLEX_KINDS:
        return Tier.REFLEX
    # a reasoning task, but no model at all: fall back to what Reflex can do
    if not have_resident and not have_teacher:
        return Tier.REFLEX
    # hard or high-value: prefer the Teacher when there is one
    if difficulty >= _HARD and have_teacher:
        return Tier.TEACHER
    # otherwise keep it local when we can
    if have_resident:
        return Tier.RESIDENT
    return Tier.TEACHER


class Cascade:
    """Route a task to a tier and run it, escalating from Resident to Teacher on an empty result."""

    def __init__(self, have_resident: bool = False, have_teacher: bool = False):
        self.have_resident = have_resident
        self.have_teacher = have_teacher

    def choose(self, kind: str, difficulty: float = 0.0) -> Tier:
        return choose_tier(kind, difficulty, self.have_resident, self.have_teacher)

    def run(self, kind: str, difficulty: float,
            reflex: Callable[[], object],
            resident: Callable[[], object] | None = None,
            teacher: Callable[[], object] | None = None) -> tuple[Tier, object]:
        """Execute the task at its chosen tier. If Resident is chosen and returns a falsy
        result while a Teacher is available, escalate. Returns (tier_that_produced, result)."""
        tier = self.choose(kind, difficulty)
        if tier is Tier.REFLEX:
            return Tier.REFLEX, reflex()
        if tier is Tier.RESIDENT and resident is not None:
            out = resident()
            if not out and self.have_teacher and teacher is not None:
                return Tier.TEACHER, teacher()
            return Tier.RESIDENT, out
        if teacher is not None:
            return Tier.TEACHER, teacher()
        # asked for a model tier we cannot actually run: degrade to Reflex
        return Tier.REFLEX, reflex()
