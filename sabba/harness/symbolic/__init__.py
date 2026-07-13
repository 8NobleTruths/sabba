"""Symbolic input synthesis for the harness.

`synth.py` models buffer-size arithmetic and uses Z3 to solve for inputs that overflow a
buffer, then verifies each one with the execution oracle.
"""
from .synth import find_overflow_sinks, hunt_symbolic, synthesize

__all__ = ["find_overflow_sinks", "hunt_symbolic", "synthesize"]
