"""Sandboxes for executing untrusted, possibly-malicious code under limits.

Two backends behind one `Sandbox` protocol, so callers swap without changing code:

  - `LocalSubprocessSandbox` (rlimits + wall-clock timeout): resource bounding on a
    trusted machine, no filesystem or network isolation.
  - `DockerSandbox` (network-cut, read-only-root, cap-dropped container): real
    containment for arbitrary or hostile code, where docker or podman is present.

`engine_available()` reports whether a container engine is on PATH.
"""
from .base import Sandbox, Limits
from .docker import DockerSandbox, engine_available
from .local import LocalSubprocessSandbox

__all__ = ["Sandbox", "Limits", "LocalSubprocessSandbox", "DockerSandbox", "engine_available"]
