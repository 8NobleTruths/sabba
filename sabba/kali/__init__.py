"""Kali security tools as scope-enforced, agent-callable capabilities.

Sabba wraps the installed security toolchain so a coding agent can run recon and scanning
through one MCP surface -- but every run is checked against an operator-set scope first, and
tool output is a candidate until Sabba's oracle proves it. Authorized targets only.
"""
