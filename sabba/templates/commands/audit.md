---
description: Security-audit a codebase with Sabba -- rank risk, find bugs, prove them
---
Security-audit the code in: $ARGUMENTS

Use the sabba MCP tools. Prefer the token-free ones.

1. `rank` the functions so you look at the riskiest ones first (native C/C++).
2. `hunt` the target to find bugs (or `solve` for native C/C++ with Z3). Every candidate is run
   before it is returned, so a finding is a proof, not a guess.
3. Report only proven findings, each with its CWE class and the evidence. Trust nothing that did
   not reproduce -- there are no "possible" or "likely" findings, only proven ones.
