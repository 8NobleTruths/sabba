# `targets/`, verification fixtures

Small, self-contained programs with **known** vulnerabilities, used to de-risk and
test the harness (Phase 0). Each target is a directory with:

- the source file(s),
- `target.json`, descriptor: `sources`, `ground_truth` (CWE / function / line / sink), and a `known_poc` that deterministically triggers the bug.

These are **intentionally vulnerable fixtures, not production code**, do not "fix" them.

| Target | CWE | Bug |
|---|---|---|
| `cwe121_stack_overflow/` | CWE-121 | `strcpy(argv[1])` into a 16-byte stack buffer |

The deterministic test (`tests/test_oracle.py`) compiles each target with AddressSanitizer,
runs its `known_poc`, and asserts the oracle returns `verified=True`, proving Milestone M0
without any LLM. The agent (`sabba scan`) must *discover* the same PoC itself.
