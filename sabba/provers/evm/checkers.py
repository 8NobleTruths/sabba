"""Turn a forge run into a Verdict, and keep the proof honest.

Two jobs:

  parse_forge_json    read the forge --json output for one named test and decide
  forbidden_cheatcodes  reject exploits that fake their own result

The second job matters as much as the first. In every other part of Sabba an independent
oracle owns the truth: ASan is ground the model does not control. On the EVM the model
writes the exploit, so the checker has to be code the model cannot influence, and the model
must not be allowed to fabricate the win. A profit that came from deal(), a state write from
vm.store(), or an impersonation from vm.prank() is not an exploit, it is the test lying to
itself. We scan the model's source for those cheatcodes and refuse to run it if it uses one.
The attacker in a real proof is the exploit contract itself, acting only through real calls.
"""
from __future__ import annotations

import json
import re

from ...types import Verdict

# Never allowed anywhere: these fabricate code, storage, return values, or reach the host,
# so they can invent a world that does not exist on chain.
_ALWAYS = (
    "vm.store(", "vm.etch(", "vm.mockCall(", "vm.mockCallRevert(",
    "vm.ffi(", "vm.setEnv(",
)
# Allowed only in setUpTarget, where they build the scenario (fund an independent victim,
# act as another user). In attack() they would fake the attacker's own profit, so they are
# forbidden there. The profit snapshot is taken after setUp, so funding in setUp cannot
# count as a gain.
_ATTACK_ONLY = (
    "deal(", "vm.deal(", "hoax(", "startHoax(",
    "vm.prank(", "vm.startPrank(", "vm.stopPrank(",
)


def forbidden_cheatcodes(solidity: str, *, allow_setup_funding: bool = True) -> list[str]:
    """Cheatcodes that would let the exploit fake its win. Non-empty means unsound.

    State-fabricating cheatcodes are rejected anywhere. Balance and identity cheatcodes are
    rejected inside attack() always, where they would manufacture the attacker's profit.

    allow_setup_funding governs setUpTarget. On a live fork the funds are already real, so
    funding cheatcodes are rejected everywhere (allow_setup_funding=False); a self-contained
    local target may fund an independent victim in setUp (allow_setup_funding=True). Even in
    setUp, funding an account the exploit controls and reclaiming it is not a real drain, so
    local targets are trusted fixtures for exercising the prover, not adversarial proofs.
    """
    text = _strip_comments(solidity)
    bad = {c for c in _ALWAYS if c in text}
    if allow_setup_funding:
        attack = _attack_body(text)
        scope = attack if attack is not None else text
        bad |= {c for c in _ATTACK_ONLY if c in scope}
    else:
        bad |= {c for c in _ATTACK_ONLY if c in text}
    return sorted(c[:-1] for c in bad)


def _attack_body(text: str) -> str | None:
    """Return the body of the attack() function, or None if it cannot be isolated."""
    m = re.search(r"function\s+attack\s*\([^)]*\)[^{]*\{", text)
    if not m:
        return None
    i = m.end() - 1  # at the opening brace
    depth, start = 0, i
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1:j]
    return None


def _strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.DOTALL)
    src = re.sub(r"//[^\n]*", " ", src)
    return src


def parse_forge_json(res, *, test_name: str = "test_exploit") -> Verdict:
    """Decide the verdict for one exploit test from a forge --json result.

    Every non-success path maps to verified=False with a clear reason, so a build error,
    a fork-fetch failure, a rate-limited RPC, or a missing test never reads as a proof.
    """
    if getattr(res, "timed_out", False):
        return Verdict(verified=False, reason="timeout_unconfirmed",
                       evidence=_tail(res.stdout) or _tail(res.stderr))

    data = _load_forge_json(res.stdout)
    if data is None:
        return Verdict(verified=False, reason="forge_error",
                       evidence=_tail(res.stderr) or _tail(res.stdout))

    status, detail = _find_test(data, test_name)
    if status is None:
        return Verdict(verified=False, reason="test_absent",
                       evidence=f"{test_name} did not run; " + (_tail(res.stdout, 400)))
    if status == "Success":
        return Verdict(verified=True, reason="exploit_confirmed",
                       evidence=detail or f"{test_name} passed on the pinned fork")
    return Verdict(verified=False, reason="no_profit",
                   evidence=detail or f"{test_name} did not hold ({status})")


def _load_forge_json(stdout: str):
    stdout = stdout or ""
    try:
        return json.loads(stdout)
    except Exception:
        pass
    # forge can print warnings before the JSON object; recover the outermost braces.
    start, end = stdout.find("{"), stdout.rfind("}")
    if 0 <= start < end:
        try:
            return json.loads(stdout[start:end + 1])
        except Exception:
            return None
    return None


def _find_test(data: dict, test_name: str):
    """Look up one test across all suites. Returns (status, detail) or (None, None)."""
    if not isinstance(data, dict):
        return None, None
    for suite in data.values():
        results = (suite or {}).get("test_results") if isinstance(suite, dict) else None
        if not isinstance(results, dict):
            continue
        for sig, r in results.items():
            if sig.split("(")[0] == test_name:
                status = (r or {}).get("status")
                detail = (r or {}).get("reason") or ""
                logs = (r or {}).get("decoded_logs") or []
                if logs:
                    detail = (detail + " | " + " ".join(str(x) for x in logs[:4])).strip(" |")
                return status, detail
    return None, None


def _tail(s: str, n: int = 1200) -> str:
    return (s or "")[-n:]
