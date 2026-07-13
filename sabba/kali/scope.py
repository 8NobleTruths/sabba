"""Authorization: nothing runs against a target the operator did not allow.

Scope is set by the OPERATOR (a scope file via SABBA_SCOPE, or the defaults), never by the
calling agent -- an agent cannot self-authorize. Default policy is deny: only loopback and
nmap's public test host (scanme.nmap.org) are allowed until the operator adds targets. Every
tool run extracts the hosts/IPs/URLs/CIDRs from its arguments and requires each to be in scope.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse

# always allowed: your own machine, and the host nmap explicitly authorizes for testing
_DEFAULT_HOSTS = {"127.0.0.1", "localhost", "::1", "scanme.nmap.org"}

_FILE_EXT = re.compile(r"\.(txt|json|xml|csv|html?|py|sh|js|ts|conf|cfg|ini|yaml|yml|log|out|md|list|db|pdf)$", re.I)
_IP_CIDR = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")
_DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", re.I)


def host_of(target: str) -> str:
    """The bare host from a URL, host:port, or plain host/IP."""
    t = target.strip()
    if "://" in t:
        t = urlparse(t).hostname or t
    else:
        t = t.split("/")[0]                       # drop any path
    if t.count(":") == 1:                         # host:port (not IPv6)
        t = t.split(":")[0]
    return t


def _as_ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def extract_targets(args: list[str]) -> list[str]:
    """Pull the host/IP/URL/CIDR tokens an offensive tool would act on, from its args.

    Conservative: flags are skipped, file-looking tokens are skipped, and anything that looks
    like a target is returned so scope can gate it. False positives fail closed (safer)."""
    out: list[str] = []
    for tok in args:
        if not tok:
            continue
        scan = tok
        if tok.startswith("-"):
            if "=" in tok:                        # a flag can embed a target: --url=http://x
                scan = tok.split("=", 1)[1]
            else:
                continue
        urls = re.findall(r"https?://[^\s'\"]+", scan)
        out += urls
        if urls or _FILE_EXT.search(scan):
            continue
        if _IP_CIDR.match(scan) or _DOMAIN.match(scan):
            out.append(scan)
    return out


class Scope:
    def __init__(self, hosts=(), cidrs=(), domains=()):
        self.hosts = set(hosts) | _DEFAULT_HOSTS
        self.domains = set(domains)
        self.cidrs = []
        for c in cidrs:
            try:
                self.cidrs.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                pass

    @classmethod
    def load(cls, path: str | None = None) -> "Scope":
        """Load the operator scope from `path` or $SABBA_SCOPE (a JSON file with hosts / cidrs /
        domains). No file means defaults only (deny everything but loopback and scanme)."""
        p = path or os.environ.get("SABBA_SCOPE")
        if not p or not Path(p).exists():
            return cls()
        try:
            data = json.loads(Path(p).read_text())
        except (json.JSONDecodeError, OSError):
            return cls()
        return cls(hosts=data.get("hosts", []), cidrs=data.get("cidrs", []),
                   domains=data.get("domains", []))

    def allows(self, target: str) -> bool:
        host = host_of(target)
        if not host:
            return False
        if host in self.hosts:
            return True
        for d in self.domains:
            if host == d or host.endswith("." + d):
                return True
        ip = _as_ip(host)
        if ip is not None:
            for net in self.cidrs:
                if ip in net:
                    return True
            if str(ip) in self.hosts:
                return True
        return False

    def check(self, args: list[str], network: bool) -> tuple[bool, str]:
        """Decide whether a run is authorized. Returns (ok, reason)."""
        targets = extract_targets(args)
        if not targets:
            if network:
                return False, ("no in-scope target found in the arguments; add the target to "
                               "the scope (SABBA_SCOPE) so it is recognized")
            return True, "no remote target"
        bad = [t for t in targets if not self.allows(t)]
        if bad:
            return False, f"out of scope: {', '.join(sorted(set(host_of(b) for b in bad)))}"
        return True, "in scope: " + ", ".join(sorted(set(host_of(t) for t in targets)))
