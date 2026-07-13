"""Curated metadata for the high-value security tools.

`network` marks a tool that acts on a remote target (so scope must find an authorized target
before it runs). `structured` names the machine-readable output a wrapper can parse; the flag
that produces it is `structured_flag`. Unknown tools are still runnable through the generic
runner and are treated as network-facing (deny-biased) by default.
"""

CATALOG = {
    "nmap":       {"category": "recon",   "network": True,  "structured": "xml",   "structured_flag": "-oX -"},
    "masscan":    {"category": "recon",   "network": True,  "structured": "json",  "structured_flag": "-oJ -"},
    "httpx":      {"category": "recon",   "network": True,  "structured": "jsonl", "structured_flag": "-json"},
    "subfinder":  {"category": "recon",   "network": True,  "structured": "jsonl", "structured_flag": "-oJ"},
    "dnsx":       {"category": "recon",   "network": True,  "structured": "jsonl", "structured_flag": "-json"},
    "amass":      {"category": "recon",   "network": True,  "structured": None,    "structured_flag": ""},
    "whatweb":    {"category": "recon",   "network": True,  "structured": None,    "structured_flag": ""},
    "wafw00f":    {"category": "recon",   "network": True,  "structured": None,    "structured_flag": ""},
    "nuclei":     {"category": "vuln",    "network": True,  "structured": "jsonl", "structured_flag": "-jsonl"},
    "nikto":      {"category": "web",     "network": True,  "structured": None,    "structured_flag": ""},
    "ffuf":       {"category": "web",     "network": True,  "structured": "json",  "structured_flag": "-of json -o -"},
    "gobuster":   {"category": "web",     "network": True,  "structured": None,    "structured_flag": ""},
    "katana":     {"category": "web",     "network": True,  "structured": "jsonl", "structured_flag": "-jsonl"},
    "sqlmap":     {"category": "web",     "network": True,  "structured": None,    "structured_flag": ""},
    "wpscan":     {"category": "web",     "network": True,  "structured": "json",  "structured_flag": "-f json"},
    "hydra":      {"category": "creds",   "network": True,  "structured": None,    "structured_flag": ""},
    "john":       {"category": "creds",   "network": False, "structured": None,    "structured_flag": ""},
    "hashcat":    {"category": "creds",   "network": False, "structured": None,    "structured_flag": ""},
    "searchsploit": {"category": "exploit", "network": False, "structured": "json", "structured_flag": "-j"},
}

_DEFAULT = {"category": "other", "network": True, "structured": None, "structured_flag": ""}


def entry(tool: str) -> dict:
    """Catalog metadata for a tool; unknown tools default to network-facing (deny-biased)."""
    return CATALOG.get(tool, _DEFAULT)
