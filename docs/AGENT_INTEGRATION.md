# Use Sabba from another agent (MCP)

Sabba runs as a Model Context Protocol server, so any MCP-capable agent, Claude Code, Codex,
OpenCode, OpenClaw, or your own tool-calling model, can spawn it and command it. The agent
hands Sabba a target, Sabba runs the oracle or a prover, and hands back a verdict. The one
rule holds across the boundary: a finding comes back only when the exploit reproduced, so the
calling agent gets a proof, not a guess.

## Start the server

```bash
sabba mcp                 # stdio, the transport every client understands (default)
sabba mcp --http          # streamable HTTP at http://127.0.0.1:8765/mcp
```

stdio is the usual choice: the client launches `sabba mcp` as a subprocess and talks to it
over stdin and stdout. Use `--http` when the agent connects to a long-lived endpoint instead.

## The tools

| Tool | What it does | Needs a model |
| --- | --- | --- |
| `doctor` | which prover toolchains and models are present | no |
| `list_provers` | the registered provers, their domain, languages, and vuln classes | no |
| `verify <dir>` | compile a native C/C++ target under a sanitizer and run its known PoC | no |
| `solve <dir>` | Z3 synthesizes overflow inputs; the oracle confirms each | no |
| `prove <dir>` | prove a change: a check that fails on the git base and passes on the head | no |
| `verify_change [path]` | prove a change works via the bundled Magga engine: a new test fails on the base ref and passes on the head, across 16 languages; `sandbox=True` runs an untrusted change in a network-cut container | no |
| `hunt <dir>` | full hunt (retrieval, Z3, the model), or the fork prover for Solidity | yes |
| `scan <dir>` | the reasoning model proposes, the oracle verifies | yes |
| `rank <dir>` | rank a C/C++ target's functions by bug likelihood (local ML, token-free) | no |
| `security_scan <file.py>` | vet a Python skill by running it (in a network-cut container when docker/podman is present); report creds/net/subprocess it touched | no |
| `run_sandboxed <cmd>` | run a shell command in an isolated sandbox: `tier=local` (rlimits, scrubbed env, kill) or `tier=container` (network-cut, read-only root, caps dropped) | no |
| `cost_estimate <tool>` | is a tool token-free or does it need a model | no |
| `list_security_tools` | which security tools (nmap, nuclei, ffuf, ...) are installed, by category | no |
| `kali_run <tool> <args>` | run a security tool, scope-checked and sandboxed, with structured parsing | no |

Twelve of fourteen tools need **no model**, so an agent can prove a suspected bug, verify its own
edit, vet a skill, or rank risk with zero extra credentials -- the work is compute, not tokens.
Only `hunt` and `scan` use the model configured in the server's environment (see the local-model
section to run that offline too). Ask `cost_estimate` if unsure.

Each tool returns JSON. `verify` on a real bug returns:

```json
{
  "target": "cwe121_stack_overflow",
  "poc": "argv=['AAAA...<64B>'] stdin=0B",
  "verdict": {
    "verified": true,
    "reason": "sanitizer_triggered",
    "class": "stack-buffer-overflow",
    "evidence": "ERROR: AddressSanitizer: stack-buffer-overflow ..."
  }
}
```

`prove` proves an edit really did something -- a check that fails on the base commit and passes
on the working tree:

```json
{
  "mode": "test",
  "proven": true,
  "reason": "the check fails on base and passes on head",
  "base": { "ref": "HEAD", "exit": 1, "passed": false },
  "head": { "exit": 0, "passed": true }
}
```

`security_scan` reports what a skill actually did when it ran:

```json
{
  "skill": "/skills/notes.py",
  "ran": true,
  "risk": "dangerous",
  "reason": "reads credential-like paths and opens the network (the exfiltration shape)",
  "observations": [
    { "kind": "credential-read", "detail": "/home/me/.ssh/id_ed25519" },
    { "kind": "network", "detail": "('198.51.100.7', 443)" }
  ]
}
```

## Register it with your agent

Every client needs the same three facts: run the command `sabba` with the argument `mcp` over
stdio.

**Claude Code**

```bash
claude mcp add sabba -- sabba mcp
```

**Codex CLI** (`~/.codex/config.toml`)

```toml
[mcp_servers.sabba]
command = "sabba"
args = ["mcp"]
```

**OpenCode** (`opencode.json`)

```json
{
  "mcp": {
    "sabba": { "type": "local", "command": ["sabba", "mcp"], "enabled": true }
  }
}
```

**Cursor** (`~/.cursor/mcp.json`, or `.cursor/mcp.json` in a project)

```json
{
  "mcpServers": {
    "sabba": { "command": "sabba", "args": ["mcp"] }
  }
}
```

**Hermes, OpenClaw, or any other MCP client** (generic server entry)

```json
{
  "mcpServers": {
    "sabba": { "command": "sabba", "args": ["mcp"] }
  }
}
```

If `sabba` is not on the agent's PATH, use the absolute path to the command (for example
`~/.sabba/venv/bin/sabba`), or `python -m sabba mcp`.

Once Sabba is published to PyPI, no install step is needed at all -- point any client at
`uvx` or `pipx`, and it fetches and runs the server on demand:

```jsonc
{ "mcpServers": { "sabba": { "command": "uvx",  "args": ["sabba", "mcp"] } } }
{ "mcpServers": { "sabba": { "command": "pipx", "args": ["run", "sabba", "mcp"] } } }
```

## Security tools, authorized targets only

`kali_run` exposes the installed security toolchain (nmap, nuclei, ffuf, httpx, subfinder,
sqlmap, and the rest) through one sandboxed surface, and `list_security_tools` shows what is
present. Every run is gated by a scope the **operator** sets, never the agent: only loopback and
`scanme.nmap.org` are allowed by default, and any other target is refused until it is added.
Point `SABBA_SCOPE` at a JSON file with your authorized targets:

```json
{ "hosts": ["10.0.0.5"], "cidrs": ["10.0.0.0/24"], "domains": ["staging.example.com"] }
```

```bash
export SABBA_SCOPE=~/engagement/scope.json
sabba mcp
```

An out-of-scope target comes back as `{"error": "blocked by scope", ...}` and nothing runs. Tool
output is a candidate, not a finding -- confirm the ones that matter with `verify` or `hunt`.

## Security command templates

`sabba templates install` drops ready-made Claude Code commands that drive these tools:

```bash
sabba templates list                    # /pentest /audit /vet-skill /prove-fix
sabba templates install --dir .claude   # into a project's Claude Code config
```

- `/pentest <target>` recon and scan an authorized target, then confirm findings
- `/audit <dir>` rank risk, hunt bugs, and prove them in a codebase
- `/vet-skill <file>` security_scan a skill before installing it
- `/prove-fix <dir>` prove a change works (base-fail / head-pass)

## Run the reasoning locally too

`hunt` and `scan` pick their model from the server's environment. Point them at a local,
OpenAI-compatible endpoint so the whole loop runs on your own machine:

```bash
export SABBA_LLM_BACKEND=local
export SABBA_LOCAL_BASE_URL=http://localhost:11434/v1   # Ollama; llama.cpp, vLLM also work
export SABBA_LOCAL_MODEL=qwen2.5-coder:7b
sabba mcp
```

The oracle and the provers never needed a model; with a local backend the model-driven tools
run offline as well.
