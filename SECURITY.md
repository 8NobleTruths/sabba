# Security policy

## Reporting a vulnerability

If you find a security issue in Sabba, please report it privately. Do not open a public issue
for anything exploitable.

- Use GitHub's private vulnerability reporting on this repository (Security tab -> Report a
  vulnerability), or
- email the maintainer listed on the GitHub profile.

Please include a minimal reproduction and, if possible, the exact commit. We aim to acknowledge
within a few days and to ship a fix or mitigation before any public disclosure. Coordinated
disclosure is appreciated; we will credit you unless you prefer otherwise.

## Using Sabba responsibly

Sabba runs security tooling. Two rules are not optional:

1. **Authorized targets only.** `kali_run` and the security tools reach out to targets. Every
   run is checked against an operator-set scope (`SABBA_SCOPE`); by default only loopback and
   `scanme.nmap.org` are allowed. Do not scan, probe, or attack systems you do not own or have
   explicit written authorization to test. You are responsible for your authorization.
2. **Run untrusted input in isolation.** `security_scan` and `run_sandboxed` execute code you may
   not trust. The current isolation is process-level (rlimits, a scrubbed environment, a
   sandboxed home and cwd, a hard timeout) -- it is observation and containment of *effect*, not
   a hard escape boundary. For genuinely hostile input, run the server inside a container or
   microVM. A container tier is planned; until then, only scan and run what you can afford to
   execute on the host.

## Scope of the guarantees

A Sabba finding is a proof: it is returned only when the exploit reproduced under the oracle.
Tool output (from `kali_run`, `hunt`, scanners) is a *candidate* until confirmed with
`verify`/`hunt`. Do not treat unconfirmed scanner output as a finding.
