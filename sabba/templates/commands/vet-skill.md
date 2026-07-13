---
description: Vet a skill or plugin before installing it, by running it under observation
---
Before installing the skill or plugin at $ARGUMENTS, vet it.

Call sabba `security_scan` on that path. It runs the skill in a sandboxed home and cwd and
reports exactly what it did: credential-looking file reads, outbound network, subprocesses.

Report the risk level (clean / suspicious / dangerous) and the observed behaviors. Do not
install a skill that reads credentials or opens the network unless you understand and accept
exactly why it does so.
