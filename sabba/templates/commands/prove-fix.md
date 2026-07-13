---
description: Prove the current change actually works, by running it (base-fail / head-pass)
---
Prove the change in $ARGUMENTS actually works -- do not claim it does until it is proven.

Call sabba `prove` with a `test` command that captures the behavior the change is supposed to
produce (for example a specific test, or a command that should now succeed). Proven means the
test FAILS on the git base and PASSES on the working tree -- that is the difference between "the
model says it works" and "it works".

Report proven true or false with the reason. If it is not proven, the change is not done.
