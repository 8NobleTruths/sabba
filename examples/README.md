# Example targets

## vuln-lab

Small self-contained C programs for exercising the solver end to end. Four have a real
memory-safety bug; two are safe twins that must not be flagged.

```bash
sabba solve examples/vuln-lab
```

Expect four confirmed findings (three stack overflows via `strcpy`/`strcat`, one heap
off-by-one via `malloc(strlen(...))`) and the two `safe_*` files left alone. Each finding
is proved: Z3 solves a triggering input, then the file is compiled under AddressSanitizer
and run, and the sanitizer has to fire before anything is reported.

What the solver covers today: `strcpy` / `strcat` / `stpcpy` into a fixed-size buffer or a
`malloc(strlen(...))` allocation, where the copied string reaches the sink through `argv`
(used directly, through a local, or through a function parameter). It does not yet model
`memcpy` with an attacker-controlled length, input from stdin or files, or bugs of other
classes.
