/* vuln.c — INTENTIONALLY VULNERABLE (CWE-121: Stack-based Buffer Overflow)
 *
 * Phase-0 demo target for the Sabba verification harness. `greet()` copies an
 * attacker-controlled argument into a fixed 16-byte stack buffer with no bounds
 * check, so a long argv[1] overflows `buf`. AddressSanitizer catches it as a
 * stack-buffer-overflow. This is the kind of bug the agent must FIND, the oracle
 * must VERIFY (reproducing PoC), and only then is a Finding emitted.
 *
 * Do not "fix" this file — it is a fixture, not production code.
 */
#include <stdio.h>
#include <string.h>

void greet(const char *name) {
    char buf[16];
    strcpy(buf, name);          /* BUG: unbounded copy into a 16-byte buffer */
    printf("Hello, %s\n", buf);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s <name>\n", argv[0]);
        return 1;
    }
    greet(argv[1]);
    return 0;
}
