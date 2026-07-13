/* parse.c — INTENTIONALLY VULNERABLE (CWE-122 / CWE-131: heap overflow via
 * incorrect buffer-size calculation). A realistic, subtle off-by-one: the buffer
 * is sized to strlen() but strcpy also writes the trailing NUL, so it writes one
 * byte past the allocation. AddressSanitizer catches it as heap-buffer-overflow.
 *
 * This is the kind of bug Sabba must DISCOVER (not be told) — the harness verifies
 * any proposed reproducing input. Do not "fix" this file — it is a fixture.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *dup_token(const char *s) {
    size_t n = strlen(s);
    char *buf = malloc(n);          /* BUG: missing + 1 for the NUL terminator */
    strcpy(buf, s);                 /* writes n + 1 bytes into an n-byte buffer */
    return buf;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s <token>\n", argv[0]);
        return 1;
    }
    char *t = dup_token(argv[1]);
    printf("token=%s\n", t);
    free(t);
    return 0;
}
