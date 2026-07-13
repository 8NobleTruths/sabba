/* VULNERABLE: CWE-122 heap buffer overflow. dup_str sizes the allocation with
 * strlen() but strcpy also writes the trailing NUL, one byte past the buffer. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *dup_str(const char *s) {
    size_t n = strlen(s);
    char *p = malloc(n);
    strcpy(p, s);
    return p;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char *d = dup_str(argv[1]);
    printf("%s\n", d);
    free(d);
    return 0;
}
