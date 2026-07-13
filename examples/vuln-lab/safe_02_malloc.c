/* SAFE: the allocation reserves room for the NUL (n + 1). This is the correct twin
 * of 02_heap_offbyone.c; Sabba should NOT flag it. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *dup_safe(const char *s) {
    size_t n = strlen(s);
    char *p = malloc(n + 1);
    strcpy(p, s);
    return p;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char *d = dup_safe(argv[1]);
    printf("%s\n", d);
    free(d);
    return 0;
}
