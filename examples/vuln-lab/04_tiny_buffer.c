/* VULNERABLE: CWE-121 stack overflow into a very small buffer. store() copies an
 * argv-controlled token into an 8-byte slot. */
#include <stdio.h>
#include <string.h>

static void store(const char *token) {
    char slot[8];
    strcpy(slot, token);
    printf("stored %s\n", slot);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    store(argv[1]);
    return 0;
}
