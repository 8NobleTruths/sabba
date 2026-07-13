/* VULNERABLE: CWE-121, source flows through a local assigned from argv. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char dst[20];
    char *input = argv[1];
    strcpy(dst, input);
    printf("%s\n", dst);
    return 0;
}
