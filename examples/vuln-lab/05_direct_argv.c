/* VULNERABLE: CWE-121, argv used directly in strcpy (no wrapper function). */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char buf[24];
    strcpy(buf, argv[1]);
    printf("%s\n", buf);
    return 0;
}
