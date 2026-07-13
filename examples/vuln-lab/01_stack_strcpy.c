/* VULNERABLE: CWE-121 stack buffer overflow. copy_name copies an argv-controlled
 * string into a fixed 32-byte stack buffer with no bound. */
#include <stdio.h>
#include <string.h>

void copy_name(const char *name) {
    char buf[32];
    strcpy(buf, name);
    printf("hello %s\n", buf);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    copy_name(argv[1]);
    return 0;
}
