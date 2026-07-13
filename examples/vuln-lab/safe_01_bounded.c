/* SAFE: bounded copy with explicit NUL. Sabba should NOT flag this. */
#include <stdio.h>
#include <string.h>

static void copy_safe(const char *name) {
    char buf[32];
    strncpy(buf, name, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    printf("hello %s\n", buf);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    copy_safe(argv[1]);
    return 0;
}
