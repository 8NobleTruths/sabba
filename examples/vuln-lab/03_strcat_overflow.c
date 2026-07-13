/* VULNERABLE: CWE-121 via strcat. build() prepends a prefix then appends an
 * argv-controlled name into a fixed 64-byte buffer with no room check. */
#include <stdio.h>
#include <string.h>

void build(const char *name) {
    char path[64];
    strcpy(path, "/data/");
    strcat(path, name);
    printf("path=%s\n", path);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    build(argv[1]);
    return 0;
}
