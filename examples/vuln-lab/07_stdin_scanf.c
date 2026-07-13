/* VULNERABLE: CWE-121, unbounded scanf("%s") reads stdin into a 16-byte buffer. */
#include <stdio.h>

int main(void) {
    char name[16];
    scanf("%s", name);
    printf("hi %s\n", name);
    return 0;
}
