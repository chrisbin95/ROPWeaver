// binsh_gadgets.c
#include <stdio.h>
#include <string.h>

char binsh[] = "/bin/sh";

void dummy() {
    asm(
        "pop %rdi; ret;"
        "pop %rsi; ret;"
        "pop %rdx; ret;"
        "pop %rax; ret;"
        "syscall;"
    );
}

int main() {
    printf("Embedded /bin/sh: %s\n", binsh);
    return 0;
}
