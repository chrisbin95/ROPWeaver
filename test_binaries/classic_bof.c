#include <stdio.h>
#include <stdlib.h>

char binsh_str[] = "/bin/sh";

void vulnerable_function() {
    char buffer[64];
    printf("[+] Enter input: ");
    gets(buffer); // Vulnerable unbound input
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== ROPWeaver Benchmark Binary ===\n");
    printf("[i] Target /bin/sh string at: %p\n", binsh_str);
    vulnerable_function();
    return 0;
}