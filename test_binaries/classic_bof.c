#include <stdio.h>
#include <stdlib.h>

char binsh_str[] = "/bin/sh";

// Benchmark gadget harness: provides register staging gadgets for ROP synthesizer benchmarks
#if defined(__x86_64__) || defined(_M_X64)
void gadget_farm() {
    __asm__ volatile ("pop %rdi; ret;");
    __asm__ volatile ("pop %rsi; ret;");
    __asm__ volatile ("pop %rdx; ret;");
    __asm__ volatile ("pop %rax; ret;");
    __asm__ volatile ("syscall; ret;");
}
#endif

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