// test.c - a simple program for generating ELF binaries

#include <stdio.h>
#include <string.h>

void print_hello() {
    printf("Hello, ROPWeaver!\n");
}

int add(int a, int b) {
    return a + b;
}

void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // unsafe function for ROP gadgets
    printf("Input was: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable_function(argv[1]);
    } else {
        print_hello();
    }
    int result = add(2, 3);
    printf("Add result: %d\n", result);
    return 0;
}
