# 🧪 Test Binaries for ROPWeaver

This folder contains sample ELF binaries compiled for various architectures to test the functionality of ROPWeaver.

## Notes

- These binaries are compiled with different settings (e.g., PIE enabled/disabled, with/without stack canaries).
- Use cross-compilation toolchains to generate binaries for ARM, RISC-V, etc.

## Example Commands

### x86 ELF (32-bit)
```bash
gcc -m32 -no-pie -fno-stack-protector -o sample_x86.elf test.c

### ARMv7 ELF (requires cross-compiler)
```bash
arm-linux-gnueabi-gcc -no-pie -fno-stack-protector -o sample_armv7.elf test.c

### RISC-V ELF
```bash
riscv64-unknown-elf-gcc -o sample_riscv.elf test.c

