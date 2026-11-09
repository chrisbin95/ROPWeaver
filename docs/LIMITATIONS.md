# ROPWeaver - Technical Limitations and Research Scope

This document details known operational boundaries, design assumptions, and future areas of development for ROPWeaver.

## 1. Operating System & ABI Staging
- **Linux Execve Synthesis**: Automated chain synthesis (`--auto-chain`) currently targets Linux x86_64 ABI (`execve("/bin/sh", NULL, NULL)` using `RDI`, `RSI`, `RDX`, `RAX = 59`, `syscall`).
- **Windows PE Staging**: Windows fastcall ABI (`RCX`, `RDX`, `R8`, `R9` + 32-byte shadow space) requires API dispatch through imports (e.g. `VirtualProtect` or `WinExec` from `KERNEL32.dll`). Auto-chain generation identifies missing staging gadgets and reports required calling conventions.
- **macOS Staging**: macOS x86_64 requires BSD syscall masks (`RAX = 0x200003B`); ARM64 enforces Apple Silicon Pointer Authentication (PAC) and branch register dispatch.

## 2. Gadget Search Depth
- Maximum instruction sequence length defaults to 5 instructions before a terminator instruction (`ret`, `syscall`, `jmp`, etc.) to minimize branch prediction overhead and avoid volatile side-effects.

## 3. ASLR / PIE Relocation
- When ASLR / PIE is enabled, reported addresses represent Preferred Virtual Addresses (VA) relative to the image base. At runtime, an address leak or base address resolution is necessary for exploit execution.

## 4. Stack Canary Heuristics
- Stack cookie / canary detection relies on inspection of import tables and binary symbol strings (`__security_cookie`, `__stack_chk_fail`). Obfuscated or stripped custom stack guards may not be detected by static heuristic scans.
