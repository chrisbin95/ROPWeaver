# ROPWeaver - Technical Limitations and Research Scope

This document details known operational boundaries, design assumptions, and future areas of development for ROPWeaver.

## 1. Operating System & ABI Staging
- **Linux Execve Synthesis**: Automated chain synthesis (`--auto-chain`) currently targets Linux x86_64 ABI (`execve("/bin/sh", NULL, NULL)` using `RDI`, `RSI`, `RDX`, `RAX = 59`, `syscall`).
- **Windows PE Staging**: Windows fastcall ABI (`RCX`, `RDX`, `R8`, `R9` + 32-byte shadow space) requires API dispatch through dynamic imports (e.g. `VirtualProtect` or `WinExec` from `KERNEL32.dll`). Automated chain synthesis is explicitly reported as unsupported for Windows PE binaries; discovered gadgets are exported to JSON with exact RVA and file offsets for manual exploit development.
- **macOS Staging**: macOS x86_64 requires BSD syscall masks (`RAX = 0x200003B`); ARM64 enforces Apple Silicon Pointer Authentication (PAC) and branch register dispatch.

## 2. Address Representation and ASLR Enforcement
- **Preferred VA vs. Runtime VA**: For binaries with `DYNAMIC_BASE` (PE) or `PIE` (ELF) enabled, reported gadget addresses represent Preferred Virtual Addresses calculated from the preferred ImageBase. `runtime_va` is explicitly reported as `null` (with a descriptive note explaining OS-level ASLR randomization at process initialization) and is never presented as a guaranteed runtime address.
- **Offset Verification**: Every discovered gadget reports its exact `rva` (Relative Virtual Address) and disk `file_offset` within the mapped section boundaries.

## 3. Mitigation Indicators: Static Compatibility vs. Runtime Enforcement
- **PE Indicators**: ROPWeaver strictly inspects PE Optional Headers, DllCharacteristics, and Load Config Data Directories:
  - `NX_COMPAT`, `DYNAMIC_BASE`, `HIGH_ENTROPY_VA`, `GUARD_CF` indicate static compiler compatibility.
  - `CET_COMPAT` reports `UNKNOWN` when the Load Config Directory is absent, indicating insufficient evidence rather than false certainty.
  - `SafeSEH` reports `NOT_APPLICABLE` for x86_64 targets (which enforce table-based unwind metadata in `.pdata`/`.xdata`).
  - `RELRO` is an ELF-specific mitigation and is never reported on PE targets.

## 2. Gadget Search Depth
- Maximum instruction sequence length defaults to 5 instructions before a terminator instruction (`ret`, `syscall`, `jmp`, etc.) to minimize branch prediction overhead and avoid volatile side-effects.

## 3. ASLR / PIE Relocation
- When ASLR / PIE is enabled, reported addresses represent Preferred Virtual Addresses (VA) relative to the image base. At runtime, an address leak or base address resolution is necessary for exploit execution.

## 4. Stack Canary Heuristics
- Stack cookie / canary detection relies on inspection of import tables and binary symbol strings (`__security_cookie`, `__stack_chk_fail`). Obfuscated or stripped custom stack guards may not be detected by static heuristic scans.

## 5. Exploit Payload Serialization, Dynamic Offset Configuration, and Exploit-Entry Boundaries
- **Architecture-Correct ROP Chain Serialization**: `ROPChain::getPayloadBytes(wordSize, endianness)` deterministically formats gadget addresses and staged values according to target bitness (4-byte words for 32-bit architectures, 8-byte words for 64-bit architectures) and container metadata endianness (`Endianness::Little` vs `Endianness::Big`).
- **Fail-Closed Semantic Gadget Validation**: `ROPChain::validate()` enforces strict, conservative semantic verification for Linux `execve` chains across x86, x86_64, ARMv7, AArch64, RISC-V 32, and RISC-V 64. Invalid chains (missing staged values, clobbered registers, unknown side-effects, reversed load ordering, dynamic or unmodelled stack adjustments, non-terminal traps, and ABI mismatches) fail closed, suppressing `payload.bin` export.
- **Dynamic Exploit Offset Configuration (Phase 3 Step 3.2)**: Exploit payload padding is fully configurable via `--offset <bytes>` and `-O <bytes>`, accepting decimal or hexadecimal (`0x`/`0X`) offsets from 0 up to 16 MiB (`16777216` bytes). When omitted, ROPWeaver preserves the existing default 104-byte padding offset for backward compatibility.
- **Demonstration Default vs. Target Exploitation**: The default 104-byte prefix is a demonstration placeholder matching bundled test fixtures; target-specific buffer overflow offsets, vulnerability discovery, stack canary bypass, and victim stack-frame reconstruction remain outside ROPWeaver's static analysis scope and must be provided by the exploit developer or external tooling.
- **External Exploit-Harness Initial SP Alignment**: For architectures utilizing link-register returns without hardware SP increments (AArch64 via `ret` / `br x30` and RISC-V via `ret`, the pseudo-instruction alias for `jalr x0, 0(ra)`, neither of which increments SP), the initial control transfer must position the runtime stack pointer at `payload + offset + word_size` (pointing directly at the first staged argument value). This initial entry alignment must be orchestrated by the external exploit harness.

## 6. Mach-O Executable Section Aggregation and Gadget Discovery Scope
- **Multi-Section Aggregation**: ROPWeaver aggregates all eligible, file-backed executable Mach-O sections in ascending virtual-address order, inserting 4-byte `0xCC` boundary fences between adjacent sections. Each aggregated section is tracked via its own `ExecBufferMapping` with its exact Preferred Virtual Address and file offset (including universal binary slice offsets exactly once).
- **Supported Architectures**: Mach-O gadget discovery is fully supported for x86 (32-bit), x86_64, and AArch64 (ARM64).
- **ARMv7 Mach-O Deferral**: Mach-O ARMv7 32-bit Thumb mode interworking and gadget discovery are explicitly deferred. Mach-O binaries do not contain ELF-style mapping symbols (`$a`, `$t`, `$d`), and ARMv7 Mach-O has been discontinued across Apple platforms. Stripped ARMv7 Mach-O binaries cannot reliably distinguish Thumb from ARM instruction sequences without full control-flow reconstruction.

## 7. Phase 3 Step 3.1: Architecture Groundwork Scope & Boundaries
- **RISC-V Compressed (RVC) Discovery**:
  - `EF_RISCV_RVC` flag in ELF `e_flags` enables 2-byte backward candidate scanning (`term_rel += 2`, `back += 2`) from terminators (`ret`, `jalr`, `ebreak`, `ecall`) under `ROPW_CS_MODE_RISCVC`.
  - Mixed 16-bit and 32-bit sequences are supported without false positives.
  - Candidates are strictly bounded within mapped section limits; candidates cannot cross section boundaries or synthetic boundary fences.
  - Byte verification (`byte_verified == true`) is enforced against mapped section memory.
- **ARMv7 ELF Mapping Symbols & Dual-Mode Scanning**:
  - Disassembles ARM and Thumb code based on `$a`, `$t`, and `$d` mapping symbols in `.symtab` and `.dynsym`.
  - Data pools (`$d`) are strictly excluded from disassembly, eliminating false positives from literal pools and jump tables.
  - Thumb gadgets expose `entry_address = address | 1` to signify the architectural CPSR T-bit transition for indirect branch dispatch, while `virtual_address` retains even physical alignment for offset resolution.
  - Stripped ARMv7 ELF binaries without mapping symbols safely fall back to pure ARM mode (`CS_MODE_ARM`), deferring speculative heuristic Thumb reconstruction.
- **Link-Register SP Alignment**:
  - For architectures utilizing link-register returns without hardware SP increments (AArch64 `ret` / `br x30` and RISC-V `ret` / `jalr x0, 0(ra)`), the initial exploit delivery harness must align SP at `payload + word_size`.

## 8. Darwin Mach-O x86_64 Chain Synthesis & Operational Boundaries (Phase 3 Step 3.4)
- **Host-Independent Static Synthesis**: Darwin Mach-O x86_64 ROP chain synthesis is supported statically and host-independently across Windows, Linux, and macOS development environments. Automated chain construction targets the 64-bit Darwin BSD system call interface (`SYS_execve = 0x200003B`) with System V AMD64 register conventions (`RDI = path`, `RSI = argv`, `RDX = envp`, `RAX = 0x200003B`, `syscall`).
- **Memory Structure Requirements**: Darwin `execve` requires valid, readable pointer arrays in memory: `argv` must be an 8-byte aligned array `{ path_addr, NULL }`, and `envp` must be an 8-byte aligned array `{ NULL }`. ROPWeaver discovers these structures via Mach-O section mappings. Chains targeting binaries lacking pre-existing, file-backed string or pointer structures fail closed during static semantic validation.
- **Fail-Closed Semantic Validation**: Validation requires an active `FileParser` to verify section containment, non-zerofill status, and memory layout. Any chain containing unmapped pointers, corrupted null terminators, mismatched syscall indices, or non-file-backed memory fails validation and suppresses payload generation.
- **PIE Runtime Relocation Transparency**: For position-independent executables (`MH_PIE`), generated chains utilize link-time Preferred Virtual Addresses (PVA). Dynamic execution requires external ASLR slide calculation (`runtime_va = preferred_va + aslr_slide`). ROPWeaver emits `aslr_slide_applied = false` and marks report status as `Success (Relocation Required)` without applying synthetic runtime relocations.
- **Native macOS Execution Excluded**: Native macOS exploitation and runtime delivery have NOT been tested and remain explicitly unsupported by this verification. ROPWeaver performs static chain synthesis and verification only, without guaranteeing victim process control-flow hijacking on live macOS kernels.

## 9. Unified Regression Runner Confinement & Platform Execution Scope (Phase 3 Step 3.5)
- **Unified Test Runner Isolation**: The unified regression harness (`tests/run_tests.py`) standardizes compilation and execution across all 18 test groups within temporary isolated directories (`isolated_dir / "bin"`), preventing artifact leakage or modification of root repository files.
- **Mach-O Standalone Test Integration**: Phase 2 Mach-O detection, parsing, and gadget discovery coverage (`tests/test_macho_detection.cpp`) is fully integrated into the unified runner as Test 18, executing 541 assertions across 18 functional groups.
- **Native macOS Execution Excluded**: While Darwin Mach-O x86_64 ROP chain synthesis, structure resolution, and fail-closed validation are host-independent and fully verified under Windows and Linux cross-environments, live runtime exploit execution and dynamic memory injection on native macOS kernels remain untested and explicitly out of scope.
