# ROPWeaver Phase 3 Step 3.4 — Darwin Mach-O x86_64 Chain Synthesis Acceptance Record

**STATUS:** COMPLETED AND VERIFIED  
**DATE:** 2026-11-15  
**PHASE:** Phase 3 (Step 3.4: Darwin Mach-O x86_64 Chain Synthesis & Semantic Validation)

---

## 1. Executive Summary & Acceptance Scope

This document serves as the formal acceptance record for **Phase 3 Step 3.4** of ROPWeaver. The objective of Step 3.4 is enabling host-independent Darwin Mach-O x86_64 ROP chain synthesis, fail-closed static semantic validation, relocation-transparent JSON reporting, and comprehensive automated test integration using synthetic Mach-O fixtures.

### 1.1 Scope of Changes
1. **Host-Independent Chain Synthesis (`core/chain_builder.h`, `core/chain_builder.cpp`)**:
   - Synthesizes 64-bit Darwin BSD execve syscall chains:
     - `RAX = 0x200003BULL` (`SYS_execve` with 0x2000000 BSD syscall class mask).
     - `RDI = binsh_addr` (executable path pointer).
     - `RSI = argv_addr` (pointer to `{ path_addr, NULL }`).
     - `RDX = envp_addr` (pointer to `{ NULL }`).
     - `syscall` gadget.
   - Resolves `/bin/sh` through Mach-O section mappings.
   - Locates 8-byte aligned valid `argv` pointer array in readable data sections.
   - Locates 8-byte aligned valid `envp` pointer array in readable data sections.
2. **Fail-Closed Semantic Chain Validation (`core/rop_chain.cpp`)**:
   - Requires an active `FileParser` instance; fails closed if parser is missing.
   - Restricts Darwin execve validation to 64-bit Mach-O x86_64 containers.
   - Validates exact syscall number `0x200003BULL`.
   - Validates that Arg 1 (/bin/sh) resolves to a mapped section, verifies string content and null termination, and rejects `S_ZEROFILL` or `__PAGEZERO`.
   - Validates that Arg 2 (argv) is non-zero, has at least 16 file-backed bytes, `argv[0] == path_addr`, and `argv[1] == 0`.
   - Validates that Arg 3 (envp) is non-zero, has at least 8 file-backed bytes, and `envp[0] == 0`.
   - Fails closed on unmapped pointers, zerofill sections, out-of-bounds arrays, and clobbered registers.
3. **Payload Generation & Telemetry (`core/payload_gen.cpp`, `main.cpp`)**:
   - Generates structured JSON report with `target_syscall = "execve (0x200003B)"` and `platform = "macOS Mach-O"`.
   - PIE relocation transparency: records `aslr_slide_applied = false`, `status = "Success (Relocation Required)"`, and explicit notes that link-time Preferred Virtual Addresses require runtime ASLR slide adjustment.
   - Preserves dynamic exploit offset configuration (`--offset`, `-O`).
   - Suppresses native exploit delivery execution one-liners for Mach-O binaries.
4. **Automated Unit & CLI Regression Test Suites (`tests/test_chain_serialization.cpp`, `tests/run_tests.py`)**:
   - Added Group 23 unit tests covering fixture parsing, gadget discovery, 72-byte payload serialization, BSD syscall staging, fail-closed validation across malformed fixtures, fat slice offsets, and PIE reporting (323/323 passed).
   - Added Test 17 to regression runner verifying end-to-end Mach-O auto-chaining, container mitigation telemetry, structured JSON report generation, PIE relocation status, and file confinement inside temporary working directories (299/299 passed).
5. **Operational Boundaries Documentation (`docs/LIMITATIONS.md`, `CHANGELOG.md`)**:
   - Added Section 8 to `docs/LIMITATIONS.md` documenting Darwin operational boundaries, memory layout requirements, and PIE slide requirements.
   - Explicitly documented that native macOS execution has not been tested and is unsupported by this validation.
   - Recorded `[v1.6.2]` release notes in `CHANGELOG.md`.

---

## 2. Technical Specification & Implementation Verification

### 2.1 Darwin Mach-O x86_64 Syscall Convention
In macOS Darwin x86_64, system calls enter via `syscall` using the System V AMD64 register convention with a BSD system call class mask:
- Register `RAX`: System call number `0x200003B` (`(2 << 24) | 59`, where `2` is `SYSCALL_CLASS_BSD` and `59` is `SYS_execve`).
- Register `RDI`: Pointer to null-terminated executable path string (e.g. `"/bin/sh"`).
- Register `RSI`: Pointer to null-terminated argument vector array (`argv[0] = path`, `argv[1] = NULL`).
- Register `RDX`: Pointer to null-terminated environment vector array (`envp[0] = NULL`).

### 2.2 Memory Array Layout & Section Resolution
Darwin's `execve` kernel implementation requires valid pointer arrays in accessible user memory. Literal `0` for `argv` or `envp` is not permitted:
- `findDarwinArgvAddress`: Scans readable non-executable data sections for an 8-byte aligned sequence where `ptr0 == binsh_addr` and `ptr1 == 0`.
- `findDarwinEnvpAddress`: Scans readable non-executable data sections for an 8-byte aligned null pointer (`ptr0 == 0`).
- If no pre-existing valid arrays exist in the target binary, chain synthesis fails with a descriptive error.

### 2.3 Fail-Closed Static Semantic Validation
Validation strictly audits every candidate chain:
- **Parser Requirement**: If a Darwin syscall number is detected without an active `FileParser`, validation fails closed immediately.
- **Section Verification**: Pointers are mapped through `parser->vaToOffsets()` to target sections. Pointers landing in non-file-backed sections (`S_ZEROFILL`), unmapped segments (`__PAGEZERO`), or exceeding section raw file boundaries fail closed.
- **Array Content Verification**: The validator inspects the underlying binary bytes:
  - Arg 1: String must be null-terminated within section bounds and match `"/bin/sh"`.
  - Arg 2: Requires at least 16 file-backed bytes; `argv[0]` must point to Arg 1 path string; `argv[1]` must be `0`.
  - Arg 3: Requires at least 8 file-backed bytes; `envp[0]` must be `0`.
- **Clobber & Control Flow Safety**: Enforces return-oriented control flow rules and rejects any intra-gadget or inter-gadget clobber of staged argument registers.

### 2.4 PIE Relocation Transparency
- For binaries with `MH_PIE` enabled, gadget and data addresses in synthesized chains represent link-time Preferred Virtual Addresses (PVA).
- ROPWeaver emits `aslr_slide_applied = false` in `output.json`.
- The report status is marked `Success (Relocation Required)` with an explicit note: `"Unresolved: Target binary has MH_PIE enabled. Generated chain uses link-time Preferred Virtual Addresses. Dynamic execution requires runtime ASLR slide adjustment."`.

### 2.5 Scope Boundaries & Native Execution Disclaimer
- ROPWeaver performs static chain synthesis and semantic verification.
- **Native macOS execution has not been tested and is explicitly unsupported.**
- Live macOS exploitation requires kernel-level vulnerability discovery, ASLR slide leakage, and environment-specific delivery orchestration outside ROPWeaver's static scope.

---

## 3. Test Verification Results

### 3.1 Unit Test Suite (`build-win/test_chain_serialization.exe`)
- **Compilation Command**:
  ```powershell
  C:\msys64\mingw64\bin\g++.exe -std=c++17 -I. tests/test_chain_serialization.cpp build-win/libropweaver_core.a -Lbuild-win -lcapstone -o build-win/test_chain_serialization.exe
  ```
- **Execution**: Run from isolated temporary directory (`$env:TEMP`).
- **Results**: **323 Passed, 0 Failed** (Exit code 0).
  - Groups 1–22: 100% Passed.
  - Group 23 (Darwin Mach-O x86_64 Chain Synthesis & Validation): All 14 test sets passed (23.1a through 23.14d).

### 3.2 Full Regression Test Suite (`python tests/run_tests.py`)
- **Command**: `python tests/run_tests.py`
- **Results**: **299 Passed, 0 Failed** (Exit code 0).
  - Tests 1–16: 100% Passed.
  - Test 17 (Darwin Mach-O x86_64 Auto-Chain & Payload Generation): 100% Passed.
  - Fail-closed isolation guard: Verified.
  - Immutability of protected baseline artifacts: Verified.

---

## 4. Protected Baseline Artifact Cryptographic Verification

All four protected artifacts were cryptographically audited via SHA-256 before and after execution:

| Artifact Path | Established Baseline SHA-256 Hash | Post-Test SHA-256 Hash | Status |
|---|---|---|---|
| `reports/output.json` | `0CBAF3B45823E96EC56E4C7AAF27B54FB51EE648FC8EDE32CB6C925975928EDE` | `0CBAF3B45823E96EC56E4C7AAF27B54FB51EE648FC8EDE32CB6C925975928EDE` | **UNMODIFIED / MATCH** |
| `payload.bin` | `7D8913B516C83E29AE83F75D42BF619DBCB3D6FA1545ABBED570D826BE39960E` | `7D8913B516C83E29AE83F75D42BF619DBCB3D6FA1545ABBED570D826BE39960E` | **UNMODIFIED / MATCH** |
| `reports/payload.bin` | `7D8913B516C83E29AE83F75D42BF619DBCB3D6FA1545ABBED570D826BE39960E` | `7D8913B516C83E29AE83F75D42BF619DBCB3D6FA1545ABBED570D826BE39960E` | **UNMODIFIED / MATCH** |
| `reports/PHASE_1.2A_KALI_LINUX_NATIVE_VALIDATION.md` | `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855` | `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855` | **UNMODIFIED / MATCH** |

---

## 5. Changed Files Scope

The following files represent the complete set of changes associated with Phase 3 Step 3.4:

1. `core/chain_builder.h`: Mach-O Darwin chain builder methods and structure scanner declarations.
2. `core/chain_builder.cpp`: Darwin `/bin/sh`, `argv`, and `envp` discovery, and BSD syscall chain construction.
3. `core/rop_chain.cpp`: Fail-closed semantic validation for Darwin Mach-O x86_64 chains.
4. `main.cpp`: CLI integration routing Mach-O targets through auto-chain and suppressing native delivery.
5. `core/payload_gen.cpp`: Mach-O JSON report formatting, PIE slide transparency, and raw payload serialization.
6. `tests/test_chain_serialization.cpp`: Group 23 unit test suite.
7. `tests/run_tests.py`: Test 17 CLI regression integration.
8. `docs/LIMITATIONS.md`: Section 8 documenting Darwin Mach-O operational boundaries.
9. `CHANGELOG.md`: Release notes for `[v1.6.2]`.
10. `docs/PHASE_3_STEP_3.4_ACCEPTANCE_RECORD.md`: This formal acceptance record.

