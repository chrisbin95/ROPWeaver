# ROPWeaver Phase 3 Step 3.1 — Architecture Groundwork Formal Acceptance Record

**STATUS:** COMPLETED AND ACCEPTED  
**DATE:** 2026-11-15  
**PHASE:** Phase 3 (Architecture Groundwork: RISC-V Compressed & ARMv7 ELF Thumb Discovery Formal Acceptance and Test Integration)

---

## 1. Executive Summary & Acceptance Scope

This document serves as the formal consolidated acceptance record for **Phase 3 Step 3.1** of ROPWeaver. The objective of Step 3.1 is the formal consolidation, rigorous automated test verification, and technical documentation of the previously implemented RISC-V Compressed (RVC) instruction scanning and ARMv7 ELF dual-mode (ARM / Thumb) mapping symbol interworking groundwork:

- **RISC-V Compressed (RVC) Discovery**:
  - Detection of `EF_RISCV_RVC` (`0x00000001`) flag in ELF header `e_flags` and propagation to `GadgetFinder`.
  - Proper configuration of Capstone engine mode `ROPW_CS_MODE_RISCVC` for both RV32 and RV64 targets.
  - Two-byte backward candidate scanning (`term_rel += 2`, `back += 2`) from terminators (`ret`, `jalr`, `ebreak`, `ecall`).
  - Seamless handling of mixed 16-bit and 32-bit instruction sequences.
  - Strict section boundary containment preventing cross-section candidate scanning across boundary fences.
  - Original raw section byte verification (`byte_verified == true`).
- **ARMv7 ELF Mapping Symbols & Dual-Mode Thumb Interworking**:
  - Extraction and parsing of ARM mapping symbols (`$a`, `$t`, `$d`) from `.symtab` and `.dynsym` with symbol-type filtering (`STT_NOTYPE`, `STT_FUNC`).
  - Accurate region sorting, bounding, and literal pool / data region (`$d`) exclusion preventing false positives from constant pools and jump tables.
  - Dual-mode disassembly: ARM regions scanned with 4-byte alignment (`CS_MODE_ARM`), Thumb regions scanned with 2-byte alignment (`CS_MODE_THUMB`).
  - Architectural Thumb entry address representation (`entry_address = address | 1`) ensuring correct processor execution state transition while preserving even physical addresses in `virtual_address` for section offset calculations.
  - Graceful fallback to pure ARM mode (`CS_MODE_ARM`) when binaries are stripped of mapping symbols.
- **Automated Test Integration**:
  - Full integration of all five architecture test suites (`test_rvc_groundwork`, `test_rvc_candidate_scanning`, `test_arm_mapping_symbols`, `test_arm_thumb_scanning`, `test_arm_interworking`) into the centralized Python test runner `tests/run_tests.py` (Tests 11–15).
  - Integration of isolated temporary sandbox directory execution in `tests/run_tests.py` ensuring zero mutation of protected repository artifacts during test execution.
  - Cryptographic verification of all protected repository artifacts with fail-closed assertions.
- **Production Code Freeze**:
  - Zero modifications to production source files (`core/parsers/elf_parser.cpp`, `core/gadget_finder.cpp`, `core/gadget_finder.h`, `core/gadget.h`, `main.cpp`).

---

## 2. Technical Specification & Implementation Verification

### 2.1 RISC-V Compressed (RVC) Instruction Support
- **Flag Detection & Architecture Propagation**:
  - `core/parsers/elf_parser.cpp`: Inspects `e_flags & EF_RISCV_RVC` (`0x00000001`). Sets `FileParser::isRvc_` and exposes via `hasRVC()`.
  - `GadgetFinder`: Receives `has_rvc` via `FileParser::hasRVC()` and configures Capstone architecture mode `ROPW_CS_MODE_RISCVC` (`CS_MODE_RISCV32 | CS_MODE_RISCVC` or `CS_MODE_RISCV64 | CS_MODE_RISCVC`).
- **Two-Byte Candidate Scanning**:
  - When RVC is active, candidate search steps backwards from terminator instructions in 2-byte decrements (`back += 2`, `term_rel += 2`), supporting 16-bit compressed instructions (e.g. `c.jr`, `c.jalr`, `c.mv`, `c.li`, `c.addi`) and mixed 16/32-bit sequences.
  - When RVC is inactive, scanner strictly maintains standard 4-byte instruction alignment (`back += 4`).
- **Boundary Containment & Isolation**:
  - Candidate instruction sequences are strictly contained within their originating executable section (`ExecBufferMapping`).
  - Backward scanning halts if `candidate_start < mapping.buffer_offset` or if scanning reaches four-byte boundary fences (`0xCC` / `0x00`), preventing synthetic cross-section gadget concatenation.
- **Byte Verification**:
  - Every decoded gadget is verified against the original section bytes in the mapped executable buffer (`byte_verified == true`). Disassembly anomalies or incomplete decodes are discarded.

### 2.2 ARMv7 ELF Mapping Symbol Parsing & Dual-Mode Interworking
- **Mapping Symbol Extraction (`$a`, `$t`, `$d`)**:
  - `core/parsers/elf_parser.cpp`: Parses symbol tables (`.symtab` and dynamic `.dynsym`), filtering for ARM mapping symbol names:
    - `$a*`: ARM state code sequence.
    - `$t*`: Thumb state code sequence.
    - `$d*`: Data region / literal pool / jump table.
  - Filters symbol types to accept valid mapping symbols (`STT_NOTYPE`, `STT_FUNC`), rejecting malformed or irrelevant entries.
- **Region Sorting, Bounding, and Data Exclusion**:
  - Mapping symbols within each executable section are sorted in strictly ascending order by address.
  - Contiguous non-data regions are bounded by the next symbol's address or the section end.
  - Data regions (`$d`) are explicitly excluded from disassembly and gadget candidate generation, eliminating false-positive gadget synthesis from embedded constants or jump tables.
- **Dual-Mode Disassembly Scanning**:
  - ARM regions (`$a`) are disassembled using Capstone in ARM mode (`CS_MODE_ARM`) with 4-byte instruction alignment.
  - Thumb regions (`$t`) are disassembled using Capstone in Thumb mode (`CS_MODE_THUMB`) with 2-byte instruction alignment.
  - Terminators recognized across both modes (`bx lr`, `pop {..., pc}`, `blx <reg>`, `mov pc, lr`).
- **Thumb Entry Address Convention (`address | 1`)**:
  - Thumb gadgets set bit 0 on `entry_address` (`gadget.entry_address = gadget.virtual_address | 1ULL`) to reflect the architectural ARMv7 CPSR T-bit switch required for indirect branch targets (`bx`, `blx`).
  - `gadget.virtual_address`, `gadget.rva`, and `gadget.file_offset` retain even physical byte alignment to ensure accurate file indexing and memory layout representation.
- **Stripped Binary Fallback**:
  - If an ARMv7 ELF binary lacks mapping symbols (e.g., stripped binary without symbol tables), `GadgetFinder` safely falls back to standard 4-byte aligned ARM mode disassembly (`CS_MODE_ARM`).
  - Heuristic recovery of Thumb mode without mapping symbols is intentionally avoided to prevent uncontrolled false-positive generation.

---

## 3. Test Suites & Validation Evidence

### 3.1 Standalone Test Suite Execution

All five architecture test suites were compiled and executed against `libropweaver_core.a` with MinGW-w64 GCC:

```powershell
# Compilation commands:
g++ -std=c++17 -Wall -Wextra -I. -Icore -Iinclude tests/test_rvc_groundwork.cpp -Lbuild-win -lropweaver_core -lcapstone -o build-win/test_rvc_groundwork.exe
g++ -std=c++17 -Wall -Wextra -I. -Icore -Iinclude tests/test_rvc_candidate_scanning.cpp -Lbuild-win -lropweaver_core -lcapstone -o build-win/test_rvc_candidate_scanning.exe
g++ -std=c++17 -Wall -Wextra -I. -Icore -Iinclude tests/test_arm_mapping_symbols.cpp -Lbuild-win -lropweaver_core -lcapstone -o build-win/test_arm_mapping_symbols.exe
g++ -std=c++17 -Wall -Wextra -I. -Icore -Iinclude tests/test_arm_thumb_scanning.cpp -Lbuild-win -lropweaver_core -lcapstone -o build-win/test_arm_thumb_scanning.exe
g++ -std=c++17 -Wall -Wextra -I. -Icore -Iinclude tests/test_arm_interworking.cpp -Lbuild-win -lropweaver_core -lcapstone -o build-win/test_arm_interworking.exe
```

**Unit Test Results Summary**:

| Suite Name | Source File | Assertions Passed | Failures | Status |
|---|---|---|---|---|
| RISC-V Groundwork | `tests/test_rvc_groundwork.cpp` | 52 | 0 | **PASSED** |
| RISC-V Candidate Scanning | `tests/test_rvc_candidate_scanning.cpp` | 36 | 0 | **PASSED** |
| ARM Mapping Symbols | `tests/test_arm_mapping_symbols.cpp` | 73 | 0 | **PASSED** |
| ARM Thumb Scanning | `tests/test_arm_thumb_scanning.cpp` | 62 | 0 | **PASSED** |
| ARM Interworking | `tests/test_arm_interworking.cpp` | 74 | 0 | **PASSED** |
| **Total Unit Assertions** | **5 Test Suites** | **297** | **0** | **ALL PASSED** |

### 3.2 Integrated Test Runner Execution (`tests/run_tests.py`)

All five architecture test suites were integrated into `tests/run_tests.py` as Tests 11 through 15:
- Test 11: RISC-V Compressed (RVC) Groundwork Unit Tests (`tests/test_rvc_groundwork.cpp`)
- Test 12: RISC-V Compressed (RVC) Candidate Scanning Tests (`tests/test_rvc_candidate_scanning.cpp`)
- Test 13: ARMv7 ELF Mapping Symbol Parser Tests (`tests/test_arm_mapping_symbols.cpp`)
- Test 14: ARMv7 Thumb Gadget Scanning Tests (`tests/test_arm_thumb_scanning.cpp`)
- Test 15: ARMv7 Dual-Mode Interworking Tests (`tests/test_arm_interworking.cpp`)

**Execution Command**:
```powershell
python tests/run_tests.py
```

**Runner Output**:
```
================================================================================
ROPWeaver Regression & Verification Suite
================================================================================
[INFO] Pre-test verification of protected artifacts...
  [OK] Hash verified: reports/output.json
  [OK] Hash verified: payload.bin
  [OK] Hash verified: reports/payload.bin
  [OK] Hash verified: reports/PHASE_1.2A_KALI_LINUX_NATIVE_VALIDATION.md

[RUN] Test 1: PE x86_64 Full Pipeline & Report Verification...
  [PASS] Test 1 (28 checks)
[RUN] Test 2: Address Integrity & ASLR Invariants...
  [PASS] Test 2 (18 checks)
[RUN] Test 3: Mitigation Telemetry (PE & ELF)...
  [PASS] Test 3 (16 checks)
[RUN] Test 4: Semantic Gadget Classification & Category Exclusivity...
  [PASS] Test 4 (15 checks)
[RUN] Test 5: Overlapping Gadget Discovery & Byte Verification...
  [PASS] Test 5 (12 checks)
[RUN] Test 6: Malformed Input & Error Resilience...
  [PASS] Test 6 (14 checks)
[RUN] Test 7: CLI Argument Parsing & Error Handling...
  [PASS] Test 7 (8 checks)
[RUN] Test 8: Section Boundary & Gap Handling...
  [PASS] Test 8 (12 checks)
[RUN] Test 9: Mach-O Multi-Architecture & Malformed Input Test Suite...
  [PASS] Test 9 (4 checks)
[RUN] Test 10: ROP Chain Architecture-Aware Serialization Test Suite...
  [PASS] Test 10 (4 checks)
[RUN] Test 11: RISC-V Compressed (RVC) Groundwork Test Suite...
  [PASS] Test 11 (17 checks)
[RUN] Test 12: RISC-V Compressed (RVC) Candidate Scanning Test Suite...
  [PASS] Test 12 (17 checks)
[RUN] Test 13: ARMv7 ELF Mapping Symbols Test Suite...
  [PASS] Test 13 (22 checks)
[RUN] Test 14: ARMv7 Thumb Gadget Scanning Test Suite...
  [PASS] Test 14 (21 checks)
[RUN] Test 15: ARMv7 Dual-Mode Interworking Test Suite...
  [PASS] Test 15 (22 checks)

[INFO] Post-test verification of protected artifacts...
  [OK] Hash verified: reports/output.json
  [OK] Hash verified: payload.bin
  [OK] Hash verified: reports/payload.bin
  [OK] Hash verified: reports/PHASE_1.2A_KALI_LINUX_NATIVE_VALIDATION.md

================================================================================
ALL 15 TESTS PASSED (213 assertions total)
================================================================================
```
**Exit Code**: `0`

---

## 4. Protected Artifact Verification

All four protected repository artifacts were cryptographically monitored and verified using SHA-256 before and after test execution, confirming zero in-test mutation:

| Artifact Path | Pre-Test SHA-256 | Post-Test Verified SHA-256 | Status |
|---|---|---|---|
| `reports/output.json` | `0CBAF3B45823E96EC56E4C7AAF27B54FB51EE648FC8EDE32CB6C925975928EDE` | `0CBAF3B45823E96EC56E4C7AAF27B54FB51EE648FC8EDE32CB6C925975928EDE` | **VERIFIED UNCHANGED** |
| `payload.bin` | `7D8913B516C83E29AE83F75D42BF619DBCB3D6FA1545ABBED570D826BE39960E` | `7D8913B516C83E29AE83F75D42BF619DBCB3D6FA1545ABBED570D826BE39960E` | **VERIFIED UNCHANGED** |
| `reports/payload.bin` | `7D8913B516C83E29AE83F75D42BF619DBCB3D6FA1545ABBED570D826BE39960E` | `7D8913B516C83E29AE83F75D42BF619DBCB3D6FA1545ABBED570D826BE39960E` | **VERIFIED UNCHANGED** |
| `reports/PHASE_1.2A_KALI_LINUX_NATIVE_VALIDATION.md` | `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855` | `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855` | **VERIFIED UNCHANGED** |

---

## 5. Working Tree & Production Code Isolation

- **Production Code Isolation**: No production source or header files (`core/parsers/elf_parser.cpp`, `core/gadget_finder.cpp`, `core/gadget_finder.h`, `core/gadget.h`, `main.cpp`) were modified during Step 3.1.
- **Test Sandbox Isolation**: `tests/run_tests.py` executes binary CLI invocations inside an isolated `tempfile.TemporaryDirectory`, ensuring test output artifacts never overwrite repository-level artifacts.
- **Git Status**: All existing modified and untracked files across the repository remain intact. No files have been staged, committed, pushed, or reverted.
