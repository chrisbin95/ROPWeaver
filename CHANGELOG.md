# ROPWeaver Changelog

All notable changes to the ROPWeaver framework are documented in this file.

## [v1.6.3] - Phase 3 Step 3.5: Unified Regression Runner Finalization & Test Isolation Standardization

### 1. Unified Regression Runner Integration (Test 18)
- **Phase 2 Mach-O Integration**: Integrated the orphaned Phase 2 standalone Mach-O test suite (`tests/test_macho_detection.cpp`) as Test 18 in `tests/run_tests.py`.
- **Complete Suite Execution**: Test 18 compiles `tests/test_macho_detection.cpp` with `-std=c++17`, `-I{PROJECT_ROOT}`, `-I{PROJECT_ROOT}/core`, linking against `libropweaver_core.a` and `-lcapstone`.
- **Comprehensive Coverage**: Executes all 541 assertions across Groups 1–18 (thin Mach-O headers, universal fat binary parsing, CPU architecture extraction, negative/malformed boundary validation, 32/64-bit load commands, non-first section ordering, zero-fill section handling, big-endian command decoding, mitigations, and gadget discovery) with 0 failures and exit code 0.
- **Darwin Status Assertion Modernization**: Modernized legacy Phase 2 Step 5.6 assertions (lines 3095–3096) in `tests/test_macho_detection.cpp` to validate against the accepted Phase 3 Step 3.4 Darwin Mach-O chain synthesis output (`status = "Failed: Required gadgets missing for Darwin execve chain synthesis"` and `target_syscall = "execve (0x200003B)"`) instead of the obsolete stubbed strings.

### 2. Standalone Test Isolation Standardization (Tests 8–10)
- **Temporary Build Confinement**: Updated Tests 8, 9, and 10 (`test_endian_readers`, `test_endian_classification`, `test_gadget_finder_endianness`) to compile their binaries into `test_build_dir` (`isolated_dir / "bin"`) rather than `build-win/` or repository source directories.
- **Isolated Working-Directory Execution**: Standardized execution of Tests 8–10 to execute strictly with `cwd=str(isolated_dir)`, mirroring read-only fixtures into `isolated_dir / "test_binaries"` to prevent any modification or side effects within the main workspace.
- **Untracked Artifact Protection**: Ensured that the untracked binary `tests/test_macho_detection.exe` is never executed, overwritten, or reused.

### 3. Full Regression Verification & Protected Artifact Immutability
- **Unified Test Results**: All 18 tests in `tests/run_tests.py` execute and pass with 303 passed assertions and 0 failures. Standalone `test_chain_serialization.exe` executes and passes with 331 passed assertions and 0 failures. Standalone `test_macho_detection.exe` executes and passes with 541 passed assertions and 0 failures.
- **Cryptographic Immutability**: All four protected baseline artifacts (`reports/output.json`, `payload.bin`, `reports/payload.bin`, `reports/PHASE_1.2A_KALI_LINUX_NATIVE_VALIDATION.md`) cryptographically verified against baseline SHA-256 hashes before and after runner execution.

## [v1.6.2] - Phase 3 Step 3.4: Darwin Mach-O x86_64 Chain Synthesis & Semantic Validation

### 1. Host-Independent Darwin Mach-O x86_64 ROP Chain Synthesis
- **Darwin BSD System Call Integration**: Implemented host-independent ROP chain synthesis for 64-bit Darwin Mach-O x86_64 targets using BSD system call conventions (`RAX = 0x200003BULL` for `SYS_execve`, `RDI = path`, `RSI = argv`, `RDX = envp`, `syscall`).
- **Section-Aware String & Structure Resolution**: Implemented section-level mapping discovery resolving `/bin/sh` from mapped `__cstring` or data sections, locating 8-byte aligned valid `argv` pointer arrays `{ path, NULL }`, and discovering 8-byte aligned `envp` pointer arrays `{ NULL }` in readable non-executable data sections.
- **Fail-Closed Semantic Validation**: Extended `ROPChain::validate()` to strictly enforce Darwin ABI requirements fail-closed. Rejects chains missing an active `FileParser`, verifies container 64-bit x86_64 Mach-O architecture, enforces exact syscall number `0x200003B`, verifies path null-termination and string content, checks file-backed readable pointer arrays, and rejects zero-fill sections (`S_ZEROFILL`), unmapped memory, and `__PAGEZERO`.
- **Relocation Transparency**: Integrated PIE relocation reporting in `core/payload_gen.cpp`. Emits `aslr_slide_applied = false`, `status = "Success (Relocation Required)"`, and notes that link-time Preferred Virtual Addresses require runtime ASLR slide calculation for dynamic execution.
- **Scope Exclusion**: Native macOS exploitation and live execution delivery remain explicitly unsupported and untested. Delivery execution prompts are suppressed for Mach-O binaries.

### 2. Regression Testing & Test Integration
- **Unit Test Coverage (Group 23)**: Added Group 23 to `tests/test_chain_serialization.cpp` testing canonical Mach-O fixtures, gadget discovery, 72-byte payload serialization, BSD syscall number staging, fail-closed validation across malformed fixtures (null parser, invalid syscall number, zero pointers, invalid argv/envp contents, zerofill sections, out-of-bounds arrays), fat binary slice offset resolution, and PIE report metadata (323/323 unit assertions passed).
- **Automated CLI Pipeline Integration (Test 17)**: Added Test 17 to `tests/run_tests.py` testing end-to-end Mach-O auto-chaining, container mitigation telemetry, structured JSON report generation, PIE relocation status, and strict file confinement within isolated temporary working directories (299/299 total runner tests passed).

## [v1.6.1] - Phase 3 Step 3.2: Dynamic Exploit Offset Configuration

### 1. Dynamic Exploit Payload Padding Configuration (Phase 3 Step 3.2)
- **Configurable Exploit Offset**: Introduced `--offset <bytes>` and `-O <bytes>` CLI options to allow dynamic configuration of the exploit payload prefix padding.
- **Backward Compatibility**: Preserved exact default 104-byte padding when no offset option is provided, ensuring zero behavioral regression for existing scripts and pipelines.
- **Strict Input Validation**: Implemented multi-stage input validation rejecting negative numbers (`-10`), explicit plus signs (`+104`), malformed strings (`abc`), trailing characters (`104xyz`), flag-as-argument (`--offset -p`), missing arguments, numerical overflow (`ERANGE`), values exceeding `size_t::max()`, and offsets exceeding the 16 MiB ceiling (`16777216` bytes).
- **Fail-Closed Argument Parsing**: Malformed or invalid offset options reliably fail parsing (`CLIOptions.valid = false`), printing descriptive diagnostics and usage help, and causing process exit code `1`.
- **Flexible Numeric Radix**: Supports decimal and standard hexadecimal notation (`0x`/`0X`), with zero (`0` / `0x0`) accepted as a valid boundary offset.

### 2. Payload Generation & Telemetry Integration (Phase 3 Step 3.2)
- **Payload Synthesis Integration**: Forwarded user-configured or default `exploitOffset` through `main.cpp` to `PayloadGenerator::generate(..., paddingSize, ...)`.
- **Console Telemetry**: Emits explicit console telemetry during payload generation indicating the selected offset and whether it is default or user-configured (`[*] Exploit padding offset: <N> bytes (<default|user-configured>)`).
- **Structured JSON Reporting**: Correctly records the selected offset in `raw_payload.verified_padding_offset` within generated JSON reports for programmatic verification.

### 3. Automated Regression Testing & Fail-Closed Guard (Phase 3 Step 3.2)
- **Unit Test Coverage (Group 22)**: Added Group 22 to `tests/test_chain_serialization.cpp` verifying payload file generation, total length calculation, prefix padding byte content (`'A'`), chain placement, and JSON metadata across default (104), custom decimal (208), hex (128), zero boundary (0), and large (4096) offsets (282/282 assertions passed).
- **CLI Pipeline Test Integration (Test 16)**: Added Test 16 to `tests/run_tests.py` testing default offsets, custom decimal offsets, short alias `-O`, hex offsets, zero offsets, large offsets, and exhaustive invalid input rejection (14 CLI test scenarios).
- **Protected Working-Directory Guard**: Implemented fail-closed protection in `run_command()` within `tests/run_tests.py` that raises a fatal `RuntimeError` if any payload-generating command (`-p`, `--payload`, `--payload-gen`) attempts execution in `PROJECT_ROOT` without an isolated working directory.
- **Protected Artifact Immutability**: All four protected baseline artifacts cryptographically verified via SHA-256 before and after runner execution (252/252 tests passed).

## [v1.6.0] - Phase 3 Step 3.1: Architecture Groundwork Formal Acceptance & Test Integration

### 1. RISC-V Compressed (RVC) Instruction Support (Phase 3 Step 3.1)
- **Flag Detection & Capstone Engine Configuration**: Detects `EF_RISCV_RVC` in ELF `e_flags` and initializes Capstone mode `ROPW_CS_MODE_RISCVC` for RV32 and RV64 targets.
- **Two-Byte Candidate Scanning**: Supports 2-byte backward scanning (`term_rel += 2`, `back += 2`) from terminators (`ret`, `jalr`, `ebreak`, `ecall`), correctly decoding 16-bit compressed instructions and mixed 16/32-bit sequences.
- **Section Boundary Containment**: Confines candidate discovery strictly to mapped executable section bounds, halting prior to boundary fences.
- **Byte Verification**: Validates all decoded gadget instruction bytes against mapped buffer contents (`byte_verified == true`).

### 2. ARMv7 ELF Mapping Symbol Parsing & Dual-Mode Interworking (Phase 3 Step 3.1)
- **Mapping Symbol Extraction**: Extracts ARM mapping symbols (`$a`, `$t`, `$d`) from `.symtab` and `.dynsym` with symbol-type filtering (`STT_NOTYPE`, `STT_FUNC`).
- **Data Region Exclusion**: Sorts and bounds mapping symbol regions, explicitly excluding literal pools and jump tables (`$d`) from disassembly scanning to prevent false-positive gadget generation.
- **Dual-Mode Disassembly**: Disassembles ARM regions with 4-byte instruction alignment (`CS_MODE_ARM`) and Thumb regions with 2-byte instruction alignment (`CS_MODE_THUMB`).
- **Thumb Entry Address**: Sets bit 0 on `entry_address` (`gadget.entry_address = gadget.virtual_address | 1ULL`) to reflect architectural Thumb execution mode, while retaining even physical byte alignment in `virtual_address` for section offset calculations.
- **Stripped Binary Fallback**: Falls back gracefully to standard 4-byte aligned ARM mode disassembly (`CS_MODE_ARM`) when binaries lack mapping symbols.

### 3. Automated Test Suite Integration & Protection (Phase 3 Step 3.1)
- **Runner Integration**: Integrated all five architecture test suites (`test_rvc_groundwork`, `test_rvc_candidate_scanning`, `test_arm_mapping_symbols`, `test_arm_thumb_scanning`, `test_arm_interworking`) into `tests/run_tests.py` as Tests 11 through 15.
- **Isolated Sandbox Execution**: Updated `tests/run_tests.py` to run CLI pipeline tests inside an isolated temporary directory, eliminating any risk of overwriting repository-level protected artifacts.
- **Protected Artifact Integrity**: All 4 protected baseline artifacts cryptographically verified via SHA-256 before and after runner execution.
- **Verification Results**: 213/213 checks passed in `tests/run_tests.py`; 297/297 unit test assertions passed across the 5 architecture test suites.

## [v1.5.0] - Phase 2: Mach-O Parsing, Multi-Section Executable Aggregation, and Gadget Discovery (Steps 5.3, 5.4, 5.5, 5.6, 6 Accepted)

### 1. Mach-O Thin and Universal Binary Parsing (Phase 2 Steps 5.3, 5.4, 5.5)
- **Thin Mach-O Parser**: Implemented robust native-endian parsing for 32-bit (`MH_MAGIC`, `MH_CIGAM`) and 64-bit (`MH_MAGIC_64`, `MH_CIGAM_64`) Mach-O binaries supporting Little-Endian and Big-Endian metadata across x86, x86_64, and AArch64.
- **Universal / Fat Binaries**: Implemented full `fat_header`, `fat_arch`, and `fat_arch_64` container parsing with slice boundary checks, strict power-of-two alignment verification, slice overlap prevention, and deterministic slice architecture selection.
- **Parser Factory Routing**: Extended `ArchDetector::createFileParser()` to recognize thin and universal Mach-O binaries, propagating explicit target architectures to universal slice selection.

### 2. Multi-Section Executable Aggregation & Boundary Fence Isolation (Phase 2 Step 6)
- **Ascending Virtual-Address Order**: Aggregates all eligible, file-backed executable Mach-O sections in strict ascending order of virtual address (`std::sort`).
- **Four-Byte INT3 Boundary Fences**: Inserts exactly four `0xCC` fence bytes between adjacent sections (`i > 0`), ensuring no fence bytes precede the first or succeed the last section. Prevents synthetic cross-section gadget discovery across discontinuous virtual memory.
- **Accurate Buffer Mappings**: Each aggregated section is mapped via its own `ExecBufferMapping` where `buffer_offset` and `size` strictly cover section code and exclude fence bytes.
- **Universal Binary Slice Offsets**: Accurately accounts universal slice offset once in section metadata (`raw_offset = sliceOffset_ + s_offset`), ensuring `FileParser::vaToOffsets()` never double-adds slice offsets.

### 3. Architecture Gadget Discovery Support (Phase 2 Step 6)
- **x86_64 Gadget Discovery**: Verified unaligned and aligned scanning, discovering `pop rdi ; ret` and `mov rax, 0x3b ; syscall` with byte verification.
- **x86 (32-bit) Gadget Discovery**: Discovers 32-bit x86 gadgets (`pop eax ; ret`) with native 32-bit virtual addresses.
- **AArch64 Gadget Discovery**: Discovers 64-bit ARM64 gadgets (`mov x0, x1 ; ret`) using 4-byte aligned instruction scanning.
- **Deferred Architecture Limitations**: Mach-O ARMv7 32-bit Thumb mode interworking and gadget discovery are explicitly deferred due to the absence of ELF-style mapping symbols (`$a`, `$t`, `$d`) in Mach-O binaries and Apple platform deprecation.

### 4. Zero-Fill and Zero-Sized Section Exclusions (Phase 2 Step 6)
- **Zero-Fill Handling**: Explicitly classifies `S_ZEROFILL`, `S_GB_ZEROFILL`, and `S_THREAD_LOCAL_ZEROFILL` before file bounds validation, unconditionally setting `raw_offset = 0`, `raw_size = 0`, and `is_executable = false`.
- **Zero-Sized Section Gating**: Enforces `s_size > 0` for executable eligibility, ensuring zero-sized sections are excluded from executable aggregation.
- **Segment Permission Gating**: Enforces `(initprot & VM_PROT_EXECUTE) != 0` on enclosing segments (`maxprot` alone does not confer execution permission).

### 5. Malformed-Input Validation & Mitigation Telemetry (Phase 2 Step 5.6)
- **Integer-Overflow Resilience**: Native-width checks for 32-bit and 64-bit segment/section virtual ranges (`vmaddr > UINT_MAX - vmsize`) and file ranges (`fileoff > UINT_MAX - filesize`).
- **Unconditional Containment**: Enforces `fileoff <= sliceSize_` unconditionally (even when `filesize == 0`), and verifies full section virtual/file containment.
- **Fail-Closed Mitigations**: Rejection on any malformation marks `mitigations_.segment_stream_complete = false; finalizeMitigations(); return false;`.
- **Mitigation Telemetry**: Inspects Stack NX, Heap NX, Segment W^X (`initprot`/`maxprot`), PIE, Stack Canary symbols, and LC_CODE_SIGNATURE SuperBlob structures.

### 6. Verification and Protected Artifact Integrity
- **Test Results**: 541 Passed, 0 Failed across all 18 test groups (`tests/test_macho_detection.exe`), exit code 0.
- **Protected Artifact Baselines**: SHA-256 hashes for `reports/output.json`, `payload.bin`, `reports/payload.bin`, and `reports/PHASE_1.2A_KALI_LINUX_NATIVE_VALIDATION.md` verified 100% identical to baseline values.

## [v1.4.0] - Phase 2: Architecture-Aware Serialization & Fail-Closed Semantic Validation

### 1. Architecture-Aware Payload Serialization (Phase 2 Step 1)
- **Word Sizing & Endianness**: Added `ROPChain::getPayloadBytes(wordSize, endianness)` supporting 4-byte (32-bit targets) and 8-byte (64-bit targets) word packaging.
- **Endianness Enforcement**: Serializes payload data using `FileParser::getMetadataEndianness()`, respecting ELF `EI_DATA` (`ELFDATA2LSB` vs `ELFDATA2MSB`).
- **Bounds Checking**: Rejects 32-bit values exceeding `0xFFFFFFFFULL` with descriptive errors.
- **Payload Suppression**: If target metadata is missing (`parser == nullptr`), payload serialization fails cleanly without assuming word size or endianness.

### 2. Explicit Step Data Model & ABI Metadata (Phase 2 Step 2)
- **Typed ROP Chain Steps**: Replaced implicit value-based step categorization with explicit `ROPStepType` enum (`RegisterAssignment`, `SystemCallSetup`, `SystemCallExecution`, `StackAdjustment`, `GadgetExecution`, `Unknown`).
- **JSON Telemetry**: Standardized `type` and `semantic_type` fields in report outputs.
- **Container ABI Invariants**: Added ELF OSABI and EABI checking (`EF_ARM_EABI_VER1-5` for ARMv7; rejection of bare-metal `ELFOSABI_STANDALONE` and RVE 16-register embedded ABI for RISC-V).

### 3. Fail-Closed Semantic Chain Validation (Phase 2 Step 3)
- **Static Semantic Validator**: Added `ROPChain::validate(arch, parser)` evaluating candidate chains against target Linux `execve` ABIs (x86, x86_64, ARMv7, AArch64, RISC-V 32/64).
- **Register Clobber Detection**: Detects intra-gadget and inter-gadget clobber of previously staged arguments across all step types.
- **Native Staging Sequences**:
  - Replaced synthetic `pop` mnemonics with native instruction patterns on AArch64 (`ldr <reg>, [sp], #8 ; ldr x30, [sp], #8 ; ret`) and RISC-V (`ld/lw <reg>, 0(sp) ; ld/lw ra, offset(sp) ; addi sp, sp, ... ; ret`).
  - Enforced strict load ordering (`target_load < link_load`), signed displacement bounds, and return-address reload verification.
- **Stack Modification Safety**: Rejected dynamic SP arithmetic (`add rsp, rbx`), logical SP operations (`and rsp, -16`), and unmodelled `StackAdjustment` steps.
- **Deceptive Payload Suppression**: Invalid semantic chains are denied payload export to `payload.bin`.

### 4. Operational Boundaries & Demonstration Scope
- **Fixed Placeholder Prefix**: The emitted `payload.bin` prefixes the serialized chain with a fixed 104-byte `'A'` padding sequence.
- **Demonstration Placeholder**: The 104-byte prefix is a hardcoded demonstration placeholder; it is not proven to match the actual overflow offset of the bundled fixture or any arbitrary binary, and is not universally valid across targets or architectures.
- **Scope Exclusion**: Vulnerability discovery, target buffer overflow offset calculation, canary bypass, and victim stack-frame reconstruction remain external exploit-engineering responsibilities.
- **Initial SP Alignment**: For architectures utilizing link-register returns without hardware SP increments (AArch64 `ret` / `br x30` and RISC-V `ret` / `jalr x0, 0(ra)`, neither of which increments SP), runtime stack pointer alignment (`SP = payload + word_size`) must be provided by the external delivery harness.


## [v1.3.0] - Comprehensive Code Audit & Engineering Upgrade (v1.2.4 Defect Corrections)

### 1. Platform-Specific Analysis & Mitigation Reporting
- **Platform Separation**: Eliminated Linux `execve` assumptions and unverified padding offsets on Windows PE targets; automated chain synthesis now reports an explicit `"Unsupported for Windows PE targets"` status.
- **Accurate PE Mitigations**: Completely replaced ELF-specific `RELRO` with Windows PE indicators: `NX_COMPAT`, `DYNAMIC_BASE`, `HIGH_ENTROPY_VA`, `GUARD_CF`, `CET_COMPAT`, `GS_COOKIE`, and `SafeSEH`.
- **Static vs. Runtime Enforcement**: Distinguishes static binary compatibility indicators from runtime enforcement. Reports `CET_COMPAT` as `UNKNOWN` when Load Config Directory evidence is absent. Reports `SafeSEH` as `NOT_APPLICABLE` on 64-bit binaries.

### 2. Multi-Dimensional Gadget Classification
- **Classification Separation**: Strictly separated stack pointer arithmetic adjustments (`add rsp, N`) from genuine stack pivots (`mov rsp, reg`, `xchg rsp, reg`, `pop rsp`, `leave`).
- **Memory Comparison Safety**: Ensured memory comparisons (`cmp`, `test` with brackets) are classified strictly as `memory_read` and NEVER as `memory_write`.
- **Multi-Label Categories**: Every gadget now belongs to all applicable categories (`register_load`, `stack_adjustment`, `memory_read`, `memory_write`, `arithmetic`, `logical`, `control_transfer`, `stack_pivot`, `syscall`).
- **Stack Tracking**: Accurate calculation of `stack_delta`, `stack_consumption`, register reads/modifications, and side-effects.

### 3. Address Representation & Gadget Validation
- **PE Address Representation**: Discovered gadgets now record `preferred_va`, `rva`, `file_offset`, and `runtime_va` (reported as `null` with a descriptive note when `DYNAMIC_BASE` is active; never claiming preferred VA is guaranteed runtime VA).
- **Overlapping Gadget Discovery**: Implemented backward-scan Pass 2 from terminators to decode legitimate overlapping instruction sequences with full byte verification (`byte_verified`).
- **Section Boundary Enforcement**: All section mappings validated against section raw and virtual sizes.

### 4. Report Consistency & Test Suite
- **Gadget Count Consistency**: Total gadget count matches the exported gadget collection size.
- **Regression Suite**: Automated regression tests (`tests/run_tests.ps1`, `tests/run_tests.sh`) covering PE/ELF x86_64, address conversion, mitigation indicators, and error resilience (46/46 passed).

