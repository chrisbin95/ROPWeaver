# ROPWeaver Changelog

All notable changes to the ROPWeaver framework are documented in this file.

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

