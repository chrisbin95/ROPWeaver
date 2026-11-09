# ROPWeaver Changelog

All notable changes to the ROPWeaver framework are documented in this file.

## [v1.3.0] - Comprehensive Code Audit & Engineering Upgrade

### 1. Gadget Discovery and Validation
- **Binary Byte Verification**: Implemented strict validation comparing decoded Capstone instructions against original binary bytes in `m_code` (`byte_verified` attribute).
- **Executable Section Concatenation**: Supported all executable sections (`SHF_EXECINSTR` for ELF, `IMAGE_SCN_MEM_EXECUTE`/`IMAGE_SCN_CNT_CODE` for PE) with `INT3` (0xCC) fences to prevent cross-boundary sequence synthesis.
- **Stack Pivot Detection Fix**: Corrected `Gadget::isStackPivot()` to examine all instructions in sequence rather than only the final terminator instruction.

### 2. Multi-Dimensional Gadget Classification
- **Multi-Category Tagging**: Replaced legacy single-string categorization with `std::vector<std::string> categories` supporting concurrent tags:
  - `register_load`
  - `stack_adjustment`
  - `memory_read`
  - `memory_write`
  - `arithmetic`
  - `logical`
  - `control_transfer`
  - `stack_pivot`
  - `syscall`
  - `misc`
- **Register Tracking**: Discovered gadgets now track `registers_read` (registers consumed) and `registers_modified` (registers written/clobbered).
- **Stack Delta Calculation**: Computed exact net stack pointer changes (`stack_delta`) accounting for `push`, `pop`, `ret`, `add rsp`, `sub rsp`, and `leave`.
- **Classification Confidence**: Added scoring (`classification_confidence`) based on sequence depth and deterministic operand attributes.

### 3. Binary Parser Upgrades
- **PE Header Bug Fix**: Corrected `DllCharacteristics` byte offset calculation (offset 70 for PE32+, offset 94 for PE32).
- **PE Mitigations**: Added detection for `HIGH_ENTROPY_VA` (`0x0020`), `Control Flow Guard (CFG)` (`0x4000`), and `SafeSEH` (`IMAGE_FILE_NO_SEH` `0x0400`).
- **Terminology Normalization**: Completely removed ELF-specific `RELRO` terminology from Windows PE reports and terminal display.
- **ELF Enhancements**: Extracted `e_entry` entry point address, parsed `PT_GNU_STACK` (NX), `ET_DYN` (PIE), `PT_GNU_RELRO` & `DT_BIND_NOW` (Full/Partial RELRO).
- **Cross-Platform Header Compatibility**: Fully eliminated dependency on system `<elf.h>` on Windows platforms by providing self-contained, standard-compliant ELF structures in `core/parsers/elf_defs.h`.

### 4. Reporting & Diagnostics
- **JSON Report Schema v1.3.0**: Expanded `reports/output.json` to serialize multi-dimensional categories, register effects, stack delta, confidence score, and platform-specific mitigation objects.
- **Automated Regression Suite**: Created automated tests (`tests/run_tests.ps1` and `tests/run_tests.sh`) validating ELF64, PE64, malformed file resilience, and mitigation checks.
- **Release Packaging**: Synchronized multi-platform release assets in `web-react/public/` for Windows (`.zip`, standalone `.exe`), Linux (`.tar.gz`, `.deb`), and macOS.
