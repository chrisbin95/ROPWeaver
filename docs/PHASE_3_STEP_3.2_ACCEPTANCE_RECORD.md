# ROPWeaver Phase 3 Step 3.2 — Dynamic Exploit Offset Configuration Acceptance Record

**STATUS:** COMPLETED AND ACCEPTED  
**DATE:** 2026-11-15  
**PHASE:** Phase 3 (Step 3.2: Dynamic Exploit Offset Configuration)

---

## 1. Executive Summary & Acceptance Scope

This document serves as the formal acceptance record for **Phase 3 Step 3.2** of ROPWeaver. The objective of Step 3.2 is replacing the hardcoded 104-byte exploit payload prefix padding with a dynamically configurable exploit offset via CLI options while maintaining complete backward compatibility with existing default behavior.

### 1.1 Scope of Changes
1. **CLI Argument Parsing**:
   - Long option: `--offset <bytes>`
   - Short alias: `-O <bytes>`
   - Configurable padding offset from 0 up to 16 MiB (`16777216` bytes).
   - Decimal and hexadecimal (`0x`/`0X`) base formats.
   - Strict validation rejecting negative values, explicit plus signs, malformed characters, trailing garbage, missing values, flag-as-argument, and numerical overflow.
   - Fail-closed error handling with exit code 1 on any parsing failure.
2. **Payload Synthesis & Telemetry**:
   - Preserves exact 104-byte default padding when no offset option is provided.
   - Configurable offset forwarded through `main.cpp` to `PayloadGenerator::generate()`.
   - Exploit padding offset reported in console telemetry during payload generation.
   - Selected offset recorded in JSON report under `raw_payload.verified_padding_offset`.
3. **Automated Test Integration**:
   - Unit tests added to `tests/test_chain_serialization.cpp` (Group 22) covering default (104), custom decimal (208), hex (128), zero boundary (0), and large (4096) offsets.
   - CLI regression suite added to `tests/run_tests.py` (Test 16) covering valid offsets, invalid input rejections, and working directory protection.
   - Fail-closed working directory guard added to `run_command()` in `tests/run_tests.py`.
4. **Documentation**:
   - `CHANGELOG.md` updated with `[v1.6.1]`.
   - `docs/LIMITATIONS.md` updated clarifying dynamic offset configurability and scope boundaries.
   - `docs/PHASE_3_STEP_3.2_ACCEPTANCE_RECORD.md` established.

---

## 2. Technical Specification & Implementation Verification

### 2.1 CLI Argument Parsing & Validation (`ui/cli.h`, `ui/cli.cpp`)
- **Data Model**: `struct CLIOptions` updated with:
  - `size_t exploitOffset = 104;`
  - `bool useCustomOffset = false;`
- **Validation Pipeline**:
  1. *Missing Argument*: Detects if `--offset` or `-O` is the final token or if the next token begins with `-` (flag-as-argument, e.g. `--offset -p`). Rejects with descriptive error and returns `opts` with `valid = false`.
  2. *Negative Values & Explicit Plus Signs*: Checks leading character. Rejects `-` (e.g. `-10`) and `+` (e.g. `+104`).
  3. *Radix Detection & Conversion*: Uses `std::strtoull(arg.c_str(), &endptr, 0)` to parse base-10 and base-16 (`0x`/`0X`) numbers.
  4. *Malformed & Trailing Characters*: Enforces `endptr != arg.c_str()` and `*endptr == '\0'` to reject inputs such as `abc` or `104xyz`.
  5. *Range & Capacity Validation*: Checks `errno == ERANGE` and verifies `val <= std::numeric_limits<size_t>::max()`.
  6. *Maximum Ceiling Enforcement*: Enforces `val <= 16ULL * 1024ULL * 1024ULL` (16 MiB), rejecting oversized offsets.
- **Strict Radix Validation & Octal Prohibition**: Values starting with `0x` or `0X` are strictly parsed as base 16. All other values are parsed as base 10; octal interpretation is strictly prohibited. Leading zeros (e.g. `010` -> decimal 10, `08` -> decimal 8) are preserved as decimal values. Unsupported prefixes (`0b`/`0B`, `0o`/`0O`) and malformed characters (`0xG1`) are strictly rejected.
- **Exit Code Guarantee**: Setting `opts.valid = false` on failure ensures `main.cpp` immediately exits with return code `1` after displaying usage information.

### 2.2 Payload Generation Integration (`main.cpp`)
- In `main.cpp`, replaced the previously hardcoded `const size_t paddingSize = 104;` with `const size_t paddingSize = options.exploitOffset;`.
- Added console telemetry logging the selected padding offset:
  ```cpp
  std::cout << "[*] Exploit padding offset: " << paddingSize << " bytes ("
            << (options.useCustomOffset ? "user-configured" : "default") << ").\n";
  ```
- Forwarded `paddingSize` to `PayloadGenerator::generate()`. In `core/payload_gen.cpp`, the payload buffer is assigned `paddingSize` `'A'` bytes (`payload.assign(paddingSize, 'A')`), and the JSON report records `paddingSize` in `raw_payload.verified_padding_offset`.

---

## 3. Test Suites & Validation Evidence

### 3.1 Unit Test Suite (`tests/test_chain_serialization.cpp`)
Group 22 tests the dynamic exploit offset functionality directly against `PayloadGenerator`:
- **Default Offset (104 bytes)**: Verifies exact payload size (`104 + chain_len`), prefix content (104 `'A'` bytes), serialized chain alignment, `raw_payload.status == "Success"`, and `raw_payload.verified_padding_offset == 104`.
- **Custom Decimal Offset (208 bytes)**: Verifies exact payload size (`208 + chain_len`), 208 `'A'` prefix bytes, chain alignment, and JSON metadata.
- **Hexadecimal Offset (128 bytes / `0x80`)**: Verifies 128-byte prefix and JSON metadata.
- **Zero Offset Boundary (0 bytes)**: Verifies 0-byte prefix (chain bytes start immediately at offset 0), file size matching chain length, and JSON metadata.
- **Large Offset Boundary (4096 bytes)**: Verifies 4096-byte prefix and JSON metadata.

**Results**:
- Total assertions passed in suite: **282 / 282**
- Failures: **0**
- Exit code: **0**

### 3.2 Regression Runner Integration (`tests/run_tests.py` — Test 16)
Test 16 integrates dynamic offset CLI scenarios and compilation into the centralized runner:
- Compilation of `test_chain_serialization.cpp` into isolated temporary directory (`test_build_dir`).
- Execution of `test_chain_serialization.exe` in temporary directory.
- CLI execution with default offset (no flag) verifying telemetry and JSON offset `104`.
- CLI execution with `--offset 208` verifying telemetry and JSON offset `208`.
- CLI execution with short alias `-O 208` verifying JSON offset `208`.
- CLI execution with `--offset 0x80` verifying telemetry and JSON offset `128`.
- CLI execution with `--offset 0` verifying telemetry and JSON offset `0`.
- CLI execution with `--offset 4096` verifying telemetry and JSON offset `4096`.
- CLI rejection of negative offset (`--offset -10`): exit code 1, diagnostic error in stdout.
- CLI rejection of explicit plus sign (`--offset +104`): exit code 1, diagnostic error in stdout.
- CLI rejection of malformed string (`--offset abc`): exit code 1, diagnostic error in stdout.
- CLI rejection of trailing characters (`--offset 104xyz`): exit code 1, diagnostic error in stdout.
- CLI rejection of flag as argument (`--offset -p`): exit code 1, diagnostic error in stdout.
- CLI rejection of missing argument (`--offset`): exit code 1, diagnostic error in stdout.
- CLI rejection of numerical overflow (`--offset 99999999999999999999`): exit code 1, diagnostic error in stdout.
- CLI rejection of offset exceeding 16 MiB (`--offset 16777217`): exit code 1, diagnostic error in stdout.
- CLI acceptance of leading-zero decimal offset (`--offset 010`): exit code 0, telemetry and JSON confirm decimal 10.
- CLI acceptance of hexadecimal offset (`--offset 0x10`): exit code 0, telemetry and JSON confirm decimal 16.
- CLI acceptance of non-octal digit with leading zero (`--offset 08`): exit code 0, telemetry and JSON confirm decimal 8.
- CLI rejection of malformed hexadecimal (`--offset 0xG1`): exit code 1, error in stdout.
- CLI rejection of unsupported binary prefix (`--offset 0b10`): exit code 1, error in stdout.
- Verification of strengthened working-directory isolation guard across 5 distinct path configurations:
  1. Active temporary directory -> accepted.
  2. Repository root -> rejected.
  3. Repository subdirectory -> rejected.
  4. Unrelated external directory -> rejected.
  5. Missing working directory (`cwd=None`) -> rejected.
- Verification that non-payload commands and `--offset` alone without payload flags do not falsely trigger the guard.

**Results**:
- Total tests passed across all 16 test groups: **270 / 270**
- Failures: **0**
- Exit code: **0**

---

## 4. Protected Working-Directory Guard Verification

To guarantee that payload-generating commands cannot overwrite protected repository artifacts, a strengthened fail-closed guard was implemented in `run_command()` within `tests/run_tests.py`:
- Inspects command arguments for payload generation flags (`-p`, `--payload`, `--payload-gen`).
- If present, strictly verifies:
  1. `cwd` is explicitly provided (`cwd is not None`).
  2. `ACTIVE_TEMP_DIR` is initialized.
  3. `Path(cwd).resolve()` is inside or equal to `ACTIVE_TEMP_DIR.resolve()` (`target_cwd.relative_to(active_root)`).
- If any check fails, raises a fatal `RuntimeError` before subprocess execution:
  ```python
  payload_generating_flags = {"-p", "--payload", "--payload-gen"}
  if any(flag in cmd_list for flag in payload_generating_flags):
      if cwd is None:
          raise RuntimeError(
              f"[GUARD FAILURE] Refusing to execute payload-generating command with missing working directory: {cmd_list}"
          )
      if ACTIVE_TEMP_DIR is None:
          raise RuntimeError(
              f"[GUARD FAILURE] Refusing to execute payload-generating command without an active temporary test directory: {cmd_list}"
          )
      target_cwd = Path(cwd).resolve()
      active_root = ACTIVE_TEMP_DIR.resolve()
      try:
          target_cwd.relative_to(active_root)
      except ValueError:
          raise RuntimeError(
              f"[GUARD FAILURE] Refusing to execute payload-generating command outside active temporary directory ({active_root}): cwd={target_cwd}"
          )
  ```
- Does not trigger on legitimate non-payload commands or `--offset` alone without payload flags.

---

## 5. Cryptographic Protected Artifact Integrity

All four protected repository artifacts were verified prior to and following all test executions. All SHA-256 hashes match their established baselines 100% byte-for-byte:

| Protected Artifact Path | Expected SHA-256 Hash | Post-Test SHA-256 Hash | Status |
|---|---|---|---|
| `reports/output.json` | `0CBAF3B45823E96EC56E4C7AAF27B54FB51EE648FC8EDE32CB6C925975928EDE` | `0CBAF3B45823E96EC56E4C7AAF27B54FB51EE648FC8EDE32CB6C925975928EDE` | **MATCH** |
| `payload.bin` | `7D8913B516C83E29AE83F75D42BF619DBCB3D6FA1545ABBED570D826BE39960E` | `7D8913B516C83E29AE83F75D42BF619DBCB3D6FA1545ABBED570D826BE39960E` | **MATCH** |
| `reports/payload.bin` | `7D8913B516C83E29AE83F75D42BF619DBCB3D6FA1545ABBED570D826BE39960E` | `7D8913B516C83E29AE83F75D42BF619DBCB3D6FA1545ABBED570D826BE39960E` | **MATCH** |
| `reports/PHASE_1.2A_KALI_LINUX_NATIVE_VALIDATION.md` | `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855` | `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855` | **MATCH** |

---

## 6. Git Status and Working Tree Verification

All changes in Phase 3 Step 3.2 are strictly confined to the authorized allowlist (8 files):
1. `ui/cli.h`
2. `ui/cli.cpp`
3. `main.cpp`
4. `tests/run_tests.py`
5. `tests/test_chain_serialization.cpp`
6. `CHANGELOG.md`
7. `docs/LIMITATIONS.md`
8. `docs/PHASE_3_STEP_3.2_ACCEPTANCE_RECORD.md`

Zero other production, parser, or model files were modified. Zero protected artifacts were altered.

