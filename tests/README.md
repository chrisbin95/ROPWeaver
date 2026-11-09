# ROPWeaver Regression Test Suite

This directory contains automated regression tests for the ROPWeaver analysis and exploit generation engine.

## Test Matrix

| Test Case | Format / Architecture | Purpose | Assertions |
|-----------|------------------------|---------|------------|
| `Test 1: binsh_test` | ELF64 / x86_64 | Full auto-chain synthesis, `/bin/sh` scan, Capstone byte verification | Architecture match, `/bin/sh` resolution, ROP chain creation, `byte_verified=true`, multi-dimensional classification categories, RELRO detection |
| `Test 2: classic_bof.exe` | PE64 / x86_64 | Windows PE mitigations & section analysis | DEP/NX detection, ASLR/DYNAMIC_BASE, HighEntropyVA, GS-Cookie heuristic, ensuring no ELF-specific mitigations (RELRO) appear for PE |
| `Test 3: malformed.bin` | Truncated ELF | Robustness against truncated or corrupt headers | Graceful termination, non-zero exit code, descriptive error output |
| `Test 4: not_a_binary.txt` | ASCII / Non-executable | Rejection of non-binary inputs | Clean exit code, rejection message, no crash or undefined behavior |

## Running the Tests

### On Windows (PowerShell)
```powershell
powershell -ExecutionPolicy Bypass -File tests/run_tests.ps1
```

### On Linux / macOS (Bash)
```bash
chmod +x tests/run_tests.sh
./tests/run_tests.sh
```
