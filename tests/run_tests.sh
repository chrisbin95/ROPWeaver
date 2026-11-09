#!/usr/bin/env bash
# ROPWeaver Regression Test Suite (Linux / macOS / Bash)
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Find binary
if [[ -x "${PROJECT_ROOT}/build-linux/ropweaver" ]]; then
    ROPWEAVER="${PROJECT_ROOT}/build-linux/ropweaver"
elif [[ -x "${PROJECT_ROOT}/build/ropweaver" ]]; then
    ROPWEAVER="${PROJECT_ROOT}/build/ropweaver"
elif [[ -x "${PROJECT_ROOT}/build-win/ropweaver.exe" ]]; then
    ROPWEAVER="${PROJECT_ROOT}/build-win/ropweaver.exe"
else
    echo "[!] ropweaver binary not found in build-linux/, build/, or build-win/"
    exit 1
fi

echo "============================================================"
echo "         ROPWeaver Comprehensive Regression Test Suite       "
echo "============================================================"
echo "[*] Using binary: ${ROPWEAVER}"

PASSED=0
FAILED=0

assert_test() {
    local name="$1"
    local condition="$2"
    if eval "${condition}"; then
        echo -e "  \033[32m[PASS]\033[0m ${name}"
        PASSED=$((PASSED + 1))
    else
        echo -e "  \033[31m[FAIL]\033[0m ${name}"
        FAILED=$((FAILED + 1))
    fi
}

# Test 1: ELF64 Analysis
echo -e "\n[*] Test 1: ELF64 Analysis & Auto-Chain (binsh_test)..."
ELF_BIN="${PROJECT_ROOT}/test_binaries/binsh_test"
OUT_JSON="${PROJECT_ROOT}/reports/output.json"
mkdir -p "${PROJECT_ROOT}/reports"
rm -f "${OUT_JSON}"

OUTPUT=$("${ROPWEAVER}" "${ELF_BIN}" -a -p 2>&1 || true)
assert_test "ELF contains /bin/sh scan result" "echo '${OUTPUT}' | grep -q 'Found /bin/sh'"
assert_test "ELF creates ROP chain" "echo '${OUTPUT}' | grep -q 'ROP chain created successfully'"
assert_test "ELF outputs report JSON" "[[ -f '${OUT_JSON}' ]]"
if [[ -f "${OUT_JSON}" ]]; then
    assert_test "JSON has byte_verified" "grep -q '\"byte_verified\": true' '${OUT_JSON}'"
    assert_test "JSON has categories array" "grep -q '\"categories\"' '${OUT_JSON}'"
    assert_test "JSON has RELRO for ELF" "grep -q '\"RELRO\"' '${OUT_JSON}'"
fi

# Test 2: PE64 Analysis
echo -e "\n[*] Test 2: PE64 Analysis & Mitigation Detection (classic_bof.exe)..."
PE_BIN="${PROJECT_ROOT}/test_binaries/classic_bof.exe"
rm -f "${OUT_JSON}"

PE_OUTPUT=$("${ROPWEAVER}" "${PE_BIN}" -a -p 2>&1 || true)
assert_test "PE shows NX_COMPAT" "echo '${PE_OUTPUT}' | grep -q 'NX_COMPAT'"
assert_test "PE shows DYNAMIC_BASE" "echo '${PE_OUTPUT}' | grep -q 'DYNAMIC_BASE'"
assert_test "PE shows CET UNKNOWN" "echo '${PE_OUTPUT}' | grep -q 'CET=UNKNOWN'"
assert_test "PE does NOT display RELRO in console" "! echo '${PE_OUTPUT}' | grep -q 'RELRO='"
assert_test "PE shows unsupported auto-chain message" "echo '${PE_OUTPUT}' | grep -q 'unsupported for Windows PE'"
if [[ -f "${OUT_JSON}" ]]; then
    assert_test "PE JSON protections do NOT have RELRO" "! grep -q '\"RELRO\"' '${OUT_JSON}'"
    assert_test "PE JSON has NX_COMPAT" "grep -q '\"NX_COMPAT\"' '${OUT_JSON}'"
    assert_test "PE JSON has DYNAMIC_BASE" "grep -q '\"DYNAMIC_BASE\"' '${OUT_JSON}'"
    assert_test "PE JSON has CET_COMPAT UNKNOWN" "grep -q '\"UNKNOWN\"' '${OUT_JSON}'"
    assert_test "PE JSON has preferred_va" "grep -q '\"preferred_va\"' '${OUT_JSON}'"
    assert_test "PE JSON has file_offset" "grep -q '\"file_offset\"' '${OUT_JSON}'"
    assert_test "PE JSON has rva" "grep -q '\"rva\"' '${OUT_JSON}'"
    assert_test "PE JSON raw_payload is Unsupported" "grep -q '\"status\": \"Unsupported' '${OUT_JSON}'"
fi

# Test 3: Malformed binary error handling
echo -e "\n[*] Test 3: Malformed Binary Handling..."
MALFORMED="${PROJECT_ROOT}/reports/malformed_test.bin"
printf '\x7fELF' > "${MALFORMED}"
set +e
"${ROPWEAVER}" "${MALFORMED}" >/dev/null 2>&1
MAL_EC=$?
set -e
rm -f "${MALFORMED}"
assert_test "Malformed binary returns non-zero exit code" "[[ ${MAL_EC} -ne 0 ]]"

echo -e "\n============================================================"
echo "Test Results: ${PASSED} Passed, ${FAILED} Failed"
echo "============================================================"

if [[ ${FAILED} -gt 0 ]]; then
    exit 1
else
    exit 0
fi

