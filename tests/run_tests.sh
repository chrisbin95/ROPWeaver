#!/usr/bin/env bash
# ==============================================================================
# ROPWeaver Regression Test Suite (POSIX Entrypoint)
# Forwards execution to the authoritative Python test runner (tests/run_tests.py)
# ==============================================================================
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PYTHON_BIN=""
if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    echo "[!] Error: python3 is required to run the ROPWeaver regression test suite." >&2
    echo "[i] Please install Python 3 (e.g. sudo apt install python3, or pkg install python)." >&2
    exit 1
fi

exec "${PYTHON_BIN}" "${PROJECT_ROOT}/tests/run_tests.py" "$@"
