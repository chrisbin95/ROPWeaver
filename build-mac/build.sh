#!/usr/bin/env bash
# ==============================================================================
# ROPWeaver macOS Build Script
# Native compilation for Apple Silicon (arm64) and Intel (x86_64) on macOS
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "==«✪»== ROPWeaver macOS Build System ==«✪»=="

# 1. Detect Architecture
ARCH="$(uname -m)"
echo "[*] Host Architecture: $ARCH"

# 2. Check Homebrew prerequisites
if [ -d "/opt/homebrew" ]; then
    HOMEBREW_PREFIX="/opt/homebrew"
elif [ -d "/usr/local" ]; then
    HOMEBREW_PREFIX="/usr/local"
else
    echo "[!] Homebrew directory not found. Please install Homebrew from https://brew.sh"
    exit 1
fi

echo "[*] Using Homebrew prefix: $HOMEBREW_PREFIX"

MISSING_DEPS=()
brew list capstone >/dev/null 2>&1 || MISSING_DEPS+=("capstone")
brew list curl >/dev/null 2>&1 || MISSING_DEPS+=("curl")
command -v cmake >/dev/null 2>&1 || MISSING_DEPS+=("cmake")

if [ ${#MISSING_DEPS[@]} -ne 0 ]; then
    echo "[!] Installing missing macOS dependencies: ${MISSING_DEPS[*]}"
    brew install "${MISSING_DEPS[@]}"
fi

# 3. Configure and compile with CMake & Clang
cd "$SCRIPT_DIR"
echo "[*] Configuring CMake with Apple Clang..."
cmake -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_OSX_DEPLOYMENT_TARGET="11.0" \
      -DCMAKE_PREFIX_PATH="$HOMEBREW_PREFIX" \
      "$SCRIPT_DIR"

NCPU=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)
echo "[*] Compiling ROPWeaver with $NCPU cores..."
make -j"$NCPU"

echo "[+] macOS build completed successfully: $SCRIPT_DIR/ropweaver"
if [ -f "$SCRIPT_DIR/ropweaver" ]; then
    chmod +x "$SCRIPT_DIR/ropweaver"
    ./ropweaver --version || true
fi
