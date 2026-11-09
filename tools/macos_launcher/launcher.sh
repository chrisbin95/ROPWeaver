#!/usr/bin/env bash
# ==============================================================================
# ROPWeaver macOS Standalone Shell Launcher
# Sourced Homebrew libraries for arm64/x86_64 and forwards CLI arguments
# ==============================================================================

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="v1.2.4"

# 1. Source Homebrew environment if installed
if [ -x "/opt/homebrew/bin/brew" ]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
elif [ -x "/usr/local/bin/brew" ]; then
    eval "$(/usr/local/bin/brew shellenv)"
fi

# 2. Locate ropweaver binary
BIN=""
if [ -x "$DIR/ropweaver" ]; then
    BIN="$DIR/ropweaver"
elif [ -x "$DIR/bin/ropweaver" ]; then
    BIN="$DIR/bin/ropweaver"
elif [ -x "$HOME/.local/share/ropweaver/ropweaver" ]; then
    BIN="$HOME/.local/share/ropweaver/ropweaver"
elif [ -x "$DIR/../../build-mac/ropweaver" ]; then
    BIN="$DIR/../../build-mac/ropweaver"
elif command -v ropweaver >/dev/null 2>&1; then
    BIN="$(command -v ropweaver)"
fi

if [ -z "$BIN" ]; then
    echo "==«✪»== ROPWeaver macOS Launcher $VERSION ==«✪»==" >&2
    echo "[!] Error: ropweaver binary not found." >&2
    echo "[i] Build with Homebrew on macOS: cd build-mac && ./build.sh" >&2
    exit 1
fi

# 3. Export library path
BREW_LIB="${HOMEBREW_PREFIX:-/opt/homebrew}/lib"
export DYLD_LIBRARY_PATH="$DIR/lib:$BREW_LIB:${DYLD_LIBRARY_PATH:-}"

# 4. Execute
exec "$BIN" "$@"
