#!/usr/bin/env bash
# ==============================================================================
# ROPWeaver Linux Standalone Shell Launcher
# Wraps dependency verification, runtime paths, and forwards all arguments
# ==============================================================================

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="v1.2.3"

# 1. Locate ropweaver binary
BIN=""
if [ -x "$DIR/ropweaver" ]; then
    BIN="$DIR/ropweaver"
elif [ -x "$DIR/bin/ropweaver" ]; then
    BIN="$DIR/bin/ropweaver"
elif [ -x "$HOME/.local/share/ropweaver/app-$VERSION/ropweaver" ]; then
    BIN="$HOME/.local/share/ropweaver/app-$VERSION/ropweaver"
elif [ -x "$DIR/../../build-linux/ropweaver" ]; then
    BIN="$DIR/../../build-linux/ropweaver"
elif [ -x "$DIR/../../build/ropweaver" ]; then
    BIN="$DIR/../../build/ropweaver"
elif command -v ropweaver >/dev/null 2>&1; then
    BIN="$(command -v ropweaver)"
fi

if [ -z "$BIN" ]; then
    echo "==«✪»== ROPWeaver Linux Launcher $VERSION ==«✪»==" >&2
    echo "[!] Error: ropweaver binary not found." >&2
    echo "[i] To build from source, run: cd build-linux && ./build.sh" >&2
    exit 1
fi

# 2. Check essential dynamic libraries
if [ -d "$DIR/lib" ]; then
    export LD_LIBRARY_PATH="$DIR/lib:${LD_LIBRARY_PATH:-/usr/local/lib:/usr/lib}"
fi

# 3. Forward execution to ropweaver
exec "$BIN" "$@"
