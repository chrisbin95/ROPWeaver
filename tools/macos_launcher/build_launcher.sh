#!/usr/bin/env bash
# ==============================================================================
# Build macOS Standalone Launcher
# Compiles launcher.c into ropweaver-macos
# ==============================================================================

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "[*] Compiling macOS Standalone Launcher (Apple Clang)..."
clang -O2 -Wall launcher.c -o ropweaver-macos
chmod +x ropweaver-macos
chmod +x launcher.sh

echo "[+] macOS Standalone Launcher ready: $DIR/ropweaver-macos"
