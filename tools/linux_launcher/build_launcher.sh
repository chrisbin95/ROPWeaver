#!/usr/bin/env bash
# ==============================================================================
# Build Linux Standalone Launcher
# Compiles launcher.c into ropweaver-linux-x64
# ==============================================================================

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "[*] Compiling Linux Standalone Launcher (launcher.c)..."
gcc -O2 -s -Wall launcher.c -o ropweaver-linux-x64
chmod +x ropweaver-linux-x64
chmod +x launcher.sh

echo "[+] Linux Standalone Launcher ready: $DIR/ropweaver-linux-x64"
