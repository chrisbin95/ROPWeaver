#!/usr/bin/env bash
# ==============================================================================
# ROPWeaver Multi-Platform Release Packager (POSIX / Linux / macOS)
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
PUBLIC_DIR="$ROOT_DIR/web-react/public"

echo "==«✪»== ROPWeaver Release Packager ==«✪»=="
mkdir -p "$PUBLIC_DIR"

# 1. Package Linux archive
echo "[*] Packaging Linux distribution..."
STAGE_LINUX="$(mktemp -d)"
PKG_LINUX="$STAGE_LINUX/ropweaver-v1.2.3-linux-x86_64"
mkdir -p "$PKG_LINUX/bin" "$PKG_LINUX/samples"

if [ -f "$ROOT_DIR/build-linux/ropweaver" ]; then
    cp "$ROOT_DIR/build-linux/ropweaver" "$PKG_LINUX/bin/"
elif [ -f "$ROOT_DIR/build/ropweaver" ]; then
    cp "$ROOT_DIR/build/ropweaver" "$PKG_LINUX/bin/"
fi

if [ -f "$ROOT_DIR/build-linux/binsh_test" ]; then
    cp "$ROOT_DIR/build-linux/binsh_test" "$PKG_LINUX/samples/"
fi

cp "$ROOT_DIR/tools/linux_launcher/launcher.sh" "$PKG_LINUX/install.sh"
cat << 'EOF' > "$PKG_LINUX/README.txt"
================================================================================
                    ROPWeaver v1.2.3 for Linux (x86_64)
            Academic Research Tool - Oxford Brookes University
================================================================================

Requirements:
  GLIBC 2.31+, Capstone Disassembly Engine, libcurl
EOF

tar -czf "$PUBLIC_DIR/ropweaver-v1.2.3-linux-x86_64.tar.gz" -C "$STAGE_LINUX" ropweaver-v1.2.3-linux-x86_64
rm -rf "$STAGE_LINUX"
echo "[+] Created: $PUBLIC_DIR/ropweaver-v1.2.3-linux-x86_64.tar.gz"

# 2. Package macOS archives
echo "[*] Packaging macOS distributions..."
STAGE_MAC="$(mktemp -d)"
PKG_ARM="$STAGE_MAC/ropweaver-v1.2.3-darwin-arm64"
PKG_X64="$STAGE_MAC/ropweaver-v1.2.3-darwin-x86_64"
mkdir -p "$PKG_ARM/bin" "$PKG_X64/bin"

cp "$ROOT_DIR/tools/macos_launcher/launcher.sh" "$PKG_ARM/bin/ropweaver"
cp "$ROOT_DIR/tools/macos_launcher/launcher.sh" "$PKG_ARM/install.sh"
cp "$ROOT_DIR/tools/macos_launcher/launcher.sh" "$PKG_X64/bin/ropweaver"
cp "$ROOT_DIR/tools/macos_launcher/launcher.sh" "$PKG_X64/install.sh"

tar -czf "$PUBLIC_DIR/ropweaver-v1.2.3-darwin-arm64.tar.gz" -C "$STAGE_MAC" ropweaver-v1.2.3-darwin-arm64
tar -czf "$PUBLIC_DIR/ropweaver-v1.2.3-darwin-x86_64.tar.gz" -C "$STAGE_MAC" ropweaver-v1.2.3-darwin-x86_64
rm -rf "$STAGE_MAC"
echo "[+] Created: $PUBLIC_DIR/ropweaver-v1.2.3-darwin-arm64.tar.gz"
echo "[+] Created: $PUBLIC_DIR/ropweaver-v1.2.3-darwin-x86_64.tar.gz"

echo "[*] Generating checksums..."
sha256sum "$PUBLIC_DIR"/ropweaver* 2>/dev/null || shasum -a 256 "$PUBLIC_DIR"/ropweaver*
echo "[+] Packaging complete."
