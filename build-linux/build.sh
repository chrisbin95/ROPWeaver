#!/usr/bin/env bash
# ==============================================================================
# ROPWeaver Linux Build Script
# Automated Native Compilation for x86_64, i386, ARM64, and RISC-V ELF Platforms
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "==«✪»== ROPWeaver Linux Native Build System ==«✪»=="
echo "[*] Project root: $PROJECT_ROOT"
echo "[*] Build directory: $SCRIPT_DIR"

# 1. Check prerequisites
echo "[*] Checking Linux build prerequisites..."
MISSING_PKGS=()

command -v cmake >/dev/null 2>&1 || MISSING_PKGS+=("cmake")
command -v make >/dev/null 2>&1 || MISSING_PKGS+=("build-essential")
command -v g++ >/dev/null 2>&1 || MISSING_PKGS+=("g++")

if [ ${#MISSING_PKGS[@]} -ne 0 ]; then
    echo "[!] Warning: The following build tools are missing: ${MISSING_PKGS[*]}"
    echo "[i] Debian/Ubuntu/Kali install command:"
    echo "    sudo apt-get update && sudo apt-get install -y cmake build-essential libcapstone-dev libcurl4-openssl-dev"
    echo "[i] Arch Linux install command:"
    echo "    sudo pacman -S cmake base-devel capstone curl"
    echo "[i] Fedora install command:"
    echo "    sudo dnf install -y cmake gcc-c++ capstone-devel libcurl-devel"
fi

# 2. Check for pkg-config or capstone headers
if ! pkg-config --exists capstone 2>/dev/null && [ ! -f /usr/include/capstone/capstone.h ]; then
    echo "[!] Warning: Capstone disassembly library headers not detected."
    echo "[i] Please ensure libcapstone-dev is installed."
fi

# 3. Configure and build with CMake
echo "[*] Configuring CMake project..."
cd "$SCRIPT_DIR"

# Clean any stale CMakeCache.txt files from previous environments
rm -f "$SCRIPT_DIR/CMakeCache.txt" "$PROJECT_ROOT/Makefile/CMakeCache.txt" "$PROJECT_ROOT/CMakeCache.txt"
find "$PROJECT_ROOT" -maxdepth 3 -name "CMakeCache.txt" -delete 2>/dev/null || true

if [ -f "$PROJECT_ROOT/CMakeLists.txt" ]; then
    CMAKE_SRC="$PROJECT_ROOT"
elif [ -f "$PROJECT_ROOT/Makefile/CMakeLists.txt" ]; then
    CMAKE_SRC="$PROJECT_ROOT/Makefile"
else
    CMAKE_SRC="$PROJECT_ROOT"
fi

cmake -DCMAKE_BUILD_TYPE=Release -DUSE_GUI=OFF "$CMAKE_SRC"

NPROC=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)
echo "[*] Compiling ROPWeaver with $NPROC parallel jobs..."
make -j"$NPROC"

echo "[+] Linux build completed successfully!"
if [ -f "$SCRIPT_DIR/ropweaver" ]; then
    chmod +x "$SCRIPT_DIR/ropweaver"
    echo "[+] Binary ready at: $SCRIPT_DIR/ropweaver"
    ./ropweaver --help || true
fi
