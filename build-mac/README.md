# ROPWeaver macOS Build Instructions

This directory contains the macOS build configuration for Return-Oriented Programming (ROP) exploit generation and gadget classification on Apple Silicon (M1/M2/M3/M4 arm64) and Intel (x86_64) hardware.

## Prerequisites

Install build tools and libraries via Homebrew:
```bash
brew install cmake capstone curl
```

## Compilation

Run the automated build script:
```bash
chmod +x build.sh
./build.sh
```

Or configure manually via CMake:
```bash
cmake -B . -DCMAKE_BUILD_TYPE=Release
make -j$(sysctl -n hw.ncpu)
```

## Running

```bash
./ropweaver <target_binary> --auto-chain --suggest-gadgets
```
