# ROPWeaver macOS Standalone Launcher

This directory contains standalone execution wrappers for macOS (Apple Silicon arm64 & Intel x86_64):

- `launcher.c`: Native C launcher compiled with Apple Clang that dynamically sets up Homebrew library paths and executes `ropweaver`.
- `launcher.sh`: Pure Bash launcher script that detects architecture, sources Homebrew, and runs `ropweaver`.
- `build_launcher.sh`: Compilation script for Apple Clang.

## Building the Launcher

```bash
chmod +x build_launcher.sh
./build_launcher.sh
```

## Running

```bash
./ropweaver-macos <binary> --auto-chain --suggest-gadgets
# OR
./launcher.sh <binary> --auto-chain
```
