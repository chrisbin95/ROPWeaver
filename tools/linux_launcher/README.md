# ROPWeaver Linux Standalone Launcher

This directory contains standalone execution wrappers for Linux (ELF 64-bit and 32-bit):

- `launcher.c`: Standalone C launcher that locates or unpacks the engine, sets library paths, and invokes `ropweaver`.
- `launcher.sh`: Pure POSIX Bash launcher for environments where compilation is not desired.
- `build_launcher.sh`: Compilation script for GCC / Clang.

## Building the Launcher

```bash
chmod +x build_launcher.sh
./build_launcher.sh
```

## Running

```bash
./ropweaver-linux-x64 <binary> --auto-chain --suggest-gadgets
# OR
./launcher.sh <binary> --auto-chain
```
