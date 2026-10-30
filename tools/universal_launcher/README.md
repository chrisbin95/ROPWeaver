# ROPWeaver Universal Multi-Platform Launcher

This launcher runs on Windows, Linux, and macOS without requiring any C/C++ compilation. It auto-detects the host operating system, resolves library dependencies (DLLs on Windows, `LD_LIBRARY_PATH` on Linux, Homebrew on macOS), and invokes the compiled ROPWeaver engine.

## Usage

```bash
# On Linux / macOS:
chmod +x ropweaver
./ropweaver <binary> --auto-chain --suggest-gadgets

# On Windows:
.\ropweaver.bat <binary> --auto-chain
```
