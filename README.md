# 📦 ROPWeaver

**Weave powerful exploits from threads of control.**

> A C/C++ powered tool for discovering, visualizing, and chaining ROP gadgets in ELF binaries for ARM, RISC-V, and x86/x86_64 architectures.

---

## 🔍 Features

- 🧠 **Multi-architecture ROP gadget extraction**: Supports `x86`, `x86_64`, `ARMv7`, `AArch64`, and `RISC-V`.
- 🕵️ **Automatic gadget classification**: Categorizes gadgets such as syscalls, register moves, memory writes, and stack pivots.
- 🔗 **Interactive ROP chain builder**: Manually or automatically link gadgets to develop and simulate exploits.
<!-- - 🎯 **Blind ROP mode**: Inspired by BROP for blind exploitation without symbols. -->
- 🛡️ **Binary sanitizer**: Detects common binary protections like NX, PIE, RELRO, and stack canaries.
- 🧰 **Debugger-assisted simulation**: Optional integration with GDB or Pwntools for runtime ROP chain validation.
- ☁️ **Firebase upload**: Upload exploit chain reports and gadget findings to Firebase for remote access and collaboration.

---

## 📁 Project Structure

```
ROPWeaver/
├── core/
│   ├── elf_parser.cpp/.h
│   ├── gadget_finder.cpp/.h
│   ├── chain_builder.cpp/.h
│   ├── arch_detector.cpp/.h
│   └── utils.cpp/.h
├── ui/
│   ├── cli.cpp/.h
│   └── qt_gui.cpp/.h
├── firebase/
│   └── firebase_uploader.cpp/.h
├── include/
│   └── ropweaver.h
├── test_binaries/
├── reports/
│   └── output.json
├── main.cpp
├── README.md
├── Makefile / CMakeLists.txt
└── config/
    └── firebase_config.json
```

---

## 🚀 Installation

```bash
git clone https://github.com/yourname/ropweaver.git
cd ropweaver
make        # or cmake . && make
./ropweaver --help
```

### 🧩 Requirements

- `capstone`
- `libelf-dev`
- `binutils`
- `g++` or `clang++`
- Optional: `GDB`, `Pwntools`, Firebase SDK

---

## 💡 Sample Usage

```bash
# List gadgets in a 32-bit ARM binary
./ropweaver -f ./target.elf --arch armv7 --list-gadgets

# Auto-generate a chain to call execve syscall
./ropweaver -f ./target.elf --auto-chain --syscall execve

# Upload report to Firebase
./ropweaver -f ./target.elf --upload-report
```

---

## 🧠 Design Philosophy

ROPWeaver is designed for:

- 🧑‍💻 **Security researchers** and **exploit developers**
- 🏁 **CTF participants**
- 🛠️ Analysts performing ROP feasibility assessments

It provides:

- Clean gadget discovery
- Scripting-friendly output formats (`JSON`, `plain`, `ROPgadget-compatible`)
- Intuitive interfaces: CLI for terminals and a planned Qt GUI

---

## 📚 Inspired By

- [ROPgadget](https://github.com/JonathanSalwan/ROPgadget)
- [BROP (Blind Return-Oriented Programming)](https://www.scs.stanford.edu/brop/)
- [Angr](https://github.com/angr/angr)
- [Pwntools](https://github.com/Gallopsled/pwntools)

---

## 🔐 Disclaimer

This tool is intended **solely for educational and ethical security research**. Do not use it on systems you do not own or lack permission to audit.

---

