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
    std::string pop_instruction = "pop " + reg + " ; ret";
    auto it = std::find_if(rop_gadgets.begin(), rop_gadgets.end(), [&](const Gadget& g) {
        return g.toString().find(pop_instruction) != std::string::npos;
    });

    if (it != rop_gadgets.end()) {
        return *it;
    }
    return std::nullopt;
}

std::optional<Gadget> ChainBuilder::findSpecificGadget(const std::string& instruction) {
    auto it = std::find_if(rop_gadgets.begin(), rop_gadgets.end(), [&](const Gadget& g) {
        return g.toString().find(instruction) != std::string::npos &&
               g.toString().find("ret") != std::string::npos;
    });
    if (it != rop_gadgets.end()) {
        return *it;
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
            chain.add_step(*syscall_gadget, 0, "Invoke execve syscall");
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
            chain.add_step(*int80_gadget, 0, "Invoke int 0x80");
            return chain;
        }
    } else if (m_arch == "aarch64") {
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
            chain.add_step(*svc_gadget, 0, "Invoke execve syscall");
            return chain;
        }
    } else if (m_arch == "armv7") {
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
            chain.add_step(*svc_gadget, 0, "Invoke execve syscall");
            return chain;
        }
    } else if (m_arch == "riscv") {
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
            chain.add_step(*ecall_gadget, 0, "Invoke ecall");
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
