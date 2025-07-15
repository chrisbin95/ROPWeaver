// chain_builder.cpp
#include "chain_builder.h"
#include <sstream>
#include <regex>

ChainBuilder::ChainBuilder(const std::vector<std::string>& gadgets)
    : rop_gadgets(gadgets) {}

// Helper to find a gadget containing all required substrings
std::string ChainBuilder::findGadget(const std::vector<std::string>& keywords) {
    for (const std::string& g : rop_gadgets) {
        bool match = true;
        for (const std::string& k : keywords) {
            if (g.find(k) == std::string::npos) {
                match = false;
                break;
            }
        }
        if (match) return g;
    }
    return "";
}

std::string ChainBuilder::buildExecveChain(const std::string& binsh_path) {
    std::ostringstream chain;
    chain << "Generated ROP chain for execve(\"" << binsh_path << "\", NULL, NULL):\n\n";

    // Attempt for x86_64 ELF/Linux
    std::string popRDI = findGadget({"pop rdi", "ret"});
    std::string popRSI = findGadget({"pop rsi", "ret"});
    std::string popRDX = findGadget({"pop rdx", "ret"});
    std::string popRAX = findGadget({"pop rax", "ret"});
    std::string syscall = findGadget({"syscall"});

    if (!popRDI.empty() && !popRSI.empty() && !popRDX.empty() && !popRAX.empty() && !syscall.empty()) {
        chain << "# x86_64 execve('/bin/sh', NULL, NULL)\n";
        chain << popRDI << "\n";
        chain << "-> Address of '/bin/sh' string\n";
        chain << popRSI << "\n";
        chain << "-> 0 (NULL)\n";
        chain << popRDX << "\n";
        chain << "-> 0 (NULL)\n";
        chain << popRAX << "\n";
        chain << "-> 59 (execve syscall number)\n";
        chain << syscall << "\n";
        return chain.str();
    }

    // Attempt for i386 (x86)
    std::string int80 = findGadget({"int", "0x80"});
    std::string movEBX = findGadget({"mov ebx", "ret"});

    if (!popRAX.empty() && !popRSI.empty() && !popRDX.empty() && int80 != "") {
        chain << "# i386 execve('/bin/sh', NULL, NULL)\n";
        chain << popRAX << " -> 11 (execve)\n";
        chain << movEBX << " -> '/bin/sh'\n";
        chain << popRSI << " -> 0 (NULL)\n";
        chain << popRDX << " -> 0 (NULL)\n";
        chain << int80 << "\n";
        return chain.str();
    }

    // ARM (ARM mode)
    std::string svc = findGadget({"svc"});
    std::string popR0 = findGadget({"pop {r0", "pc"});
    std::string popR1 = findGadget({"pop {r1", "pc"});
    std::string popR2 = findGadget({"pop {r2", "pc"});
    std::string popR7 = findGadget({"pop {r7", "pc"});

    if (!svc.empty() && !popR0.empty() && !popR1.empty() && !popR2.empty() && !popR7.empty()) {
        chain << "# ARM execve('/bin/sh', NULL, NULL)\n";
        chain << popR0 << " -> Address of '/bin/sh'\n";
        chain << popR1 << " -> 0\n";
        chain << popR2 << " -> 0\n";
        chain << popR7 << " -> 11 (syscall number for execve)\n";
        chain << svc << "\n";
        return chain.str();
    }

    // RISC-V (limited gadget availability typically)
    std::string ecall = findGadget({"ecall"});
    std::string loadA0 = findGadget({"mv a0", "ret"});
    std::string loadA1 = findGadget({"mv a1", "ret"});
    std::string loadA2 = findGadget({"mv a2", "ret"});
    std::string loadA7 = findGadget({"li a7", "ret"});

    if (!ecall.empty() && !loadA0.empty() && !loadA1.empty() && !loadA2.empty() && !loadA7.empty()) {
        chain << "# RISC-V execve('/bin/sh', NULL, NULL)\n";
        chain << loadA0 << " -> Address of '/bin/sh'\n";
        chain << loadA1 << " -> 0\n";
        chain << loadA2 << " -> 0\n";
        chain << loadA7 << " -> 221 (syscall number)\n";
        chain << ecall << "\n";
        return chain.str();
    }

    // Fallback
    return "Unable to construct a ROP chain for execve(). Required gadgets not found.\n";
}
