// chain_builder.cpp
#include "chain_builder.h"

Gadget ChainBuilder::findGadget(const std::vector<std::string>& keywords) {
    for (const Gadget& g : rop_gadgets) {
        bool match = true;
        for (const std::string& k : keywords) {
            if (g.instruction.find(k) == std::string::npos) {
                match = false;
                break;
            }
        }
        if (match) return g;  // Return the whole gadget
    }
    return Gadget("", 0); // return invalid gadget
}

ROPChain ChainBuilder::buildExecveChain(const std::string& binsh_path) {
    ROPChain chain;

    Gadget popRDI = findGadget({"pop rdi", "ret"});
    Gadget popRSI = findGadget({"pop rsi", "ret"});
    Gadget popRDX = findGadget({"pop rdx", "ret"});
    Gadget popRAX = findGadget({"pop rax", "ret"});
    Gadget syscall = findGadget({"syscall"});

    // Check if gadgets are valid by checking if address != 0
    if (popRDI.address != 0 && popRSI.address != 0 && popRDX.address != 0 && popRAX.address != 0 && syscall.address != 0) {
        chain.steps.push_back({popRDI, "pop rdi; set pointer to '" + binsh_path + "'"});
        chain.steps.push_back({popRSI, "pop rsi; set to NULL"});
        chain.steps.push_back({popRDX, "pop rdx; set to NULL"});
        chain.steps.push_back({popRAX, "pop rax; set to 59 (execve syscall)"});
        chain.steps.push_back({syscall, "syscall; invoke execve"});
        return chain;
    }

    // i386 (x86) example — note findGadget must return Gadget, not std::string here too
    Gadget int80 = findGadget({"int", "0x80"});
    Gadget movEBX = findGadget({"mov ebx", "ret"});

    if (popRAX.address != 0 && popRSI.address != 0 && popRDX.address != 0 && int80.address != 0 && movEBX.address != 0) {
        chain.steps.push_back({popRAX, "pop rax; set to 11 (execve syscall)"});
        chain.steps.push_back({movEBX, "mov ebx; set pointer to '" + binsh_path + "'"});
        chain.steps.push_back({popRSI, "pop rsi; set to NULL"});
        chain.steps.push_back({popRDX, "pop rdx; set to NULL"});
        chain.steps.push_back({int80, "int 0x80; invoke syscall"});
        return chain;
    }

    // ARM
    Gadget svc = findGadget({"svc"});
    Gadget popR0 = findGadget({"pop {r0", "pc"});
    Gadget popR1 = findGadget({"pop {r1", "pc"});
    Gadget popR2 = findGadget({"pop {r2", "pc"});
    Gadget popR7 = findGadget({"pop {r7", "pc"});

    if (svc.address != 0 && popR0.address != 0 && popR1.address != 0 && popR2.address != 0 && popR7.address != 0) {
        chain.steps.push_back({popR0, "pop r0; set pointer to '" + binsh_path + "'"});
        chain.steps.push_back({popR1, "pop r1; set to 0"});
        chain.steps.push_back({popR2, "pop r2; set to 0"});
        chain.steps.push_back({popR7, "pop r7; set to 11 (execve syscall)"});
        chain.steps.push_back({svc, "svc; invoke syscall"});
        return chain;
    }

    // RISC-V
    Gadget ecall = findGadget({"ecall"});
    Gadget loadA0 = findGadget({"mv a0", "ret"});
    Gadget loadA1 = findGadget({"mv a1", "ret"});
    Gadget loadA2 = findGadget({"mv a2", "ret"});
    Gadget loadA7 = findGadget({"li a7", "ret"});

    if (ecall.address != 0 && loadA0.address != 0 && loadA1.address != 0 && loadA2.address != 0 && loadA7.address != 0) {
        chain.steps.push_back({loadA0, "mv a0; set pointer to '" + binsh_path + "'"});
        chain.steps.push_back({loadA1, "mv a1; set to 0"});
        chain.steps.push_back({loadA2, "mv a2; set to 0"});
        chain.steps.push_back({loadA7, "li a7; set to 221 (execve syscall)"});
        chain.steps.push_back({ecall, "ecall; invoke syscall"});
        return chain;
    }

    return chain; // empty if no suitable chain found
}
