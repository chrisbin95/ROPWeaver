// gadget_finder.cpp
#include "gadget_finder.h"
#include <capstone/capstone.h>
#include <sstream>
#include <iomanip>
#include <iostream>

GadgetFinder::GadgetFinder(const std::vector<uint8_t>& code, const std::string& arch)
    : binary_code(code), architecture(arch), handle(0) {}

void GadgetFinder::findGadgets() {
    cs_arch arch;
    cs_mode mode;

    // Detect architecture
    if (architecture == "x86_64") {
        arch = CS_ARCH_X86;
        mode = CS_MODE_64;
    } else if (architecture == "i386") {
        arch = CS_ARCH_X86;
        mode = CS_MODE_32;
    } else if (architecture == "arm") {
        arch = CS_ARCH_ARM;
        mode = CS_MODE_ARM;
    } else if (architecture == "aarch64") {
        arch = CS_ARCH_ARM64;
        mode = CS_MODE_ARM;
    } else {
        std::cerr << "Unsupported architecture: " << architecture << std::endl;
        return;
    }

    if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
        std::cerr << "Failed to initialize Capstone" << std::endl;
        return;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    const size_t max_gadget_len = 10; // Max instructions per gadget
    const size_t max_bytes = 16;      // Max bytes per gadget
    const size_t align = 1;

    // Slide window over the binary code
    for (size_t i = 0; i < binary_code.size(); i += align) {
        size_t size = std::min(max_bytes, binary_code.size() - i);
        const uint8_t* code_ptr = binary_code.data() + i;

        cs_insn* insn;
        size_t count = cs_disasm(handle, code_ptr, size, 0x1000 + i, max_gadget_len, &insn);
        if (count > 0) {
            std::ostringstream gadget;
            for (size_t j = 0; j < count; ++j) {
                gadget << std::hex << insn[j].address << ": " << insn[j].mnemonic << " " << insn[j].op_str << " ; ";
                // Stop at ret/jmp/call/syscall for ROP gadget
                std::string mnem = insn[j].mnemonic;
                if (mnem == "ret" || mnem == "syscall" || mnem.find("jmp") == 0 || mnem.find("call") == 0) {
                    gadgets.push_back(gadget.str());
                    break;
                }
            }
            cs_free(insn, count);
        }
    }

    cs_close(&handle);
}

std::vector<std::string> GadgetFinder::getGadgets() const {
    return gadgets;
}
