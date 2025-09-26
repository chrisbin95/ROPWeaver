#include "gadget_finder.h"
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <algorithm>
#include <capstone/capstone.h>
#include <vector>
#include <cstring>
#include <map>
#include <cctype>

// Helper: Detect ELF class for RISC-V
static cs_mode get_riscv_mode_from_binary(const std::string& binary_path) {
    std::ifstream file(binary_path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Could not open binary file.");
    }
    unsigned char e_ident[16];
    if (!file.read(reinterpret_cast<char*>(e_ident), sizeof(e_ident))) {
        throw std::runtime_error("Failed to read ELF header.");
    }
    if (e_ident[4] == 1) { // 32-bit ELF
        return CS_MODE_RISCV32;
    } else if (e_ident[4] == 2) { // 64-bit ELF
        return CS_MODE_RISCV64;
    }
    throw std::runtime_error("Unsupported ELF class.");
}

GadgetFinder::GadgetFinder(const std::vector<unsigned char>& code,
                           uint64_t base,
                           const std::string& arch,
                           const std::string& binary_path,
                           size_t maxSize)
    : m_code(code), m_baseAddress(base), m_arch(arch), m_binaryPath(binary_path), m_maxSize(maxSize) 
{
    // Choose Capstone arch/mode
    if (arch == "x86") {
        arch_id = CS_ARCH_X86;
        mode = CS_MODE_32;
    } else if (arch == "x86_64") {
        arch_id = CS_ARCH_X86;
        mode = CS_MODE_64;
    } else if (arch == "aarch64" || arch == "arm64") {
        arch_id = CS_ARCH_ARM64;
        mode = CS_MODE_LITTLE_ENDIAN;
    } else if (arch == "armv7" || arch == "arm") {
        arch_id = CS_ARCH_ARM;
        // We'll let capstone autodetect thumb/arm based on binary usage; default to ARM mode.
        mode = CS_MODE_ARM;
    } else if (arch == "riscv32") {
        arch_id = CS_ARCH_RISCV;
        mode = get_riscv_mode_from_binary(binary_path);
        if (mode != CS_MODE_RISCV32) mode = CS_MODE_RISCV32;
    } else if (arch == "riscv64") {
        arch_id = CS_ARCH_RISCV;
        mode = get_riscv_mode_from_binary(binary_path);
        if (mode != CS_MODE_RISCV64) mode = CS_MODE_RISCV64;
    } else {
        throw std::runtime_error("Unsupported architecture: " + arch);
    }

    if (cs_open(arch_id, mode, &handle) != CS_ERR_OK) {
        throw std::runtime_error("Failed to initialize Capstone handle");
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
}

GadgetFinder::~GadgetFinder() {
    cs_close(&handle);
}

void GadgetFinder::findGadgets() {
    cs_insn *all_insns = nullptr;
    size_t count = cs_disasm(handle, m_code.data(), m_code.size(), m_baseAddress, 0, &all_insns);
    if (count == 0) {
        std::cerr << "[!] Failed to disassemble code!" << std::endl;
        return;
    }

    for (size_t i = 0; i < count; ++i) {
        bool is_ret = false;
        const auto& insn = all_insns[i];

        // Uniform check: many caps alias returns to "ret"
        if (std::string(insn.mnemonic) == "ret") {
            is_ret = true;
        }

        // For architectures where "ret" isn't canonical
        if (!is_ret) {
            std::string mnem = insn.mnemonic ? insn.mnemonic : "";
            std::string ops  = insn.op_str ? insn.op_str : "";
            // Normalize to lowercase (Capstone usually already returns lowercase)
            std::transform(mnem.begin(), mnem.end(), mnem.begin(), [](unsigned char c){ return std::tolower(c); });
            std::transform(ops.begin(), ops.end(), ops.begin(), [](unsigned char c){ return std::tolower(c); });

            if (m_arch == "armv7" || m_arch == "arm") {
                if (mnem == "bx" && (ops.find("lr") != std::string::npos || ops.find("r14") != std::string::npos)) {
                    is_ret = true;
                }
                if (mnem == "pop" && ops.find("pc") != std::string::npos) {
                    is_ret = true;
                }
            } else if (m_arch == "riscv32" || m_arch == "riscv64") {
                // Capstone usually gives 'ret' for jalr ra,0(ra)
                if (mnem == "jalr" && (ops.find("ra") != std::string::npos)) {
                    // treat as ret
                    is_ret = true;
                }
            }
        }

        if (is_ret) {
            Gadget g;
            g.architecture = m_arch;

            // Gather up to m_maxSize instructions ending at the return instruction
            for (int j = 0; j < static_cast<int>(m_maxSize) && (static_cast<int>(i) - j) >= 0; ++j) {
                const auto& current_insn = all_insns[i - j];
                std::string mnem = current_insn.mnemonic ? current_insn.mnemonic : "";
                std::string ops  = current_insn.op_str ? current_insn.op_str : "";
 
                g.instructions.insert(g.instructions.begin(), { mnem, ops });
                g.address = current_insn.address;
            }
            m_gadgets.push_back(g);
        }
    }

    cs_free(all_insns, count);
}

// Utility helpers for parsing operand strings (simple, conservative)
static bool contains_register(const std::string &opstr, const std::string &reg) {
    if (opstr.empty()) return false;
    // naive substring check
    return opstr.find(reg) != std::string::npos;
}

static bool op_contains_any_reg(const std::string &opstr, const std::vector<std::string> &regs) {
    for (const auto &r : regs) if (contains_register(opstr, r)) return true;
    return false;
}

// categorizeGadgets to support ARM32 (ARM/Thumb)
std::map<std::string, std::vector<Gadget>> GadgetFinder::categorizeGadgets() const {
    std::map<std::string, std::vector<Gadget>> categories;

    for (const auto& g : m_gadgets) {
        bool categorized = false;

        // Indirect jump/call detection
        if (g.isIndirectJumpOrCall()) {
            categories["indirect jump/call"].push_back(g);
            categorized = true;
        }

        // Stack pivot detection
        if (g.isStackPivot()) {
            categories["stack pivot"].push_back(g);
            categorized = true;
        }

        // Syscall detection: cover ARM SVC/SWI arches
        if (g.hasMnemonic("syscall") || g.hasMnemonic("sysenter") || g.hasMnemonic("int80")) {
            categories["syscall"].push_back(g);
            categorized = true;
        }
        if (!categorized) {
            // ARM specific: SVC (Supervisor Call) / SWI
            if ((m_arch == "armv7" || m_arch == "arm") && g.hasMnemonic("svc")) {
                categories["syscall"].push_back(g);
                categorized = true;
            }
            if ((m_arch == "armv7" || m_arch == "arm") && g.hasMnemonic("swi")) {
                categories["syscall"].push_back(g);
                categorized = true;
            }
        }

        // POP-style gadgets
        if (!categorized && g.hasMnemonic("pop")) {
            // Identify which registers are popped
            for (const auto &ins : g.instructions) {

                if (ins.mnemonic == "pop") { 

                    std::string ops = ins.op_str;
                    
                    // clean spaces, lowercase
                    std::transform(ops.begin(), ops.end(), ops.begin(), [](unsigned char c){ return std::tolower(c); });
                    // remove braces/spaces
                    // Simple checks for common registers
                    std::vector<std::string> arm_regs = {"r0","r1","r2","r3","r4","r5","r6","r7","r8","r9","r10","r11","r12","sp","lr","pc"};
                    for (const auto &reg : arm_regs) {
                        if (ops.find(reg) != std::string::npos) {
                            categories["pop " + reg].push_back(g);
                            categorized = true;
                        }
                    }
                    // Also handle combined pops like "{r0, r1}" -> put into "pop {r0,r1}" bucket
                    if (!categorized && ops.find('{') != std::string::npos && ops.find('}') != std::string::npos) {
                        // normalize content inside braces
                        auto start = ops.find('{');
                        auto end = ops.find('}');
                        if (start != std::string::npos && end != std::string::npos && end > start + 1) {
                            std::string inside = ops.substr(start + 1, end - start - 1);
                            
                            inside.erase(std::remove_if(inside.begin(), inside.end(), ::isspace), inside.end());
                            categories["pop {" + inside + "}"].push_back(g);
                            categorized = true;
                        }
                    }
                    
                    if (!categorized && ops.find("pc") != std::string::npos) {
                        categories["pop pc"].push_back(g);
                        categorized = true;
                    }
                }
            }
        }

        // ARM-specific: detect stack pivot patterns and mov/ldr sp gadgets
        if (!categorized && (m_arch == "armv7" || m_arch == "arm")) {
            
            bool found_stack_pivot = false;
            for (const auto &ins : g.instructions) {
                std::string mnem = ins.mnemonic; 
                std::string ops  = ins.op_str;
                // If 'op_str' is the member name, change to: std::string ops = ins.op_str;

                std::transform(mnem.begin(), mnem.end(), mnem.begin(), [](unsigned char c){ return std::tolower(c); });
                std::transform(ops.begin(), ops.end(), ops.begin(), [](unsigned char c){ return std::tolower(c); });

                if (mnem == "mov" && ops.find("sp,") != std::string::npos) {
                    found_stack_pivot = true;
                    categories["stack pivot/mov sp"].push_back(g);
                    categorized = true;
                    break;
                }
                if ((mnem == "add" || mnem == "sub") && ops.find("sp, sp") != std::string::npos) {
                    found_stack_pivot = true;
                    categories["stack pivot/addsub sp"].push_back(g);
                    categorized = true;
                    break;
                }
                if ((mnem == "ldr" || mnem == "ldm" || mnem == "pop") && ops.find("sp") != std::string::npos) {
                    // ldr sp, [rX, ...] or ldm sp!, {..} etc
                    // if it loads into sp, it's a pivot
                    if (mnem == "ldr" && ops.find("sp,") != std::string::npos) {
                        found_stack_pivot = true;
                        categories["stack pivot/ldr sp"].push_back(g);
                        categorized = true;
                        break;
                    }
                    if (mnem == "ldm" && ops.find("sp") != std::string::npos) {
                        found_stack_pivot = true;
                        categories["stack pivot/ldm sp"].push_back(g);
                        categorized = true;
                        break;
                    }
                }
            }
            if (found_stack_pivot) {
                // already categorized and pushed above
            }
        }

        // pop-specific categorization for x86/x86_64 handled by generic code
        if (!categorized && g.hasMnemonic("pop") && (m_arch == "x86" || m_arch == "x86_64")) {
            // rely on g.popInstructionCount() (existing Gadget methods)
            if (g.popInstructionCount() > 0) {
                categories["pop"].push_back(g);
                categorized = true;
            }
        }

        // Syscall detection for aarch64
        if (!categorized && m_arch == "aarch64" && g.hasMnemonic("svc")) {
            categories["syscall"].push_back(g);
            categorized = true;
        }

        // Arithmetic/logic category (generic)
        if (!categorized && g.hasArithmeticOrLogic()) {
            categories["arithmetic/logic"].push_back(g);
            categorized = true;
        }

        // fallback
        if (!categorized) {
            categories["others"].push_back(g);
        }
    }

    return categories;
}