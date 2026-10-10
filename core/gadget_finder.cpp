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

#include <set>

GadgetFinder::~GadgetFinder() {
    cs_close(&handle);
}

static bool is_terminator_instruction(const cs_insn& insn, const std::string& arch) {
    std::string mnem = insn.mnemonic ? insn.mnemonic : "";
    std::string ops  = insn.op_str ? insn.op_str : "";
    std::transform(mnem.begin(), mnem.end(), mnem.begin(), [](unsigned char c){ return std::tolower(c); });
    std::transform(ops.begin(), ops.end(), ops.begin(), [](unsigned char c){ return std::tolower(c); });

    // Universal / x86 / x86_64 returns
    if (mnem == "ret" || mnem == "retf" || mnem == "retfq" || mnem == "iret" || mnem == "iretd" || mnem == "iretq") {
        return true;
    }

    // x86 / x86_64 syscall / interrupt
    if (mnem == "syscall" || mnem == "sysenter") {
        return true;
    }
    if (mnem == "int" && ops.find("0x80") != std::string::npos) {
        return true;
    }

    // ARM / Thumb
    if (arch == "armv7" || arch == "arm" || arch == "thumb") {
        if (mnem == "bx" && (ops.find("lr") != std::string::npos || ops.find("r14") != std::string::npos)) {
            return true;
        }
        if (mnem == "pop" && ops.find("pc") != std::string::npos) {
            return true;
        }
        if (mnem == "svc" || mnem == "swi") {
            return true;
        }
    }

    // AArch64
    if (arch == "aarch64" || arch == "arm64") {
        if (mnem == "ret" || mnem == "eret" || mnem == "svc") {
            return true;
        }
    }

    // RISC-V
    if (arch == "riscv32" || arch == "riscv64") {
        if (mnem == "ret" || (mnem == "jalr" && (ops.find("ra") != std::string::npos || ops.find("zero") != std::string::npos))) {
            return true;
        }
        if (mnem == "ecall") {
            return true;
        }
    }

    return false;
}

static bool is_invalid_or_branch_instruction(const cs_insn& insn, const std::string& arch) {
    std::string mnem = insn.mnemonic ? insn.mnemonic : "";
    std::transform(mnem.begin(), mnem.end(), mnem.begin(), [](unsigned char c){ return std::tolower(c); });

    // Halting / trapping / illegal
    if (mnem == "hlt" || mnem == "ud2" || mnem == "int3" || mnem == "ill") {
        return true;
    }

    // Intermediate returns and system calls
    if (mnem == "ret" || mnem == "retf" || mnem == "retfq" || mnem == "syscall" || mnem == "sysenter" || mnem == "ecall") {
        return true;
    }
    if (mnem == "int") {
        return true;
    }

    // Intermediate calls
    if (mnem == "call" || mnem == "callq" || mnem == "bl" || mnem == "blx" || mnem == "jal") {
        return true;
    }

    // Intermediate jumps & loops
    if (arch == "x86" || arch == "x86_64") {
        if (mnem.rfind("j", 0) == 0 || mnem.rfind("loop", 0) == 0) {
            return true;
        }
    } else if (arch == "armv7" || arch == "arm" || arch == "thumb" || arch == "aarch64" || arch == "arm64") {
        if (mnem.rfind("b", 0) == 0 || mnem == "cbz" || mnem == "cbnz") {
            return true;
        }
    } else if (arch == "riscv32" || arch == "riscv64") {
        if (mnem.rfind("b", 0) == 0 || mnem.rfind("j", 0) == 0) {
            return true;
        }
    }

    return false;
}

static bool is_padding_or_prefix(const cs_insn& insn) {
    std::string mnem = insn.mnemonic ? insn.mnemonic : "";
    std::transform(mnem.begin(), mnem.end(), mnem.begin(), [](unsigned char c){ return std::tolower(c); });
    return (mnem == "nop" || mnem == "endbr64" || mnem == "endbr32");
}

void GadgetFinder::findGadgets() {
    m_gadgets.clear();

    cs_insn *all_insns = nullptr;
    size_t count = cs_disasm(handle, m_code.data(), m_code.size(), m_baseAddress, 0, &all_insns);
    if (count == 0) {
        std::cerr << "[!] Failed to disassemble code!" << std::endl;
        return;
    }

    // Maximum gadget instruction depth (typically 5 instructions max)
    size_t max_depth = std::min<size_t>(m_maxSize, 5);
    if (max_depth < 1) max_depth = 1;

    std::set<std::pair<uint64_t, std::string>> seen_gadgets;

    for (size_t i = 0; i < count; ++i) {
        if (!is_terminator_instruction(all_insns[i], m_arch)) {
            continue;
        }

        // Test sequences ending at all_insns[i] with length 1 to max_depth
        for (size_t len = 1; len <= max_depth && (i + 1) >= len; ++len) {
            size_t start_idx = i - (len - 1);

            // Skip multi-instruction candidates that begin with padding or endbr
            if (len > 1 && is_padding_or_prefix(all_insns[start_idx])) {
                continue;
            }

            // Check contiguity and ensure no branches/calls/traps/intermediate terminators
            bool valid = true;
            for (size_t k = start_idx; k < i; ++k) {
                // Must be physically contiguous in memory
                if (all_insns[k].address + all_insns[k].size != all_insns[k + 1].address) {
                    valid = false;
                    break;
                }
                // No control flow or invalid instruction before the terminator
                if (is_invalid_or_branch_instruction(all_insns[k], m_arch)) {
                    valid = false;
                    break;
                }
            }
            if (!valid) continue;

            // Also check the terminator itself isn't a trap
            std::string term_mnem = all_insns[i].mnemonic ? all_insns[i].mnemonic : "";
            std::transform(term_mnem.begin(), term_mnem.end(), term_mnem.begin(), [](unsigned char c){ return std::tolower(c); });
            if (term_mnem == "hlt" || term_mnem == "ud2" || term_mnem == "int3") {
                continue;
            }

            Gadget g;
            g.architecture = m_arch;
            g.address = all_insns[start_idx].address;

            std::string asm_str;
            for (size_t k = start_idx; k <= i; ++k) {
                std::string mnem = all_insns[k].mnemonic ? all_insns[k].mnemonic : "";
                std::string ops  = all_insns[k].op_str ? all_insns[k].op_str : "";
                g.instructions.push_back({ mnem, ops });

                if (!asm_str.empty()) asm_str += " ; ";
                asm_str += mnem;
                if (!ops.empty()) asm_str += " " + ops;
            }
            g.assembly = asm_str;

            // Target register for pop gadgets
            if (g.instructions.size() == 2 && g.instructions[0].mnemonic == "pop") {
                g.target_register = g.instructions[0].op_str;
            }

            if (seen_gadgets.insert({ g.address, g.assembly }).second) {
                m_gadgets.push_back(g);
            }
        }
    }

    cs_free(all_insns, count);

    // Sort gadgets by address ascending
    std::sort(m_gadgets.begin(), m_gadgets.end(), [](const Gadget& a, const Gadget& b) {
        if (a.address != b.address) return a.address < b.address;
        return a.instructions.size() < b.instructions.size();
    });
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

        // Syscall detection: cover ARM SVC/SWI and x86 int 0x80
        if (g.hasMnemonic("syscall") || g.hasMnemonic("sysenter") || g.hasMnemonic("int80") ||
            (g.hasMnemonic("int") && !g.instructions.empty() && g.instructions.back().op_str.find("0x80") != std::string::npos)) {
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
                    std::transform(ops.begin(), ops.end(), ops.begin(), [](unsigned char c){ return std::tolower(c); });

                    std::vector<std::string> target_regs;
                    if (m_arch == "x86" || m_arch == "x86_64") {
                        target_regs = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"};
                    } else {
                        target_regs = {"r0","r1","r2","r3","r4","r5","r6","r7","r8","r9","r10","r11","r12","sp","lr","pc"};
                    }
                    for (const auto &reg : target_regs) {
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