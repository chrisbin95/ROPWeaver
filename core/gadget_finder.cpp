#include "gadget_finder.h"
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <algorithm>
#include <capstone/capstone.h>
#include <vector>
#include <cstring>
#include <map>
#include <set>
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

// Forward declaration
static void classify_gadget_multidim(Gadget &g, const std::string &arch);

void GadgetFinder::findGadgets() {
    m_gadgets.clear();

    if (m_code.empty()) {
        return;
    }

    // Maximum gadget instruction depth (typically 5 instructions max)
    size_t max_depth = std::min<size_t>(m_maxSize, 5);
    if (max_depth < 1) max_depth = 1;

    std::set<std::pair<uint64_t, std::string>> seen_gadgets;

    // --- Pass 1: Linear Disassembly ---
    cs_insn *all_insns = nullptr;
    size_t count = cs_disasm(handle, m_code.data(), m_code.size(), m_baseAddress, 0, &all_insns);

    if (count > 0) {
        for (size_t i = 0; i < count; ++i) {
            if (!is_terminator_instruction(all_insns[i], m_arch)) {
                continue;
            }

            for (size_t len = 1; len <= max_depth && (i + 1) >= len; ++len) {
                size_t start_idx = i - (len - 1);

                if (len > 1 && is_padding_or_prefix(all_insns[start_idx])) {
                    continue;
                }

                bool valid = true;
                for (size_t k = start_idx; k < i; ++k) {
                    if (all_insns[k].address + all_insns[k].size != all_insns[k + 1].address) {
                        valid = false;
                        break;
                    }
                    if (is_invalid_or_branch_instruction(all_insns[k], m_arch)) {
                        valid = false;
                        break;
                    }
                }
                if (!valid) continue;

                std::string term_mnem = all_insns[i].mnemonic ? all_insns[i].mnemonic : "";
                std::transform(term_mnem.begin(), term_mnem.end(), term_mnem.begin(), [](unsigned char c){ return std::tolower(c); });
                if (term_mnem == "hlt" || term_mnem == "ud2" || term_mnem == "int3") {
                    continue;
                }

                Gadget g;
                g.architecture = m_arch;
                g.address = all_insns[start_idx].address;
                g.preferred_va = g.address;

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

                if (g.instructions.size() == 2 && g.instructions[0].mnemonic == "pop") {
                    g.target_register = g.instructions[0].op_str;
                }

                // Validate gadget bytes against m_code
                if (g.address >= m_baseAddress) {
                    size_t code_offset = static_cast<size_t>(g.address - m_baseAddress);
                    size_t total_bytes = static_cast<size_t>((all_insns[i].address + all_insns[i].size) - all_insns[start_idx].address);
                    if (code_offset + total_bytes <= m_code.size()) {
                        bool b_ok = true;
                        size_t cur = code_offset;
                        for (size_t k = start_idx; k <= i; ++k) {
                            if (std::memcmp(m_code.data() + cur, all_insns[k].bytes, all_insns[k].size) != 0) {
                                b_ok = false;
                                break;
                            }
                            cur += all_insns[k].size;
                        }
                        g.byte_verified = b_ok;
                    }
                }

                if (seen_gadgets.insert({ g.address, g.assembly }).second) {
                    m_gadgets.push_back(g);
                }
            }
        }
        cs_free(all_insns, count);
    }

    // --- Pass 2: Overlapping instruction sequences for x86/x86_64 (Requirement 5) ---
    if (m_arch == "x86" || m_arch == "x86_64") {
        for (size_t term_idx = 0; term_idx < m_code.size(); ++term_idx) {
            uint8_t b = m_code[term_idx];
            bool is_term = (b == 0xC3 || b == 0xCB || b == 0xC2 || b == 0xCA);
            if (!is_term && term_idx + 1 < m_code.size()) {
                if (b == 0x0F && (m_code[term_idx + 1] == 0x05 || m_code[term_idx + 1] == 0x34)) is_term = true;
                if (b == 0xCD && m_code[term_idx + 1] == 0x80) is_term = true;
            }
            if (!is_term) continue;

            size_t max_back = std::min<size_t>(term_idx, 15);
            for (size_t back = 1; back <= max_back; ++back) {
                size_t start_idx = term_idx - back;

                cs_insn *sub_insns = nullptr;
                size_t sub_count = cs_disasm(handle, m_code.data() + start_idx, back + 4,
                                             m_baseAddress + start_idx, max_depth, &sub_insns);
                if (sub_count == 0) continue;

                bool match = false;
                size_t end_insn_idx = 0;
                for (size_t k = 0; k < sub_count; ++k) {
                    if (sub_insns[k].address == m_baseAddress + term_idx) {
                        if (is_terminator_instruction(sub_insns[k], m_arch)) {
                            match = true;
                            end_insn_idx = k;
                            break;
                        }
                    }
                }

                if (match && end_insn_idx < max_depth) {
                    bool valid = true;
                    for (size_t k = 0; k < end_insn_idx; ++k) {
                        if (sub_insns[k].address + sub_insns[k].size != sub_insns[k + 1].address) {
                            valid = false;
                            break;
                        }
                        if (is_invalid_or_branch_instruction(sub_insns[k], m_arch)) {
                            valid = false;
                            break;
                        }
                    }
                    if (end_insn_idx > 0 && is_padding_or_prefix(sub_insns[0])) {
                        valid = false;
                    }

                    if (valid) {
                        Gadget g;
                        g.architecture = m_arch;
                        g.address = sub_insns[0].address;
                        g.preferred_va = g.address;

                        std::string asm_str;
                        for (size_t k = 0; k <= end_insn_idx; ++k) {
                            std::string mnem = sub_insns[k].mnemonic ? sub_insns[k].mnemonic : "";
                            std::string ops  = sub_insns[k].op_str ? sub_insns[k].op_str : "";
                            g.instructions.push_back({ mnem, ops });
                            if (!asm_str.empty()) asm_str += " ; ";
                            asm_str += mnem;
                            if (!ops.empty()) asm_str += " " + ops;
                        }
                        g.assembly = asm_str;

                        if (g.instructions.size() == 2 && g.instructions[0].mnemonic == "pop") {
                            g.target_register = g.instructions[0].op_str;
                        }

                        // Validate bytes
                        size_t total_bytes = static_cast<size_t>(
                            (sub_insns[end_insn_idx].address + sub_insns[end_insn_idx].size) - sub_insns[0].address);
                        if (start_idx + total_bytes <= m_code.size()) {
                            bool b_ok = true;
                            size_t cur = start_idx;
                            for (size_t k = 0; k <= end_insn_idx; ++k) {
                                if (std::memcmp(m_code.data() + cur, sub_insns[k].bytes, sub_insns[k].size) != 0) {
                                    b_ok = false;
                                    break;
                                }
                                cur += sub_insns[k].size;
                            }
                            g.byte_verified = b_ok;
                        }

                        if (seen_gadgets.insert({ g.address, g.assembly }).second) {
                            m_gadgets.push_back(g);
                        }
                    }
                }
                cs_free(sub_insns, sub_count);
            }
        }
    }

    // Sort gadgets by address ascending
    std::sort(m_gadgets.begin(), m_gadgets.end(), [](const Gadget& a, const Gadget& b) {
        if (a.address != b.address) return a.address < b.address;
        return a.instructions.size() < b.instructions.size();
    });

    // Run multi-dimensional classification on all gadgets
    for (auto& g : m_gadgets) {
        classify_gadget_multidim(g, m_arch);
    }
}

static bool contains_reg_token(const std::string& text, const std::string& reg) {
    size_t pos = 0;
    while ((pos = text.find(reg, pos)) != std::string::npos) {
        bool left_ok = (pos == 0) || (!isalnum((unsigned char)text[pos - 1]) && text[pos - 1] != '_');
        size_t end = pos + reg.length();
        bool right_ok = (end == text.length()) || (!isalnum((unsigned char)text[end]) && text[end] != '_');
        if (left_ok && right_ok) return true;
        pos += reg.length();
    }
    return false;
}

// ---------------------------------------------------------------------------
// classify_gadget_multidim: populates g.categories, g.registers_read,
// g.registers_modified, g.stack_delta, g.stack_consumption, g.has_memory_read,
// g.has_memory_write, g.side_effects, g.terminator_type, g.instruction_count,
// g.classification_confidence.
// ---------------------------------------------------------------------------
static void classify_gadget_multidim(Gadget &g, const std::string &arch) {
    g.categories.clear();
    g.registers_read.clear();
    g.registers_modified.clear();
    g.side_effects.clear();
    g.stack_delta = 0;
    g.stack_consumption = 0;
    g.has_memory_read = false;
    g.has_memory_write = false;
    g.terminator_type.clear();
    g.instruction_count = static_cast<uint8_t>(g.instructions.size());
    g.classification_confidence = 50;

    if (g.instructions.empty()) {
        g.categories.push_back("misc");
        g.category = "misc";
        return;
    }

    auto lc = [](std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
        return s;
    };

    bool is_x86 = (arch == "x86" || arch == "x86_64");
    bool is_arm  = (arch == "armv7" || arch == "arm");

    // Terminator type
    {
        const auto &last = g.instructions.back();
        std::string lm = lc(last.mnemonic);
        if (lm == "ret" || lm == "retf" || lm == "retfq") {
            g.terminator_type = "RET";
        } else if (lm == "syscall" || lm == "sysenter" || lm == "ecall" || lm == "svc" || lm == "swi" ||
                   (lm == "int" && last.op_str.find("0x80") != std::string::npos)) {
            g.terminator_type = "SYSCALL";
        } else if (lm == "jmp" || lm == "b") {
            g.terminator_type = "JMP";
        } else if (lm == "call" || lm == "bl" || lm == "blx" || lm == "blr") {
            g.terminator_type = "CALL";
        } else if (lm == "bx" && (last.op_str.find("lr") != std::string::npos)) {
            g.terminator_type = "RET";
        } else if (lm == "pop" && last.op_str.find("pc") != std::string::npos) {
            g.terminator_type = "RET";
        } else if (lm == "jalr") {
            g.terminator_type = "RET";
        } else {
            g.terminator_type = lm;
        }
    }

    bool has_register_load   = false;
    bool has_stack_adjust    = false;
    bool has_arithmetic      = false;
    bool has_logical         = false;
    bool has_mem_read        = false;
    bool has_mem_write       = false;
    bool has_control_xfer    = false;
    bool has_stack_pivot     = false;
    bool has_syscall         = false;

    std::set<std::string> regs_read_set, regs_mod_set;

    static const std::vector<std::string> x86_gp_regs = {
        "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
        "r8","r9","r10","r11","r12","r13","r14","r15",
        "eax","ebx","ecx","edx","esi","edi","ebp","esp",
        "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d",
        "ax","bx","cx","dx","si","di","bp","sp",
        "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w",
        "al","bl","cl","dl","ah","bh","ch","dh",
        "sil","dil","bpl","spl",
        "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"
    };
    static const std::vector<std::string> arm_gp_regs = {
        "r0","r1","r2","r3","r4","r5","r6","r7","r8","r9","r10","r11","r12","sp","lr","pc",
        "x0","x1","x2","x3","x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15",
        "x16","x17","x18","x19","x20","x21","x22","x23","x24","x25","x26","x27","x28","x29","x30",
        "w0","w1","w2","w3","w4","w5","w6","w7","w8","w9","w10","w11","w12","w13","w14","w15"
    };

    const std::vector<std::string>& gp_regs = is_x86 ? x86_gp_regs : arm_gp_regs;

    for (size_t idx = 0; idx < g.instructions.size(); ++idx) {
        const auto &ins  = g.instructions[idx];
        bool is_term_ins = (idx == g.instructions.size() - 1);
        std::string mnem = lc(ins.mnemonic);
        std::string ops  = lc(ins.op_str);

        // --- Stack delta & consumption tracking ---
        if (is_x86) {
            int ptr_sz = (arch == "x86_64") ? 8 : 4;
            std::string sp_reg = (arch == "x86_64") ? "rsp" : "esp";
            if (mnem == "push") {
                g.stack_delta -= ptr_sz;
                regs_read_set.insert(sp_reg);
                regs_mod_set.insert(sp_reg);
                for (const auto &r : gp_regs) {
                    if (contains_reg_token(ops, r)) { regs_read_set.insert(r); break; }
                }
            } else if (mnem == "pop") {
                g.stack_delta += ptr_sz;
                g.stack_consumption += ptr_sz;
                regs_read_set.insert(sp_reg);
                // Check if pop target is rsp (stack pivot) or other register (load)
                if (ops == "rsp" || ops == "esp") {
                    has_stack_pivot = true;
                    regs_mod_set.insert(sp_reg);
                } else {
                    for (const auto &r : gp_regs) {
                        if (contains_reg_token(ops, r) && r != "rsp" && r != "esp") {
                            has_register_load = true;
                            regs_mod_set.insert(r);
                            break;
                        }
                    }
                    regs_mod_set.insert(sp_reg);
                }
            } else if (mnem == "ret" || mnem == "retf" || mnem == "retfq") {
                g.stack_delta += ptr_sz;
                g.stack_consumption += ptr_sz;
                regs_read_set.insert(sp_reg);
                regs_mod_set.insert(sp_reg);
            } else if (mnem == "add" && (ops.rfind("rsp,", 0) == 0 || ops.rfind("esp,", 0) == 0)) {
                has_stack_adjust = true;
                regs_read_set.insert(sp_reg);
                regs_mod_set.insert(sp_reg);
                size_t comma = ops.find(',');
                if (comma != std::string::npos) {
                    try {
                        std::string val = ops.substr(comma + 1);
                        val.erase(std::remove_if(val.begin(), val.end(), ::isspace), val.end());
                        int64_t disp = (int64_t)std::stoll(val, nullptr, 0);
                        g.stack_delta += disp;
                        if (disp > 0) g.stack_consumption += disp;
                    } catch (...) {}
                }
            } else if (mnem == "sub" && (ops.rfind("rsp,", 0) == 0 || ops.rfind("esp,", 0) == 0)) {
                has_stack_adjust = true;
                regs_read_set.insert(sp_reg);
                regs_mod_set.insert(sp_reg);
                size_t comma = ops.find(',');
                if (comma != std::string::npos) {
                    try {
                        std::string val = ops.substr(comma + 1);
                        val.erase(std::remove_if(val.begin(), val.end(), ::isspace), val.end());
                        g.stack_delta -= (int64_t)std::stoll(val, nullptr, 0);
                    } catch (...) {}
                }
            } else if (mnem == "leave") {
                // Frame pointer pivot: mov rsp, rbp ; pop rbp
                g.stack_delta += ptr_sz;
                g.stack_consumption += ptr_sz;
                has_stack_pivot = true;
                regs_read_set.insert("rbp");
                regs_mod_set.insert(sp_reg);
                regs_mod_set.insert("rbp");
            }
        } else if (is_arm) {
            if (mnem == "push") { g.stack_delta -= 4; regs_read_set.insert("sp"); regs_mod_set.insert("sp"); }
            else if (mnem == "pop")  { g.stack_delta += 4; g.stack_consumption += 4; regs_read_set.insert("sp"); regs_mod_set.insert("sp"); }
        }

        // --- Memory access and comparison detection ---
        bool has_bracket = (ops.find('[') != std::string::npos || ops.find("ptr") != std::string::npos);

        // ARM load/store instructions
        if (mnem == "ldr" || mnem == "ldrb" || mnem == "ldrh") {
            has_mem_read = true;
            has_register_load = true;
        } else if (mnem == "str" || mnem == "strb" || mnem == "strh") {
            has_mem_write = true;
        }

        // COMPARISON INSTRUCTIONS: cmp, test
        // MUST NEVER be classified as memory write!
        if (mnem == "cmp" || mnem == "test") {
            has_logical = true;
            if (has_bracket) {
                has_mem_read = true;
            }
            // Add read registers
            for (const auto &r : gp_regs) {
                if (contains_reg_token(ops, r)) regs_read_set.insert(r);
            }
        }
        else if (has_bracket) {
            size_t comma = ops.find(',');
            if (comma != std::string::npos) {
                std::string dst = ops.substr(0, comma);
                std::string src = ops.substr(comma + 1);
                dst.erase(std::remove_if(dst.begin(), dst.end(), ::isspace), dst.end());
                src.erase(std::remove_if(src.begin(), src.end(), ::isspace), src.end());

                if (mnem == "lea") {
                    // LEA computes effective address without accessing memory
                    has_register_load = true;
                    for (const auto &r : gp_regs) {
                        if (contains_reg_token(dst, r)) regs_mod_set.insert(r);
                        if (contains_reg_token(src, r)) regs_read_set.insert(r);
                    }
                } else if (dst.find('[') != std::string::npos) {
                    // Writing to memory operand
                    has_mem_write = true;
                    if (mnem != "mov" && mnem != "movzx" && mnem != "movsx") {
                        has_mem_read = true; // Read-modify-write
                    }
                    for (const auto &r : gp_regs) {
                        if (contains_reg_token(dst, r)) regs_read_set.insert(r);
                        if (contains_reg_token(src, r)) regs_read_set.insert(r);
                    }
                } else if (src.find('[') != std::string::npos) {
                    // Reading from memory operand
                    has_mem_read = true;
                    if (mnem == "mov" || mnem == "movzx" || mnem == "movsx" || mnem == "ldr") {
                        has_register_load = true;
                    }
                    for (const auto &r : gp_regs) {
                        if (contains_reg_token(dst, r)) regs_mod_set.insert(r);
                        if (contains_reg_token(src, r)) regs_read_set.insert(r);
                    }
                }
            } else if (mnem != "lea") {
                if (mnem == "inc" || mnem == "dec" || mnem == "not" || mnem == "neg") {
                    has_mem_read = true;
                    has_mem_write = true;
                } else {
                    has_mem_read = true;
                }
                for (const auto &r : gp_regs) {
                    if (contains_reg_token(ops, r)) regs_read_set.insert(r);
                }
            }
        }

        // --- Register exchange / Stack Pivots ---
        if (mnem == "xchg") {
            size_t comma = ops.find(',');
            if (comma != std::string::npos) {
                std::string op1 = ops.substr(0, comma);
                std::string op2 = ops.substr(comma + 1);
                op1.erase(std::remove_if(op1.begin(), op1.end(), ::isspace), op1.end());
                op2.erase(std::remove_if(op2.begin(), op2.end(), ::isspace), op2.end());

                for (const auto &r : gp_regs) {
                    if (contains_reg_token(op1, r)) { regs_read_set.insert(r); regs_mod_set.insert(r); }
                    if (contains_reg_token(op2, r)) { regs_read_set.insert(r); regs_mod_set.insert(r); }
                }

                if (op1 == "rsp" || op2 == "rsp" || op1 == "esp" || op2 == "esp" || op1 == "sp" || op2 == "sp") {
                    has_stack_pivot = true;
                }
            }
        } else if (mnem == "mov" || mnem == "movzx" || mnem == "movsx" || mnem == "movsxd") {
            size_t comma = ops.find(',');
            if (comma != std::string::npos) {
                std::string dst = ops.substr(0, comma);
                std::string src = ops.substr(comma + 1);
                dst.erase(std::remove_if(dst.begin(), dst.end(), ::isspace), dst.end());
                src.erase(std::remove_if(src.begin(), src.end(), ::isspace), src.end());

                if ((dst == "rsp" || dst == "esp" || dst == "sp") && src != "rsp" && src != "esp") {
                    has_stack_pivot = true; // mov rsp, rax is a stack pivot
                    for (const auto &r : gp_regs) {
                        if (contains_reg_token(src, r)) regs_read_set.insert(r);
                    }
                    regs_mod_set.insert(dst);
                } else if (dst.find('[') == std::string::npos) {
                    has_register_load = true;
                    for (const auto &r : gp_regs) {
                        if (contains_reg_token(dst, r)) regs_mod_set.insert(r);
                        if (contains_reg_token(src, r)) regs_read_set.insert(r);
                    }
                }
            }
        } else if (mnem == "lea") {
            size_t comma = ops.find(',');
            if (comma != std::string::npos) {
                std::string dst = ops.substr(0, comma);
                std::string src = ops.substr(comma + 1);
                dst.erase(std::remove_if(dst.begin(), dst.end(), ::isspace), dst.end());
                src.erase(std::remove_if(src.begin(), src.end(), ::isspace), src.end());
                has_register_load = true;
                for (const auto &r : gp_regs) {
                    if (contains_reg_token(dst, r)) regs_mod_set.insert(r);
                    if (contains_reg_token(src, r)) regs_read_set.insert(r);
                }
            }
        } else if (mnem == "add" || mnem == "sub" || mnem == "mul" || mnem == "imul" ||
                   mnem == "div" || mnem == "idiv" || mnem == "inc" || mnem == "dec" ||
                   mnem == "neg" || mnem == "adc" || mnem == "sbb") {
            // If operating on general registers, it's arithmetic
            if (ops.find("rsp") == std::string::npos && ops.find("esp") == std::string::npos) {
                has_arithmetic = true;
                size_t comma = ops.find(',');
                if (comma != std::string::npos) {
                    std::string dst = ops.substr(0, comma);
                    std::string src = ops.substr(comma + 1);
                    dst.erase(std::remove_if(dst.begin(), dst.end(), ::isspace), dst.end());
                    src.erase(std::remove_if(src.begin(), src.end(), ::isspace), src.end());
                    for (const auto &r : gp_regs) {
                        if (contains_reg_token(dst, r)) { regs_read_set.insert(r); regs_mod_set.insert(r); }
                        if (contains_reg_token(src, r)) { regs_read_set.insert(r); }
                    }
                } else {
                    for (const auto &r : gp_regs) {
                        if (contains_reg_token(ops, r)) { regs_read_set.insert(r); regs_mod_set.insert(r); }
                    }
                }
            }
        } else if (mnem == "xor" || mnem == "and" || mnem == "or" || mnem == "not" ||
                   mnem == "shl" || mnem == "shr" || mnem == "sar" || mnem == "rol" || mnem == "ror") {
            has_logical = true;
            size_t comma = ops.find(',');
            if (comma != std::string::npos) {
                std::string dst = ops.substr(0, comma);
                std::string src = ops.substr(comma + 1);
                dst.erase(std::remove_if(dst.begin(), dst.end(), ::isspace), dst.end());
                src.erase(std::remove_if(src.begin(), src.end(), ::isspace), src.end());
                for (const auto &r : gp_regs) {
                    if (contains_reg_token(dst, r)) { regs_read_set.insert(r); regs_mod_set.insert(r); }
                    if (contains_reg_token(src, r)) { regs_read_set.insert(r); }
                }
            } else {
                for (const auto &r : gp_regs) {
                    if (contains_reg_token(ops, r)) { regs_read_set.insert(r); regs_mod_set.insert(r); }
                }
            }
        } else if (mnem == "syscall" || mnem == "sysenter" || mnem == "ecall" || mnem == "svc" || mnem == "swi" ||
                   (mnem == "int" && ops.find("0x80") != std::string::npos)) {
            has_syscall = true;
        } else if (mnem == "jmp" || mnem == "call" || mnem == "b" || mnem == "bl" || mnem == "blx" || mnem == "blr") {
            has_control_xfer = true;
            for (const auto &r : gp_regs) {
                if (contains_reg_token(ops, r)) regs_read_set.insert(r);
            }
        }
    }

    g.has_memory_read  = has_mem_read;
    g.has_memory_write = has_mem_write;

    // --- Build Multi-Dimensional Categories Vector ---
    if (has_syscall)        g.categories.push_back("syscall");
    if (has_stack_pivot)    g.categories.push_back("stack_pivot");
    if (has_stack_adjust)   g.categories.push_back("stack_adjustment");
    if (has_register_load)  g.categories.push_back("register_load");
    if (has_mem_write)      g.categories.push_back("memory_write");
    if (has_mem_read)       g.categories.push_back("memory_read");
    if (has_arithmetic)     g.categories.push_back("arithmetic");
    if (has_logical)        g.categories.push_back("logical");
    if (has_control_xfer || g.terminator_type == "JMP" || g.terminator_type == "CALL" || g.terminator_type == "RET") {
        g.categories.push_back("control_transfer");
    }
    if (g.categories.empty()) {
        g.categories.push_back("misc");
    }

    // Populate sorted register lists
    for (const auto &r : regs_read_set)  g.registers_read.push_back(r);
    for (const auto &r : regs_mod_set)   g.registers_modified.push_back(r);
    std::sort(g.registers_read.begin(), g.registers_read.end());
    std::sort(g.registers_modified.begin(), g.registers_modified.end());

    // Record notable Side Effects
    g.side_effects.clear();
    if (g.stack_delta != 0) {
        g.side_effects.push_back("stack_delta: " + std::to_string(g.stack_delta));
    }
    if (has_mem_write) {
        g.side_effects.push_back("memory_write");
    }
    if (has_mem_read) {
        g.side_effects.push_back("memory_read");
    }
    if (has_arithmetic) {
        g.side_effects.push_back("arithmetic");
    }
    if (has_logical) {
        g.side_effects.push_back("logical");
    }
    if (regs_mod_set.size() > 1 || (regs_mod_set.size() == 1 && regs_mod_set.find(g.target_register) == regs_mod_set.end())) {
        std::string clob = "clobbers: ";
        bool first = true;
        for (const auto& r : regs_mod_set) {
            if (r == g.target_register) continue;
            if (!first) clob += ", ";
            clob += r;
            first = false;
        }
        if (!first) g.side_effects.push_back(clob);
    }

    // Confidence scoring
    if (g.instructions.size() == 1) g.classification_confidence = 95;
    else if (g.instructions.size() == 2) g.classification_confidence = 85;
    else if (g.instructions.size() == 3) g.classification_confidence = 75;
    else g.classification_confidence = 60;

    g.category = g.categories[0];
}

std::string GadgetFinder::determineCategory(const Gadget& g) const {
    if (g.isIndirectJumpOrCall()) return "indirect jump/call";
    if (g.isStackPivot()) return "stack pivot";

    if (g.hasMnemonic("syscall") || g.hasMnemonic("sysenter") || g.hasMnemonic("int80") ||
        (g.hasMnemonic("int") && !g.instructions.empty() && g.instructions.back().op_str.find("0x80") != std::string::npos)) {
        return "syscall";
    }

    if ((m_arch == "armv7" || m_arch == "arm") && (g.hasMnemonic("svc") || g.hasMnemonic("swi"))) {
        return "syscall";
    }

    if (g.hasMnemonic("pop")) {
        for (const auto &ins : g.instructions) {
            if (ins.mnemonic == "pop") {
                std::string ops = ins.op_str;
                std::transform(ops.begin(), ops.end(), ops.begin(), [](unsigned char c){ return std::tolower(c); });

                std::vector<std::string> target_regs;
                if (m_arch == "x86" || m_arch == "x86_64") {
                    target_regs = {"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15","eax","ebx","ecx","edx","esi","edi","ebp","esp"};
                } else {
                    target_regs = {"r0","r1","r2","r3","r4","r5","r6","r7","r8","r9","r10","r11","r12","sp","lr","pc"};
                }
                for (const auto &reg : target_regs) {
                    if (ops.find(reg) != std::string::npos) {
                        return "pop " + reg;
                    }
                }
                if (ops.find("pc") != std::string::npos) return "pop pc";
            }
        }
    }

    if (g.hasMnemonic("pop") && (m_arch == "x86" || m_arch == "x86_64")) {
        if (g.popInstructionCount() > 0) return "pop";
    }

    if (g.hasArithmeticOrLogic()) return "arithmetic/logic";

    return "others";
}

// Multi-label grouping: gadgets belong to all of their categories (Requirement 2)
std::map<std::string, std::vector<Gadget>> GadgetFinder::categorizeGadgets() {
    std::map<std::string, std::vector<Gadget>> categories;
    for (auto& g : m_gadgets) {
        classify_gadget_multidim(g, m_arch);
        for (const auto& cat : g.categories) {
            categories[cat].push_back(g);
        }
    }
    return categories;
}

std::map<std::string, std::vector<Gadget>> GadgetFinder::categorizeGadgets() const {
    std::map<std::string, std::vector<Gadget>> categories;
    for (const auto& g : m_gadgets) {
        if (!g.categories.empty()) {
            for (const auto& cat : g.categories) {
                categories[cat].push_back(g);
            }
        } else {
            std::string cat = g.category.empty() ? determineCategory(g) : g.category;
            categories[cat].push_back(g);
        }
    }
    return categories;
}
