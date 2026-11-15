#include "rop_chain.h"
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <algorithm>
#include <cctype>
#include <set>
#include <map>
#include <fstream>
#include "nlohmann/json.hpp" // Required for the toJson() method

#if __has_include("parsers/elf_defs.h")
#include "parsers/elf_defs.h"
#elif __has_include("elf_defs.h")
#include "elf_defs.h"
#elif __has_include("core/parsers/elf_defs.h")
#include "core/parsers/elf_defs.h"
#endif

#if __has_include("parsers/file_parser.h")
#include "parsers/file_parser.h"
#elif __has_include("file_parser.h")
#include "file_parser.h"
#elif __has_include("core/parsers/file_parser.h")
#include "core/parsers/file_parser.h"
#endif

using json = nlohmann::json;

// Helper to format addresses as hex
static inline std::string to_hex(uint64_t addr) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(16) << std::setfill('0') << addr;
    return oss.str();
}

// Original legacy overloads forwarding to explicit-type implementation
void ROPChain::add_step(const Gadget& gadget, const std::string& comment) {
    add_step(gadget, comment, ROPStepType::GadgetExecution);
}

void ROPChain::add_step(const Gadget& gadget, uint64_t value, const std::string& comment) {
    add_step(gadget, value, comment, ROPStepType::GadgetExecution);
}

// Explicit-type overloads
void ROPChain::add_step(const Gadget& gadget, const std::string& comment, ROPStepType type) {
    ROPChainStep step;
    step.gadget = gadget;
    step.comment = comment;
    step.has_value = false;
    step.type = type;
    step.target_register = gadget.target_register;
    m_steps.push_back(step);
}

// Explicit overload without value and with explicit target register
void ROPChain::add_step(const Gadget& gadget, const std::string& comment, ROPStepType type, const std::string& target_reg) {
    ROPChainStep step;
    step.gadget = gadget;
    step.comment = comment;
    step.has_value = false;
    step.type = type;
    step.target_register = target_reg.empty() ? gadget.target_register : target_reg;
    m_steps.push_back(step);
}

// Explicit-type overloads with value
void ROPChain::add_step(const Gadget& gadget, uint64_t value, const std::string& comment, ROPStepType type) {
    ROPChainStep step;
    step.gadget = gadget;
    step.value = value;
    step.comment = comment;
    step.has_value = true;
    step.type = type;
    step.target_register = gadget.target_register;
    m_steps.push_back(step);
}

// Explicit overload with explicit target register
void ROPChain::add_step(const Gadget& gadget, uint64_t value, const std::string& comment, ROPStepType type, const std::string& target_reg) {
    ROPChainStep step;
    step.gadget = gadget;
    step.value = value;
    step.comment = comment;
    step.has_value = true;
    step.type = type;
    step.target_register = target_reg.empty() ? gadget.target_register : target_reg;
    m_steps.push_back(step);
}

// Explicit overload with category before comment
void ROPChain::add_step(const Gadget& gadget, ROPStepType type, const std::string& comment) {
    add_step(gadget, comment, type);
}

// Explicit overload with value and category before comment
void ROPChain::add_step(const Gadget& gadget, uint64_t value, ROPStepType type, const std::string& comment) {
    add_step(gadget, value, comment, type);
}

// FIX 1: Implement isSuccessful() required by payload_gen.cpp
bool ROPChain::isSuccessful() const {
    return !m_steps.empty();
}

// FIX 2: Implement toJson() required by payload_gen.cpp
json ROPChain::toJson() const {
    json chain_array = json::array();
    
    for (size_t i = 0; i < m_steps.size(); ++i) {
        const auto& step = m_steps[i];
        
        json step_json = {
            {"index", i + 1},
            {"type", stepTypeToString(step.type)},
            {"semantic_type", stepTypeToString(step.type)},
            
            {"gadget_address", to_hex(step.gadget.address)},
            {"assembly", step.gadget.assembly},
            
            {"value_loaded", step.has_value ? to_hex(step.value) : "N/A"},
            {"register", step.gadget.target_register},
            {"comment", step.comment}
        };
        chain_array.push_back(step_json);
    }
    
    return chain_array;
}

// to_string() and getPayloadBytes()

std::string ROPChain::to_string() const {
    std::stringstream ss;
    ss << "ROP Chain:\n";
    for (const auto& step : m_steps) {
        ss << "--------------------------------\n";
        ss << "Gadget: " << step.gadget.toString() << "\n";
        ss << "Address: " << to_hex(step.gadget.address) << "\n";
        ss << "Type: " << stepTypeToString(step.type) << "\n";
        if (step.has_value) {
            ss << "Value: " << to_hex(step.value) << "\n";
        }
        ss << "Comment: " << step.comment << "\n";
    }
    ss << "--------------------------------\n";
    return ss.str();
}

std::vector<char> ROPChain::getPayloadBytes() const {
    return getPayloadBytes(8, Endianness::Little);
}

std::vector<char> ROPChain::getPayloadBytes(size_t wordSize, Endianness endianness) const {
    if (wordSize != 4 && wordSize != 8) {
        throw std::invalid_argument("Invalid word size: " + std::to_string(wordSize) + " (must be 4 or 8 bytes)");
    }
    if (endianness != Endianness::Little && endianness != Endianness::Big) {
        throw std::invalid_argument("Unsupported or unknown endianness for serialization");
    }

    if (m_steps.empty()) {
        return {};
    }

    std::vector<char> bytes;
    bytes.reserve(m_steps.size() * 2 * wordSize);

    auto append_word = [&](uint64_t val, const char* desc) {
        if (wordSize == 4) {
            if (val > 0xFFFFFFFFULL) {
                std::ostringstream oss;
                oss << desc << " (0x" << std::hex << val << ") exceeds 32-bit range for 32-bit target";
                throw std::runtime_error(oss.str());
            }
            uint32_t val32 = static_cast<uint32_t>(val);
            if (endianness == Endianness::Little) {
                bytes.push_back(static_cast<char>((val32 >> 0) & 0xFF));
                bytes.push_back(static_cast<char>((val32 >> 8) & 0xFF));
                bytes.push_back(static_cast<char>((val32 >> 16) & 0xFF));
                bytes.push_back(static_cast<char>((val32 >> 24) & 0xFF));
            } else {
                bytes.push_back(static_cast<char>((val32 >> 24) & 0xFF));
                bytes.push_back(static_cast<char>((val32 >> 16) & 0xFF));
                bytes.push_back(static_cast<char>((val32 >> 8) & 0xFF));
                bytes.push_back(static_cast<char>((val32 >> 0) & 0xFF));
            }
        } else { // wordSize == 8
            if (endianness == Endianness::Little) {
                for (int i = 0; i < 8; ++i) {
                    bytes.push_back(static_cast<char>((val >> (8 * i)) & 0xFF));
                }
            } else {
                for (int i = 7; i >= 0; --i) {
                    bytes.push_back(static_cast<char>((val >> (8 * i)) & 0xFF));
                }
            }
        }
    };

    for (const auto& step : m_steps) {
        append_word(step.gadget.address, "Gadget address");
        if (step.has_value) {
            append_word(step.value, "Step value");
        }
    }

    return bytes;
}

namespace {

static inline std::string to_lower_str(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (!s.empty() && s[0] == '%') s = s.substr(1);
    s.erase(std::remove(s.begin(), s.end(), '{'), s.end());
    s.erase(std::remove(s.begin(), s.end(), '}'), s.end());
    s.erase(std::remove_if(s.begin(), s.end(), ::isspace), s.end());
    return s;
}

static std::string canonicalize_register(const std::string& arch, const std::string& reg) {
    std::string r = to_lower_str(reg);
    std::string a = to_lower_str(arch);
    if (a == "x86_64") {
        if (r == "rax" || r == "eax" || r == "ax" || r == "al" || r == "ah") return "rax";
        if (r == "rdi" || r == "edi" || r == "di" || r == "dil") return "rdi";
        if (r == "rsi" || r == "esi" || r == "si" || r == "sil") return "rsi";
        if (r == "rdx" || r == "edx" || r == "dx" || r == "dl" || r == "dh") return "rdx";
        if (r == "rcx" || r == "ecx" || r == "cx" || r == "cl" || r == "ch") return "rcx";
        if (r == "rbx" || r == "ebx" || r == "bx" || r == "bl" || r == "bh") return "rbx";
        if (r == "rsp" || r == "esp" || r == "sp" || r == "spl") return "rsp";
        if (r == "rbp" || r == "ebp" || r == "bp" || r == "bpl") return "rbp";
        if (r == "r8"  || r == "r8d"  || r == "r8w"  || r == "r8b")  return "r8";
        if (r == "r9"  || r == "r9d"  || r == "r9w"  || r == "r9b")  return "r9";
        if (r == "r10" || r == "r10d" || r == "r10w" || r == "r10b") return "r10";
        if (r == "r11" || r == "r11d" || r == "r11w" || r == "r11b") return "r11";
        if (r == "r12" || r == "r12d" || r == "r12w" || r == "r12b") return "r12";
        if (r == "r13" || r == "r13d" || r == "r13w" || r == "r13b") return "r13";
        if (r == "r14" || r == "r14d" || r == "r14w" || r == "r14b") return "r14";
        if (r == "r15" || r == "r15d" || r == "r15w" || r == "r15b") return "r15";
        return r;
    }
    if (a == "x86") {
        if (r == "eax" || r == "ax" || r == "al" || r == "ah") return "eax";
        if (r == "ebx" || r == "bx" || r == "bl" || r == "bh") return "ebx";
        if (r == "ecx" || r == "cx" || r == "cl" || r == "ch") return "ecx";
        if (r == "edx" || r == "dx" || r == "dl" || r == "dh") return "edx";
        if (r == "esp" || r == "sp") return "esp";
        if (r == "ebp" || r == "bp") return "ebp";
        if (r == "esi" || r == "si") return "esi";
        if (r == "edi" || r == "di") return "edi";
        return r;
    }
    if (a == "aarch64" || a == "arm64") {
        if (r == "x0" || r == "w0") return "x0";
        if (r == "x1" || r == "w1") return "x1";
        if (r == "x2" || r == "w2") return "x2";
        if (r == "x3" || r == "w3") return "x3";
        if (r == "x4" || r == "w4") return "x4";
        if (r == "x5" || r == "w5") return "x5";
        if (r == "x6" || r == "w6") return "x6";
        if (r == "x7" || r == "w7") return "x7";
        if (r == "x8" || r == "w8") return "x8";
        if (r == "sp" || r == "wsp") return "sp";
        return r;
    }
    if (a == "armv7" || a == "arm") {
        if (r == "r0") return "r0";
        if (r == "r1") return "r1";
        if (r == "r2") return "r2";
        if (r == "r3") return "r3";
        if (r == "r4") return "r4";
        if (r == "r5") return "r5";
        if (r == "r6") return "r6";
        if (r == "r7") return "r7";
        if (r == "r8") return "r8";
        if (r == "r9") return "r9";
        if (r == "r10") return "r10";
        if (r == "r11" || r == "fp") return "r11";
        if (r == "r12" || r == "ip") return "r12";
        if (r == "sp") return "sp";
        if (r == "lr") return "lr";
        if (r == "pc") return "pc";
        return r;
    }
    if (a == "riscv" || a == "riscv32" || a == "riscv64") {
        if (r == "a0" || r == "x10") return "a0";
        if (r == "a1" || r == "x11") return "a1";
        if (r == "a2" || r == "x12") return "a2";
        if (r == "a3" || r == "x13") return "a3";
        if (r == "a4" || r == "x14") return "a4";
        if (r == "a5" || r == "x15") return "a5";
        if (r == "a6" || r == "x16") return "a6";
        if (r == "a7" || r == "x17") return "a7";
        if (r == "sp" || r == "x2")  return "sp";
        if (r == "ra" || r == "x1")  return "ra";
        return r;
    }
    return r;
}

static inline std::string get_canonical_sp(const std::string& arch) {
    return canonicalize_register(arch, "sp");
}

static inline bool is_stack_pointer_reg(const std::string& arch, const std::string& reg) {
    std::string canon = canonicalize_register(arch, reg);
    return canon == get_canonical_sp(arch);
}

static bool gadget_instructions_support_dest(const std::string& arch, const std::vector<Instruction>& insns, const std::string& canonical_dest) {
    if (insns.empty()) return false;
    for (const auto& insn : insns) {
        std::string mnem = to_lower_str(insn.mnemonic);
        std::string ops  = to_lower_str(insn.op_str);
        if (mnem == "pop") {
            if (arch == "aarch64" || arch == "arm64" || arch == "riscv" || arch == "riscv32" || arch == "riscv64") {
                continue; // Native pop does not exist on AArch64 / RISC-V
            }
            size_t pos = 0;
            while (pos < ops.size()) {
                size_t next_comma = ops.find(',', pos);
                std::string token = (next_comma != std::string::npos) ? ops.substr(pos, next_comma - pos) : ops.substr(pos);
                token = to_lower_str(token);
                if (canonicalize_register(arch, token) == canonical_dest) return true;
                if (next_comma == std::string::npos) break;
                pos = next_comma + 1;
            }
        } else if (mnem == "mov" || mnem == "mv" || mnem == "movzx" || mnem == "movsx" || mnem == "movsxd" ||
                   mnem == "ldr" || mnem == "ld" || mnem == "lw") {
            size_t comma = ops.find(',');
            if (comma != std::string::npos) {
                std::string dst = to_lower_str(ops.substr(0, comma));
                if (canonicalize_register(arch, dst) == canonical_dest) return true;
            }
        }
    }
    return false;
}

static bool match_trap_instruction(const std::string& arch, const Instruction& insn) {
    std::string lm = to_lower_str(insn.mnemonic);
    std::string lop = to_lower_str(insn.op_str);
    std::string a = to_lower_str(arch);
    if (a == "x86_64") {
        return (lm == "syscall" && lop.empty());
    }
    if (a == "x86") {
        return (lm == "int" && (lop == "0x80" || lop == "128"));
    }
    if (a == "aarch64" || a == "arm64") {
        return (lm == "svc" && (lop == "#0" || lop == "0" || lop == "#0x0"));
    }
    if (a == "armv7" || a == "arm") {
        return ((lm == "svc" || lm == "swi") && (lop == "#0" || lop == "0" || lop == "#0x0"));
    }
    if (a == "riscv" || a == "riscv32" || a == "riscv64") {
        return (lm == "ecall" && lop.empty());
    }
    return false;
}

static bool parse_immediate_value(const std::string& token, int64_t& out_val) {
    std::string s = token;
    s.erase(0, s.find_first_not_of(" \t\r\n#$"));
    if (!s.empty()) {
        s.erase(s.find_last_not_of(" \t\r\n") + 1);
    }
    if (s.empty()) return false;
    try {
        if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
            out_val = std::stoll(s, nullptr, 16);
            return true;
        }
        out_val = std::stoll(s, nullptr, 10);
        return true;
    } catch (...) {
        return false;
    }
}

static int64_t get_aarch64_post_index_sp_displacement(const std::string& op_str) {
    std::string ops = to_lower_str(op_str);
    size_t post_brack = ops.find("],");
    if (post_brack == std::string::npos) return -1;
    size_t lbrack = ops.rfind('[', post_brack);
    if (lbrack == std::string::npos) return -1;
    std::string base = ops.substr(lbrack + 1, post_brack - lbrack - 1);
    base.erase(std::remove_if(base.begin(), base.end(), ::isspace), base.end());
    if (base != "sp" && base != "wsp") return -1;

    std::string disp_str = ops.substr(post_brack + 2);
    int64_t disp = 0;
    if (!parse_immediate_value(disp_str, disp)) {
        return -2;
    }
    return disp;
}

static bool parse_riscv_load_operand(const std::string& arch, const std::string& op_str,
                                     std::string& out_dst, std::string& out_base,
                                     int64_t& out_disp, std::string* out_err = nullptr) {
    (void)arch;
    auto set_err = [&](const std::string& msg) {
        if (out_err) *out_err = msg;
    };
    std::string s = op_str;
    size_t comma = s.find(',');
    if (comma == std::string::npos) {
        set_err("Missing comma in RISC-V load operand '" + op_str + "'");
        return false;
    }
    out_dst = to_lower_str(s.substr(0, comma));
    if (out_dst.empty()) {
        set_err("Empty destination register in RISC-V load operand '" + op_str + "'");
        return false;
    }

    std::string mem = s.substr(comma + 1);
    mem.erase(0, mem.find_first_not_of(" \t\r\n"));
    if (!mem.empty()) {
        mem.erase(mem.find_last_not_of(" \t\r\n") + 1);
    }
    if (mem.empty()) {
        set_err("Empty memory operand in RISC-V load operand '" + op_str + "'");
        return false;
    }

    size_t open_paren = mem.find('(');
    size_t close_paren = mem.find(')');
    if (open_paren == std::string::npos || close_paren == std::string::npos || close_paren <= open_paren) {
        set_err("Malformed memory operand (missing parentheses) in RISC-V load '" + op_str + "'");
        return false;
    }
    std::string trailing = mem.substr(close_paren + 1);
    trailing.erase(0, trailing.find_first_not_of(" \t\r\n"));
    if (!trailing.empty()) {
        set_err("Unexpected trailing characters after ')' in RISC-V load '" + op_str + "'");
        return false;
    }

    out_base = to_lower_str(mem.substr(open_paren + 1, close_paren - open_paren - 1));
    out_base.erase(std::remove_if(out_base.begin(), out_base.end(), ::isspace), out_base.end());
    if (out_base.empty()) {
        set_err("Empty base register in RISC-V load '" + op_str + "'");
        return false;
    }

    std::string disp_str = mem.substr(0, open_paren);
    disp_str.erase(0, disp_str.find_first_not_of(" \t\r\n"));
    if (!disp_str.empty()) {
        disp_str.erase(disp_str.find_last_not_of(" \t\r\n") + 1);
    }

    if (disp_str.empty()) {
        out_disp = 0;
    } else {
        if (!parse_immediate_value(disp_str, out_disp)) {
            set_err("Invalid immediate displacement '" + disp_str + "' in RISC-V load '" + op_str + "'");
            return false;
        }
    }
    return true;
}

static bool is_valid_arm_register_token(const std::string& reg) {
    static const std::set<std::string> valid_arm = {
        "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
        "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc",
        "ip", "fp"
    };
    return valid_arm.find(reg) != valid_arm.end();
}

static int count_arm_pop_data_registers(const std::string& op_str, std::string* out_error = nullptr) {
    auto set_err = [&](const std::string& msg) {
        if (out_error) *out_error = msg;
    };

    std::string s = op_str;
    s.erase(0, s.find_first_not_of(" \t\r\n"));
    if (!s.empty()) {
        s.erase(s.find_last_not_of(" \t\r\n") + 1);
    }
    if (s.empty()) {
        set_err("Empty register list in '" + op_str + "'");
        return -1;
    }

    size_t open_brace = s.find('{');
    size_t close_brace = s.find('}');
    std::string inner;
    if (open_brace != std::string::npos || close_brace != std::string::npos) {
        if (open_brace == std::string::npos || close_brace == std::string::npos || close_brace < open_brace) {
            set_err("Malformed ARM pop syntax: Unbalanced braces in '" + s + "'");
            return -2;
        }
        inner = s.substr(open_brace + 1, close_brace - open_brace - 1);
    } else {
        inner = s;
    }

    inner.erase(0, inner.find_first_not_of(" \t\r\n"));
    if (!inner.empty()) {
        inner.erase(inner.find_last_not_of(" \t\r\n") + 1);
    }
    if (inner.empty()) {
        set_err("Empty register list in '" + s + "'");
        return -1;
    }

    if (inner.find('-') != std::string::npos) {
        set_err("Unsupported register-range syntax in '" + s + "'");
        return -3;
    }

    int data_count = 0;
    size_t pos = 0;
    while (pos <= inner.size()) {
        size_t next_comma = inner.find(',', pos);
        std::string token = (next_comma != std::string::npos) ? inner.substr(pos, next_comma - pos) : inner.substr(pos);
        token.erase(0, token.find_first_not_of(" \t\r\n"));
        if (!token.empty()) {
            token.erase(token.find_last_not_of(" \t\r\n") + 1);
        }
        std::transform(token.begin(), token.end(), token.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        if (token.empty()) {
            set_err("Malformed ARM pop syntax: Empty token or trailing/double comma in '" + s + "'");
            return -2;
        }

        if (!is_valid_arm_register_token(token)) {
            set_err("Unrecognized register token '" + token + "' in '" + s + "'");
            return -4;
        }

        std::string canon = canonicalize_register("armv7", token);
        if (canon != "pc") {
            data_count++;
        }

        if (next_comma == std::string::npos) break;
        pos = next_comma + 1;
    }

    return data_count;
}

static bool extract_gadget_modified_registers(const std::string& arch, const Gadget& g, std::set<std::string>& out_modified) {
    out_modified.clear();
    for (const auto& r : g.registers_modified) {
        out_modified.insert(canonicalize_register(arch, r));
    }
    for (const auto& insn : g.instructions) {
        std::string mnem = to_lower_str(insn.mnemonic);
        std::string ops  = to_lower_str(insn.op_str);
        if (mnem == "pop") {
            if (arch == "aarch64" || arch == "arm64" || arch == "riscv" || arch == "riscv32" || arch == "riscv64") {
                // AArch64 and RISC-V have no native pop instruction; fail closed
                return false;
            }
            if (arch == "armv7" || arch == "arm") {
                std::string err;
                int count = count_arm_pop_data_registers(insn.op_str, &err);
                if (count < 0) {
                    return false; // Malformed/unsupported ARM pop cannot be safely established
                }
            }
            size_t pos = 0;
            while (pos < ops.size()) {
                size_t next_comma = ops.find(',', pos);
                std::string token = (next_comma != std::string::npos) ? ops.substr(pos, next_comma - pos) : ops.substr(pos);
                token = to_lower_str(token);
                if (!token.empty()) {
                    out_modified.insert(canonicalize_register(arch, token));
                }
                if (next_comma == std::string::npos) break;
                pos = next_comma + 1;
            }
            out_modified.insert(canonicalize_register(arch, "sp"));
        } else if (mnem == "ret" || mnem == "retf" || mnem == "retfq") {
            out_modified.insert(canonicalize_register(arch, "sp"));
        } else if (mnem == "nop") {
            // NOP modifies no architectural registers
            continue;
        } else if (mnem == "mov" || mnem == "mv" || mnem == "movzx" || mnem == "movsx" || mnem == "movsxd" ||
                   mnem == "ldr" || mnem == "ld" || mnem == "lw") {
            size_t comma = ops.find(',');
            if (comma != std::string::npos) {
                std::string dst = to_lower_str(ops.substr(0, comma));
                if (dst.find('[') == std::string::npos) {
                    std::string canon_dst = canonicalize_register(arch, dst);
                    if (is_stack_pointer_reg(arch, canon_dst)) {
                        // Register-indirect SP assignment (e.g. mv sp, s0 / mov rsp, rbp / mov esp, ebp)
                        // Source register value cannot be proven; fails closed!
                        return false;
                    }
                    out_modified.insert(canon_dst);
                }
            }
            // Check for pre-indexed writeback: e.g. [reg, #imm]!
            size_t excl = ops.find("]!");
            if (excl != std::string::npos) {
                size_t lbrack = ops.rfind('[', excl);
                if (lbrack != std::string::npos) {
                    size_t base_comma = ops.find(',', lbrack);
                    size_t end_base = (base_comma != std::string::npos && base_comma < excl) ? base_comma : excl;
                    std::string base = to_lower_str(ops.substr(lbrack + 1, end_base - lbrack - 1));
                    if (!base.empty()) {
                        out_modified.insert(canonicalize_register(arch, base));
                    }
                }
            }
            // Check for post-indexed writeback: e.g. [reg], #imm
            size_t post_brack = ops.find("],");
            if (post_brack != std::string::npos) {
                size_t lbrack = ops.rfind('[', post_brack);
                if (lbrack != std::string::npos) {
                    std::string base = to_lower_str(ops.substr(lbrack + 1, post_brack - lbrack - 1));
                    if (!base.empty()) {
                        out_modified.insert(canonicalize_register(arch, base));
                    }
                }
            }
        } else if (mnem == "and" || mnem == "andi" || mnem == "or" || mnem == "ori" || mnem == "xor" || mnem == "xori") {
            size_t comma = ops.find(',');
            if (comma != std::string::npos) {
                std::string dst = to_lower_str(ops.substr(0, comma));
                if (dst.find('[') == std::string::npos) {
                    std::string canon_dst = canonicalize_register(arch, dst);
                    if (is_stack_pointer_reg(arch, canon_dst)) {
                        // Any logical operation modifying the stack pointer is unmodeled; fail closed!
                        return false;
                    }
                    out_modified.insert(canon_dst);
                }
            }
        } else if (mnem == "add" || mnem == "addi" || mnem == "sub") {
            size_t comma = ops.find(',');
            if (comma != std::string::npos) {
                std::string dst = to_lower_str(ops.substr(0, comma));
                if (dst.find('[') == std::string::npos) {
                    std::string canon_dst = canonicalize_register(arch, dst);
                    if (is_stack_pointer_reg(arch, canon_dst)) {
                        // For SP arithmetic, check if second operand is dynamic register
                        size_t last_comma = ops.rfind(',');
                        std::string second_op = (last_comma != std::string::npos) ? ops.substr(last_comma + 1) : "";
                        int64_t imm_val = 0;
                        if (!parse_immediate_value(second_op, imm_val)) {
                            // Dynamic register-based SP arithmetic (e.g. add rsp, rbx / add esp, ebx / add sp, sp, s0)!
                            // Resulting displacement cannot be established; fails closed!
                            return false;
                        }
                    }
                    out_modified.insert(canon_dst);
                }
            }
        } else if (mnem == "syscall" || mnem == "int" || mnem == "svc" || mnem == "swi" || mnem == "ecall") {
            // Trap instruction
        } else {
            // Unknown or unsupported instruction with unverifiable side effects!
            return false;
        }
    }
    if (g.instructions.empty() && g.registers_modified.empty()) {
        return false;
    }
    return true;
}

} // anonymous namespace

ChainValidationResult ROPChain::validate(const std::string& arch, const FileParser* parser) const {
    ChainValidationResult res;
    auto fail = [&](const std::string& msg) {
        res.valid = false;
        res.error_message = msg;
        return res;
    };

    if (m_steps.empty()) {
        return fail("Chain contains no steps.");
    }

    std::string norm_arch = to_lower_str(arch);
    if (norm_arch == "arm64") norm_arch = "aarch64";
    if (norm_arch == "arm") norm_arch = "armv7";
    if (norm_arch == "riscv") norm_arch = (parser && !parser->is64Bit()) ? "riscv32" : "riscv64";

    // 1. Verify parser architecture and bitness consistency
    bool is_macho = (parser != nullptr && parser->getBinaryType() == "Mach-O");
    bool is_elf = (parser != nullptr && parser->getBinaryType() == "ELF");

    bool has_darwin_syscall = false;
    for (const auto& st : m_steps) {
        if (st.type == ROPStepType::SystemCallSetup && st.has_value && st.value == 0x200003BULL) {
            has_darwin_syscall = true;
            break;
        }
    }

    if (has_darwin_syscall && parser == nullptr) {
        return fail("Darwin Mach-O semantic validation requires an active FileParser to verify mapped section memory and array contents.");
    }

    if (parser != nullptr) {
        if (!is_elf && !is_macho) {
            return fail("Semantic execve validation is only supported for ELF and Mach-O binaries.");
        }
        if (is_macho) {
            if (!parser->is64Bit()) {
                return fail("Mach-O Darwin execve chain validation requires 64-bit target.");
            }
            if (norm_arch != "x86_64") {
                return fail("Mach-O Darwin execve chain validation only supports x86_64.");
            }
            if (parser->getMachOSegments().empty()) {
                return fail("Segment metadata is unavailable for Darwin Mach-O validation.");
            }
        } else if (is_elf) {
            if (parser->is64Bit() && (norm_arch == "x86" || norm_arch == "armv7" || norm_arch == "riscv32")) {
                return fail("Architecture bitness mismatch: Requested 32-bit architecture '" + arch + "', but target ELF binary is 64-bit.");
            }
            if (!parser->is64Bit() && (norm_arch == "x86_64" || norm_arch == "aarch64" || norm_arch == "riscv64")) {
                return fail("Architecture bitness mismatch: Requested 64-bit architecture '" + arch + "', but target ELF binary is 32-bit.");
            }

            std::string parsed_arch = to_lower_str(parser->getArchitecture());
            if (parsed_arch == "arm") parsed_arch = "armv7";
            if (parsed_arch == "arm64") parsed_arch = "aarch64";
            if (parsed_arch == "x86_64" && norm_arch != "x86_64") {
                return fail("Architecture mismatch: Parsed binary is x86_64, but requested architecture is " + arch + ".");
            }
            if (parsed_arch == "x86" && norm_arch != "x86") {
                return fail("Architecture mismatch: Parsed binary is x86, but requested architecture is " + arch + ".");
            }
            if (parsed_arch == "aarch64" && norm_arch != "aarch64") {
                return fail("Architecture mismatch: Parsed binary is aarch64, but requested architecture is " + arch + ".");
            }
            if (parsed_arch == "armv7" && norm_arch != "armv7") {
                return fail("Architecture mismatch: Parsed binary is armv7, but requested architecture is " + arch + ".");
            }
            if ((parsed_arch == "riscv32" || parsed_arch == "riscv64") && (norm_arch != "riscv32" && norm_arch != "riscv64")) {
                return fail("Architecture mismatch: Parsed binary is RISC-V, but requested architecture is " + arch + ".");
            }

            // Apply Step 2C container ABI validation
            if (norm_arch == "armv7") {
                if (!parser->isArmEabi()) {
                    return fail("Target ARM binary has an unknown or unsupported ARM EABI version (e_flags EABI version 0 / unspecified). Automated chain synthesis requires verified ARM EABI (EF_ARM_EABI_VER1-5 with R7 syscall dispatch).");
                }
                uint8_t osabi = parser->getOsAbi();
                if (osabi != ropweaver::ELFOSABI_NONE && osabi != ropweaver::ELFOSABI_GNU && osabi != ropweaver::ELFOSABI_ARM_AEABI) {
                    return fail("Non-Linux ARM OSABI detected (EI_OSABI=" + std::to_string(osabi) + "). Linux execve syscall conventions do not apply.");
                }
            } else if (norm_arch == "riscv32" || norm_arch == "riscv64") {
                if (parser->getElfFlags() & ropweaver::EF_RISCV_RVE) {
                    return fail("Target RISC-V binary uses RVE embedded ABI (16 registers; A7/X17 unavailable for Linux syscall convention).");
                }
                uint8_t osabi = parser->getOsAbi();
                if (osabi == ropweaver::ELFOSABI_STANDALONE) {
                    return fail("Target RISC-V binary has ELFOSABI_STANDALONE (bare-metal embedded). Linux execve syscall ABI is not supported on bare-metal targets.");
                }
                if (osabi != ropweaver::ELFOSABI_NONE && osabi != ropweaver::ELFOSABI_GNU) {
                    return fail("Ambiguous or non-Linux RISC-V OSABI detected (EI_OSABI=" + std::to_string(osabi) + "). Linux execve syscall conventions cannot be applied.");
                }
            }
        }
    }

    // 2. Target ABI Specification
    size_t word_size = 8;
    std::string arg1_reg, arg2_reg, arg3_reg, syscall_reg;
    uint64_t expected_syscall_nr = 0;

    if (norm_arch == "x86_64") {
        word_size = 8;
        arg1_reg = "rdi"; arg2_reg = "rsi"; arg3_reg = "rdx";
        syscall_reg = "rax";
        expected_syscall_nr = is_macho ? 0x200003BULL : 59;
    } else if (norm_arch == "x86") {
        word_size = 4;
        arg1_reg = "ebx"; arg2_reg = "ecx"; arg3_reg = "edx";
        syscall_reg = "eax"; expected_syscall_nr = 11;
    } else if (norm_arch == "aarch64") {
        word_size = 8;
        arg1_reg = "x0"; arg2_reg = "x1"; arg3_reg = "x2";
        syscall_reg = "x8"; expected_syscall_nr = 221;
    } else if (norm_arch == "armv7") {
        word_size = 4;
        arg1_reg = "r0"; arg2_reg = "r1"; arg3_reg = "r2";
        syscall_reg = "r7"; expected_syscall_nr = 11;
    } else if (norm_arch == "riscv64") {
        word_size = 8;
        arg1_reg = "a0"; arg2_reg = "a1"; arg3_reg = "a2";
        syscall_reg = "a7"; expected_syscall_nr = 221;
    } else if (norm_arch == "riscv32") {
        word_size = 4;
        arg1_reg = "a0"; arg2_reg = "a1"; arg3_reg = "a2";
        syscall_reg = "a7"; expected_syscall_nr = 221;
    } else {
        return fail("Unsupported architecture for semantic execve chain validation: " + arch);
    }

    if (parser != nullptr) {
        word_size = parser->is64Bit() ? 8 : 4;
    }

    // 3. Chain Step Evaluation
    std::map<std::string, uint64_t> staged_registers;
    bool syscall_step_seen = false;

    for (size_t i = 0; i < m_steps.size(); ++i) {
        const auto& step = m_steps[i];

        // Rule A: No instructions or steps after syscall execution
        if (syscall_step_seen) {
            return fail("Dead code detected: Step " + std::to_string(i + 1) + " appears after SystemCallExecution.");
        }

        // Rule B: 32-bit Word Size Bounds Check
        if (word_size == 4) {
            if (step.gadget.address > 0xFFFFFFFFULL) {
                return fail("Gadget address 0x" + to_hex(step.gadget.address) + " exceeds 32-bit bounds for 32-bit architecture " + arch + ".");
            }
            if (step.has_value && step.value > 0xFFFFFFFFULL) {
                return fail("Staged value 0x" + to_hex(step.value) + " exceeds 32-bit bounds for 32-bit architecture " + arch + ".");
            }
        }

        // Check if gadget explicitly loads link register (x30 for AArch64, ra/x1 for RISC-V) from stack
        bool step_loads_link_reg = false;
        for (const auto& insn : step.gadget.instructions) {
            std::string m = to_lower_str(insn.mnemonic);
            std::string op = to_lower_str(insn.op_str);
            if (norm_arch == "aarch64") {
                if (m == "ldr") {
                    if (op.find("[sp") != std::string::npos || op.find("[wsp") != std::string::npos) {
                        size_t comma = op.find(',');
                        std::string dst = (comma != std::string::npos) ? op.substr(0, comma) : "";
                        std::string c_dst = canonicalize_register(norm_arch, dst);
                        if (c_dst == "x30" || c_dst == "lr") {
                            step_loads_link_reg = true;
                        }
                    }
                }
            } else if (norm_arch == "riscv64" || norm_arch == "riscv32") {
                if (m == "ld" || m == "lw") {
                    std::string r_dst, r_base;
                    int64_t r_disp = 0;
                    if (parse_riscv_load_operand(norm_arch, insn.op_str, r_dst, r_base, r_disp)) {
                        if (is_stack_pointer_reg(norm_arch, r_base)) {
                            std::string c_dst = canonicalize_register(norm_arch, r_dst);
                            if (c_dst == "ra" || c_dst == "x1") {
                                step_loads_link_reg = true;
                            }
                        }
                    }
                }
            }
        }

        std::string decl_target;
        if (step.type == ROPStepType::RegisterAssignment || step.type == ROPStepType::SystemCallSetup) {
            decl_target = step.target_register.empty() ? step.gadget.target_register : step.target_register;
            decl_target = canonicalize_register(norm_arch, decl_target);
            if (decl_target.empty()) {
                return fail("Step " + std::to_string(i + 1) + " (" + stepTypeToString(step.type) + ") has no declared target register.");
            }
        }

        // Rule C (Part 1): Instruction-level stack validation & effect extraction
        size_t stack_load_count = 0;
        int64_t net_stack_displacement = 0;
        bool has_explicit_sp_adjustment = false;
        int target_load_idx = -1;
        int link_load_idx = -1;
        int target_load_count = 0;
        int link_load_count = 0;

        if (step.type == ROPStepType::RegisterAssignment || step.type == ROPStepType::SystemCallSetup) {
            for (size_t insn_idx = 0; insn_idx < step.gadget.instructions.size(); ++insn_idx) {
                const auto& insn = step.gadget.instructions[insn_idx];
                std::string m = to_lower_str(insn.mnemonic);
                std::string op = to_lower_str(insn.op_str);

                if (m == "pop") {
                    if (norm_arch == "aarch64" || norm_arch == "arm64" ||
                        norm_arch == "riscv" || norm_arch == "riscv32" || norm_arch == "riscv64") {
                        return fail("Unsupported instruction: Architecture '" + norm_arch + "' has no native 'pop' instruction in step " + std::to_string(i + 1) + ".");
                    }
                    if (norm_arch == "armv7" || norm_arch == "arm") {
                        std::string pop_err;
                        int arm_data_regs = count_arm_pop_data_registers(insn.op_str, &pop_err);
                        if (arm_data_regs < 0) {
                            return fail("ARM pop instruction in step " + std::to_string(i + 1) + " has invalid or unsupported register list: " + pop_err);
                        }
                        if (arm_data_regs > 1) {
                            return fail("Multi-pop gadget rejected: Step " + std::to_string(i + 1) + " consumes unmodeled stack words (ARM multi-register pop list: " + insn.op_str + ").");
                        }
                        stack_load_count += static_cast<size_t>(arm_data_regs);
                        net_stack_displacement += static_cast<int64_t>(arm_data_regs * word_size);
                        target_load_idx = static_cast<int>(insn_idx);
                        target_load_count += arm_data_regs;
                    } else {
                        std::string canon_pop = canonicalize_register(norm_arch, op);
                        stack_load_count++;
                        net_stack_displacement += static_cast<int64_t>(word_size);
                        if (canon_pop == decl_target) {
                            target_load_idx = static_cast<int>(insn_idx);
                            target_load_count++;
                        }
                    }
                } else if (m == "ldp") {
                    // AArch64 load pair always loads 2 registers from stack
                    return fail("Multi-register load gadget rejected: Step " + std::to_string(i + 1) + " consumes unmodeled stack words (AArch64 ldp instruction).");
                } else if (m == "ldr") {
                    if (op.find("[sp") != std::string::npos || op.find("[wsp") != std::string::npos) {
                        if (op.find("]!") != std::string::npos) {
                            return fail("Unsupported stack effect: Step " + std::to_string(i + 1) + " uses pre-indexed SP writeback (" + insn.op_str + "), which modifies stack pointer before loading value.");
                        }
                        if (op.find("],") != std::string::npos) {
                            int64_t disp = get_aarch64_post_index_sp_displacement(insn.op_str);
                            if (disp < 0 || disp != static_cast<int64_t>(word_size)) {
                                return fail("Unmodeled stack displacement: Step " + std::to_string(i + 1) + " uses post-indexed SP load (" + insn.op_str + ") with displacement " + (disp >= 0 ? ("#" + std::to_string(disp)) : "unparseable") + ", which does not match serialized stack word size (" + std::to_string(word_size) + " bytes).");
                            }
                            has_explicit_sp_adjustment = true;
                            net_stack_displacement += disp;
                        }
                        size_t comma = op.find(',');
                        std::string dst = (comma != std::string::npos) ? op.substr(0, comma) : "";
                        std::string canon_dst = canonicalize_register(norm_arch, dst);
                        if (canon_dst == "x30" || canon_dst == "lr") {
                            link_load_idx = static_cast<int>(insn_idx);
                            link_load_count++;
                        } else {
                            stack_load_count++;
                            if (canon_dst == decl_target) {
                                target_load_idx = static_cast<int>(insn_idx);
                                target_load_count++;
                            }
                        }
                    }
                } else if (m == "ld" || m == "lw") {
                    if (norm_arch == "riscv" || norm_arch == "riscv32" || norm_arch == "riscv64") {
                        std::string r_dst, r_base, r_err;
                        int64_t r_disp = 0;
                        if (!parse_riscv_load_operand(norm_arch, insn.op_str, r_dst, r_base, r_disp, &r_err)) {
                            return fail("Malformed or unsupported RISC-V load instruction in step " + std::to_string(i + 1) + ": " + r_err);
                        }
                        if (is_stack_pointer_reg(norm_arch, r_base)) {
                            std::string canon_dst = canonicalize_register(norm_arch, r_dst);
                            if (canon_dst == "ra" || canon_dst == "x1") {
                                if (r_disp != static_cast<int64_t>(word_size)) {
                                    return fail("Unmodeled stack displacement: RISC-V load of link register in step " + std::to_string(i + 1) +
                                                " has displacement " + std::to_string(r_disp) + ", expected " + std::to_string(word_size) + ".");
                                }
                                link_load_idx = static_cast<int>(insn_idx);
                                link_load_count++;
                            } else {
                                stack_load_count++;
                                if (stack_load_count > 1) {
                                    return fail("Multi-pop / Multi-register load gadget rejected: Step " + std::to_string(i + 1) +
                                                " consumes unmodeled stack words (RISC-V multi-register load).");
                                }
                                if (r_disp != 0) {
                                    return fail("Unmodeled stack displacement: RISC-V load of data register '" + canon_dst + "' in step " + std::to_string(i + 1) +
                                                " has displacement " + std::to_string(r_disp) + ", expected 0.");
                                }
                                if (canon_dst == decl_target) {
                                    target_load_idx = static_cast<int>(insn_idx);
                                    target_load_count++;
                                }
                            }
                        }
                    }
                } else if (m == "add" || m == "addi" || m == "sub") {
                    size_t comma = op.find(',');
                    if (comma != std::string::npos) {
                        std::string dst = op.substr(0, comma);
                        if (is_stack_pointer_reg(norm_arch, dst)) {
                            size_t last_comma = op.rfind(',');
                            std::string second_op = (last_comma != std::string::npos) ? op.substr(last_comma + 1) : "";
                            int64_t imm_val = 0;
                            if (!parse_immediate_value(second_op, imm_val)) {
                                return fail("Unmodeled stack modification: Step " + std::to_string(i + 1) + " uses dynamic SP arithmetic (" + insn.op_str + ") with unestablished displacement.");
                            }
                            if (m == "sub") imm_val = -imm_val;
                            net_stack_displacement += imm_val;
                            has_explicit_sp_adjustment = true;
                        }
                    }
                } else if (m == "and" || m == "andi" || m == "or" || m == "ori" || m == "xor" || m == "xori") {
                    size_t comma = op.find(',');
                    if (comma != std::string::npos) {
                        std::string dst = op.substr(0, comma);
                        if (is_stack_pointer_reg(norm_arch, dst)) {
                            return fail("Unmodeled stack modification: Step " + std::to_string(i + 1) +
                                        " modifies stack pointer via logical operation (" + insn.op_str + "), which is not supported.");
                        }
                    }
                }
            }

            if (stack_load_count > 1) {
                return fail("Multi-pop / Multi-register load gadget rejected: Step " + std::to_string(i + 1) + " consumes unmodeled stack words (load count: " + std::to_string(stack_load_count) + ").");
            }
        }

        if (step.type == ROPStepType::GadgetExecution) {
            for (const auto& insn : step.gadget.instructions) {
                std::string m = to_lower_str(insn.mnemonic);
                std::string op = to_lower_str(insn.op_str);
                if (m == "add" || m == "addi" || m == "sub" || m == "mov" || m == "mv" ||
                    m == "and" || m == "andi" || m == "or" || m == "ori" || m == "xor" || m == "xori") {
                    size_t comma = op.find(',');
                    if (comma != std::string::npos) {
                        std::string dst = op.substr(0, comma);
                        if (is_stack_pointer_reg(norm_arch, dst)) {
                            return fail("Unmodeled stack modification: Step " + std::to_string(i + 1) +
                                        " modifies stack pointer (" + insn.op_str + "), which is not supported in GadgetExecution.");
                        }
                    }
                }
            }
        }

        if (step.type == ROPStepType::StackAdjustment) {
            return fail("Unmodeled stack adjustment: Step " + std::to_string(i + 1) +
                        " (" + step.gadget.assembly + ") uses StackAdjustment, which is not supported without a cumulative stack-offset layout model.");
        }

        // Rule D: Extract Verified Modified Registers
        std::set<std::string> step_modified;
        if (!extract_gadget_modified_registers(norm_arch, step.gadget, step_modified)) {
            return fail("Gadget register effects cannot be established reliably for step " + std::to_string(i + 1) + ".");
        }

        // Rule E: Declared Target Register & Instruction Verification
        if (step.type == ROPStepType::RegisterAssignment || step.type == ROPStepType::SystemCallSetup) {
            if (!gadget_instructions_support_dest(norm_arch, step.gadget.instructions, decl_target)) {
                return fail("Target-register inconsistency: Gadget instructions in step " + std::to_string(i + 1) + " do not write to declared target register '" + decl_target + "'.");
            }
            if (!step.gadget.registers_modified.empty()) {
                bool found_in_mod = false;
                for (const auto& r : step.gadget.registers_modified) {
                    if (canonicalize_register(norm_arch, r) == decl_target) {
                        found_in_mod = true;
                        break;
                    }
                }
                if (!found_in_mod) {
                    return fail("Target-register inconsistency: Declared target register '" + decl_target + "' is missing from gadget registers_modified in step " + std::to_string(i + 1) + ".");
                }
            }
        }

        // Rule F: Global Clobber Detection Across EVERY Step Type
        for (const auto& mod_reg : step_modified) {
            if (staged_registers.find(mod_reg) != staged_registers.end() && mod_reg != decl_target) {
                res.clobbered_registers.push_back(mod_reg);
                return fail("Register clobber: Step " + std::to_string(i + 1) + " (" + stepTypeToString(step.type) + ") clobbers previously staged register '" + mod_reg + "' before syscall execution.");
            }
        }

        // Rule C (Part 2): Control flow and load-ordering verification
        if (step.type == ROPStepType::RegisterAssignment || step.type == ROPStepType::SystemCallSetup) {
            if (!step.gadget.instructions.empty()) {
                const auto& term_insn = step.gadget.instructions.back();
                std::string term_m = to_lower_str(term_insn.mnemonic);
                if (term_m == "ret") {
                    if (norm_arch == "aarch64") {
                        if (link_load_count == 0) {
                            return fail("Unsupported control flow: AArch64 gadget in step " + std::to_string(i + 1) +
                                        " terminates with 'ret' (br x30) without loading link register x30 from stack.");
                        }
                        if (link_load_count > 1) {
                            return fail("Ambiguous stack loads: Step " + std::to_string(i + 1) + " contains multiple loads of link register x30.");
                        }
                        if (target_load_count != 1) {
                            return fail("Unsupported staging gadget: AArch64 gadget in step " + std::to_string(i + 1) +
                                        " must load target register '" + decl_target + "' from stack.");
                        }
                        if (target_load_idx >= link_load_idx) {
                            return fail("Unsupported control flow: AArch64 gadget in step " + std::to_string(i + 1) +
                                        " loads link register x30 before loading target register '" + decl_target + "', which inverts payload words and causes control flow divergence.");
                        }
                        int64_t expected_disp = static_cast<int64_t>(2 * word_size);
                        if (net_stack_displacement != expected_disp) {
                            return fail("Unmodeled stack displacement: Step " + std::to_string(i + 1) +
                                        " instructions advance SP by " + std::to_string(net_stack_displacement) +
                                        " bytes, which does not match serialized stack word size (" + std::to_string(expected_disp) + " bytes).");
                        }
                    } else if (norm_arch == "riscv64" || norm_arch == "riscv32") {
                        if (link_load_count == 0) {
                            return fail("Unsupported control flow: RISC-V gadget in step " + std::to_string(i + 1) +
                                        " terminates with 'ret' (jalr ra) without loading link register ra (x1) from stack.");
                        }
                        if (link_load_count > 1) {
                            return fail("Ambiguous stack loads: Step " + std::to_string(i + 1) + " contains multiple loads of link register ra.");
                        }
                        if (target_load_count != 1) {
                            return fail("Unsupported staging gadget: RISC-V gadget in step " + std::to_string(i + 1) +
                                        " must load target register '" + decl_target + "' from stack.");
                        }
                        if (target_load_idx >= link_load_idx) {
                            return fail("Unsupported control flow: RISC-V gadget in step " + std::to_string(i + 1) +
                                        " loads link register ra before loading target register '" + decl_target + "', which inverts payload words and causes control flow divergence.");
                        }
                        int64_t expected_disp = static_cast<int64_t>(2 * word_size);
                        if (!has_explicit_sp_adjustment || net_stack_displacement != expected_disp) {
                            return fail("Unmodeled stack displacement: RISC-V gadget in step " + std::to_string(i + 1) +
                                        " instructions advance SP by " + std::to_string(net_stack_displacement) +
                                        " bytes, which does not match serialized stack word size (" + std::to_string(expected_disp) + " bytes).");
                        }
                    } else {
                        int64_t expected_disp = static_cast<int64_t>(stack_load_count * word_size);
                        if (has_explicit_sp_adjustment && net_stack_displacement != expected_disp) {
                            return fail("Unmodeled stack displacement: Step " + std::to_string(i + 1) +
                                        " instructions advance SP by " + std::to_string(net_stack_displacement) +
                                        " bytes, which does not match serialized stack word size (" + std::to_string(expected_disp) + " bytes).");
                        }
                    }
                }
            }
        }

        if (step.type == ROPStepType::GadgetExecution) {
            for (const auto& insn : step.gadget.instructions) {
                std::string m = to_lower_str(insn.mnemonic);
                std::string op = to_lower_str(insn.op_str);
                if (m == "add" || m == "addi" || m == "sub" || m == "mov" || m == "mv" ||
                    m == "and" || m == "andi" || m == "or" || m == "ori" || m == "xor" || m == "xori") {
                    size_t comma = op.find(',');
                    if (comma != std::string::npos) {
                        std::string dst = op.substr(0, comma);
                        if (is_stack_pointer_reg(norm_arch, dst)) {
                            return fail("Unmodeled stack modification: Step " + std::to_string(i + 1) +
                                        " modifies stack pointer (" + insn.op_str + "), which is not supported in GadgetExecution.");
                        }
                    }
                }
            }
        }

        if (step.type == ROPStepType::StackAdjustment) {
            return fail("Unmodeled stack adjustment: Step " + std::to_string(i + 1) +
                        " (" + step.gadget.assembly + ") uses StackAdjustment, which is not supported without a cumulative stack-offset layout model.");
        }

        // Control flow verification: AArch64 and RISC-V require link-register reloading from stack before 'ret'
        if (step.type != ROPStepType::SystemCallExecution) {
            if (!step.gadget.instructions.empty()) {
                const auto& term_insn = step.gadget.instructions.back();
                std::string term_m = to_lower_str(term_insn.mnemonic);
                if (term_m == "ret") {
                    if (norm_arch == "aarch64") {
                        if (!step_loads_link_reg) {
                            return fail("Unsupported control flow: AArch64 gadget in step " + std::to_string(i + 1) +
                                        " terminates with 'ret' (br x30) without loading link register x30 from stack.");
                        }
                    } else if (norm_arch == "riscv64" || norm_arch == "riscv32") {
                        if (!step_loads_link_reg) {
                            return fail("Unsupported control flow: RISC-V gadget in step " + std::to_string(i + 1) +
                                        " terminates with 'ret' (jalr ra) without loading link register ra (x1) from stack.");
                        }
                    }
                }
            }
        }

        // Rule G: Semantic Staging Invariants
        if (step.type == ROPStepType::RegisterAssignment || step.type == ROPStepType::SystemCallSetup) {
            if (!step.has_value) {
                return fail("Step " + std::to_string(i + 1) + " (" + stepTypeToString(step.type) + ") is missing an explicitly staged value (has_value == false).");
            }

            if (step.type == ROPStepType::RegisterAssignment) {
                if (decl_target == arg1_reg) {
                    if (step.value == 0) {
                        return fail("Arg 1 (/bin/sh address) must be a non-zero pointer, got 0 in step " + std::to_string(i + 1) + ".");
                    }
                    if (is_macho) {
                        uint64_t fo = 0, rva = 0;
                        if (!parser->vaToOffsets(step.value, fo, rva)) {
                            return fail("Arg 1 address 0x" + to_hex(step.value) + " does not resolve to any mapped section.");
                        }
                        const SectionInfo* found_sec = nullptr;
                        for (const auto& sec : parser->getSections()) {
                            if (step.value >= sec.virtual_address && step.value < sec.virtual_address + sec.virtual_size) {
                                found_sec = &sec;
                                break;
                            }
                        }
                        if (!found_sec) {
                            return fail("Arg 1 address does not resolve to any section.");
                        }
                        if (found_sec->raw_size == 0 || (found_sec->characteristics & 0xFF) == 1 /* S_ZEROFILL */) {
                            return fail("Arg 1 resides in non-file-backed / zero-fill section (" + found_sec->name + ").");
                        }
                        if (found_sec->name.rfind("__PAGEZERO", 0) == 0) {
                            return fail("Arg 1 resides in unmapped __PAGEZERO segment.");
                        }

                        // Segment metadata and permissions validation
                        const MachOSegmentInfo* found_seg = nullptr;
                        for (const auto& seg : parser->getMachOSegments()) {
                            if (!found_sec->segment_name.empty() && seg.name == found_sec->segment_name) {
                                found_seg = &seg;
                                break;
                            }
                            auto comma_pos = found_sec->name.find(',');
                            if (comma_pos != std::string::npos && seg.name == found_sec->name.substr(0, comma_pos)) {
                                found_seg = &seg;
                                break;
                            }
                        }
                        if (!found_seg) {
                            for (const auto& seg : parser->getMachOSegments()) {
                                if (found_sec->virtual_address >= seg.vmaddr &&
                                    found_sec->virtual_address + found_sec->virtual_size <= seg.vmaddr + seg.vmsize) {
                                    found_seg = &seg;
                                    break;
                                }
                            }
                        }
                        if (!found_seg || found_sec->virtual_address < found_seg->vmaddr ||
                            (found_sec->virtual_address + found_sec->virtual_size) > (found_seg->vmaddr + found_seg->vmsize)) {
                            return fail("Missing or inconsistent segment metadata for section (" + found_sec->name + ").");
                        }
                        if ((found_seg->initprot & 0x1 /* VM_PROT_READ */) == 0) {
                            return fail("Arg 1 resides in segment without VM_PROT_READ permission (" + found_seg->name + ").");
                        }

                        uint64_t delta = step.value - found_sec->virtual_address;
                        if (delta >= found_sec->raw_size) {
                            return fail("Arg 1 offset exceeds section raw file size.");
                        }
                        std::ifstream bfile(parser->getFilePath(), std::ios::binary);
                        if (!bfile) {
                            return fail("Could not open binary file to verify Arg 1 string.");
                        }
                        bfile.seekg(fo, std::ios::beg);
                        size_t max_read = found_sec->raw_size - delta;
                        std::vector<char> str_buf(max_read);
                        bfile.read(str_buf.data(), max_read);
                        size_t actual_read = bfile.gcount();
                        auto null_it = std::find(str_buf.begin(), str_buf.begin() + actual_read, '\0');
                        if (null_it == str_buf.begin() + actual_read) {
                            return fail("Arg 1 path string is not null-terminated within section bounds.");
                        }
                        std::string actual_path(str_buf.data());
                        if (actual_path != "/bin/sh") {
                            return fail("Arg 1 path string does not equal '/bin/sh' (got '" + actual_path + "').");
                        }

                        // Validate full range of path string including null terminator against segment boundary
                        size_t path_range_len = actual_path.size() + 1;
                        if (step.value > UINT64_MAX - path_range_len) {
                            return fail("Arg 1 address range overflows 64-bit integer.");
                        }
                        if (step.value + path_range_len > found_seg->vmaddr + found_seg->vmsize) {
                            return fail("Arg 1 path string crosses readable segment boundary (" + found_seg->name + ").");
                        }
                        if (step.value + path_range_len > found_sec->virtual_address + found_sec->virtual_size) {
                            return fail("Arg 1 path string crosses section boundary (" + found_sec->name + ").");
                        }
                    }
                    staged_registers[decl_target] = step.value;
                    res.has_arg1 = true;
                } else if (decl_target == arg2_reg) {
                    if (is_macho) {
                        if (step.value == 0) {
                            return fail("Arg 2 (argv array address) must be a non-zero pointer on Darwin, got 0 in step " + std::to_string(i + 1) + ".");
                        }
                        if (step.value > UINT64_MAX - 16) {
                            return fail("Arg 2 address range overflows 64-bit integer.");
                        }
                        uint64_t fo = 0, rva = 0;
                        if (!parser->vaToOffsets(step.value, fo, rva)) {
                            return fail("Arg 2 address 0x" + to_hex(step.value) + " does not resolve to any mapped section.");
                        }
                        const SectionInfo* found_sec = nullptr;
                        for (const auto& sec : parser->getSections()) {
                            if (step.value >= sec.virtual_address && step.value < sec.virtual_address + sec.virtual_size) {
                                found_sec = &sec;
                                break;
                            }
                        }
                        if (!found_sec) {
                            return fail("Arg 2 address does not resolve to any section.");
                        }
                        if (found_sec->raw_size == 0 || (found_sec->characteristics & 0xFF) == 1 /* S_ZEROFILL */) {
                            return fail("Arg 2 resides in non-file-backed / zero-fill section (" + found_sec->name + ").");
                        }
                        if (found_sec->name.rfind("__PAGEZERO", 0) == 0) {
                            return fail("Arg 2 resides in unmapped __PAGEZERO segment.");
                        }

                        // Segment metadata and permissions validation
                        const MachOSegmentInfo* found_seg = nullptr;
                        for (const auto& seg : parser->getMachOSegments()) {
                            if (!found_sec->segment_name.empty() && seg.name == found_sec->segment_name) {
                                found_seg = &seg;
                                break;
                            }
                            auto comma_pos = found_sec->name.find(',');
                            if (comma_pos != std::string::npos && seg.name == found_sec->name.substr(0, comma_pos)) {
                                found_seg = &seg;
                                break;
                            }
                        }
                        if (!found_seg) {
                            for (const auto& seg : parser->getMachOSegments()) {
                                if (found_sec->virtual_address >= seg.vmaddr &&
                                    found_sec->virtual_address + found_sec->virtual_size <= seg.vmaddr + seg.vmsize) {
                                    found_seg = &seg;
                                    break;
                                }
                            }
                        }
                        if (!found_seg || found_sec->virtual_address < found_seg->vmaddr ||
                            (found_sec->virtual_address + found_sec->virtual_size) > (found_seg->vmaddr + found_seg->vmsize)) {
                            return fail("Missing or inconsistent segment metadata for section (" + found_sec->name + ").");
                        }
                        if ((found_seg->initprot & 0x1 /* VM_PROT_READ */) == 0) {
                            return fail("Arg 2 resides in segment without VM_PROT_READ permission (" + found_seg->name + ").");
                        }
                        if (step.value + 16 > found_seg->vmaddr + found_seg->vmsize) {
                            return fail("Arg 2 argv array crosses readable segment boundary (" + found_seg->name + ").");
                        }

                        uint64_t delta = step.value - found_sec->virtual_address;
                        if (found_sec->raw_size < 16 || delta > found_sec->raw_size - 16) {
                            return fail("Arg 2 array requires at least 16 file-backed bytes for { path, NULL } within section bounds.");
                        }
                        if (delta > found_sec->virtual_size - 16) {
                            return fail("Arg 2 argv array crosses section boundary (" + found_sec->name + ").");
                        }
                        std::ifstream bfile(parser->getFilePath(), std::ios::binary);
                        if (!bfile) {
                            return fail("Could not open binary file to verify Arg 2 argv array.");
                        }
                        bfile.seekg(fo, std::ios::beg);
                        uint64_t argv0 = 0, argv1 = 0;
                        bfile.read(reinterpret_cast<char*>(&argv0), 8);
                        bfile.read(reinterpret_cast<char*>(&argv1), 8);
                        if (bfile.gcount() < 8) {
                            return fail("Could not read complete 16-byte argv array.");
                        }
                        if (argv0 == 0) {
                            return fail("argv[0] is NULL (must point to executable path).");
                        }
                        if (staged_registers.find(arg1_reg) != staged_registers.end() && argv0 != staged_registers[arg1_reg]) {
                            return fail("argv[0] (0x" + to_hex(argv0) + ") does not equal Arg 1 path address (0x" + to_hex(staged_registers[arg1_reg]) + ").");
                        }
                        if (argv1 != 0) {
                            return fail("argv[1] is not NULL (got 0x" + to_hex(argv1) + ").");
                        }
                        staged_registers[decl_target] = step.value;
                        res.has_arg2 = true;
                    } else {
                        if (step.value != 0) {
                            return fail("Arg 2 (argv) must be explicitly NULL (0), got 0x" + to_hex(step.value) + " in step " + std::to_string(i + 1) + ".");
                        }
                        staged_registers[decl_target] = 0;
                        res.has_arg2 = true;
                    }
                } else if (decl_target == arg3_reg) {
                    if (is_macho) {
                        if (step.value == 0) {
                            return fail("Arg 3 (envp array address) must be a non-zero pointer on Darwin, got 0 in step " + std::to_string(i + 1) + ".");
                        }
                        if (step.value > UINT64_MAX - 8) {
                            return fail("Arg 3 address range overflows 64-bit integer.");
                        }
                        uint64_t fo = 0, rva = 0;
                        if (!parser->vaToOffsets(step.value, fo, rva)) {
                            return fail("Arg 3 address 0x" + to_hex(step.value) + " does not resolve to any mapped section.");
                        }
                        const SectionInfo* found_sec = nullptr;
                        for (const auto& sec : parser->getSections()) {
                            if (step.value >= sec.virtual_address && step.value < sec.virtual_address + sec.virtual_size) {
                                found_sec = &sec;
                                break;
                            }
                        }
                        if (!found_sec) {
                            return fail("Arg 3 address does not resolve to any section.");
                        }
                        if (found_sec->raw_size == 0 || (found_sec->characteristics & 0xFF) == 1 /* S_ZEROFILL */) {
                            return fail("Arg 3 resides in non-file-backed / zero-fill section (" + found_sec->name + ").");
                        }
                        if (found_sec->name.rfind("__PAGEZERO", 0) == 0) {
                            return fail("Arg 3 resides in unmapped __PAGEZERO segment.");
                        }

                        // Segment metadata and permissions validation
                        const MachOSegmentInfo* found_seg = nullptr;
                        for (const auto& seg : parser->getMachOSegments()) {
                            if (!found_sec->segment_name.empty() && seg.name == found_sec->segment_name) {
                                found_seg = &seg;
                                break;
                            }
                            auto comma_pos = found_sec->name.find(',');
                            if (comma_pos != std::string::npos && seg.name == found_sec->name.substr(0, comma_pos)) {
                                found_seg = &seg;
                                break;
                            }
                        }
                        if (!found_seg) {
                            for (const auto& seg : parser->getMachOSegments()) {
                                if (found_sec->virtual_address >= seg.vmaddr &&
                                    found_sec->virtual_address + found_sec->virtual_size <= seg.vmaddr + seg.vmsize) {
                                    found_seg = &seg;
                                    break;
                                }
                            }
                        }
                        if (!found_seg || found_sec->virtual_address < found_seg->vmaddr ||
                            (found_sec->virtual_address + found_sec->virtual_size) > (found_seg->vmaddr + found_seg->vmsize)) {
                            return fail("Missing or inconsistent segment metadata for section (" + found_sec->name + ").");
                        }
                        if ((found_seg->initprot & 0x1 /* VM_PROT_READ */) == 0) {
                            return fail("Arg 3 resides in segment without VM_PROT_READ permission (" + found_seg->name + ").");
                        }
                        if (step.value + 8 > found_seg->vmaddr + found_seg->vmsize) {
                            return fail("Arg 3 envp array crosses readable segment boundary (" + found_seg->name + ").");
                        }

                        uint64_t delta = step.value - found_sec->virtual_address;
                        if (found_sec->raw_size < 8 || delta > found_sec->raw_size - 8) {
                            return fail("Arg 3 array requires at least 8 file-backed bytes for NULL terminator within section bounds.");
                        }
                        if (delta > found_sec->virtual_size - 8) {
                            return fail("Arg 3 envp array crosses section boundary (" + found_sec->name + ").");
                        }
                        std::ifstream bfile(parser->getFilePath(), std::ios::binary);
                        if (!bfile) {
                            return fail("Could not open binary file to verify Arg 3 envp array.");
                        }
                        bfile.seekg(fo, std::ios::beg);
                        uint64_t envp0 = 0;
                        bfile.read(reinterpret_cast<char*>(&envp0), 8);
                        if (bfile.gcount() < 8) {
                            return fail("Could not read complete 8-byte envp array.");
                        }
                        if (envp0 != 0) {
                            return fail("envp[0] is not NULL (got 0x" + to_hex(envp0) + ").");
                        }
                        staged_registers[decl_target] = step.value;
                        res.has_arg3 = true;
                    } else {
                        if (step.value != 0) {
                            return fail("Arg 3 (envp) must be explicitly NULL (0), got 0x" + to_hex(step.value) + " in step " + std::to_string(i + 1) + ".");
                        }
                        staged_registers[decl_target] = 0;
                        res.has_arg3 = true;
                    }
                } else {
                    staged_registers[decl_target] = step.value;
                }
            } else { // SystemCallSetup
                if (decl_target == syscall_reg) {
                    if (step.value != expected_syscall_nr) {
                        return fail("Syscall number mismatch: Expected " + std::to_string(expected_syscall_nr) + ", got " + std::to_string(step.value) + " in step " + std::to_string(i + 1) + ".");
                    }
                    staged_registers[decl_target] = step.value;
                    res.has_syscall_setup = true;
                } else {
                    staged_registers[decl_target] = step.value;
                }
            }
        } else if (step.type == ROPStepType::SystemCallExecution) {
            if (syscall_step_seen) {
                return fail("Multiple SystemCallExecution steps detected in chain.");
            }
            if (step.gadget.instructions.empty()) {
                return fail("Syscall execution gadget has no instructions.");
            }
            // Locate trap instruction in gadget
            int trap_idx = -1;
            for (size_t insn_idx = 0; insn_idx < step.gadget.instructions.size(); ++insn_idx) {
                if (match_trap_instruction(norm_arch, step.gadget.instructions[insn_idx])) {
                    trap_idx = static_cast<int>(insn_idx);
                    break;
                }
            }
            if (trap_idx < 0) {
                return fail("Syscall gadget does not contain the expected architecture trap instruction.");
            }
            // Check terminal trap instruction position: exact final instruction required
            size_t total_insns = step.gadget.instructions.size();
            if (static_cast<size_t>(trap_idx) != total_insns - 1) {
                return fail("Syscall trap instruction is not at terminal position in gadget (followed by subsequent instructions).");
            }
            // Pre-trap clobber check inside the syscall gadget
            if (trap_idx > 0) {
                for (int insn_idx = 0; insn_idx < trap_idx; ++insn_idx) {
                    const auto& pre_insn = step.gadget.instructions[insn_idx];
                    std::string m = to_lower_str(pre_insn.mnemonic);
                    std::string op = to_lower_str(pre_insn.op_str);
                    size_t comma = op.find(',');
                    std::string dst = (comma != std::string::npos) ? op.substr(0, comma) : op;
                    dst = canonicalize_register(norm_arch, dst);
                    if (staged_registers.find(dst) != staged_registers.end()) {
                        res.clobbered_registers.push_back(dst);
                        return fail("Pre-trap instruction in syscall gadget clobbers required register '" + dst + "'.");
                    }
                }
            }
            syscall_step_seen = true;
            res.has_syscall_exec = true;
        }
    }

    // 4. Invariant Completeness Check
    if (!res.has_arg1 || !res.has_arg2 || !res.has_arg3 || !res.has_syscall_setup || !res.has_syscall_exec) {
        return fail("Incomplete execve ROP chain: missing one or more required components (Arg1, Arg2, Arg3, SyscallSetup, or SyscallExecution).");
    }

    res.valid = true;
    res.staged_registers = staged_registers;
    res.bounds_verified = true;
    res.abi_conformance_verified = true;
    return res;
}