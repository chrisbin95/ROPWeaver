#include "gadget.h"
#include <algorithm>
#include <string>
#include <sstream>
#include <iomanip>
#include <cctype>

// ANSI escape codes for coloring
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_ORANGE  "\033[33m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

// Gadget Methods
bool Gadget::isValid() const {
    return !instructions.empty();
}

bool Gadget::hasMnemonic(const std::string& mnem) const {
    return std::any_of(instructions.begin(), instructions.end(),
                       [&](const Instruction& instr) { return instr.mnemonic == mnem; });
}

bool Gadget::isTerminator() const {
    if (instructions.empty()) return false;
    const auto& last_instr = instructions.back();
    std::string mnem = last_instr.mnemonic;

    // generic terminators
    if (mnem == "ret" || mnem == "retf" || mnem == "retfq" || mnem == "jmp" || mnem == "call") return true;
    if (mnem == "syscall" || mnem == "sysenter" || mnem == "ecall") return true;
    if (mnem == "int" && last_instr.op_str.find("0x80") != std::string::npos) return true;

    // ARM/Thumb terminators
    if ((architecture == "arm" || architecture == "thumb" || architecture == "armv7") &&
        ((mnem == "bx" && (last_instr.op_str.find("lr") != std::string::npos || last_instr.op_str.find("r14") != std::string::npos)) || 
         (mnem == "pop" && last_instr.op_str.find("pc") != std::string::npos) ||
         mnem == "svc" || mnem == "swi")) {
        return true;
    }

    // AArch64 terminators
    if ((architecture == "aarch64" || architecture == "arm64") && (mnem == "blr" || mnem == "ret" || mnem == "svc")) return true;

    // RISC-V terminators
    if ((architecture == "riscv32" || architecture == "riscv64") && 
        (mnem == "ret" || mnem == "ecall" || 
         (mnem == "jalr" && (last_instr.op_str.find("ra") != std::string::npos || last_instr.op_str.find("zero") != std::string::npos)))) {
        return true;
    }

    return false;
}

bool Gadget::isIndirectJumpOrCall() const {
    if (instructions.empty()) return false;
    const auto& last_instr = instructions.back();

    // x86/x86_64
    if (last_instr.mnemonic == "jmp" || last_instr.mnemonic == "call") {
        if (last_instr.op_str.find("ptr") != std::string::npos ||
            last_instr.op_str.find("[") != std::string::npos) {
            return true;
        }
        if (architecture == "x86_64" && (last_instr.op_str.find("r") == 0 || last_instr.op_str.find("e") == 0))
            return true;
        if (architecture == "x86" && last_instr.op_str.find("e") == 0)
            return true;
    }

    // ARM32/Thumb
    if ((architecture == "arm" || architecture == "thumb") &&
        (last_instr.mnemonic == "bx" || last_instr.mnemonic == "blx")) {
        return true;
    }

    // AArch64
    if ((architecture == "aarch64" || architecture == "arm64") &&
        (last_instr.mnemonic == "blr" || last_instr.mnemonic == "b")) {
        return true;
    }

    return false;
}

size_t Gadget::popInstructionCount() const {
    return std::count_if(instructions.begin(), instructions.end(),
                         [](const Instruction& instr) { return instr.mnemonic == "pop"; });
}

// ---------------------------------------------------------------------------
// isStackPivot: Genuine stack pivot ONLY (Requirement 2)
// Swapping or replacing the stack pointer with an arbitrary or register-based address.
// NOTE: Relative stack adjustments (add rsp, N / sub rsp, N) are strictly stack
// adjustments, NOT stack pivots!
// ---------------------------------------------------------------------------
bool Gadget::isStackPivot() const {
    if (instructions.empty()) return false;

    for (const auto& instr : instructions) {
        std::string mnem = instr.mnemonic;
        std::string ops  = instr.op_str;
        std::transform(mnem.begin(), mnem.end(), mnem.begin(), [](unsigned char c){ return std::tolower(c); });
        std::transform(ops.begin(), ops.end(), ops.begin(), [](unsigned char c){ return std::tolower(c); });

        // x86/x86_64 genuine stack pivots
        if (architecture == "x86" || architecture == "x86_64") {
            // Frame pointer pivot
            if (mnem == "leave") return true;

            // Register exchange with stack pointer
            if (mnem == "xchg" && (ops.find("rsp") != std::string::npos || ops.find("esp") != std::string::npos)) {
                return true;
            }

            // Direct loading of stack pointer from another register or memory
            if (mnem == "mov") {
                // e.g. "mov rsp, rax", "mov esp, ebp"
                size_t comma = ops.find(',');
                if (comma != std::string::npos) {
                    std::string dst = ops.substr(0, comma);
                    std::string src = ops.substr(comma + 1);
                    dst.erase(std::remove_if(dst.begin(), dst.end(), ::isspace), dst.end());
                    src.erase(std::remove_if(src.begin(), src.end(), ::isspace), src.end());
                    if ((dst == "rsp" || dst == "esp") && src != "rsp" && src != "esp") {
                        return true;
                    }
                }
            }

            // Direct pop into stack pointer
            if (mnem == "pop" && (ops == "rsp" || ops == "esp")) {
                return true;
            }
        }

        // AArch64
        if (architecture == "aarch64" || architecture == "arm64") {
            if (mnem == "mov" && ops.rfind("sp,", 0) == 0 && ops != "sp, sp") return true;
        }

        // ARM32/Thumb
        if (architecture == "arm" || architecture == "thumb" || architecture == "armv7") {
            if (mnem == "mov" && ops.rfind("sp,", 0) == 0 && ops != "sp, sp") return true;
            if (mnem == "ldr" && ops.rfind("sp,", 0) == 0) return true;
            if (mnem == "pop" && ops.find("sp") != std::string::npos) return true;
        }
    }

    return false;
}

bool Gadget::hasArithmeticOrLogic() const {
    static const std::vector<std::string> arithOps = {
        "add", "sub", "xor", "and", "or", "mul", "imul", "div", "idiv",
        "inc", "dec", "neg", "not", "shl", "shr", "sar", "rol", "ror", "test", "cmp"
    };
    return std::any_of(instructions.begin(), instructions.end(),
                       [&](const Instruction& instr) {
                           return std::find(arithOps.begin(), arithOps.end(), instr.mnemonic) != arithOps.end();
                       });
}

std::string Gadget::toString() const {
    std::stringstream ss;
    ss << ANSI_COLOR_GREEN << "0x" << std::hex 
       << std::setw(16) << std::setfill('0') << address 
       << ANSI_COLOR_RESET << ": ";

    for (size_t i = 0; i < instructions.size(); ++i) {
        ss << instructions[i].mnemonic;
        if (!instructions[i].op_str.empty())
            ss << " " << instructions[i].op_str;
        if (i < instructions.size() - 1) ss << " ; ";
    }

    // Add multi-category tags and stack delta
    if (!categories.empty()) {
        ss << "  " << ANSI_COLOR_CYAN << "[";
        for (size_t c = 0; c < categories.size(); ++c) {
            ss << categories[c];
            if (c + 1 < categories.size()) ss << ", ";
        }
        ss << "]" << ANSI_COLOR_RESET;
    }

    if (stack_delta != 0) {
        ss << " (" << (stack_delta > 0 ? "+" : "") << std::dec << stack_delta << " stack delta)";
    }

    return ss.str();
}
