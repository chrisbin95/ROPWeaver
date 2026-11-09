// core/gadget.h

#ifndef GADGET_H
#define GADGET_H

#include <cstdint>
#include <string>
#include <vector>

struct Instruction {
    std::string mnemonic;
    std::string op_str;
};

struct Gadget {
    uint64_t address = 0; // Legacy address alias (equals preferred_va)

    // Accurate address representation (Requirement 4)
    uint64_t file_offset = 0;              // Raw disk offset in binary file
    uint64_t rva = 0;                      // Relative Virtual Address
    uint64_t preferred_va = 0;             // Preferred Virtual Address (ImageBase + RVA)
    // runtime_va: only known when ASLR / DYNAMIC_BASE is disabled. When ASLR is active,
    // runtime VA is randomized by the OS loader and unknown statically.
    std::string runtime_va = "ASLR Dependent";

    std::vector<Instruction> instructions;
    std::string architecture;

    // Assembly string and target register (backward compat)
    std::string assembly;        // e.g., "pop rdi; pop rsi; ret"
    std::string target_register; // e.g., "rdi"

    // Primary category alias (backward compat = categories[0] or "others")
    std::string category = "others";

    // --- Multi-dimensional classification metadata ---
    std::vector<std::string> categories;         // e.g., {"register_load", "stack_adjustment"}
    std::vector<std::string> registers_read;     // Registers consumed by gadget
    std::vector<std::string> registers_modified; // Registers written by gadget
    int64_t stack_delta = 0;                     // Net RSP/SP change in bytes (+pop, -push, add/sub rsp)
    int64_t stack_consumption = 0;               // Total bytes popped/read from stack
    bool has_memory_read = false;                // Gadget reads from memory
    bool has_memory_write = false;               // Gadget writes to memory
    std::vector<std::string> side_effects;       // Secondary effects (clobbers, stack change, etc.)
    std::string terminator_type;                 // "RET", "SYSCALL", "JMP", "CALL", etc.
    uint8_t instruction_count = 0;               // Number of instructions in sequence
    int classification_confidence = 0;           // 0-100 confidence score
    bool byte_verified = false;                  // Gadget bytes validated against binary

    // Returns the primary classification category
    std::string primaryCategory() const {
        return categories.empty() ? category : categories[0];
    }

    bool isValid() const;
    bool hasMnemonic(const std::string& mnem) const;
    bool isTerminator() const;
    bool isIndirectJumpOrCall() const;
    size_t popInstructionCount() const;
    bool isStackPivot() const;
    bool hasArithmeticOrLogic() const;
    std::string toString() const;
};

#endif // GADGET_H
