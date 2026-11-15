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
    uint64_t address = 0; // Legacy address alias (equals preferred_va, physical instruction address)

    // Accurate address representation (Requirement 4 & Phase 2 Step 4.5)
    uint64_t file_offset = 0;              // Raw disk offset in binary file
    uint64_t rva = 0;                      // Relative Virtual Address
    uint64_t preferred_va = 0;             // Preferred Virtual Address (ImageBase + RVA, physical instruction address)
    uint64_t entry_address = 0;            // Execution entry address (with Thumb bit 0 set for ARM Thumb mode)
    bool is_thumb = false;                 // True if decoded in ARM Thumb mode
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

    // Step 4.5: ARM / Thumb Address Helpers
    bool isThumb() const { return is_thumb; }
    uint64_t getPhysicalAddress() const { return address; }
    uint64_t getInterworkingAddress() const {
        if (entry_address != 0) return entry_address;
        if (is_thumb && (architecture == "armv7" || architecture == "arm" || architecture == "thumb")) {
            return address | 1ULL;
        }
        return address;
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

// ARM / Thumb Interworking Address Helper Functions (AAELF32 §4.5.2)
inline uint64_t to_thumb_interwork_address(uint64_t physical_addr) {
    return physical_addr | 1ULL;
}

inline uint64_t to_physical_instruction_address(uint64_t addr) {
    return addr & ~1ULL;
}

inline bool is_thumb_interwork_address(uint64_t addr) {
    return (addr & 1ULL) != 0;
}

#endif // GADGET_H
