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
  uint64_t address = 0;
  std::vector<Instruction> instructions;
  std::string architecture;

  // Assembly string and target register (backward compat)
  std::string assembly; // e.g., "pop rdi; pop rsi; ret"
  std::string
      target_register; // e.g., "rdi" (Used for categorization/chain building)

  // Primary category (backward compat alias = categories[0] or "others")
  std::string category = "others";

  // --- Multi-dimensional classification metadata ---
  std::vector<std::string>
      categories; // e.g., {"register_load", "stack_adjustment"}
  std::vector<std::string> registers_read;     // Registers consumed by gadget
  std::vector<std::string> registers_modified; // Registers written by gadget
  int64_t stack_delta = 0;           // Net RSP/SP change in bytes (+pop, -push)
  bool has_memory_read = false;      // Gadget reads from memory
  bool has_memory_write = false;     // Gadget writes to memory
  std::string terminator_type;       // "RET", "SYSCALL", "JMP", "CALL", etc.
  uint8_t instruction_count = 0;     // Number of instructions in sequence
  int classification_confidence = 0; // 0-100 confidence score
  bool byte_verified = false;        // Gadget bytes validated against binary

  // Returns the primary classification category
  std::string primaryCategory() const {
    return categories.empty() ? category : categories[0];
  }

  bool isValid() const;
  bool hasMnemonic(const std::string &mnem) const;
  bool isTerminator() const;
  bool isIndirectJumpOrCall() const;
  size_t popInstructionCount() const;
  bool isStackPivot() const;
  bool hasArithmeticOrLogic() const;
  std::string toString() const;
};

#endif // GADGET_H