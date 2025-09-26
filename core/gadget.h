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

    // FIX 1: Add the two missing members required by ROPChain::toJson()
    std::string assembly;        // e.g., "pop rdi; pop rsi; ret"
    std::string target_register; // e.g., "rdi" (Used for categorization/chain building)

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