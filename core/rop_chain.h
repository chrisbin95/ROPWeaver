#ifndef ROP_CHAIN_H
#define ROP_CHAIN_H

#include <vector>
#include <string>
#include <cstdint>
#include <cstddef>
#include "gadget.h"

// Required for the ROPChain::toJson() method
#include "nlohmann/json.hpp" 

// Endianness definition from file_parser.h
#if __has_include("parsers/file_parser.h")
#include "parsers/file_parser.h"
#elif __has_include("file_parser.h")
#include "file_parser.h"
#elif __has_include("core/parsers/file_parser.h")
#include "core/parsers/file_parser.h"
#else
enum class Endianness;
#endif

// Explicit semantic categories for ROP chain steps
enum class ROPStepType {
    Unknown,
    GadgetExecution,
    RegisterAssignment,
    SystemCallSetup,
    SystemCallExecution,
    StackAdjustment
};

inline const char* stepTypeToString(ROPStepType type) {
    switch (type) {
        case ROPStepType::GadgetExecution:     return "GadgetExecution";
        case ROPStepType::RegisterAssignment:  return "RegisterAssignment";
        case ROPStepType::SystemCallSetup:     return "SystemCallSetup";
        case ROPStepType::SystemCallExecution: return "SystemCallExecution";
        case ROPStepType::StackAdjustment:     return "StackAdjustment";
        case ROPStepType::Unknown:
        default:                               return "Unknown";
    }
}

inline const char* to_string(ROPStepType type) {
    return stepTypeToString(type);
}

// Forward declaration of FileParser
class FileParser;

// Validation result for semantic chain verification
struct ChainValidationResult {
    bool valid = false;
    std::string error_message;
    bool has_arg1 = false;
    bool has_arg2 = false;
    bool has_arg3 = false;
    bool has_syscall_setup = false;
    bool has_syscall_exec = false;
    bool bounds_verified = false;
    bool abi_conformance_verified = false;
    std::vector<std::string> clobbered_registers;
    std::map<std::string, uint64_t> staged_registers;

    nlohmann::json toJson() const {
        return {
            {"valid", valid},
            {"error_message", error_message.empty() ? "None" : error_message},
            {"has_arg1", has_arg1},
            {"has_arg2", has_arg2},
            {"has_arg3", has_arg3},
            {"has_syscall_setup", has_syscall_setup},
            {"has_syscall_exec", has_syscall_exec},
            {"bounds_verified", bounds_verified},
            {"abi_conformance_verified", abi_conformance_verified},
            {"clobbered_registers", clobbered_registers}
        };
    }
};

// A single step in the ROP chain, combining a gadget and its associated value.
struct ROPChainStep {
    Gadget gadget;
    uint64_t value = 0;
    std::string comment;
    bool has_value = false; // Indicates if the step has a value
    ROPStepType type = ROPStepType::Unknown;
    std::string target_register; // Explicit destination register (e.g. "rdi", "rax", "a7")
};

class ROPChain {
public:
    ROPChain() = default;

    // Original legacy overloads (forward to explicit-type implementation with default GadgetExecution)
    void add_step(const Gadget& gadget, const std::string& comment);
    void add_step(const Gadget& gadget, uint64_t value, const std::string& comment);

    // Explicit-type overloads
    void add_step(const Gadget& gadget, const std::string& comment, ROPStepType type);
    void add_step(const Gadget& gadget, const std::string& comment, ROPStepType type, const std::string& target_reg);
    void add_step(const Gadget& gadget, uint64_t value, const std::string& comment, ROPStepType type);
    void add_step(const Gadget& gadget, ROPStepType type, const std::string& comment);
    void add_step(const Gadget& gadget, uint64_t value, ROPStepType type, const std::string& comment);
    void add_step(const Gadget& gadget, uint64_t value, const std::string& comment, ROPStepType type, const std::string& target_reg);

    // Getters
    const std::vector<ROPChainStep>& get_steps() const { return m_steps; }
    std::string to_string() const;
    std::vector<char> getPayloadBytes() const;
    std::vector<char> getPayloadBytes(size_t wordSize, Endianness endianness) const;

    bool isSuccessful() const;
    nlohmann::json toJson() const;

    // Semantic validation against Linux execve ABI and architecture invariants
    ChainValidationResult validate(const std::string& arch = "x86_64", const FileParser* parser = nullptr) const;

private:
    std::vector<ROPChainStep> m_steps;
};

#endif // ROP_CHAIN_H