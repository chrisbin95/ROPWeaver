#include "rop_chain.h"
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include "nlohmann/json.hpp" // Required for the toJson() method

using json = nlohmann::json;

// Helper to format addresses as hex
static inline std::string to_hex(uint64_t addr) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(16) << std::setfill('0') << addr;
    return oss.str();
}

// Overload for gadget-only steps
void ROPChain::add_step(const Gadget& gadget, const std::string& comment) {
    ROPChainStep step;
    step.gadget = gadget;
    step.comment = comment;
    step.has_value = false;
    m_steps.push_back(step);
}

// Overload for gadget-value steps
void ROPChain::add_step(const Gadget& gadget, uint64_t value, const std::string& comment) {
    ROPChainStep step;
    step.gadget = gadget;
    step.value = value;
    step.comment = comment;
    step.has_value = true;
    m_steps.push_back(step);
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
            {"type", step.has_value ? "Register_Load" : "Syscall_Execution"},
            
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
        if (step.has_value) {
            ss << "Value: " << to_hex(step.value) << "\n";
        }
        ss << "Comment: " << step.comment << "\n";
    }
    ss << "--------------------------------\n";
    return ss.str();
}

std::vector<char> ROPChain::getPayloadBytes() const {
    std::vector<char> bytes;
    for (const auto& step : m_steps) {
        // Add gadget address (little-endian)
        uint64_t addr = step.gadget.address;
        for (int i = 0; i < 8; ++i) {
            bytes.push_back(static_cast<char>((addr >> (8 * i)) & 0xFF));
        }

        // If a value exists, add it to the payload (little-endian)
        if (step.has_value) {
            uint64_t value = step.value;
            for (int i = 0; i < 8; ++i) {
                bytes.push_back(static_cast<char>((value >> (8 * i)) & 0xFF));
            }
        }
    }
    return bytes;
}