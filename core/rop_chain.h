#ifndef ROP_CHAIN_H
#define ROP_CHAIN_H

#include <vector>
#include <string>
#include <cstdint>
#include "gadget.h"

// Required for the ROPChain::toJson() method
#include "nlohmann/json.hpp" 

// A single step in the ROP chain, combining a gadget and its associated value.
struct ROPChainStep {
    Gadget gadget;
    uint64_t value;
    std::string comment;
    bool has_value = false; // Indicates if the step has a value
    // NOTE: Add a 'type' field here later for cleaner JSON generation.
};

class ROPChain {
public:
    ROPChain() = default;

    // Adds a gadget-only step to the chain.
    void add_step(const Gadget& gadget, const std::string& comment);

    // Adds a gadget-value step to the chain.
    void add_step(const Gadget& gadget, uint64_t value, const std::string& comment);

    // Getters
    const std::vector<ROPChainStep>& get_steps() const { return m_steps; }
    std::string to_string() const;
    std::vector<char> getPayloadBytes() const;

    bool isSuccessful() const;
    nlohmann::json toJson() const;

private:
    std::vector<ROPChainStep> m_steps;
};

#endif // ROP_CHAIN_H