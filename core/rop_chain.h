// rop_chain.h
#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include "gadget.h"

struct ROPChainStep {
    Gadget gadget;
    uint64_t address;        // Address of the gadget step
    std::string description; // Description or instruction of this step

    ROPChainStep(const Gadget& g, const std::string& desc)
        : gadget(g), address(g.address), description(desc) {}
    // Sets address = gadget.address automatically
};

struct ROPChain {
    std::vector<ROPChainStep> steps;

    std::string toString() const {
        std::string result;
        for (const auto& step : steps) {
            result += step.description + ": " + step.gadget.instruction + " @ 0x" +
                      to_hex(step.address) + "\n";
        }
        return result;
    }

private:
    std::string to_hex(uint64_t addr) const {
        char buffer[20];
        snprintf(buffer, sizeof(buffer), "%016lx", addr);
        return std::string(buffer);
    }
};
