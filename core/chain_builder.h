#pragma once
#include "rop_chain.h"
#include "gadget.h"
#include <string>
#include <vector>
#include <cstdint>
#include <optional>

struct MemoryRegion {
    uint64_t start;
    uint64_t end;
    std::string path;
};

class ChainBuilder {
public:
    ChainBuilder(const std::vector<Gadget>& gadgets, const std::string& arch);

    std::optional<Gadget> findOptimalPopGadget(const std::string& reg);
    std::optional<Gadget> findSpecificGadget(const std::string& instruction);

    ROPChain buildExecveChain(const std::vector<MemoryRegion>& memoryRegions);
    ROPChain buildExecveChain(uint64_t binsh_addr);
    uint64_t findBinShAddress(const std::vector<MemoryRegion>& memoryRegions);

private:
    std::vector<Gadget> rop_gadgets;
    std::string m_arch;
    
    ROPChain buildExecveChainInternal(uint64_t binsh_addr);
};
