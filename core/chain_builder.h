// chain_builder.h
#pragma once
#include "gadget.h"
#include "rop_chain.h"
#include <string>
#include <vector>

class ChainBuilder {
public:
    ChainBuilder(const std::vector<Gadget>& gadgets);
    Gadget findGadget(const std::vector<std::string>& keywords);
    // Returns a ROPChain object (not string)
    ROPChain buildExecveChain(const std::string& binsh_path);

private:
    std::vector<Gadget> rop_gadgets;
};
