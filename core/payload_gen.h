#pragma once
#include "../core/rop_chain.h"
#include <vector>
#include <string>
#include <cstddef> 

class PayloadGenerator {
public:
    // Requires std::string and size_t to be defined
    void generate(const ROPChain& chain, size_t paddingSize, const std::string& filename);
};