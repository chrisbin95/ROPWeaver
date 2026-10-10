#pragma once
#include "../core/rop_chain.h"
#include "../core/gadget.h"
#include "nlohmann/json.hpp"
#include <vector>
#include <string>
#include <cstddef> 

class PayloadGenerator {
public:
    void generate(const ROPChain& chain, size_t paddingSize, const std::string& filename,
                  const std::vector<Gadget>& gadgets = {},
                  const std::string& architecture = "x86_64",
                  const std::string& fileType = "ELF",
                  const nlohmann::json& protections = {},
                  const std::string& customReportId = "",
                  const std::string& fileHash = "");
};