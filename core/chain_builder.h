// chain_builder.h
#pragma once
#include <string>
#include <vector>

class ChainBuilder {
public:
    ChainBuilder(const std::vector<std::string>& gadgets);
    std::string buildExecveChain(const std::string& binsh_path);

private:
    std::string findGadget(const std::vector<std::string>& keywords);
    std::vector<std::string> rop_gadgets;
};