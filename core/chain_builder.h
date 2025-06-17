// chain_builder.h
#pragma once
#include <vector>
#include <string>

class ChainBuilder {
public:
    ChainBuilder(const std::vector<std::string>& gadgets);
    std::string buildExecveChain(const std::string& binsh_path);
private:
    std::vector<std::string> rop_gadgets;
};