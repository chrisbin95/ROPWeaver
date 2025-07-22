// gadget.h
#pragma once
#include <string>
#include <cstdint>

struct Gadget {
    uint64_t address;       // Gadget address (e.g. code offset)
    std::string instruction; // Disassembled instruction string

    Gadget(const std::string& t, uint64_t addr) : instruction(t), address(addr) {}
};
