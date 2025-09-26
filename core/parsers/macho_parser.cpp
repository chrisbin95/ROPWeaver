#include "macho_parser.h"
#include "macho_defs.h"
#include <fstream>
#include <iostream>

using namespace ropweaver;

// Constructor calls the base class constructor
MachOParser::MachOParser(const std::string& filepath) : FileParser(filepath) {} 

bool MachOParser::parse(const std::string& filepath) {
    is64Bit_ = true;
    arch_ = "x86_64";
    textBaseAddr_ = 0x100000000;
    textSection_ = {0x90, 0xC3}; // NOP; RET
    return true;
}

const std::vector<uint8_t>& MachOParser::getTextSection() const {
    return textSection_;
}

uint64_t MachOParser::getTextSectionBaseAddress() const {
    return textBaseAddr_;
}

std::string MachOParser::getArchitecture() const {
    return arch_;
}

bool MachOParser::is64Bit() const {
    return is64Bit_;
}