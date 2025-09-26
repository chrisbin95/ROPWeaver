#include "pe_parser.h"
#include "pe_defs.h"
#include <fstream>
#include <iostream>

using namespace ropweaver;

PEParser::PEParser(const std::string& filepath) : FileParser(filepath) {}

bool PEParser::parse(const std::string& filepath) {
    is64Bit_ = true; 
    arch_ = "x86_64";
    textBaseAddr_ = 0x400000;
    textSection_ = {0x90, 0xC3}; // NOP; RET
    return true;
}

const std::vector<uint8_t>& PEParser::getTextSection() const {
    return textSection_;
}

uint64_t PEParser::getTextSectionBaseAddress() const {
    return textBaseAddr_;
}

std::string PEParser::getArchitecture() const {
    return arch_;
}

bool PEParser::is64Bit() const {
    return is64Bit_;
}