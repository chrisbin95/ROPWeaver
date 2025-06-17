// elf_parser.cpp
#include "elf_parser.h"
#include <fstream>
#include <iostream>

ELFParser::ELFParser(const std::string& filename) : filepath(filename) {}

bool ELFParser::parse() {
    // ELF parsing logic
    // Populate text_section and arch
    return true;
}

std::vector<uint8_t> ELFParser::getTextSection() const {
    return text_section;
}

std::string ELFParser::getArchitecture() const {
    return arch;
}