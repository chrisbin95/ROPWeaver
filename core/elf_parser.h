// elf_parser.h
#pragma once
#include <string>
#include <vector>
#include <elf.h>

class ELFParser {
public:
    explicit ELFParser(const std::string& filename);
    bool parse();
    std::vector<uint8_t> getTextSection() const;
    std::string getArchitecture() const;
private:
    std::string filepath;
    std::vector<uint8_t> text_section;
    std::string arch;
};