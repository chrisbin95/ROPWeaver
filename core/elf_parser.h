// elf_parser.h
#pragma once
#include <string>
// elf_parser.h
#include <vector>
#include <cstdint>
#include <elf.h>

class ELFParser {
public:
    explicit ELFParser(const std::string& filename);
    bool parse();
    bool isValidELF() const;
    std::vector<uint8_t> getTextSection() const;
    std::string getArchitecture() const;
    Elf64_Ehdr getHeader() const;

private:
    std::string filepath;
    std::vector<uint8_t> data;
    std::vector<uint8_t> text_section;
    std::string arch;
    Elf64_Ehdr elf_header {};
};
