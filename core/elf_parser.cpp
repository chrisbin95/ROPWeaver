// elf_parser.cpp
#include "elf_parser.h"
#include <fstream>
#include <iostream>
#include <cstring>

ELFParser::ELFParser(const std::string& filename) : filepath(filename) {}

bool ELFParser::parse() {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filepath << std::endl;
        return false;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    data.resize(size);
    if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
        std::cerr << "Failed to read ELF file." << std::endl;
        return false;
    }

    if (data.size() < EI_NIDENT || std::memcmp(data.data(), ELFMAG, SELFMAG) != 0) {
        std::cerr << "Not a valid ELF file." << std::endl;
        return false;
    }

    const Elf64_Ehdr* ehdr = reinterpret_cast<const Elf64_Ehdr*>(data.data());

    // Set architecture string
    switch (ehdr->e_machine) {
        case EM_X86_64:
            arch = "x86_64";
            break;
        case EM_386:
            arch = "i386";
            break;
        case EM_ARM:
            arch = "arm";
            break;
        case EM_AARCH64:
            arch = "aarch64";
            break;
        default:
            arch = "unknown";
            break;
    }

    // Parse section headers to find .text section
    const Elf64_Shdr* sh_table = reinterpret_cast<const Elf64_Shdr*>(data.data() + ehdr->e_shoff);
    const char* sh_strtab = reinterpret_cast<const char*>(data.data() + sh_table[ehdr->e_shstrndx].sh_offset);

    for (int i = 0; i < ehdr->e_shnum; ++i) {
        const Elf64_Shdr& sh = sh_table[i];
        std::string sectionName(sh_strtab + sh.sh_name);

        if (sectionName == ".text") {
            text_section.insert(
                text_section.end(),
                data.begin() + sh.sh_offset,
                data.begin() + sh.sh_offset + sh.sh_size
            );
            break;
        }
    }

    return true;
}

bool ELFParser::isValidELF() const {
    return !data.empty() && std::memcmp(data.data(), ELFMAG, SELFMAG) == 0;
}

std::vector<uint8_t> ELFParser::getTextSection() const {
    return text_section;
}

std::string ELFParser::getArchitecture() const {
    return arch;
}