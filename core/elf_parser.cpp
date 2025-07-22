// elf_parser.cpp
#include "elf_parser.h"
#include <fstream>
#include <iostream>
#include <cstring>
#include <elf.h>

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

    // Save a copy of the ELF header
    std::memcpy(&elf_header, data.data(), sizeof(Elf64_Ehdr));

    // Set architecture string
    switch (elf_header.e_machine) {
        case EM_X86_64:  arch = "x86_64"; break;
        case EM_386:     arch = "i386"; break;
        case EM_ARM:     arch = "arm"; break;
        case EM_AARCH64: arch = "aarch64"; break;
        default:         arch = "unknown"; break;
    }

    // Section headers
    const Elf64_Shdr* sh_table = reinterpret_cast<const Elf64_Shdr*>(data.data() + elf_header.e_shoff);
    if (elf_header.e_shstrndx == SHN_UNDEF) {
        std::cerr << "Invalid section string table index.\n";
        return false;
    }

    const Elf64_Shdr& sh_strtab_hdr = sh_table[elf_header.e_shstrndx];
    const char* sh_strtab = reinterpret_cast<const char*>(data.data() + sh_strtab_hdr.sh_offset);

    for (int i = 0; i < elf_header.e_shnum; ++i) {
        const Elf64_Shdr& sh = sh_table[i];
        std::string sectionName(sh_strtab + sh.sh_name);

        if (sectionName == ".text") {
            text_section.assign(
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

// returns the ELF header
Elf64_Ehdr ELFParser::getHeader() const {
    return elf_header;
}
