#include "aarch64_parser.h"
#include "elf_defs.h"    // ropweaver::Elf64_Ehdr, Elf64_Shdr
#include <elf.h>
#include <fstream>
#include <iostream>
#include <cstring>
#include <algorithm> // for std::copy

using namespace ropweaver;

// Implementation of pure virtual functions

const std::vector<uint8_t>& AArch64Parser::getTextSection() const {
    return m_text_section;
}

uint64_t AArch64Parser::getTextSectionBaseAddress() const {
    return m_text_base_addr;
}

std::string AArch64Parser::getArchitecture() const {
    return m_architecture;
}

bool AArch64Parser::is64Bit() const {
    return true; // AArch64 is 64-bit
}

// Parse function with data extraction

bool AArch64Parser::parse(const std::string& filepath) {
    // 1. Load the file into memory
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    m_file_data.resize(size);

    if (!file.read(reinterpret_cast<char*>(m_file_data.data()), size)) return false;

    const auto* data = m_file_data.data();
    if (size < EI_NIDENT) return false;

    // 2. Verify ELF magic and 64-bit class
    if (data[EI_MAG0] != ELFMAG0 || data[EI_MAG1] != ELFMAG1 ||
        data[EI_MAG2] != ELFMAG2 || data[EI_MAG3] != ELFMAG3) {
        return false;
    }
    
    if (data[EI_CLASS] != ELFCLASS64) {
        std::cerr << "[!] Expected 64-bit AArch64 ELF file but detected 32-bit class." << std::endl;
        return false;
    }

    // 3. Get ELF headers (using custom ropweaver definitions)
    const ropweaver::Elf64_Ehdr* ehdr = reinterpret_cast<const ropweaver::Elf64_Ehdr*>(data);
    
    // Safety check for section header table bounds
    if (ehdr->e_shoff + (ehdr->e_shnum * ehdr->e_shentsize) > m_file_data.size()) {
        std::cerr << "[!] Section Header Table extends beyond end of file." << std::endl;
        return false;
    }

    const ropweaver::Elf64_Shdr* shdrs = reinterpret_cast<const ropweaver::Elf64_Shdr*>(data + ehdr->e_shoff);

    // 4. Iterate sections to find the executable (.text) section
    for (uint16_t i = 0; i < ehdr->e_shnum; ++i) {
        // Find executable program section (typically .text)
        if (shdrs[i].sh_type == SHT_PROGBITS && (shdrs[i].sh_flags & SHF_EXECINSTR)) {
            
            // Check if section data is within file bounds
            if (shdrs[i].sh_offset + shdrs[i].sh_size > m_file_data.size()) {
                 std::cerr << "[!] Executable section data extends beyond end of file." << std::endl;
                 continue;
            }
            
            // Extract the section data
            m_text_section.resize(shdrs[i].sh_size);
            std::copy(
                m_file_data.begin() + shdrs[i].sh_offset, 
                m_file_data.begin() + shdrs[i].sh_offset + shdrs[i].sh_size, 
                m_text_section.begin()
            );

            // Store the base address
            m_text_base_addr = shdrs[i].sh_addr;

            std::cout << "[*] AArch64 .text section found. Address: 0x" << std::hex << m_text_base_addr << std::endl;
            // Assuming the first executable section is the one we want.
            return true;
        }
    }
    
    std::cerr << "[!] Could not find an executable section in the AArch64 file." << std::endl;
    return false;
}