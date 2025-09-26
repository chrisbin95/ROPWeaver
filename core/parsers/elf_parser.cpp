#include "elf_parser.h"
#include <elf.h>
#include <fstream>
#include <iostream>
#include <cstring>

using namespace ropweaver;

// Helper to determine architecture from e_machine field
static std::string getElfMachineArchitecture(uint16_t e_machine) {
    switch (e_machine) {
        case EM_386: return "x86";
        case EM_X86_64: return "x86_64";
        case EM_ARM: return "armv7";
        case EM_AARCH64: return "aarch64";
        case EM_RISCV: return "riscv";
        default: return "unknown";
    }
}

// Helper to find and extract the .text section
template <typename Elf_Ehdr, typename Elf_Shdr>
bool extract_text_section(const uint8_t* data, size_t size, const Elf_Ehdr& ehdr, 
                          std::vector<uint8_t>& out_text, uint64_t& out_base_addr) 
{
    // Section Header Table offset and entry size
    size_t sh_off = ehdr.e_shoff;
    uint16_t sh_num = ehdr.e_shnum;
    uint16_t sh_entsize = ehdr.e_shentsize;

    if (sh_off == 0 || sh_num == 0 || sh_entsize != sizeof(Elf_Shdr)) {
        std::cerr << "[!] Invalid or missing section header table.\n";
        return false;
    }
    
    // Check bounds for Section Header Table
    size_t sh_table_size = static_cast<size_t>(sh_num) * sh_entsize;
    if (sh_off + sh_table_size > size) {
        std::cerr << "[!] Section Header Table out of file bounds.\n";
        return false;
    }

    const Elf_Shdr* shdr_table = reinterpret_cast<const Elf_Shdr*>(data + sh_off);
    
    // Get Section Header String Table
    if (ehdr.e_shstrndx == SHN_UNDEF || ehdr.e_shstrndx >= sh_num) {
         std::cerr << "[!] Invalid section header string table index.\n";
         return false;
    }
    const Elf_Shdr& shstr_hdr = shdr_table[ehdr.e_shstrndx];
    const char* shstr_table = reinterpret_cast<const char*>(data + shstr_hdr.sh_offset);

    for (uint16_t i = 0; i < sh_num; ++i) {
        const Elf_Shdr& shdr = shdr_table[i];
        const char* sh_name = shstr_table + shdr.sh_name;

        if (std::strcmp(sh_name, ".text") == 0) {
            // Found .text section
            size_t raw_size = shdr.sh_size;
            size_t raw_offset = shdr.sh_offset;

            if (raw_offset + raw_size > size) {
                std::cerr << "[!] .text section raw data out of file bounds.\n";
                return false;
            }
            
            // Copy raw bytes
            out_text.resize(raw_size);
            std::memcpy(out_text.data(), data + raw_offset, raw_size);
            out_base_addr = shdr.sh_addr;
            return true;
        }
    }
    
    std::cerr << "[!] .text section not found in ELF file.\n";
    return false;
}

// ELFParser Implementation

bool ELFParser::parse(const std::string& filepath) {
    // Standard file reading logic
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "[!] Could not open file: " << filepath << std::endl;
        return false;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    m_file_data.resize(size);

    if (!file.read(reinterpret_cast<char*>(m_file_data.data()), size)) {
        std::cerr << "[!] Read error in file: " << filepath << std::endl;
        return false;
    }

    const auto* data = m_file_data.data();
    if (size < EI_NIDENT) return false;

    // ELF Magic Check
    if (data[EI_MAG0] != ELFMAG0 || data[EI_MAG1] != ELFMAG1 ||
        data[EI_MAG2] != ELFMAG2 || data[EI_MAG3] != ELFMAG3) {
        std::cerr << "[!] Not a valid ELF file: " << filepath << std::endl;
        return false;
    }

    // Determine 32-bit or 64-bit
    if (data[EI_CLASS] == ELFCLASS32) {
        if (size < sizeof(Elf32_Ehdr)) return false;
        hdr32 = *reinterpret_cast<const Elf32_Ehdr*>(data);
        m_arch = getElfMachineArchitecture(hdr32.e_machine);
        
        // Extract .text section using 32-bit types
        if (!extract_text_section<Elf32_Ehdr, Elf32_Shdr>(data, size, hdr32, 
                                                         m_text_section, m_text_section_base_address)) {
             return false;
        }
    } else if (data[EI_CLASS] == ELFCLASS64) {
        if (size < sizeof(Elf64_Ehdr)) return false;
        hdr64 = *reinterpret_cast<const Elf64_Ehdr*>(data);
        m_arch = getElfMachineArchitecture(hdr64.e_machine);
        
        // Extract .text section using 64-bit types
        if (!extract_text_section<Elf64_Ehdr, Elf64_Shdr>(data, size, hdr64, 
                                                         m_text_section, m_text_section_base_address)) {
             return false;
        }
    } else {
        std::cerr << "[!] Unknown ELF class: " << int(data[EI_CLASS]) << std::endl;
        return false;
    }

    // Handling RISC-V since EM_RISCV is common for both 32/64 bit
    if (m_arch == "riscv" && data[EI_CLASS] == ELFCLASS32) {
        m_arch = "riscv32";
    } else if (m_arch == "riscv" && data[EI_CLASS] == ELFCLASS64) {
        m_arch = "riscv64";
    }

    return true;
}

// --- Implementation of pure virtual getters ---

const std::vector<uint8_t>& ELFParser::getTextSection() const {
    return m_text_section;
}

uint64_t ELFParser::getTextSectionBaseAddress() const {
    return m_text_section_base_address;
}

std::string ELFParser::getArchitecture() const {
    return m_arch;
}

bool ELFParser::is64Bit() const {
    // Determine from the stored header, falling back to file data if necessary
    if (hdr64.e_ident[EI_CLASS] == ELFCLASS64) return true;
    if (hdr32.e_ident[EI_CLASS] == ELFCLASS32) return false;
    
    // Fallback on m_file_data if headers haven't been fully populated (shouldn't happen post-parse)
    if (!m_file_data.empty() && m_file_data[EI_CLASS] == ELFCLASS64) return true;
    return false; // Default to 32-bit if no valid class is found
}