#include "arch_detector.h"

#include <elf.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <cstring>
#include <memory>
#include <algorithm>

#include "parsers/file_parser.h" 
#include "parsers/elf_parser.h"
#include "parsers/armv7_parser.h"
#include "parsers/aarch64_parser.h"
#include "parsers/riscv32_parser.h"
#include "parsers/riscv64_parser.h"
#include "parsers/pe_parser.h"
#include "parsers/macho_parser.h"
#include "parsers/elf_defs.h"
#include "parsers/pe_defs.h"
#include "parsers/macho_defs.h"

namespace ropweaver {

// Supported architectures
bool ArchDetector::isSupported(const std::string& arch) const {
    return arch == "x86" || arch == "x86_64" ||
           arch == "armv7" || arch == "aarch64" ||
           arch == "riscv32" || arch == "riscv64";
}

// DEFINITIONS (FIXED NAMESPACE SCOPING)

// 1. ELF 32-bit Architecture Detection
std::string ArchDetector::detectArchitecture32(std::ifstream& file) const {
    file.seekg(0, std::ios::beg);
    Elf32_Ehdr ehdr; 
    if (file.read(reinterpret_cast<char*>(&ehdr), sizeof(ehdr))) {
        switch (ehdr.e_machine) {
            case EM_386:
                return "x86";
            case EM_ARM:
                return "armv7"; 
            case EM_RISCV:
                return "riscv32";
            default:
                std::cerr << "[!] Unknown 32-bit ELF machine type: 0x" << std::hex << ehdr.e_machine << std::endl;
                return "unknown";
        }
    }
    return "unknown";
}

// 2. ELF 64-bit Architecture Detection
std::string ArchDetector::detectArchitecture64(std::ifstream& file) const {
    file.seekg(0, std::ios::beg);
    Elf64_Ehdr ehdr; 
    if (file.read(reinterpret_cast<char*>(&ehdr), sizeof(ehdr))) {
        switch (ehdr.e_machine) {
            case EM_X86_64:
                return "x86_64";
            case EM_AARCH64:
                return "aarch64";
            case EM_RISCV:
                return "riscv64";
            default:
                std::cerr << "[!] Unknown 64-bit ELF machine type: 0x" << std::hex << ehdr.e_machine << std::endl;
                return "unknown";
        }
    }
    return "unknown";
}

// 3. PE Architecture Detection
std::string ArchDetector::detectPEArchitecture(const std::vector<uint8_t>& data) const {
    // STRUCT uses ropweaver::
    if (data.size() < sizeof(ropweaver::PE_DOS_HEADER)) return "unknown";

    // STRUCT uses ropweaver::
    const ropweaver::PE_DOS_HEADER* dos_hdr = reinterpret_cast<const ropweaver::PE_DOS_HEADER*>(data.data());
    
    // Check for "PE\0\0" signature at the offset specified by e_lfanew
    if (dos_hdr->e_lfanew + 4 < data.size() && 
        data[dos_hdr->e_lfanew] == 'P' && data[dos_hdr->e_lfanew+1] == 'E') 
    {
        // STRUCT uses ropweaver::
        const ropweaver::PE_NT_HEADERS32* nt_hdr_32 = reinterpret_cast<const ropweaver::PE_NT_HEADERS32*>(data.data() + dos_hdr->e_lfanew);
        
        switch (nt_hdr_32->FileHeader.Machine) {
            // CONSTANTS use GLOBAL scope
            case IMAGE_FILE_MACHINE_I386:
                return "x86";
            case IMAGE_FILE_MACHINE_AMD64:
                return "x86_64";
            default:
                return "unknown";
        }
    }
    return "unknown";
}

// 4. Mach-O Architecture Detection
std::string ArchDetector::detectMachOArchitecture(const std::vector<uint8_t>& data) const {
    if (data.size() < 4) return "unknown";

    uint32_t magic;
    std::memcpy(&magic, data.data(), 4);

    // CONSTANTS use GLOBAL scope
    if (magic == MH_MAGIC || magic == MH_MAGIC_64) {
        // STRUCT uses ropweaver::
        const ropweaver::MachO_Header* header = reinterpret_cast<const ropweaver::MachO_Header*>(data.data());
        switch (header->cputype) {
            // CONSTANTS use GLOBAL scope
            case CPU_TYPE_X86: 
                return "x86";
            case CPU_TYPE_X86_64:
                return "x86_64";
            case CPU_TYPE_ARM64:
                return "aarch64";
            default:
                return "unknown";
        }
    } else if (magic == FAT_MAGIC || magic == FAT_MAGIC_64) {
        return "fat"; 
    }
    
    // Simplistic check for little-endian magic bytes (MH_CIGAM/MH_CIGAM_64)
    uint32_t reversed_magic = (magic >> 24) | ((magic >> 8) & 0x0000FF00) | ((magic << 8) & 0x00FF0000) | (magic << 24);
    
    if (reversed_magic == MH_MAGIC || reversed_magic == MH_MAGIC_64 || reversed_magic == FAT_MAGIC || reversed_magic == FAT_MAGIC_64) {
        return "x86_64"; 
    }

    return "unknown";
}

// Factory function
std::unique_ptr<FileParser> ArchDetector::createFileParser(const std::string& filepath) const {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[!] Could not open file: " << filepath << std::endl;
        return nullptr;
    }

    // Read bytes to check ELF class (EI_CLASS is at offset 4)
    std::vector<uint8_t> buffer(5, 0); 
    if (!file.read(reinterpret_cast<char*>(buffer.data()), buffer.size())) {
        std::cerr << "[!] File too small or read error: " << filepath << std::endl;
        return nullptr;
    }
    file.seekg(0, std::ios::beg); // Rewind file for parsers

    // ELF detection
    if (buffer[0] == ELFMAG0 && buffer[1] == ELFMAG1 &&
        buffer[2] == ELFMAG2 && buffer[3] == ELFMAG3) {

        // Use buffer[4] to check ELF class
        std::string arch = (buffer[4] == ELFCLASS32) ?
             detectArchitecture32(file) :
             detectArchitecture64(file);

        if (arch == "x86" || arch == "x86_64") return std::make_unique<ropweaver::ELFParser>(filepath);
        if (arch == "armv7") return std::make_unique<ropweaver::ARMv7Parser>(filepath);
        if (arch == "aarch64") return std::make_unique<ropweaver::AArch64Parser>(filepath);
        if (arch == "riscv32") return std::make_unique<ropweaver::RISCV32Parser>(filepath);
        if (arch == "riscv64") return std::make_unique<ropweaver::RISCV64Parser>(filepath);

        std::cerr << "[!] ELF file detected, but architecture " << arch << " not supported.\n";
        return nullptr;
    }

    // PE detection
    if (buffer[0] == 'M' && buffer[1] == 'Z') {
        // Read enough for full headers (512 bytes is usually enough for DOS+NT headers)
        std::vector<uint8_t> pe_buffer(512, 0);
        file.seekg(0, std::ios::beg);
        if (file.read(reinterpret_cast<char*>(pe_buffer.data()), pe_buffer.size())) {
            std::string arch = detectPEArchitecture(pe_buffer);
            if (arch != "unknown") return std::make_unique<ropweaver::PEParser>(filepath);
        }
    }

    // Mach-O detection
    if (buffer[0] == 0xca || buffer[0] == 0xfe) { // Check for common Mach-O magic starts
        // Read enough for Mach-O header/fat header
        std::vector<uint8_t> machoBuffer(1024, 0);
        file.seekg(0, std::ios::beg);
        if (file.read(reinterpret_cast<char*>(machoBuffer.data()), machoBuffer.size())) {
            std::string arch = detectMachOArchitecture(machoBuffer);
            if (arch == "x86" || arch == "x86_64" || arch == "fat") return std::make_unique<ropweaver::MachOParser>(filepath);
        }
    }

    std::cerr << "[x] Unsupported file format or unknown architecture: " << filepath << std::endl;
    return nullptr;
}

} // namespace ropweaver