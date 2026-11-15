#include "arch_detector.h"

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
        uint8_t data_encoding = ehdr.e_ident[EI_DATA];
        if (data_encoding != ELFDATA2LSB && data_encoding != ELFDATA2MSB) {
            std::cerr << "[!] Invalid or unsupported 32-bit ELF data encoding: " << static_cast<int>(data_encoding) << std::endl;
            return "unknown";
        }
        bool is_be = (data_encoding == ELFDATA2MSB);
        uint16_t machine = read_u16(reinterpret_cast<const uint8_t*>(&ehdr.e_machine), is_be);
        switch (machine) {
            case EM_386:
                return "x86";
            case EM_ARM:
                return "armv7"; 
            case EM_RISCV:
                return "riscv32";
            default:
                std::cerr << "[!] Unknown 32-bit ELF machine type: 0x" << std::hex << machine << std::endl;
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
        uint8_t data_encoding = ehdr.e_ident[EI_DATA];
        if (data_encoding != ELFDATA2LSB && data_encoding != ELFDATA2MSB) {
            std::cerr << "[!] Invalid or unsupported 64-bit ELF data encoding: " << static_cast<int>(data_encoding) << std::endl;
            return "unknown";
        }
        bool is_be = (data_encoding == ELFDATA2MSB);
        uint16_t machine = read_u16(reinterpret_cast<const uint8_t*>(&ehdr.e_machine), is_be);
        switch (machine) {
            case EM_X86_64:
                return "x86_64";
            case EM_AARCH64:
                return "aarch64";
            case EM_RISCV:
                return "riscv64";
            default:
                std::cerr << "[!] Unknown 64-bit ELF machine type: 0x" << std::hex << machine << std::endl;
                return "unknown";
        }
    }
    return "unknown";
}

// 3. PE Architecture Detection
std::string ArchDetector::detectPEArchitecture(const std::vector<uint8_t>& data) const {
    if (data.size() < sizeof(ropweaver::PE_DOS_HEADER)) return "unknown";

    const ropweaver::PE_DOS_HEADER* dos_hdr = reinterpret_cast<const ropweaver::PE_DOS_HEADER*>(data.data());
    if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) return "unknown";

    if (dos_hdr->e_lfanew <= 0 || static_cast<size_t>(dos_hdr->e_lfanew) + sizeof(ropweaver::PE_NT_HEADERS32) > data.size()) {
        return "unknown";
    }

    size_t nt_offset = static_cast<size_t>(dos_hdr->e_lfanew);
    const ropweaver::PE_NT_HEADERS32* nt_hdr_32 = reinterpret_cast<const ropweaver::PE_NT_HEADERS32*>(data.data() + nt_offset);
    if (nt_hdr_32->Signature != IMAGE_NT_SIGNATURE) return "unknown";

    switch (nt_hdr_32->FileHeader.Machine) {
        case IMAGE_FILE_MACHINE_I386:   return "x86";
        case IMAGE_FILE_MACHINE_AMD64:  return "x86_64";
        case IMAGE_FILE_MACHINE_ARM:    return "armv7";
        case IMAGE_FILE_MACHINE_ARM64:  return "aarch64";
        default:                        return "unknown";
    }
}

// 4. Mach-O Architecture Detection
std::string ArchDetector::detectMachOArchitecture(const std::vector<uint8_t>& data) const {
    if (data.size() < 4) return "unknown";

    MachOFormat fmt = detectMachOFormat(data.data());
    if (fmt == MachOFormat::Invalid) return "unknown";

    if (isFatMachO(fmt)) {
        return "fat";
    }

    // Thin Mach-O: need at least 8 bytes to decode cputype at offset 4
    if (data.size() < 8) return "unknown";

    bool is_be = isMachOBigEndian(fmt);
    bool is_64 = isMachO64(fmt);
    int32_t cputype = read_i32(data.data() + 4, is_be);

    if (is_64) {
        switch (cputype) {
            case CPU_TYPE_X86_64:
                return "x86_64";
            case CPU_TYPE_ARM64:
                return "aarch64";
            default:
                return "unknown";
        }
    } else {
        switch (cputype) {
            case CPU_TYPE_X86:
                return "x86";
            case CPU_TYPE_ARM:
                return "armv7";
            default:
                return "unknown";
        }
    }
}

// Factory function
std::unique_ptr<FileParser> ArchDetector::createFileParser(const std::string& filepath, const std::string& targetArch) const {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[!] Could not open file: " << filepath << std::endl;
        return nullptr;
    }

    // Read ELF identification bytes (EI_NIDENT = 16)
    std::vector<uint8_t> buffer(EI_NIDENT, 0); 
    if (!file.read(reinterpret_cast<char*>(buffer.data()), buffer.size())) {
        std::cerr << "[!] File too small or read error: " << filepath << std::endl;
        return nullptr;
    }
    file.seekg(0, std::ios::beg); // Rewind file for parsers

    // ELF detection
    if (buffer[EI_MAG0] == ELFMAG0 && buffer[EI_MAG1] == ELFMAG1 &&
        buffer[EI_MAG2] == ELFMAG2 && buffer[EI_MAG3] == ELFMAG3) {

        uint8_t elf_class = buffer[EI_CLASS];
        uint8_t elf_data = buffer[EI_DATA];

        if (elf_class != ELFCLASS32 && elf_class != ELFCLASS64) {
            std::cerr << "[!] ELF file has invalid class: " << static_cast<int>(elf_class) << "\n";
            return nullptr;
        }

        if (elf_data != ELFDATA2LSB && elf_data != ELFDATA2MSB) {
            std::cerr << "[!] ELF file has invalid or unsupported data encoding: " << static_cast<int>(elf_data) << "\n";
            return nullptr;
        }

        std::string arch = (elf_class == ELFCLASS32) ?
             detectArchitecture32(file) :
             detectArchitecture64(file);

        // All supported ELF architectures are unified under ropweaver::ELFParser
        if (arch == "x86" || arch == "x86_64" ||
            arch == "armv7" || arch == "aarch64" ||
            arch == "riscv32" || arch == "riscv64") {
            return std::make_unique<ropweaver::ELFParser>(filepath);
        }

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
    MachOFormat macho_fmt = detectMachOFormat(buffer.data());
    if (macho_fmt != MachOFormat::Invalid) {
        // Read enough for Mach-O header/fat header
        std::vector<uint8_t> machoBuffer(1024, 0);
        file.seekg(0, std::ios::beg);
        file.read(reinterpret_cast<char*>(machoBuffer.data()), machoBuffer.size());
        std::streamsize bytes_read = file.gcount();
        if (bytes_read >= 4) {
            machoBuffer.resize(static_cast<size_t>(bytes_read));
            std::string arch = detectMachOArchitecture(machoBuffer);
            if (arch == "x86" || arch == "x86_64" || arch == "armv7" || arch == "aarch64" || arch == "fat") {
                return std::make_unique<ropweaver::MachOParser>(filepath, targetArch);
            }
        }
    }

    std::cerr << "[x] Unsupported file format or unknown architecture: " << filepath << std::endl;
    return nullptr;
}

} // namespace ropweaver