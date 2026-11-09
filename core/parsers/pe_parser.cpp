#include "pe_parser.h"
#include "pe_defs.h"
#include <fstream>
#include <iostream>
#include <cstring>
#include <algorithm>

using namespace ropweaver;

PEParser::PEParser(const std::string& filepath) : FileParser(filepath) {}

bool PEParser::parse(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[!] PEParser: Could not open file: " << filepath << std::endl;
        return false;
    }

    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    if (fileSize < sizeof(PE_DOS_HEADER)) {
        std::cerr << "[!] PEParser: File too small for PE DOS header.\n";
        return false;
    }

    std::vector<uint8_t> buffer(fileSize);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), fileSize)) {
        std::cerr << "[!] PEParser: Failed to read file data.\n";
        return false;
    }

    const PE_DOS_HEADER* dosHdr = reinterpret_cast<const PE_DOS_HEADER*>(buffer.data());
    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "[!] PEParser: Invalid DOS signature (expected MZ).\n";
        return false;
    }

    if (dosHdr->e_lfanew <= 0 || static_cast<size_t>(dosHdr->e_lfanew) + 4 + sizeof(PE_FILE_HEADER) > fileSize) {
        std::cerr << "[!] PEParser: e_lfanew out of file bounds.\n";
        return false;
    }

    size_t ntHdrOffset = static_cast<size_t>(dosHdr->e_lfanew);
    uint32_t signature = *reinterpret_cast<const uint32_t*>(&buffer[ntHdrOffset]);
    if (signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "[!] PEParser: Invalid NT signature (expected PE\\0\\0).\n";
        return false;
    }

    const PE_FILE_HEADER* fileHdr = reinterpret_cast<const PE_FILE_HEADER*>(&buffer[ntHdrOffset + 4]);
    switch (fileHdr->Machine) {
        case IMAGE_FILE_MACHINE_AMD64: arch_ = "x86_64"; is64Bit_ = true;  break;
        case IMAGE_FILE_MACHINE_I386:  arch_ = "x86";    is64Bit_ = false; break;
        case IMAGE_FILE_MACHINE_ARM:   arch_ = "armv7";  is64Bit_ = false; break;
        case IMAGE_FILE_MACHINE_ARM64: arch_ = "aarch64";is64Bit_ = true;  break;
        default:                       arch_ = "unknown"; is64Bit_ = false; break;
    }

    // IMAGE_FILE_NO_SEH: file header Characteristics bit 0x0400
    noSEH_ = (fileHdr->Characteristics & IMAGE_FILE_NO_SEH) != 0;

    size_t optHdrOffset = ntHdrOffset + 4 + sizeof(PE_FILE_HEADER);
    imageBase_ = 0x400000; // safe default

    if (fileHdr->SizeOfOptionalHeader >= 2 && optHdrOffset + fileHdr->SizeOfOptionalHeader <= fileSize) {
        uint16_t optMagic = *reinterpret_cast<const uint16_t*>(&buffer[optHdrOffset]);

        // ----------------------------------------------------------------
        // Optional Header field offsets (from start of optional header):
        //
        //  Field                  PE32 (0x010b)   PE32+ (0x020b)
        //  Magic                   0               0
        //  AddressOfEntryPoint     16              16
        //  ImageBase               28 (uint32)     24 (uint64)
        //  DllCharacteristics      94              70
        // ----------------------------------------------------------------
        size_t dllCharOffset = 0;

        if (optMagic == 0x020b) { // PE32+ (64-bit)
            is64Bit_ = true;
            // ImageBase at offset 24 (uint64)
            if (fileHdr->SizeOfOptionalHeader >= 32 && optHdrOffset + 32 <= fileSize) {
                imageBase_ = *reinterpret_cast<const uint64_t*>(&buffer[optHdrOffset + 24]);
            }
            // AddressOfEntryPoint at offset 16 (uint32 RVA)
            if (fileHdr->SizeOfOptionalHeader >= 20 && optHdrOffset + 20 <= fileSize) {
                uint32_t epRVA = *reinterpret_cast<const uint32_t*>(&buffer[optHdrOffset + 16]);
                entryPoint_ = imageBase_ + epRVA;
            }
            // DllCharacteristics at offset 70 for PE32+
            dllCharOffset = optHdrOffset + 70;

        } else if (optMagic == 0x010b) { // PE32 (32-bit)
            is64Bit_ = false;
            // ImageBase at offset 28 (uint32)
            if (fileHdr->SizeOfOptionalHeader >= 32 && optHdrOffset + 32 <= fileSize) {
                imageBase_ = *reinterpret_cast<const uint32_t*>(&buffer[optHdrOffset + 28]);
            }
            // AddressOfEntryPoint at offset 16 (uint32 RVA)
            if (fileHdr->SizeOfOptionalHeader >= 20 && optHdrOffset + 20 <= fileSize) {
                uint32_t epRVA = *reinterpret_cast<const uint32_t*>(&buffer[optHdrOffset + 16]);
                entryPoint_ = imageBase_ + epRVA;
            }
            // DllCharacteristics at offset 94 for PE32
            dllCharOffset = optHdrOffset + 94;
        }

        // Parse DllCharacteristics with correct architecture-specific offset
        if (dllCharOffset > 0 && dllCharOffset + 2 <= fileSize) {
            uint16_t dllChar = *reinterpret_cast<const uint16_t*>(&buffer[dllCharOffset]);
            nxEnabled_      = (dllChar & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)      != 0;
            pieEnabled_     = (dllChar & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)   != 0;
            highEntropyVA_  = (dllChar & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0;
            cfgEnabled_     = (dllChar & IMAGE_DLLCHARACTERISTICS_GUARD_CF)       != 0;
        }
    }

    // ----------------------------------------------------------------
    // Section parsing: collect ALL executable sections.
    // Primary text section = first .text or first executable section.
    // Concatenate all executable sections into textSection_ for gadget
    // discovery (preserving contiguous VA ordering).
    // ----------------------------------------------------------------
    size_t sectionHdrOffset = optHdrOffset + fileHdr->SizeOfOptionalHeader;
    size_t totalSectionHdrsSize = static_cast<size_t>(fileHdr->NumberOfSections) * sizeof(PE_SECTION_HEADER);
    if (sectionHdrOffset + totalSectionHdrsSize > fileSize) {
        std::cerr << "[!] PEParser: Section headers table out of file bounds.\n";
        return false;
    }

    const PE_SECTION_HEADER* sections = reinterpret_cast<const PE_SECTION_HEADER*>(&buffer[sectionHdrOffset]);

    // Collect executable sections in VA order
    struct ExecSection {
        uint64_t va;
        size_t   rawOffset;
        size_t   rawSize;
        std::string name;
    };
    std::vector<ExecSection> execSections;

    for (uint16_t i = 0; i < fileHdr->NumberOfSections; ++i) {
        char name[9] = {0};
        std::memcpy(name, sections[i].Name, 8);

        bool isExec = (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                      (sections[i].Characteristics & IMAGE_SCN_CNT_CODE);
        if (!isExec) continue;

        size_t rawOffset = sections[i].PointerToRawData;
        size_t rawSize   = sections[i].SizeOfRawData;
        if (sections[i].VirtualSize > 0 && sections[i].VirtualSize < rawSize) {
            rawSize = sections[i].VirtualSize;
        }
        if (rawOffset >= fileSize) continue;
        if (rawOffset + rawSize > fileSize) {
            rawSize = fileSize - rawOffset;
        }
        if (rawSize == 0) continue;

        execSections.push_back({ imageBase_ + sections[i].VirtualAddress, rawOffset, rawSize, name });
    }

    if (execSections.empty()) {
        std::cerr << "[!] PEParser: No executable sections found.\n";
        return false;
    }

    // Sort by VA to process in address order
    std::sort(execSections.begin(), execSections.end(),
              [](const ExecSection& a, const ExecSection& b){ return a.va < b.va; });

    // Use the first executable section as the base address for GadgetFinder
    textBaseAddr_ = execSections[0].va;

    // Concatenate all executable section bytes into one flat buffer.
    // GadgetFinder will see one contiguous byte stream; gadget addresses
    // remain correct because m_baseAddress is set to textBaseAddr_ and
    // Capstone uses that as the starting address.
    // Note: gaps between non-contiguous sections are filled with 0xCC (int3)
    // so the disassembler stops cleanly at section boundaries.
    textSection_.clear();
    uint64_t prevEnd = textBaseAddr_;
    for (const auto& sec : execSections) {
        if (sec.va > prevEnd) {
            // Fill gap with INT3 (0xCC) to prevent cross-section gadgets
            size_t gap = static_cast<size_t>(sec.va - prevEnd);
            // Limit gap fill to avoid huge allocations for sparse maps
            if (gap <= 0x10000) {
                textSection_.insert(textSection_.end(), gap, 0xCC);
            } else {
                // Large gap: use a minimal 4-byte fence
                textSection_.push_back(0xCC);
                textSection_.push_back(0xCC);
                textSection_.push_back(0xCC);
                textSection_.push_back(0xCC);
            }
        }
        const uint8_t* ptr = buffer.data() + sec.rawOffset;
        textSection_.insert(textSection_.end(), ptr, ptr + sec.rawSize);
        prevEnd = sec.va + sec.rawSize;
    }

    // Check imports/symbols for __security_cookie or __security_check_cookie
    canaryEnabled_ = checkCanaryProtection(buffer);

    return !textSection_.empty();
}

bool PEParser::checkCanaryProtection(const std::vector<uint8_t>& buffer) {
    const std::vector<std::string> canarySymbols = {
        "__security_cookie",
        "__security_check_cookie",
        "@__security_check_cookie",
        "__stack_chk_fail",
        "__stack_chk_guard"
    };

    for (const auto& sym : canarySymbols) {
        auto it = std::search(buffer.begin(), buffer.end(), sym.begin(), sym.end());
        if (it != buffer.end()) {
            return true;
        }
    }
    return false;
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