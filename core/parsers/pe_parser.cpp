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
        case IMAGE_FILE_MACHINE_AMD64:
            arch_ = "x86_64";
            is64Bit_ = true;
            break;
        case IMAGE_FILE_MACHINE_I386:
            arch_ = "x86";
            is64Bit_ = false;
            break;
        case IMAGE_FILE_MACHINE_ARM:
            arch_ = "armv7";
            is64Bit_ = false;
            break;
        case IMAGE_FILE_MACHINE_ARM64:
            arch_ = "aarch64";
            is64Bit_ = true;
            break;
        default:
            arch_ = "unknown";
            is64Bit_ = false;
            break;
    }

    size_t optHdrOffset = ntHdrOffset + 4 + sizeof(PE_FILE_HEADER);
    uint64_t imageBase = 0x400000; // default fallback

    if (fileHdr->SizeOfOptionalHeader >= 2 && optHdrOffset + fileHdr->SizeOfOptionalHeader <= fileSize) {
        uint16_t optMagic = *reinterpret_cast<const uint16_t*>(&buffer[optHdrOffset]);
        if (optMagic == 0x020b) { // PE32+ (64-bit)
            is64Bit_ = true;
            if (fileHdr->SizeOfOptionalHeader >= 32) {
                imageBase = *reinterpret_cast<const uint64_t*>(&buffer[optHdrOffset + 24]);
            }
        } else if (optMagic == 0x010b) { // PE32 (32-bit)
            is64Bit_ = false;
            if (fileHdr->SizeOfOptionalHeader >= 32) {
                imageBase = *reinterpret_cast<const uint32_t*>(&buffer[optHdrOffset + 28]);
            }
        }

        // Parse DllCharacteristics (at offset 70 in both PE32 and PE32+ Optional Header)
        if (fileHdr->SizeOfOptionalHeader >= 72 && optHdrOffset + 72 <= fileSize) {
            uint16_t dllCharacteristics = *reinterpret_cast<const uint16_t*>(&buffer[optHdrOffset + 70]);
            nxEnabled_ = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
            pieEnabled_ = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
        }
    }

    size_t sectionHdrOffset = optHdrOffset + fileHdr->SizeOfOptionalHeader;
    size_t totalSectionHdrsSize = static_cast<size_t>(fileHdr->NumberOfSections) * sizeof(PE_SECTION_HEADER);
    if (sectionHdrOffset + totalSectionHdrsSize > fileSize) {
        std::cerr << "[!] PEParser: Section headers table out of file bounds.\n";
        return false;
    }

    const PE_SECTION_HEADER* sections = reinterpret_cast<const PE_SECTION_HEADER*>(&buffer[sectionHdrOffset]);
    const PE_SECTION_HEADER* targetSection = nullptr;

    // First search for .text section explicitly
    for (uint16_t i = 0; i < fileHdr->NumberOfSections; ++i) {
        char name[9] = {0};
        std::memcpy(name, sections[i].Name, 8);
        if (std::strcmp(name, ".text") == 0 || std::strncmp(name, ".text", 5) == 0) {
            targetSection = &sections[i];
            break;
        }
    }

    // Fallback: search for any section with executable characteristics
    if (!targetSection) {
        for (uint16_t i = 0; i < fileHdr->NumberOfSections; ++i) {
            if ((sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                (sections[i].Characteristics & IMAGE_SCN_CNT_CODE)) {
                targetSection = &sections[i];
                break;
            }
        }
    }

    if (!targetSection) {
        std::cerr << "[!] PEParser: No .text or executable section found.\n";
        return false;
    }

    size_t rawOffset = targetSection->PointerToRawData;
    size_t rawSize = targetSection->SizeOfRawData;
    if (targetSection->VirtualSize > 0 && targetSection->VirtualSize < rawSize) {
        rawSize = targetSection->VirtualSize;
    }

    if (rawOffset + rawSize > fileSize) {
        if (rawOffset < fileSize) {
            rawSize = fileSize - rawOffset;
        } else {
            std::cerr << "[!] PEParser: Section raw data pointer out of file bounds.\n";
            return false;
        }
    }

    textBaseAddr_ = imageBase + targetSection->VirtualAddress;
    textSection_.assign(buffer.begin() + rawOffset, buffer.begin() + rawOffset + rawSize);

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