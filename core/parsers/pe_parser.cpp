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
    mitigations_.no_seh = (fileHdr->Characteristics & IMAGE_FILE_NO_SEH) != 0;

    size_t optHdrOffset = ntHdrOffset + 4 + sizeof(PE_FILE_HEADER);
    imageBase_ = 0x400000; // safe default

    uint32_t loadConfigRva = 0;
    uint32_t loadConfigSize = 0;

    if (fileHdr->SizeOfOptionalHeader >= 2 && optHdrOffset + fileHdr->SizeOfOptionalHeader <= fileSize) {
        uint16_t optMagic = *reinterpret_cast<const uint16_t*>(&buffer[optHdrOffset]);
        size_t dllCharOffset = 0;
        size_t dataDirOffset = 0;

        if (optMagic == 0x020b) { // PE32+ (64-bit)
            is64Bit_ = true;
            if (fileHdr->SizeOfOptionalHeader >= 32 && optHdrOffset + 32 <= fileSize) {
                imageBase_ = *reinterpret_cast<const uint64_t*>(&buffer[optHdrOffset + 24]);
            }
            if (fileHdr->SizeOfOptionalHeader >= 20 && optHdrOffset + 20 <= fileSize) {
                entryPoint_ = imageBase_ + *reinterpret_cast<const uint32_t*>(&buffer[optHdrOffset + 16]);
            }
            dllCharOffset = optHdrOffset + 70;
            dataDirOffset = optHdrOffset + 112;

        } else if (optMagic == 0x010b) { // PE32 (32-bit)
            is64Bit_ = false;
            if (fileHdr->SizeOfOptionalHeader >= 32 && optHdrOffset + 32 <= fileSize) {
                imageBase_ = *reinterpret_cast<const uint32_t*>(&buffer[optHdrOffset + 28]);
            }
            if (fileHdr->SizeOfOptionalHeader >= 20 && optHdrOffset + 20 <= fileSize) {
                entryPoint_ = imageBase_ + *reinterpret_cast<const uint32_t*>(&buffer[optHdrOffset + 16]);
            }
            dllCharOffset = optHdrOffset + 94;
            dataDirOffset = optHdrOffset + 96;
        }

        // Parse DllCharacteristics with correct architecture-specific offset
        if (dllCharOffset > 0 && dllCharOffset + 2 <= fileSize) {
            uint16_t dllChar = *reinterpret_cast<const uint16_t*>(&buffer[dllCharOffset]);
            mitigations_.nx_compat       = (dllChar & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)       != 0;
            mitigations_.dynamic_base    = (dllChar & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)    != 0;
            mitigations_.high_entropy_va = (dllChar & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)  != 0;
            mitigations_.guard_cf        = (dllChar & IMAGE_DLLCHARACTERISTICS_GUARD_CF)        != 0;
        }

        // Parse Load Config Data Directory entry (index 10)
        size_t loadConfigDirEntry = dataDirOffset + (IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG * 8);
        if (loadConfigDirEntry + 8 <= optHdrOffset + fileHdr->SizeOfOptionalHeader && loadConfigDirEntry + 8 <= fileSize) {
            loadConfigRva  = *reinterpret_cast<const uint32_t*>(&buffer[loadConfigDirEntry]);
            loadConfigSize = *reinterpret_cast<const uint32_t*>(&buffer[loadConfigDirEntry + 4]);
        }
    }

    // Parse all Section Headers
    size_t sectionHdrOffset = optHdrOffset + fileHdr->SizeOfOptionalHeader;
    size_t totalSectionHdrsSize = static_cast<size_t>(fileHdr->NumberOfSections) * sizeof(PE_SECTION_HEADER);
    if (sectionHdrOffset + totalSectionHdrsSize > fileSize) {
        std::cerr << "[!] PEParser: Section headers table out of file bounds.\n";
        return false;
    }

    const PE_SECTION_HEADER* peSections = reinterpret_cast<const PE_SECTION_HEADER*>(&buffer[sectionHdrOffset]);
    sections_.clear();

    struct ExecSection {
        uint64_t va;
        size_t   rawOffset;
        size_t   rawSize;
        std::string name;
    };
    std::vector<ExecSection> execSections;

    for (uint16_t i = 0; i < fileHdr->NumberOfSections; ++i) {
        char name[9] = {0};
        std::memcpy(name, peSections[i].Name, 8);

        SectionInfo secInfo;
        secInfo.name = name;
        secInfo.virtual_address = imageBase_ + peSections[i].VirtualAddress;
        secInfo.virtual_size = peSections[i].VirtualSize;
        secInfo.raw_offset = peSections[i].PointerToRawData;
        secInfo.raw_size = peSections[i].SizeOfRawData;
        secInfo.characteristics = peSections[i].Characteristics;
        secInfo.is_executable = (peSections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                                (peSections[i].Characteristics & IMAGE_SCN_CNT_CODE);
        sections_.push_back(secInfo);

        if (!secInfo.is_executable) continue;

        size_t rawOffset = peSections[i].PointerToRawData;
        size_t rawSize   = peSections[i].SizeOfRawData;
        if (peSections[i].VirtualSize > 0 && peSections[i].VirtualSize < rawSize) {
            rawSize = peSections[i].VirtualSize;
        }
        if (rawOffset >= fileSize) continue;
        if (rawOffset + rawSize > fileSize) {
            rawSize = fileSize - rawOffset;
        }
        if (rawSize == 0) continue;

        execSections.push_back({ imageBase_ + peSections[i].VirtualAddress, rawOffset, rawSize, name });
    }

    // Inspect Load Config Directory if present
    if (loadConfigRva != 0 && loadConfigSize >= 64) {
        mitigations_.has_load_config = true;
        mitigations_.load_config_size = loadConfigSize;

        // Resolve loadConfigRva to file offset
        uint64_t loadConfigPreferredVa = imageBase_ + loadConfigRva;
        uint64_t lcFileOff = 0, lcRva = 0;
        if (vaToOffsets(loadConfigPreferredVa, lcFileOff, lcRva) && lcFileOff + 64 <= fileSize) {
            if (is64Bit_) {
                // In IMAGE_LOAD_CONFIG_DIRECTORY64:
                // SecurityCookie is at offset 88 (uint64_t)
                if (loadConfigSize >= 96 && lcFileOff + 96 <= fileSize) {
                    mitigations_.security_cookie_va = *reinterpret_cast<const uint64_t*>(&buffer[lcFileOff + 88]);
                }
                // GuardFlags is at offset 112 (uint32_t)
                if (loadConfigSize >= 116 && lcFileOff + 116 <= fileSize) {
                    mitigations_.guard_flags = *reinterpret_cast<const uint32_t*>(&buffer[lcFileOff + 112]);
                    mitigations_.cf_instrumented  = (mitigations_.guard_flags & IMAGE_GUARD_CF_INSTRUMENTED) != 0;
                    mitigations_.cf_table_present = (mitigations_.guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT) != 0;
                    mitigations_.cet_compat       = (mitigations_.guard_flags & IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT) != 0;
                    mitigations_.cet_unknown      = false;
                }
            } else {
                // In IMAGE_LOAD_CONFIG_DIRECTORY32:
                // SecurityCookie is at offset 60 (uint32_t)
                if (loadConfigSize >= 64 && lcFileOff + 64 <= fileSize) {
                    mitigations_.security_cookie_va = *reinterpret_cast<const uint32_t*>(&buffer[lcFileOff + 60]);
                }
                // GuardFlags is at offset 84 (uint32_t)
                if (loadConfigSize >= 88 && lcFileOff + 88 <= fileSize) {
                    mitigations_.guard_flags = *reinterpret_cast<const uint32_t*>(&buffer[lcFileOff + 84]);
                    mitigations_.cf_instrumented  = (mitigations_.guard_flags & IMAGE_GUARD_CF_INSTRUMENTED) != 0;
                    mitigations_.cf_table_present = (mitigations_.guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT) != 0;
                    mitigations_.cet_compat       = (mitigations_.guard_flags & IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT) != 0;
                    mitigations_.cet_unknown      = false;
                }
            }
        }
    } else {
        mitigations_.has_load_config = false;
        mitigations_.cet_unknown = true; // Evidence insufficient because Load Config is absent
    }

    // Determine GS Cookie status
    if (mitigations_.has_load_config && mitigations_.security_cookie_va != 0) {
        mitigations_.gs_status = "CONFIRMED (Load Config SecurityCookie registered)";
    } else if (checkCanaryProtection(buffer)) {
        mitigations_.gs_status = "HEURISTIC_PRESENT (Symbolic check in imports/strings)";
    } else {
        mitigations_.gs_status = "NOT_DETECTED";
    }

    // Determine SafeSEH status
    if (is64Bit_) {
        mitigations_.safeseh_status = "NOT_APPLICABLE (x86_64 uses .pdata/.xdata table unwinding)";
    } else if (mitigations_.no_seh) {
        mitigations_.safeseh_status = "NO_SEH (Image specifies no SEH)";
    } else if (mitigations_.has_load_config) {
        mitigations_.safeseh_status = "DISABLED (No registered SafeSEH handlers in Load Config)";
    } else {
        mitigations_.safeseh_status = "UNKNOWN (Load Config table absent)";
    }

    if (execSections.empty()) {
        std::cerr << "[!] PEParser: No executable sections found.\n";
        return false;
    }

    // Sort executable sections by VA
    std::sort(execSections.begin(), execSections.end(),
              [](const ExecSection& a, const ExecSection& b){ return a.va < b.va; });

    textBaseAddr_ = execSections[0].va;

    textSection_.clear();
    uint64_t prevEnd = textBaseAddr_;
    for (const auto& sec : execSections) {
        if (sec.va > prevEnd) {
            size_t gap = static_cast<size_t>(sec.va - prevEnd);
            if (gap <= 0x10000) {
                textSection_.insert(textSection_.end(), gap, 0xCC);
            } else {
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
