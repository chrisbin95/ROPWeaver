#pragma once
#include "file_parser.h"
#include <string>
#include <vector>
#include <cstdint>

namespace ropweaver { 

struct PEMitigations {
    // Static header compatibility flags
    bool nx_compat = false;            // IMAGE_DLLCHARACTERISTICS_NX_COMPAT (0x0100)
    bool dynamic_base = false;         // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040)
    bool high_entropy_va = false;      // IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA (0x0020)
    bool guard_cf = false;             // IMAGE_DLLCHARACTERISTICS_GUARD_CF (0x4000)
    bool no_seh = false;               // IMAGE_FILE_NO_SEH (0x0400) in FileHeader.Characteristics
    
    // Load Config indicators
    bool has_load_config = false;
    uint32_t load_config_size = 0;
    uint64_t security_cookie_va = 0;   // Address of security cookie from Load Config
    uint32_t guard_flags = 0;          // GuardFlags from Load Config
    bool cf_instrumented = false;      // IMAGE_GUARD_CF_INSTRUMENTED (0x00000100)
    bool cf_table_present = false;     // IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT (0x00000400)
    bool cet_compat = false;           // IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT or CET flag
    bool cet_unknown = true;           // True if evidence is insufficient (e.g. no Load Config)
    
    // GS Cookie detection
    std::string gs_status = "NOT_DETECTED"; // "CONFIRMED (Load Config)", "HEURISTIC_PRESENT", "NOT_DETECTED"
    
    // SafeSEH status
    std::string safeseh_status = "NOT_APPLICABLE"; // "NOT_APPLICABLE (x64)", "ENABLED", "DISABLED", "NO_SEH"
};

class PEParser : public FileParser {
public:
    explicit PEParser(const std::string& filepath);

    bool parse(const std::string& filepath) override;
    const std::vector<uint8_t>& getTextSection() const override;
    uint64_t getTextSectionBaseAddress() const override;
    std::string getArchitecture() const override;

    bool is64Bit() const override;
    std::string getBinaryType() const override { return "PE"; }
    std::string getFilePath() const override { return m_filepath; } 

    // Legacy FileParser interface
    bool isNxEnabled() const override { return mitigations_.nx_compat; }
    bool isPieEnabled() const override { return mitigations_.dynamic_base; }
    bool isCanaryEnabled() const override { return mitigations_.gs_status != "NOT_DETECTED"; }
    std::string getRelro() const override { return "N/A"; } // Never applicable to PE

    // Extended PE Mitigations & Characteristics
    const PEMitigations& getPEMitigations() const { return mitigations_; }
    bool isHighEntropyVAEnabled() const { return mitigations_.high_entropy_va; }
    bool isCFGEnabled() const { return mitigations_.guard_cf; }
    bool isSafeSEHDisabled() const { return mitigations_.no_seh; }

    // Section and Address Resolution
    uint64_t getImageBase() const override { return imageBase_; }
    uint64_t getEntryPoint() const override { return entryPoint_; }
    const std::vector<SectionInfo>& getSections() const override { return sections_; }

private:
    bool checkCanaryProtection(const std::vector<uint8_t>& buffer);

    std::vector<uint8_t> textSection_;
    uint64_t textBaseAddr_ = 0;
    bool is64Bit_ = false;
    std::string arch_ = "unknown";

    uint64_t imageBase_   = 0x400000;
    uint64_t entryPoint_  = 0;

    PEMitigations mitigations_;
    std::vector<SectionInfo> sections_;
};

} // namespace ropweaver
