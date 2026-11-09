#pragma once
#include "file_parser.h"
#include <string>
#include <vector>
#include <cstdint>

namespace ropweaver { 

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

    // Security mitigations
    bool isNxEnabled() const override { return nxEnabled_; }
    bool isPieEnabled() const override { return pieEnabled_; }
    bool isCanaryEnabled() const override { return canaryEnabled_; }
    // RELRO is an ELF concept; never apply to PE files
    std::string getRelro() const override { return "N/A"; }

    // Additional PE-specific mitigations
    bool isHighEntropyVAEnabled() const { return highEntropyVA_; }
    bool isCFGEnabled() const { return cfgEnabled_; }
    bool isSafeSEHDisabled() const { return noSEH_; } // true = IMAGE_FILE_NO_SEH set

    // Address information
    uint64_t getImageBase() const { return imageBase_; }
    uint64_t getEntryPoint() const { return entryPoint_; }   // Preferred VA of entry point

private:
    bool checkCanaryProtection(const std::vector<uint8_t>& buffer);

    std::vector<uint8_t> textSection_;
    uint64_t textBaseAddr_ = 0;
    bool is64Bit_ = false;
    std::string arch_ = "unknown";

    uint64_t imageBase_   = 0x400000;
    uint64_t entryPoint_  = 0;

    // Mitigation flags
    bool nxEnabled_       = false;
    bool pieEnabled_      = false;
    bool canaryEnabled_   = false;
    bool highEntropyVA_   = false;  // IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA (0x0020)
    bool cfgEnabled_      = false;  // IMAGE_DLLCHARACTERISTICS_GUARD_CF (0x4000)
    bool noSEH_           = false;  // IMAGE_FILE_NO_SEH in FileHeader.Characteristics
};

} // namespace ropweaver
