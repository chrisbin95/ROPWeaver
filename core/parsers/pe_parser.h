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

    bool isNxEnabled() const override { return nxEnabled_; }
    bool isPieEnabled() const override { return pieEnabled_; }
    bool isCanaryEnabled() const override { return canaryEnabled_; }
    std::string getRelro() const override { return "N/A (PE format)"; }

private:
    bool checkCanaryProtection(const std::vector<uint8_t>& buffer);

    std::vector<uint8_t> textSection_;
    uint64_t textBaseAddr_ = 0;
    bool is64Bit_ = false;
    std::string arch_ = "unknown";

    bool nxEnabled_ = false;
    bool pieEnabled_ = false;
    bool canaryEnabled_ = false;
};

} // namespace ropweaver
