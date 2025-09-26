#pragma once
#include "file_parser.h"
#include <string>
#include <vector>
#include <cstdint>

namespace ropweaver { 

class MachOParser : public FileParser {
public:
    
    explicit MachOParser(const std::string& filepath);

    bool parse(const std::string& filepath) override;
    const std::vector<uint8_t>& getTextSection() const override;
    uint64_t getTextSectionBaseAddress() const override;
    std::string getArchitecture() const override;

    // Implementation of pure virtual functions
    bool is64Bit() const override;
    std::string getBinaryType() const override { return "Mach-O"; }
    // Returns m_filepath from the base class (FileParser)
    std::string getFilePath() const override { return m_filepath; }

private:
    
    std::vector<uint8_t> textSection_;
    uint64_t textBaseAddr_ = 0;
    bool is64Bit_ = false;
    std::string arch_ = "unknown";
};

} // namespace ropweaver