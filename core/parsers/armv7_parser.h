#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <fstream>
#include "file_parser.h"

namespace ropweaver {

class ARMv7Parser : public FileParser {
public:
    ARMv7Parser(const std::string& path) : FileParser(path) {}
    virtual ~ARMv7Parser() = default;

    // Existing virtual functions
    virtual bool parse(const std::string& filepath) override;
    
    // Implementations of the pure virtual functions from FileParser
    virtual const std::vector<uint8_t>& getTextSection() const override;
    virtual uint64_t getTextSectionBaseAddress() const override;
    virtual std::string getArchitecture() const override;
    virtual bool is64Bit() const override;
    virtual std::string getBinaryType() const override { return "ELF"; } // ARMv7 is typically an ELF too
    virtual std::string getFilePath() const override { return m_filepath; }

private:
    std::vector<uint8_t> m_file_data; // Holds the entire file data
    // Members to store the parsed section data
    std::vector<uint8_t> m_text_section;
    uint64_t m_text_base_addr = 0;
    std::string m_architecture = "armv7"; // Set default architecture
};

} // namespace ropweaver