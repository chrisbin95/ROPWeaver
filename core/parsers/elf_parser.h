#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include "file_parser.h"
#include "elf_defs.h" 

namespace ropweaver {

class ELFParser : public FileParser {
public:
    explicit ELFParser(const std::string& path) : FileParser(path) {}

    virtual ~ELFParser() = default;
    virtual bool parse(const std::string& filepath) override;

    // Implementation of pure virtual functions from FileParser
    virtual const std::vector<uint8_t>& getTextSection() const override;
    virtual uint64_t getTextSectionBaseAddress() const override;
    virtual std::string getArchitecture() const override;
    virtual bool is64Bit() const override;
    virtual std::string getBinaryType() const override { return "ELF"; }
    virtual std::string getFilePath() const override { return m_filepath; }

    const Elf32_Ehdr& getHeader32() const { return hdr32; }
    const Elf64_Ehdr& getHeader64() const { return hdr64; }

private:
    Elf32_Ehdr hdr32{};
    Elf64_Ehdr hdr64{};
    std::vector<uint8_t> m_file_data;

    // Members needed to satisfy FileParser getters
    std::vector<uint8_t> m_text_section;
    uint64_t m_text_section_base_address = 0;
    std::string m_arch = "unknown";
};

} // namespace ropweaver