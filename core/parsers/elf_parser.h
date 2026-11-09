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

    // Extended information
    uint64_t getEntryPoint() const { return m_entry_point; }
    uint64_t getImageBase() const { return 0; } // ELF PIE base is 0 by convention

    // Security mitigations (override FileParser defaults)
    bool isNxEnabled() const override { return m_nx_enabled; }
    bool isPieEnabled() const override { return m_pie_enabled; }
    bool isCanaryEnabled() const override { return m_canary_enabled; }
    std::string getRelro() const override { return m_relro; }

private:
    Elf32_Ehdr hdr32{};
    Elf64_Ehdr hdr64{};
    std::vector<uint8_t> m_file_data;

    // Members needed to satisfy FileParser getters
    std::vector<uint8_t> m_text_section;
    uint64_t m_text_section_base_address = 0;
    uint64_t m_entry_point = 0;
    std::string m_arch = "unknown";

    // Mitigation detection results
    bool m_nx_enabled     = false;
    bool m_pie_enabled    = false;
    bool m_canary_enabled = false;
    std::string m_relro   = "None";
};

} // namespace ropweaver
