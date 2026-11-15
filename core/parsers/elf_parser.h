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
    uint64_t getEntryPoint() const override { return m_entry_point; }
    uint64_t getImageBase() const override { return m_image_base; }
    const std::vector<SectionInfo>& getSections() const override { return m_sections; }
    const std::vector<ExecBufferMapping>& getExecBufferMappings() const override { return m_exec_mappings; }

    // Endianness and ELF metadata
    Endianness getMetadataEndianness() const override { return m_metadata_endianness; }
    Endianness getInstructionEndianness() const override { return m_instruction_endianness; }
    bool isBigEndian() const { return m_metadata_endianness == Endianness::Big; }
    bool isArmBe8() const { return m_arm_be8; }
    uint32_t getElfFlags() const override { return m_elf_flags; }
    uint8_t getOsAbi() const override { return m_osabi; }
    bool isArmEabi() const override {
        if (m_arch != "armv7" && hdr32.e_machine != EM_ARM) return false;
        uint32_t ver = m_elf_flags & EF_ARM_EABIMASK;
        return (ver == EF_ARM_EABI_VER1 || ver == EF_ARM_EABI_VER2 ||
                ver == EF_ARM_EABI_VER3 || ver == EF_ARM_EABI_VER4 ||
                ver == EF_ARM_EABI_VER5);
    }
    bool isRvcEnabled() const override;

    // ARM ELF Mapping symbols and Code/Data regions (AAELF32 §4.5.2)
    const std::vector<ArmMappingSymbol>& getArmMappingSymbols() const override { return m_arm_mapping_symbols; }
    const std::vector<ArmCodeRegion>& getArmCodeRegions() const override { return m_arm_code_regions; }
    bool hasArmMappingSymbols() const override { return !m_arm_mapping_symbols.empty(); }

    // Security mitigations (override FileParser defaults)
    bool isNxEnabled() const override { return m_nx_enabled; }
    bool isPieEnabled() const override { return m_pie_enabled; }
    bool isCanaryEnabled() const override { return m_canary_enabled; }
    std::string getRelro() const override { return m_relro; }

private:
    Elf32_Ehdr hdr32{};
    Elf64_Ehdr hdr64{};
    std::vector<uint8_t> m_file_data;

    // Endianness and flags
    Endianness m_metadata_endianness    = Endianness::Unknown;
    Endianness m_instruction_endianness = Endianness::Unknown;
    bool m_is_big_endian                = false;
    bool m_arm_be8                      = false;
    uint32_t m_elf_flags                = 0;
    uint8_t m_osabi                     = 0;

    // Members needed to satisfy FileParser getters
    std::vector<uint8_t> m_text_section;
    uint64_t m_text_section_base_address = 0;
    uint64_t m_entry_point = 0;
    uint64_t m_image_base = 0;
    std::string m_arch = "unknown";
    std::vector<SectionInfo> m_sections;
    std::vector<ExecBufferMapping> m_exec_mappings;
    std::vector<ArmMappingSymbol> m_arm_mapping_symbols;
    std::vector<ArmCodeRegion> m_arm_code_regions;

    // Mitigation detection results
    bool m_nx_enabled     = false;
    bool m_pie_enabled    = false;
    bool m_canary_enabled = false;
    std::string m_relro   = "None";
};

} // namespace ropweaver
