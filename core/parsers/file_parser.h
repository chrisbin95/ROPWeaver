#pragma once
#include <cstdint>
#include <string>
#include <vector>

// Mach-O Segment Metadata
struct MachOSegmentInfo {
  std::string name;
  uint64_t vmaddr = 0;
  uint64_t vmsize = 0;
  uint64_t fileoff = 0;
  uint64_t filesize = 0;
  uint32_t initprot = 0;
  uint32_t maxprot = 0;
  uint32_t nsects = 0;
  uint32_t flags = 0;
};

struct SectionInfo {
  std::string name;
  uint64_t virtual_address = 0; // Preferred Virtual Address
  uint64_t virtual_size = 0;
  uint64_t raw_offset = 0; // Raw file offset on disk
  uint64_t raw_size = 0;
  uint32_t characteristics = 0;
  bool is_executable = false;
  std::string segment_name;
  uint32_t segment_initprot = 0;
  uint32_t segment_maxprot = 0;
  uint64_t segment_vmaddr = 0;
  uint64_t segment_vmsize = 0;
};

// Represents the mapping of an executable section inside a packed code buffer
struct ExecBufferMapping {
  uint64_t virtual_address = 0;
  size_t buffer_offset = 0;
  size_t size = 0;
  uint64_t raw_offset = 0;
  std::string section_name;
};

// Endianness classification for container metadata and instruction byte order
enum class Endianness {
  Little,
  Big,
  Unknown,
  Unsupported
};

// ARM ELF mapping-symbol instruction/data region classification (AAELF32 §4.5.2)
enum class ArmRegionType {
  Arm,    // $a: ARM instruction region
  Thumb,  // $t: Thumb instruction region
  Data    // $d: Data region (literal pool, jump tables)
};

struct ArmMappingSymbol {
  uint64_t address = 0;
  ArmRegionType type = ArmRegionType::Arm;
  std::string name;
  std::string section_name;
};

struct ArmCodeRegion {
  uint64_t start_address = 0;
  uint64_t end_address = 0; // Exclusive [start_address, end_address)
  size_t buffer_offset = 0;
  size_t size = 0;
  ArmRegionType type = ArmRegionType::Arm;
  std::string section_name;
  bool is_executable = false; // true for Arm and Thumb, false for Data
};

class FileParser {
public:
  explicit FileParser(const std::string &path) : m_filepath(path) {}
  virtual ~FileParser() = default;

  virtual bool parse(const std::string &filepath) = 0;
  virtual const std::vector<uint8_t> &getTextSection() const = 0;
  virtual uint64_t getTextSectionBaseAddress() const = 0;
  virtual std::string getArchitecture() const = 0;

  // Pure virtuals
  virtual bool is64Bit() const = 0;
  virtual std::string getBinaryType() const = 0; // ELF, PE, Mach-O
  virtual std::string getFilePath() const = 0;

  // Endianness classification (defaults to Unknown for unestablished formats)
  virtual Endianness getMetadataEndianness() const { return Endianness::Unknown; }
  virtual Endianness getInstructionEndianness() const { return Endianness::Unknown; }

  // ELF ABI and platform classification (defaults for non-ELF or unestablished formats)
  virtual uint8_t getOsAbi() const { return 0; }
  virtual uint32_t getElfFlags() const { return 0; }
  virtual bool isArmEabi() const { return false; }
  virtual bool isRvcEnabled() const { return false; }

  // ARM ELF Mapping symbols and Code/Data regions (AAELF32 §4.5.2)
  virtual const std::vector<ArmMappingSymbol>& getArmMappingSymbols() const {
    static const std::vector<ArmMappingSymbol> empty;
    return empty;
  }
  virtual const std::vector<ArmCodeRegion>& getArmCodeRegions() const {
    static const std::vector<ArmCodeRegion> empty;
    return empty;
  }
  virtual bool hasArmMappingSymbols() const { return false; }

  // Security mitigations (defaults)
  virtual bool isNxEnabled() const { return false; }
  virtual bool isPieEnabled() const { return false; }
  virtual bool isCanaryEnabled() const { return false; }
  virtual std::string getRelro() const { return "None"; }

  // Section and Address Resolution
  virtual uint64_t getImageBase() const { return 0; }
  virtual uint64_t getEntryPoint() const { return 0; }
  virtual const std::vector<SectionInfo> &getSections() const {
    static const std::vector<SectionInfo> empty;
    return empty;
  }
  virtual const std::vector<MachOSegmentInfo> &getMachOSegments() const {
    static const std::vector<MachOSegmentInfo> empty;
    return empty;
  }
  virtual const std::vector<ExecBufferMapping> &getExecBufferMappings() const {
    static const std::vector<ExecBufferMapping> empty;
    return empty;
  }

  // Resolves a Preferred Virtual Address to (raw file offset, RVA)
  virtual bool vaToOffsets(uint64_t preferred_va, uint64_t &out_file_offset,
                           uint64_t &out_rva) const {
    uint64_t base = getImageBase();
    out_rva = (preferred_va >= base) ? (preferred_va - base) : preferred_va;
    for (const auto &sec : getSections()) {
      uint64_t v_span =
          (sec.virtual_size > 0) ? sec.virtual_size : sec.raw_size;
      if (preferred_va >= sec.virtual_address &&
          preferred_va < sec.virtual_address + v_span) {
        uint64_t delta = preferred_va - sec.virtual_address;
        if (sec.raw_size > 0 && delta >= sec.raw_size) {
          continue; // Address is in unmapped file area
        }
        out_file_offset = sec.raw_offset + delta;
        return true;
      }
    }
    return false;
  }

protected:
  std::string m_filepath;
};
