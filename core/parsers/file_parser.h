#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct SectionInfo {
  std::string name;
  uint64_t virtual_address = 0; // Preferred Virtual Address
  uint64_t virtual_size = 0;
  uint64_t raw_offset = 0; // Raw file offset on disk
  uint64_t raw_size = 0;
  uint32_t characteristics = 0;
  bool is_executable = false;
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
