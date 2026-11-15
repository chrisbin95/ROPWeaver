#pragma once
#include "file_parser.h"
#include "macho_defs.h"
#include <string>
#include <vector>
#include <cstdint>

namespace ropweaver { 

enum class CanaryStatus {
    SymbolDetected,
    NotDetected,
    Unknown
};

enum class HeapNxStatus {
    ExplicitEnabled,
    Unknown
};

enum class SegmentWxStatus {
    Compliant,
    InitViolation,
    MaxprotPermissive,
    IncompleteOrUnavailable
};

struct MachOMitigations {
    // Stack NX
    bool stack_nx = true;

    // Heap NX
    HeapNxStatus heap_nx = HeapNxStatus::Unknown;

    // Segment W^X
    SegmentWxStatus segment_wx_status = SegmentWxStatus::IncompleteOrUnavailable;
    bool has_wx_initprot = false;
    bool has_wx_maxprot  = false;
    uint32_t total_declared_segments = 0;
    uint32_t inspected_segments = 0;
    bool segment_stream_complete = false;

    // Position Independent Executable
    bool pie = false;

    // Stack Canary
    CanaryStatus canary_status = CanaryStatus::Unknown;
    std::string  canary_symbol_name;

    // Code Signature
    bool has_code_signature_cmd    = false;
    bool data_range_valid          = false;
    bool superblob_header_valid    = false;
    bool cryptographically_verified = false; // Always false
    std::string code_signature_notes;

    // RELRO
    std::string relro = "NOT_APPLICABLE";
};

class MachOParser : public FileParser {
public:
    explicit MachOParser(const std::string& filepath, const std::string& targetArch = "");

    bool parse(const std::string& filepath) override;
    bool parse(const std::string& filepath, const std::string& targetArch);
    const std::vector<uint8_t>& getTextSection() const override;
    uint64_t getTextSectionBaseAddress() const override;
    std::string getArchitecture() const override;

    // Implementation of pure virtual functions
    bool is64Bit() const override;
    std::string getBinaryType() const override { return "Mach-O"; }
    // Returns m_filepath from the base class (FileParser)
    std::string getFilePath() const override { return m_filepath; }

    // Endianness overrides
    Endianness getMetadataEndianness() const override;
    Endianness getInstructionEndianness() const override;

    // Address and Section Resolution overrides
    uint64_t getImageBase() const override { return imageBase_; }
    const std::vector<SectionInfo>& getSections() const override { return sections_; }
    const std::vector<MachOSegmentInfo>& getMachOSegments() const override { return segments_; }
    const std::vector<ExecBufferMapping>& getExecBufferMappings() const override { return execMappings_; }
    bool isNxEnabled() const override;
    bool isPieEnabled() const override { return (flags_ & MH_PIE) != 0; }
    bool isCanaryEnabled() const override { return mitigations_.canary_status == CanaryStatus::SymbolDetected; }
    std::string getRelro() const override { return "NOT_APPLICABLE"; }

    const MachOMitigations& getMachOMitigations() const { return mitigations_; }

    // Parsed thin Mach-O header getters
    bool isBigEndian() const { return isBigEndian_; }
    uint32_t getCpuType() const { return cputype_; }
    uint32_t getCpuSubType() const { return cpusubtype_; }
    uint32_t getFileType() const { return filetype_; }
    uint32_t getNumCmds() const { return ncmds_; }
    uint32_t getSizeOfCmds() const { return sizeofcmds_; }
    uint32_t getFlags() const { return flags_; }

    const MachO_Header_32& getHeader32() const { return header32_; }
    const MachO_Header_64& getHeader64() const { return header64_; }

    // Universal / Fat Mach-O methods
    bool isFat() const { return isFat_; }
    uint64_t getSliceOffset() const { return sliceOffset_; }
    uint64_t getSliceSize() const { return sliceSize_; }
    const std::vector<FatSlice>& getFatSlices() const { return fatSlices_; }

    void setTargetArchitecture(const std::string& arch) { targetArch_ = arch; }
    const std::string& getTargetArchitecture() const { return targetArch_; }
    void setSlice(uint64_t offset, uint64_t size) {
        sliceOffset_ = offset;
        sliceSize_ = size;
        isExplicitSlice_ = true;
    }

private:
    bool parseFatContainer(std::ifstream& file, size_t fileSize, MachOFormat fmt, FatSlice& selectedSlice);
    static std::string classifySubtype(int32_t cputype, int32_t cpusubtype);
    static std::string normalizeArch(const std::string& arch);

    void parseSymtab(std::ifstream& file, size_t fileSize, const uint8_t* cmd_ptr, uint32_t cmdsize);
    void parseCodeSignature(std::ifstream& file, size_t fileSize, const uint8_t* cmd_ptr, uint32_t cmdsize);
    void finalizeMitigations();

    MachOMitigations mitigations_;
    bool seen_symtab_cmd_ = false;
    bool seen_code_signature_cmd_ = false;

    std::vector<uint8_t> textSection_;
    uint64_t textBaseAddr_ = 0;
    uint64_t imageBase_ = 0;
    bool is64Bit_ = false;
    bool isBigEndian_ = false;
    std::string arch_ = "unknown";

    std::vector<SectionInfo> sections_;
    std::vector<MachOSegmentInfo> segments_;
    std::vector<ExecBufferMapping> execMappings_;

    MachO_Header_32 header32_{};
    MachO_Header_64 header64_{};

    uint32_t cputype_ = 0;
    uint32_t cpusubtype_ = 0;
    uint32_t filetype_ = 0;
    uint32_t ncmds_ = 0;
    uint32_t sizeofcmds_ = 0;
    uint32_t flags_ = 0;

    // Fat binary state
    bool isFat_ = false;
    bool isExplicitSlice_ = false;
    uint64_t sliceOffset_ = 0;
    uint64_t sliceSize_ = 0;
    std::string targetArch_;
    std::vector<FatSlice> fatSlices_;
};

} // namespace ropweaver