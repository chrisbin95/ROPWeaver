#include "macho_parser.h"
#include "macho_defs.h"
#include "elf_defs.h"
#include <fstream>
#include <iostream>
#include <cstring>
#include <algorithm>
#include <limits>

using namespace ropweaver;

// Constructor calls the base class constructor
MachOParser::MachOParser(const std::string& filepath, const std::string& targetArch)
    : FileParser(filepath), targetArch_(targetArch) {}

bool MachOParser::parse(const std::string& filepath, const std::string& targetArch) {
    targetArch_ = targetArch;
    return parse(filepath);
}

std::string MachOParser::classifySubtype(int32_t cputype, int32_t cpusubtype) {
    uint32_t clean = static_cast<uint32_t>(cpusubtype) & ~CPU_SUBTYPE_MASK;
    switch (cputype) {
        case CPU_TYPE_X86_64:
            if (clean == CPU_SUBTYPE_X86_64_ALL || clean == CPU_SUBTYPE_X86_64_H) {
                return "x86_64";
            }
            return "unknown";
        case CPU_TYPE_ARM64:
            if (clean == CPU_SUBTYPE_ARM64_ALL || clean == CPU_SUBTYPE_ARM64_V8 || clean == CPU_SUBTYPE_ARM64E) {
                return "aarch64";
            }
            return "unknown";
        case CPU_TYPE_X86:
            if (clean == CPU_SUBTYPE_I386_ALL || clean == CPU_SUBTYPE_486 || clean == CPU_SUBTYPE_586) {
                return "x86";
            }
            return "unknown";
        case CPU_TYPE_ARM:
            if (clean == CPU_SUBTYPE_ARM_V7 || clean == CPU_SUBTYPE_ARM_V7S ||
                clean == CPU_SUBTYPE_ARM_V7K || clean == CPU_SUBTYPE_ARM_ALL) {
                return "armv7";
            }
            return "unknown";
        default:
            return "unknown";
    }
}

std::string MachOParser::normalizeArch(const std::string& arch) {
    if (arch == "arm64" || arch == "aarch64") return "aarch64";
    if (arch == "x86_64" || arch == "amd64" || arch == "x64") return "x86_64";
    if (arch == "x86" || arch == "i386" || arch == "i686") return "x86";
    if (arch == "arm" || arch == "armv7" || arch == "armv7l") return "armv7";
    return arch;
}

bool MachOParser::parseFatContainer(std::ifstream& file, size_t fileSize, MachOFormat fmt, FatSlice& selectedSlice) {
    bool isFat64 = (fmt == MachOFormat::Fat64_BE || fmt == MachOFormat::Fat64_LE);
    bool isFatBE = (fmt == MachOFormat::Fat32_BE || fmt == MachOFormat::Fat64_BE);

    if (fileSize < sizeof(fat_header)) {
        std::cerr << "[!] MachOParser: Truncated universal Mach-O header: " << m_filepath << std::endl;
        return false;
    }

    uint8_t hdr_buf[sizeof(fat_header)];
    file.seekg(0, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(hdr_buf), sizeof(hdr_buf))) {
        std::cerr << "[!] MachOParser: Failed to read universal Mach-O header: " << m_filepath << std::endl;
        return false;
    }

    uint32_t nfat_arch = read_u32(hdr_buf + 4, isFatBE);
    if (nfat_arch == 0) {
        std::cerr << "[!] MachOParser: Universal binary has zero architecture count: " << m_filepath << std::endl;
        return false;
    }

    constexpr uint32_t MAX_FAT_ARCH = 1024;
    if (nfat_arch > MAX_FAT_ARCH) {
        std::cerr << "[!] MachOParser: Excessive architecture count in universal binary: " << m_filepath << std::endl;
        return false;
    }

    size_t entry_size = isFat64 ? sizeof(fat_arch_64) : sizeof(fat_arch);
    uint64_t table_data_size = static_cast<uint64_t>(nfat_arch) * entry_size;
    uint64_t total_table_size = sizeof(fat_header) + table_data_size;

    if (total_table_size > fileSize) {
        std::cerr << "[!] MachOParser: Architecture table exceeds file size: " << m_filepath << std::endl;
        return false;
    }

    std::vector<uint8_t> table_buf(static_cast<size_t>(table_data_size));
    if (!file.read(reinterpret_cast<char*>(table_buf.data()), table_buf.size())) {
        std::cerr << "[!] MachOParser: Failed to read architecture table: " << m_filepath << std::endl;
        return false;
    }

    fatSlices_.clear();
    fatSlices_.reserve(nfat_arch);

    for (uint32_t i = 0; i < nfat_arch; ++i) {
        const uint8_t* p = table_buf.data() + i * entry_size;
        FatSlice slice;
        if (isFat64) {
            slice.cputype    = read_i32(p, isFatBE);
            slice.cpusubtype = read_i32(p + 4, isFatBE);
            slice.offset     = read_u64(p + 8, isFatBE);
            slice.size       = read_u64(p + 16, isFatBE);
            slice.align      = read_u32(p + 24, isFatBE);
        } else {
            slice.cputype    = read_i32(p, isFatBE);
            slice.cpusubtype = read_i32(p + 4, isFatBE);
            slice.offset     = read_u32(p + 8, isFatBE);
            slice.size       = read_u32(p + 12, isFatBE);
            slice.align      = read_u32(p + 16, isFatBE);
        }

        // 1. Slice offset/size integer overflow check
        if (slice.offset > UINT64_MAX - slice.size) {
            std::cerr << "[!] MachOParser: Slice offset + size overflows 64-bit integer: " << m_filepath << std::endl;
            return false;
        }

        // 2. Alignment exponent validation: FAT32 requires align < 32; FAT64 requires align < 64
        uint32_t max_align = isFat64 ? 64 : 32;
        if (slice.align >= max_align) {
            std::cerr << "[!] MachOParser: Malformed alignment exponent (>= " << std::dec << max_align << "): " << m_filepath << std::endl;
            return false;
        }

        // 3. Natural alignment check for slice offset (if align == 0, 2^0 = 1, always aligned)
        if (slice.align > 0) {
            uint64_t align_bytes = 1ULL << slice.align;
            if ((slice.offset & (align_bytes - 1)) != 0) {
                std::cerr << "[!] MachOParser: Slice offset not aligned to 2^align: " << m_filepath << std::endl;
                return false;
            }
        }

        // 4. Slice / header / table overlap
        if (slice.offset < total_table_size) {
            std::cerr << "[!] MachOParser: Slice overlaps universal header/table: " << m_filepath << std::endl;
            return false;
        }

        // 5. Minimum thin-header size check
        if (slice.size < 28) {
            std::cerr << "[!] MachOParser: Slice size smaller than minimum Mach-O header: " << m_filepath << std::endl;
            return false;
        }

        // 6. Slice containment within file
        if (slice.offset > fileSize || slice.size > fileSize - slice.offset) {
            std::cerr << "[!] MachOParser: Slice range exceeds file size: " << m_filepath << std::endl;
            return false;
        }

        // 7. Subtype / arch classification
        slice.archName = classifySubtype(slice.cputype, slice.cpusubtype);

        fatSlices_.push_back(slice);
    }

    // 8. Inter-slice overlap validation across ALL slices
    for (size_t i = 0; i < fatSlices_.size(); ++i) {
        for (size_t j = i + 1; j < fatSlices_.size(); ++j) {
            uint64_t start = std::max(fatSlices_[i].offset, fatSlices_[j].offset);
            uint64_t end   = std::min(fatSlices_[i].offset + fatSlices_[i].size,
                                      fatSlices_[j].offset + fatSlices_[j].size);
            if (start < end) {
                std::cerr << "[!] MachOParser: Slices " << i << " and " << j
                          << " overlap in universal binary: " << m_filepath << std::endl;
                return false;
            }
        }
    }

    // 9. Slice selection
    if (!targetArch_.empty()) {
        std::string normReq = normalizeArch(targetArch_);
        bool found = false;
        for (const auto& slice : fatSlices_) {
            if (normalizeArch(slice.archName) == normReq) {
                selectedSlice = slice;
                found = true;
                break;
            }
        }
        if (!found) {
            std::cerr << "[!] MachOParser: Requested architecture '" << targetArch_
                      << "' not found in universal binary: " << m_filepath << std::endl;
            return false;
        }
    } else {
        // Deterministic default selection: x86_64 -> aarch64 -> x86 -> armv7
        const std::vector<std::string> priority = { "x86_64", "aarch64", "x86", "armv7" };
        bool found = false;
        for (const auto& prio_arch : priority) {
            // First pass: prefer standard/generic subtype
            for (const auto& slice : fatSlices_) {
                if (slice.archName == prio_arch) {
                    uint32_t clean = static_cast<uint32_t>(slice.cpusubtype) & ~CPU_SUBTYPE_MASK;
                    bool is_std = false;
                    if (prio_arch == "x86_64" && clean == CPU_SUBTYPE_X86_64_ALL) is_std = true;
                    else if (prio_arch == "aarch64" && (clean == CPU_SUBTYPE_ARM64_ALL || clean == CPU_SUBTYPE_ARM64_V8)) is_std = true;
                    else if (prio_arch == "x86" && clean == CPU_SUBTYPE_I386_ALL) is_std = true;
                    else if (prio_arch == "armv7" && clean == CPU_SUBTYPE_ARM_V7) is_std = true;

                    if (is_std) {
                        selectedSlice = slice;
                        found = true;
                        break;
                    }
                }
            }
            if (found) break;

            // Second pass: any compatible subtype for this architecture
            for (const auto& slice : fatSlices_) {
                if (slice.archName == prio_arch) {
                    selectedSlice = slice;
                    found = true;
                    break;
                }
            }
            if (found) break;
        }

        if (!found) {
            std::cerr << "[!] MachOParser: No supported architecture slice found in universal binary: " << m_filepath << std::endl;
            return false;
        }
    }

    return true;
}

bool MachOParser::parse(const std::string& filepath) {
    m_filepath = filepath;
    textSection_.clear();
    textBaseAddr_ = 0;
    imageBase_ = 0;
    sections_.clear();
    segments_.clear();
    execMappings_.clear();
    is64Bit_ = false;
    isBigEndian_ = false;
    arch_ = "unknown";
    cputype_ = 0;
    cpusubtype_ = 0;
    filetype_ = 0;
    ncmds_ = 0;
    sizeofcmds_ = 0;
    flags_ = 0;
    fatSlices_.clear();
    isFat_ = false;
    std::memset(&header32_, 0, sizeof(header32_));
    std::memset(&header64_, 0, sizeof(header64_));

    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[!] MachOParser: Could not open file: " << filepath << std::endl;
        return false;
    }

    file.seekg(0, std::ios::end);
    size_t file_size = static_cast<size_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    if (!isExplicitSlice_) {
        uint8_t magic_buf[4];
        if (!file.read(reinterpret_cast<char*>(magic_buf), sizeof(magic_buf))) {
            std::cerr << "[!] MachOParser: File too small for Mach-O magic: " << filepath << std::endl;
            return false;
        }

        MachOFormat fmt = detectMachOFormat(magic_buf);
        if (isFatMachO(fmt)) {
            FatSlice selectedSlice;
            if (!parseFatContainer(file, file_size, fmt, selectedSlice)) {
                return false;
            }
            sliceOffset_ = selectedSlice.offset;
            sliceSize_   = selectedSlice.size;
            isFat_       = true;
        } else if (isThinMachO(fmt)) {
            sliceOffset_ = 0;
            sliceSize_   = file_size;
            isFat_       = false;
        } else {
            std::cerr << "[!] MachOParser: Not a recognized Mach-O binary (format=" << static_cast<int>(fmt) << "): " << filepath << std::endl;
            return false;
        }
    } else {
        if (sliceOffset_ > file_size || sliceSize_ > file_size - sliceOffset_) {
            std::cerr << "[!] MachOParser: Explicit slice bounds exceed file size: " << filepath << std::endl;
            return false;
        }
        if (sliceSize_ < 28) {
            std::cerr << "[!] MachOParser: Explicit slice too small: " << filepath << std::endl;
            return false;
        }
        isFat_ = true;
    }

    // Now parse the thin Mach-O slice at [sliceOffset_, sliceOffset_ + sliceSize_)
    file.seekg(sliceOffset_, std::ios::beg);
    uint8_t slice_magic_buf[4];
    if (!file.read(reinterpret_cast<char*>(slice_magic_buf), sizeof(slice_magic_buf))) {
        std::cerr << "[!] MachOParser: Truncated slice header: " << filepath << std::endl;
        return false;
    }

    MachOFormat sliceFmt = detectMachOFormat(slice_magic_buf);
    if (!isThinMachO(sliceFmt)) {
        std::cerr << "[!] MachOParser: Slice does not start with valid thin Mach-O magic: " << filepath << std::endl;
        return false;
    }

    is64Bit_     = isMachO64(sliceFmt);
    isBigEndian_ = isMachOBigEndian(sliceFmt);

    size_t header_size = is64Bit_ ? sizeof(MachO_Header_64) : sizeof(MachO_Header_32);
    if (sliceSize_ < header_size) {
        std::cerr << "[!] MachOParser: Truncated Mach-O header in slice: " << filepath << std::endl;
        return false;
    }

    std::vector<uint8_t> header_buf(header_size, 0);
    file.seekg(sliceOffset_, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(header_buf.data()), header_buf.size())) {
        std::cerr << "[!] MachOParser: Failed to read Mach-O header: " << filepath << std::endl;
        return false;
    }

    const uint8_t* p = header_buf.data();
    uint32_t magic_val = read_u32(p, isBigEndian_);
    cputype_    = read_u32(p + 4, isBigEndian_);
    cpusubtype_ = read_u32(p + 8, isBigEndian_);
    filetype_   = read_u32(p + 12, isBigEndian_);
    ncmds_      = read_u32(p + 16, isBigEndian_);
    sizeofcmds_ = read_u32(p + 20, isBigEndian_);
    flags_      = read_u32(p + 24, isBigEndian_);

    if (is64Bit_) {
        header64_.magic      = magic_val;
        header64_.cputype    = static_cast<int32_t>(cputype_);
        header64_.cpusubtype = static_cast<int32_t>(cpusubtype_);
        header64_.filetype   = filetype_;
        header64_.ncmds      = ncmds_;
        header64_.sizeofcmds = sizeofcmds_;
        header64_.flags      = flags_;
        header64_.reserved   = read_u32(p + 28, isBigEndian_);
    } else {
        header32_.magic      = magic_val;
        header32_.cputype    = static_cast<int32_t>(cputype_);
        header32_.cpusubtype = static_cast<int32_t>(cpusubtype_);
        header32_.filetype   = filetype_;
        header32_.ncmds      = ncmds_;
        header32_.sizeofcmds = sizeofcmds_;
        header32_.flags      = flags_;
    }

    // Reset mitigations and populate initial header-derived protections
    mitigations_ = MachOMitigations();
    seen_symtab_cmd_ = false;
    seen_code_signature_cmd_ = false;
    mitigations_.stack_nx = (flags_ & MH_ALLOW_STACK_EXECUTION) == 0;
    mitigations_.heap_nx  = ((flags_ & MH_NO_HEAP_EXECUTION) != 0) ? HeapNxStatus::ExplicitEnabled : HeapNxStatus::Unknown;
    mitigations_.pie      = (flags_ & MH_PIE) != 0;

    if (is64Bit_) {
        switch (static_cast<int32_t>(cputype_)) {
            case CPU_TYPE_X86_64:
                arch_ = "x86_64";
                break;
            case CPU_TYPE_ARM64:
                arch_ = "aarch64";
                break;
            default:
                std::cerr << "[!] MachOParser: Unsupported or mismatched 64-bit Mach-O CPU type: 0x" << std::hex << cputype_ << std::endl;
                arch_ = "unknown";
                return false;
        }
    } else {
        switch (static_cast<int32_t>(cputype_)) {
            case CPU_TYPE_X86:
                arch_ = "x86";
                break;
            case CPU_TYPE_ARM:
                arch_ = "armv7";
                break;
            default:
                std::cerr << "[!] MachOParser: Unsupported or mismatched 32-bit Mach-O CPU type: 0x" << std::hex << cputype_ << std::endl;
                arch_ = "unknown";
                return false;
        }
    }

    // If explicit target architecture was requested for a thin binary, verify match
    if (!isFat_ && !targetArch_.empty()) {
        if (normalizeArch(arch_) != normalizeArch(targetArch_)) {
            std::cerr << "[!] MachOParser: Thin binary architecture (" << arch_
                      << ") does not match requested (" << targetArch_ << ")" << std::endl;
            return false;
        }
    }

    // Header-only buffer compatibility check
    if (sliceSize_ == header_size) {
        finalizeMitigations();
        return true;
    }

    // Validate load commands stream boundary against slice size
    if (sizeofcmds_ > sliceSize_ - header_size) {
        std::cerr << "[!] MachOParser: sizeofcmds extends beyond slice size: " << filepath << std::endl;
        return false;
    }

    std::vector<uint8_t> cmds_buf(sizeofcmds_, 0);
    if (sizeofcmds_ > 0) {
        file.seekg(sliceOffset_ + header_size, std::ios::beg);
        if (!file.read(reinterpret_cast<char*>(cmds_buf.data()), sizeofcmds_)) {
            std::cerr << "[!] MachOParser: Failed to read load commands buffer: " << filepath << std::endl;
            return false;
        }
    }

    size_t cmd_offset = 0;
    bool found_text_section = false;
    uint64_t text_sec_addr = 0;

    for (uint32_t i = 0; i < ncmds_; ++i) {
        if (cmd_offset + sizeof(load_command) > sizeofcmds_) {
            std::cerr << "[!] MachOParser: Truncated load command header: " << filepath << std::endl;
            mitigations_.segment_stream_complete = false;
            finalizeMitigations();
            return false;
        }

        const uint8_t* cmd_ptr = cmds_buf.data() + cmd_offset;
        uint32_t cmd     = read_u32(cmd_ptr, isBigEndian_);
        uint32_t cmdsize = read_u32(cmd_ptr + 4, isBigEndian_);

        // Account for declared segments immediately upon recognizing segment command type,
        // BEFORE validating cmdsize, command bounds, segment width, segment fields, or sections.
        if (cmd == LC_SEGMENT || cmd == LC_SEGMENT_64) {
            mitigations_.total_declared_segments++;
        }

        if (cmdsize < sizeof(load_command) || (cmdsize % 4) != 0) {
            std::cerr << "[!] MachOParser: Invalid load command size or alignment: " << filepath << std::endl;
            mitigations_.segment_stream_complete = false;
            finalizeMitigations();
            return false;
        }

        if (cmdsize > sizeofcmds_ - cmd_offset) {
            std::cerr << "[!] MachOParser: Load command extends past sizeofcmds: " << filepath << std::endl;
            mitigations_.segment_stream_complete = false;
            finalizeMitigations();
            return false;
        }

        if (cmd == LC_SEGMENT) {
            if (is64Bit_) {
                std::cerr << "[!] MachOParser: 32-bit LC_SEGMENT in 64-bit Mach-O binary: " << filepath << std::endl;
                mitigations_.segment_stream_complete = false;
                finalizeMitigations();
                return false;
            }
            if (cmdsize < sizeof(segment_command)) {
                std::cerr << "[!] MachOParser: Truncated segment_command: " << filepath << std::endl;
                mitigations_.segment_stream_complete = false;
                finalizeMitigations();
                return false;
            }

            char segname[17] = {0};
            std::memcpy(segname, cmd_ptr + 8, 16);
            uint32_t vmaddr   = read_u32(cmd_ptr + 24, isBigEndian_);
            uint32_t vmsize   = read_u32(cmd_ptr + 28, isBigEndian_);
            uint32_t fileoff  = read_u32(cmd_ptr + 32, isBigEndian_);
            uint32_t filesize = read_u32(cmd_ptr + 36, isBigEndian_);
            int32_t  maxprot  = read_i32(cmd_ptr + 40, isBigEndian_);
            int32_t  initprot = read_i32(cmd_ptr + 44, isBigEndian_);
            uint32_t nsects   = read_u32(cmd_ptr + 48, isBigEndian_);
            uint32_t segflags = read_u32(cmd_ptr + 52, isBigEndian_);
            (void)segflags;

            if (nsects > (cmdsize - sizeof(segment_command)) / sizeof(section)) {
                std::cerr << "[!] MachOParser: nsects exceeds segment command size: " << filepath << std::endl;
                mitigations_.segment_stream_complete = false;
                finalizeMitigations();
                return false;
            }

            // 1. Virtual segment range overflow (32-bit)
            if (vmaddr > UINT32_MAX - vmsize) {
                std::cerr << "[!] MachOParser: 32-bit segment virtual range overflows 32-bit address space: " << filepath << std::endl;
                mitigations_.segment_stream_complete = false;
                finalizeMitigations();
                return false;
            }

            // 2. File segment range overflow (32-bit)
            if (fileoff > UINT32_MAX - filesize) {
                std::cerr << "[!] MachOParser: 32-bit segment file range overflows 32-bit address space: " << filepath << std::endl;
                mitigations_.segment_stream_complete = false;
                finalizeMitigations();
                return false;
            }

            // 3. Unconditional file offset containment within slice (even if filesize == 0)
            uint64_t fileoff64 = static_cast<uint64_t>(fileoff);
            if (fileoff64 > sliceSize_) {
                std::cerr << "[!] MachOParser: Segment fileoff exceeds slice size: " << filepath << std::endl;
                mitigations_.segment_stream_complete = false;
                finalizeMitigations();
                return false;
            }

            // 4. File range containment within slice for non-zero filesize
            uint64_t filesize64 = static_cast<uint64_t>(filesize);
            if (filesize64 > sliceSize_ - fileoff64) {
                std::cerr << "[!] MachOParser: Segment file range exceeds slice size: " << filepath << std::endl;
                mitigations_.segment_stream_complete = false;
                finalizeMitigations();
                return false;
            }

            if (std::strncmp(segname, "__TEXT", 16) == 0) {
                imageBase_ = vmaddr;
            }

            MachOSegmentInfo segInfo;
            segInfo.name = std::string(segname, strnlen(segname, 16));
            segInfo.vmaddr = vmaddr;
            segInfo.vmsize = vmsize;
            segInfo.fileoff = fileoff;
            segInfo.filesize = filesize;
            segInfo.maxprot = static_cast<uint32_t>(maxprot);
            segInfo.initprot = static_cast<uint32_t>(initprot);
            segInfo.nsects = nsects;
            segInfo.flags = segflags;
            segments_.push_back(segInfo);

            for (uint32_t s = 0; s < nsects; ++s) {
                const uint8_t* sec_ptr = cmd_ptr + sizeof(segment_command) + s * sizeof(section);
                char s_sectname[17] = {0};
                std::memcpy(s_sectname, sec_ptr, 16);
                char s_segname[17] = {0};
                std::memcpy(s_segname, sec_ptr + 16, 16);
                uint32_t s_addr   = read_u32(sec_ptr + 32, isBigEndian_);
                uint32_t s_size   = read_u32(sec_ptr + 36, isBigEndian_);
                uint32_t s_offset = read_u32(sec_ptr + 40, isBigEndian_);
                uint32_t s_align  = read_u32(sec_ptr + 44, isBigEndian_);
                uint32_t s_reloff = read_u32(sec_ptr + 48, isBigEndian_);
                uint32_t s_nreloc = read_u32(sec_ptr + 52, isBigEndian_);
                uint32_t s_flags  = read_u32(sec_ptr + 56, isBigEndian_);
                (void)s_align;
                (void)s_reloff;
                (void)s_nreloc;

                if (std::strncmp(s_segname, segname, 16) != 0) {
                    std::cerr << "[!] MachOParser: Section segname does not match segment: " << filepath << std::endl;
                    mitigations_.segment_stream_complete = false;
                    finalizeMitigations();
                    return false;
                }

                // Section virtual range overflow check
                if (s_addr > UINT32_MAX - s_size) {
                    std::cerr << "[!] MachOParser: Section virtual range overflows 32-bit integer: " << filepath << std::endl;
                    mitigations_.segment_stream_complete = false;
                    finalizeMitigations();
                    return false;
                }

                // Section virtual address before segment vmaddr
                if (s_addr < vmaddr) {
                    std::cerr << "[!] MachOParser: Section virtual address before segment vmaddr: " << filepath << std::endl;
                    mitigations_.segment_stream_complete = false;
                    finalizeMitigations();
                    return false;
                }

                uint32_t va_delta = s_addr - vmaddr;
                if (va_delta > vmsize) {
                    std::cerr << "[!] MachOParser: Section virtual offset exceeds segment vmsize: " << filepath << std::endl;
                    mitigations_.segment_stream_complete = false;
                    finalizeMitigations();
                    return false;
                }
                uint32_t remaining_vm = vmsize - va_delta;
                if (s_size > remaining_vm) {
                    std::cerr << "[!] MachOParser: Section virtual range exceeds segment: " << filepath << std::endl;
                    mitigations_.segment_stream_complete = false;
                    finalizeMitigations();
                    return false;
                }

                bool is_zerofill = isZeroFillSection(s_flags);
                if (!is_zerofill && s_size > 0) {
                    uint64_t s_off64 = static_cast<uint64_t>(s_offset);
                    if (s_offset > UINT32_MAX - s_size) {
                        std::cerr << "[!] MachOParser: Section file range overflows 32-bit integer: " << filepath << std::endl;
                        mitigations_.segment_stream_complete = false;
                        finalizeMitigations();
                        return false;
                    }
                    if (s_offset < fileoff) {
                        std::cerr << "[!] MachOParser: Section file offset before segment fileoff: " << filepath << std::endl;
                        mitigations_.segment_stream_complete = false;
                        finalizeMitigations();
                        return false;
                    }
                    uint32_t fileoff_delta = s_offset - fileoff;
                    if (fileoff_delta > filesize) {
                        std::cerr << "[!] MachOParser: Section file offset exceeds segment filesize: " << filepath << std::endl;
                        mitigations_.segment_stream_complete = false;
                        finalizeMitigations();
                        return false;
                    }
                    uint32_t remaining_filesize = filesize - fileoff_delta;
                    if (s_size > remaining_filesize) {
                        std::cerr << "[!] MachOParser: Section file range exceeds segment filesize: " << filepath << std::endl;
                        mitigations_.segment_stream_complete = false;
                        finalizeMitigations();
                        return false;
                    }
                    if (s_off64 > sliceSize_) {
                        std::cerr << "[!] MachOParser: Section file offset exceeds slice size: " << filepath << std::endl;
                        mitigations_.segment_stream_complete = false;
                        finalizeMitigations();
                        return false;
                    }
                    uint64_t remaining_slice = sliceSize_ - s_off64;
                    if (static_cast<uint64_t>(s_size) > remaining_slice) {
                        std::cerr << "[!] MachOParser: Section file range exceeds slice size: " << filepath << std::endl;
                        mitigations_.segment_stream_complete = false;
                        finalizeMitigations();
                        return false;
                    }
                    uint64_t total_file_size = static_cast<uint64_t>(file_size);
                    if (sliceOffset_ > total_file_size) {
                        std::cerr << "[!] MachOParser: Slice offset exceeds container file size: " << filepath << std::endl;
                        mitigations_.segment_stream_complete = false;
                        finalizeMitigations();
                        return false;
                    }
                    uint64_t remaining_file_after_slice = total_file_size - sliceOffset_;
                    if (s_off64 > remaining_file_after_slice) {
                        std::cerr << "[!] MachOParser: Section file offset exceeds container file bounds: " << filepath << std::endl;
                        mitigations_.segment_stream_complete = false;
                        finalizeMitigations();
                        return false;
                    }
                    uint64_t remaining_file_after_sec = remaining_file_after_slice - s_off64;
                    if (static_cast<uint64_t>(s_size) > remaining_file_after_sec) {
                        std::cerr << "[!] MachOParser: Section file size exceeds container file bounds: " << filepath << std::endl;
                        mitigations_.segment_stream_complete = false;
                        finalizeMitigations();
                        return false;
                    }
                }

                SectionInfo secInfo;
                std::string sect_name_str(s_sectname, strnlen(s_sectname, 16));
                std::string seg_name_str(s_segname, strnlen(s_segname, 16));
                secInfo.name = seg_name_str + "," + sect_name_str;
                secInfo.virtual_address = s_addr;
                secInfo.virtual_size = s_size;
                secInfo.raw_offset = is_zerofill ? 0 : (sliceOffset_ + s_offset);
                secInfo.raw_size = is_zerofill ? 0 : s_size;
                secInfo.characteristics = s_flags;
                secInfo.segment_name = segInfo.name;
                secInfo.segment_initprot = segInfo.initprot;
                secInfo.segment_maxprot = segInfo.maxprot;
                secInfo.segment_vmaddr = segInfo.vmaddr;
                secInfo.segment_vmsize = segInfo.vmsize;
                secInfo.is_executable = !is_zerofill &&
                                        (s_size > 0) &&
                                        ((initprot & VM_PROT_EXECUTE) != 0) &&
                                        (((s_flags & (S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS)) != 0) ||
                                         (sect_name_str == "__text" && seg_name_str == "__TEXT"));
                sections_.push_back(secInfo);

                if (std::strncmp(s_segname, "__TEXT", 16) == 0 && std::strncmp(s_sectname, "__text", 16) == 0) {
                    found_text_section = true;
                    text_sec_addr = s_addr;
                }
            }

            if ((initprot & (VM_PROT_WRITE | VM_PROT_EXECUTE)) == (VM_PROT_WRITE | VM_PROT_EXECUTE)) {
                mitigations_.has_wx_initprot = true;
            }
            if ((maxprot & (VM_PROT_WRITE | VM_PROT_EXECUTE)) == (VM_PROT_WRITE | VM_PROT_EXECUTE)) {
                mitigations_.has_wx_maxprot = true;
            }
            mitigations_.inspected_segments++;
        } else if (cmd == LC_SEGMENT_64) {
            if (!is64Bit_) {
                std::cerr << "[!] MachOParser: 64-bit LC_SEGMENT_64 in 32-bit Mach-O binary: " << filepath << std::endl;
                mitigations_.segment_stream_complete = false;
                finalizeMitigations();
                return false;
            }
            if (cmdsize < sizeof(segment_command_64)) {
                std::cerr << "[!] MachOParser: Truncated segment_command_64: " << filepath << std::endl;
                mitigations_.segment_stream_complete = false;
                finalizeMitigations();
                return false;
            }

            char segname[17] = {0};
            std::memcpy(segname, cmd_ptr + 8, 16);
            uint64_t vmaddr   = read_u64(cmd_ptr + 24, isBigEndian_);
            uint64_t vmsize   = read_u64(cmd_ptr + 32, isBigEndian_);
            uint64_t fileoff  = read_u64(cmd_ptr + 40, isBigEndian_);
            uint64_t filesize = read_u64(cmd_ptr + 48, isBigEndian_);
            int32_t  maxprot  = read_i32(cmd_ptr + 56, isBigEndian_);
            int32_t  initprot = read_i32(cmd_ptr + 60, isBigEndian_);
            uint32_t nsects   = read_u32(cmd_ptr + 64, isBigEndian_);
            uint32_t segflags = read_u32(cmd_ptr + 68, isBigEndian_);
            (void)segflags;

            if (nsects > (cmdsize - sizeof(segment_command_64)) / sizeof(section_64)) {
                std::cerr << "[!] MachOParser: nsects exceeds segment_64 command size: " << filepath << std::endl;
                mitigations_.segment_stream_complete = false;
                finalizeMitigations();
                return false;
            }

            // 1. Virtual segment range overflow (64-bit)
            if (vmaddr > UINT64_MAX - vmsize) {
                std::cerr << "[!] MachOParser: 64-bit segment virtual range overflows 64-bit address space: " << filepath << std::endl;
                mitigations_.segment_stream_complete = false;
                finalizeMitigations();
                return false;
            }

            // 2. File segment range overflow (64-bit)
            if (fileoff > UINT64_MAX - filesize) {
                std::cerr << "[!] MachOParser: 64-bit segment file range overflows 64-bit address space: " << filepath << std::endl;
                mitigations_.segment_stream_complete = false;
                finalizeMitigations();
                return false;
            }

            // 3. Unconditional file offset containment within slice (even if filesize == 0)
            if (fileoff > sliceSize_) {
                std::cerr << "[!] MachOParser: Segment fileoff exceeds slice size: " << filepath << std::endl;
                mitigations_.segment_stream_complete = false;
                finalizeMitigations();
                return false;
            }

            // 4. File range containment within slice for non-zero filesize
            if (filesize > sliceSize_ - fileoff) {
                std::cerr << "[!] MachOParser: Segment file range exceeds slice size: " << filepath << std::endl;
                mitigations_.segment_stream_complete = false;
                finalizeMitigations();
                return false;
            }

            if (std::strncmp(segname, "__TEXT", 16) == 0) {
                imageBase_ = vmaddr;
            }

            MachOSegmentInfo segInfo;
            segInfo.name = std::string(segname, strnlen(segname, 16));
            segInfo.vmaddr = vmaddr;
            segInfo.vmsize = vmsize;
            segInfo.fileoff = fileoff;
            segInfo.filesize = filesize;
            segInfo.maxprot = static_cast<uint32_t>(maxprot);
            segInfo.initprot = static_cast<uint32_t>(initprot);
            segInfo.nsects = nsects;
            segInfo.flags = segflags;
            segments_.push_back(segInfo);

            for (uint32_t s = 0; s < nsects; ++s) {
                const uint8_t* sec_ptr = cmd_ptr + sizeof(segment_command_64) + s * sizeof(section_64);
                char s_sectname[17] = {0};
                std::memcpy(s_sectname, sec_ptr, 16);
                char s_segname[17] = {0};
                std::memcpy(s_segname, sec_ptr + 16, 16);
                uint64_t s_addr   = read_u64(sec_ptr + 32, isBigEndian_);
                uint64_t s_size   = read_u64(sec_ptr + 40, isBigEndian_);
                uint32_t s_offset = read_u32(sec_ptr + 48, isBigEndian_);
                uint32_t s_align  = read_u32(sec_ptr + 52, isBigEndian_);
                uint32_t s_reloff = read_u32(sec_ptr + 56, isBigEndian_);
                uint32_t s_nreloc = read_u32(sec_ptr + 60, isBigEndian_);
                uint32_t s_flags  = read_u32(sec_ptr + 64, isBigEndian_);
                (void)s_align;
                (void)s_reloff;
                (void)s_nreloc;

                if (std::strncmp(s_segname, segname, 16) != 0) {
                    std::cerr << "[!] MachOParser: Section segname does not match segment: " << filepath << std::endl;
                    mitigations_.segment_stream_complete = false;
                    finalizeMitigations();
                    return false;
                }

                // Section virtual range overflow check
                if (s_addr > UINT64_MAX - s_size) {
                    std::cerr << "[!] MachOParser: Section virtual range overflows 64-bit integer: " << filepath << std::endl;
                    mitigations_.segment_stream_complete = false;
                    finalizeMitigations();
                    return false;
                }

                // Section virtual address before segment vmaddr
                if (s_addr < vmaddr) {
                    std::cerr << "[!] MachOParser: Section virtual address before segment vmaddr: " << filepath << std::endl;
                    mitigations_.segment_stream_complete = false;
                    finalizeMitigations();
                    return false;
                }

                uint64_t va_delta = s_addr - vmaddr;
                if (va_delta > vmsize) {
                    std::cerr << "[!] MachOParser: Section virtual offset exceeds segment vmsize: " << filepath << std::endl;
                    mitigations_.segment_stream_complete = false;
                    finalizeMitigations();
                    return false;
                }
                uint64_t remaining_vm = vmsize - va_delta;
                if (s_size > remaining_vm) {
                    std::cerr << "[!] MachOParser: Section virtual range exceeds segment: " << filepath << std::endl;
                    mitigations_.segment_stream_complete = false;
                    finalizeMitigations();
                    return false;
                }

                bool is_zerofill = isZeroFillSection(s_flags);
                if (!is_zerofill && s_size > 0) {
                    uint64_t s_off64 = static_cast<uint64_t>(s_offset);
                    if (s_off64 > UINT64_MAX - s_size) {
                        std::cerr << "[!] MachOParser: Section file range overflows 64-bit integer: " << filepath << std::endl;
                        mitigations_.segment_stream_complete = false;
                        finalizeMitigations();
                        return false;
                    }
                    if (s_off64 < fileoff) {
                        std::cerr << "[!] MachOParser: Section file offset before segment fileoff: " << filepath << std::endl;
                        mitigations_.segment_stream_complete = false;
                        finalizeMitigations();
                        return false;
                    }
                    uint64_t fileoff_delta = s_off64 - fileoff;
                    if (fileoff_delta > filesize) {
                        std::cerr << "[!] MachOParser: Section file offset exceeds segment filesize: " << filepath << std::endl;
                        mitigations_.segment_stream_complete = false;
                        finalizeMitigations();
                        return false;
                    }
                    uint64_t remaining_filesize = filesize - fileoff_delta;
                    if (s_size > remaining_filesize) {
                        std::cerr << "[!] MachOParser: Section file range exceeds segment filesize: " << filepath << std::endl;
                        mitigations_.segment_stream_complete = false;
                        finalizeMitigations();
                        return false;
                    }
                    if (s_off64 > sliceSize_) {
                        std::cerr << "[!] MachOParser: Section file offset exceeds slice size: " << filepath << std::endl;
                        mitigations_.segment_stream_complete = false;
                        finalizeMitigations();
                        return false;
                    }
                    uint64_t remaining_slice = sliceSize_ - s_off64;
                    if (s_size > remaining_slice) {
                        std::cerr << "[!] MachOParser: Section file range exceeds slice size: " << filepath << std::endl;
                        mitigations_.segment_stream_complete = false;
                        finalizeMitigations();
                        return false;
                    }
                    uint64_t total_file_size = static_cast<uint64_t>(file_size);
                    if (sliceOffset_ > total_file_size) {
                        std::cerr << "[!] MachOParser: Slice offset exceeds container file size: " << filepath << std::endl;
                        mitigations_.segment_stream_complete = false;
                        finalizeMitigations();
                        return false;
                    }
                    uint64_t remaining_file_after_slice = total_file_size - sliceOffset_;
                    if (s_off64 > remaining_file_after_slice) {
                        std::cerr << "[!] MachOParser: Section file offset exceeds container file bounds: " << filepath << std::endl;
                        mitigations_.segment_stream_complete = false;
                        finalizeMitigations();
                        return false;
                    }
                    uint64_t remaining_file_after_sec = remaining_file_after_slice - s_off64;
                    if (s_size > remaining_file_after_sec) {
                        std::cerr << "[!] MachOParser: Section file size exceeds container file bounds: " << filepath << std::endl;
                        mitigations_.segment_stream_complete = false;
                        finalizeMitigations();
                        return false;
                    }
                }

                SectionInfo secInfo;
                std::string sect_name_str(s_sectname, strnlen(s_sectname, 16));
                std::string seg_name_str(s_segname, strnlen(s_segname, 16));
                secInfo.name = seg_name_str + "," + sect_name_str;
                secInfo.virtual_address = s_addr;
                secInfo.virtual_size = s_size;
                secInfo.raw_offset = is_zerofill ? 0 : (sliceOffset_ + s_offset);
                secInfo.raw_size = is_zerofill ? 0 : s_size;
                secInfo.characteristics = s_flags;
                secInfo.segment_name = segInfo.name;
                secInfo.segment_initprot = segInfo.initprot;
                secInfo.segment_maxprot = segInfo.maxprot;
                secInfo.segment_vmaddr = segInfo.vmaddr;
                secInfo.segment_vmsize = segInfo.vmsize;
                secInfo.is_executable = !is_zerofill &&
                                        (s_size > 0) &&
                                        ((initprot & VM_PROT_EXECUTE) != 0) &&
                                        (((s_flags & (S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS)) != 0) ||
                                         (sect_name_str == "__text" && seg_name_str == "__TEXT"));
                sections_.push_back(secInfo);

                if (std::strncmp(s_segname, "__TEXT", 16) == 0 && std::strncmp(s_sectname, "__text", 16) == 0) {
                    found_text_section = true;
                    text_sec_addr = s_addr;
                }
            }

            if ((initprot & (VM_PROT_WRITE | VM_PROT_EXECUTE)) == (VM_PROT_WRITE | VM_PROT_EXECUTE)) {
                mitigations_.has_wx_initprot = true;
            }
            if ((maxprot & (VM_PROT_WRITE | VM_PROT_EXECUTE)) == (VM_PROT_WRITE | VM_PROT_EXECUTE)) {
                mitigations_.has_wx_maxprot = true;
            }
            mitigations_.inspected_segments++;
        } else if (cmd == LC_SYMTAB) {
            parseSymtab(file, file_size, cmd_ptr, cmdsize);
        } else if (cmd == LC_CODE_SIGNATURE) {
            parseCodeSignature(file, file_size, cmd_ptr, cmdsize);
        }

        cmd_offset += cmdsize;
    }

    mitigations_.segment_stream_complete = true;
    finalizeMitigations();

    // Aggregate eligible executable sections:
    // 1. Must be marked executable (initprot & VM_PROT_EXECUTE != 0, instructions flag or __TEXT,__text)
    // 2. Must be file-backed and non-empty (raw_size > 0)
    std::vector<SectionInfo> exec_secs;
    for (const auto& sec : sections_) {
        if (sec.is_executable && sec.raw_size > 0) {
            exec_secs.push_back(sec);
        }
    }

    if (exec_secs.empty()) {
        std::cerr << "[!] MachOParser: No eligible executable sections found: " << filepath << std::endl;
        return false;
    }

    // Sort eligible sections in ascending order of virtual address
    std::sort(exec_secs.begin(), exec_secs.end(), [](const SectionInfo& a, const SectionInfo& b) {
        return a.virtual_address < b.virtual_address;
    });

    if (found_text_section) {
        textBaseAddr_ = text_sec_addr;
    } else {
        textBaseAddr_ = exec_secs[0].virtual_address;
    }

    textSection_.clear();
    execMappings_.clear();

    for (size_t i = 0; i < exec_secs.size(); ++i) {
        const auto& sec = exec_secs[i];

        if (sec.raw_size > static_cast<uint64_t>(SIZE_MAX)) {
            std::cerr << "[!] MachOParser: Section raw size exceeds host size_t: " << filepath << std::endl;
            textSection_.clear();
            execMappings_.clear();
            return false;
        }
        size_t sec_bytes = static_cast<size_t>(sec.raw_size);

        if (i > 0) {
            if (textSection_.size() > SIZE_MAX - 4) {
                std::cerr << "[!] MachOParser: Buffer growth overflows size_t on fence: " << filepath << std::endl;
                textSection_.clear();
                execMappings_.clear();
                return false;
            }
            // 4-byte 0xCC boundary fence between sections
            textSection_.push_back(0xCC);
            textSection_.push_back(0xCC);
            textSection_.push_back(0xCC);
            textSection_.push_back(0xCC);
        }

        if (sec_bytes > SIZE_MAX - textSection_.size()) {
            std::cerr << "[!] MachOParser: Buffer growth overflows size_t on section data: " << filepath << std::endl;
            textSection_.clear();
            execMappings_.clear();
            return false;
        }

        ExecBufferMapping mapping;
        mapping.virtual_address = sec.virtual_address;
        mapping.buffer_offset   = textSection_.size();
        mapping.size            = sec.raw_size;
        mapping.raw_offset      = sec.raw_offset; // sliceOffset_ + s_offset (applied exactly once)
        mapping.section_name    = sec.name;
        execMappings_.push_back(mapping);

        file.seekg(sec.raw_offset, std::ios::beg);
        size_t cur_pos = textSection_.size();
        textSection_.resize(cur_pos + sec_bytes);
        if (!file.read(reinterpret_cast<char*>(textSection_.data() + cur_pos), sec_bytes)) {
            std::cerr << "[!] MachOParser: Failed to read executable section data: " << filepath << std::endl;
            textSection_.clear();
            execMappings_.clear();
            return false;
        }
    }

    return true;
}

const std::vector<uint8_t>& MachOParser::getTextSection() const {
    return textSection_;
}

uint64_t MachOParser::getTextSectionBaseAddress() const {
    return textBaseAddr_;
}

std::string MachOParser::getArchitecture() const {
    return arch_;
}

bool MachOParser::is64Bit() const {
    return is64Bit_;
}

Endianness MachOParser::getMetadataEndianness() const {
    return isBigEndian_ ? Endianness::Big : Endianness::Little;
}

Endianness MachOParser::getInstructionEndianness() const {
    if (arch_ == "x86" || arch_ == "x86_64") {
        return isBigEndian_ ? Endianness::Unsupported : Endianness::Little;
    }
    if (arch_ == "armv7" || arch_ == "aarch64") {
        return isBigEndian_ ? Endianness::Unsupported : Endianness::Little;
    }
    return Endianness::Unknown;
}

bool MachOParser::isNxEnabled() const {
    // Conservative summary: Reflects Stack Non-Executability
    return (flags_ & MH_ALLOW_STACK_EXECUTION) == 0;
}

void MachOParser::parseSymtab(std::ifstream& file, size_t fileSize, const uint8_t* cmd_ptr, uint32_t cmdsize) {
    if (seen_symtab_cmd_) {
        std::cerr << "[!] MachOParser: Duplicate LC_SYMTAB load command detected" << std::endl;
        if (mitigations_.canary_status != CanaryStatus::SymbolDetected) {
            mitigations_.canary_status = CanaryStatus::Unknown;
        }
        return;
    }
    seen_symtab_cmd_ = true;

    if (cmdsize < sizeof(symtab_command)) {
        mitigations_.canary_status = CanaryStatus::Unknown;
        return;
    }

    uint32_t symoff  = read_u32(cmd_ptr + 8,  isBigEndian_);
    uint32_t nsyms   = read_u32(cmd_ptr + 12, isBigEndian_);
    uint32_t stroff  = read_u32(cmd_ptr + 16, isBigEndian_);
    uint32_t strsize = read_u32(cmd_ptr + 20, isBigEndian_);

    if (nsyms == 0 || strsize == 0) {
        mitigations_.canary_status = CanaryStatus::Unknown;
        return;
    }

    size_t entry_size = is64Bit_ ? sizeof(nlist_64) : sizeof(nlist_32);
    if (entry_size > 0 && static_cast<uint64_t>(nsyms) > ((std::numeric_limits<size_t>::max)() / entry_size)) {
        mitigations_.canary_status = CanaryStatus::Unknown;
        return;
    }
    size_t symtab_bytes = static_cast<size_t>(nsyms) * entry_size;

    const size_t MAX_ALLOCATION_LIMIT = 16 * 1024 * 1024; // 16 MB
    if (symtab_bytes > MAX_ALLOCATION_LIMIT || strsize > MAX_ALLOCATION_LIMIT) {
        mitigations_.canary_status = CanaryStatus::Unknown;
        return;
    }

    // Bounds checks: slice-relative and physical file
    if (symoff > sliceSize_ || symtab_bytes > sliceSize_ - symoff) {
        mitigations_.canary_status = CanaryStatus::Unknown;
        return;
    }
    if (stroff > sliceSize_ || strsize > sliceSize_ - stroff) {
        mitigations_.canary_status = CanaryStatus::Unknown;
        return;
    }
    if (sliceOffset_ + symoff > fileSize || symtab_bytes > fileSize - (sliceOffset_ + symoff)) {
        mitigations_.canary_status = CanaryStatus::Unknown;
        return;
    }
    if (sliceOffset_ + stroff > fileSize || strsize > fileSize - (sliceOffset_ + stroff)) {
        mitigations_.canary_status = CanaryStatus::Unknown;
        return;
    }

    std::vector<char> str_table(strsize);
    file.seekg(sliceOffset_ + stroff, std::ios::beg);
    if (!file.read(str_table.data(), strsize)) {
        mitigations_.canary_status = CanaryStatus::Unknown;
        return;
    }

    if (str_table[0] != '\0') {
        mitigations_.canary_status = CanaryStatus::Unknown;
        return;
    }

    std::vector<uint8_t> sym_table(symtab_bytes);
    file.seekg(sliceOffset_ + symoff, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(sym_table.data()), symtab_bytes)) {
        mitigations_.canary_status = CanaryStatus::Unknown;
        return;
    }

    bool found_canary = false;
    bool had_malformed_entry = false;

    for (uint32_t s = 0; s < nsyms; ++s) {
        const uint8_t* entry_ptr = sym_table.data() + s * entry_size;
        uint32_t n_strx = read_u32(entry_ptr, isBigEndian_);
        uint8_t  n_type = *(entry_ptr + 4);
        uint8_t  n_sect = *(entry_ptr + 5);
        uint16_t n_desc = read_u16(entry_ptr + 6, isBigEndian_);
        uint64_t n_value = is64Bit_ ? read_u64(entry_ptr + 8, isBigEndian_) : static_cast<uint64_t>(read_u32(entry_ptr + 8, isBigEndian_));
        (void)n_sect;
        (void)n_desc;
        (void)n_value;

        // n_strx == 0 is valid empty string reference
        if (n_strx == 0) {
            continue;
        }

        if (n_strx >= strsize) {
            had_malformed_entry = true;
            continue;
        }

        // Bounded NUL-termination check within string table
        size_t max_len = strsize - n_strx;
        const char* str_start = str_table.data() + n_strx;
        const char* nul_pos = static_cast<const char*>(std::memchr(str_start, '\0', max_len));
        if (!nul_pos) {
            had_malformed_entry = true;
            continue;
        }

        std::string sym_name(str_start, nul_pos - str_start);
        if (sym_name == "___stack_chk_fail" || sym_name == "___stack_chk_guard") {
            // Verify undefined external symbol
            if (((n_type & N_TYPE) == N_UNDF || (n_type & N_TYPE) == N_PBUD) && (n_type & N_EXT) != 0) {
                found_canary = true;
                mitigations_.canary_symbol_name = sym_name;
                break; // Positive validated evidence established
            }
        }
    }

    // Precedence:
    // 1. Positive validated canary symbol establishes SYMBOL_DETECTED
    // 2. If no canary symbol and any entry malformed -> UNKNOWN
    // 3. Otherwise, 100% complete and clean -> NOT_DETECTED
    if (found_canary) {
        mitigations_.canary_status = CanaryStatus::SymbolDetected;
    } else if (had_malformed_entry) {
        mitigations_.canary_status = CanaryStatus::Unknown;
    } else {
        mitigations_.canary_status = CanaryStatus::NotDetected;
    }
}

void MachOParser::parseCodeSignature(std::ifstream& file, size_t fileSize, const uint8_t* cmd_ptr, uint32_t cmdsize) {
    if (seen_code_signature_cmd_) {
        std::cerr << "[!] MachOParser: Duplicate LC_CODE_SIGNATURE command detected" << std::endl;
        mitigations_.has_code_signature_cmd = true;
        mitigations_.data_range_valid = false;
        mitigations_.superblob_header_valid = false;
        mitigations_.code_signature_notes = "Ambiguous: Duplicate LC_CODE_SIGNATURE commands detected; metadata untrusted.";
        return;
    }
    seen_code_signature_cmd_ = true;
    mitigations_.has_code_signature_cmd = true;

    if (cmdsize != sizeof(linkedit_data_command)) {
        mitigations_.data_range_valid = false;
        mitigations_.superblob_header_valid = false;
        mitigations_.code_signature_notes = "Malformed LC_CODE_SIGNATURE cmdsize (must be exactly 16 bytes)";
        return;
    }

    uint32_t dataoff  = read_u32(cmd_ptr + 8,  isBigEndian_);
    uint32_t datasize = read_u32(cmd_ptr + 12, isBigEndian_);

    if (datasize < 12) {
        mitigations_.data_range_valid = false;
        mitigations_.superblob_header_valid = false;
        mitigations_.code_signature_notes = "LC_CODE_SIGNATURE datasize too small for SuperBlob header";
        return;
    }

    if (dataoff > sliceSize_ || datasize > sliceSize_ - dataoff) {
        mitigations_.data_range_valid = false;
        mitigations_.superblob_header_valid = false;
        mitigations_.code_signature_notes = "LC_CODE_SIGNATURE data range exceeds slice bounds";
        return;
    }
    if (sliceOffset_ + dataoff > fileSize || datasize > fileSize - (sliceOffset_ + dataoff)) {
        mitigations_.data_range_valid = false;
        mitigations_.superblob_header_valid = false;
        mitigations_.code_signature_notes = "LC_CODE_SIGNATURE data range exceeds physical file bounds";
        return;
    }

    mitigations_.data_range_valid = true;

    uint8_t sb_hdr[12];
    file.seekg(sliceOffset_ + dataoff, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(sb_hdr), 12)) {
        mitigations_.superblob_header_valid = false;
        mitigations_.code_signature_notes = "Failed to read CS_SuperBlob header";
        return;
    }

    // Decode SuperBlob fields strictly as big-endian
    uint32_t sb_magic  = read_u32(sb_hdr + 0, true);
    uint32_t sb_length = read_u32(sb_hdr + 4, true);
    uint32_t sb_count  = read_u32(sb_hdr + 8, true);

    if (sb_magic == CSMAGIC_EMBEDDED_SIGNATURE &&
        sb_length >= 12 && sb_length <= datasize) {
        // Validate index array size using overflow-safe arithmetic:
        // count <= (length - 12) / 8
        if (sb_count <= (sb_length - 12) / 8) {
            mitigations_.superblob_header_valid = true;
            mitigations_.code_signature_notes = "Structural SuperBlob header validation only; individual blob indexes and cryptographic certificate chains were not verified.";
        } else {
            mitigations_.superblob_header_valid = false;
            mitigations_.code_signature_notes = "CS_SuperBlob index count exceeds declared blob length";
        }
    } else {
        mitigations_.superblob_header_valid = false;
        mitigations_.code_signature_notes = "CS_SuperBlob magic or length mismatch";
    }
}

void MachOParser::finalizeMitigations() {
    // Precedence:
    // 1. InitViolation
    // 2. IncompleteOrUnavailable
    // 3. MaxprotPermissive
    // 4. Compliant
    if (mitigations_.has_wx_initprot) {
        mitigations_.segment_wx_status = SegmentWxStatus::InitViolation;
    } else if (!mitigations_.segment_stream_complete ||
               mitigations_.inspected_segments == 0 ||
               mitigations_.inspected_segments < mitigations_.total_declared_segments) {
        mitigations_.segment_wx_status = SegmentWxStatus::IncompleteOrUnavailable;
    } else if (mitigations_.has_wx_maxprot) {
        mitigations_.segment_wx_status = SegmentWxStatus::MaxprotPermissive;
    } else {
        mitigations_.segment_wx_status = SegmentWxStatus::Compliant;
    }
}
