#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

// Global constants for Mach-O magic numbers
#define MH_MAGIC     0xfeedface
#define MH_CIGAM     0xcefaedfe
#define MH_MAGIC_64  0xfeedfacf
#define MH_CIGAM_64  0xcffaedfe
#define FAT_MAGIC    0xcafebabe
#define FAT_CIGAM    0xbebafeca
#define FAT_MAGIC_64 0xcafebabf
#define FAT_CIGAM_64 0xbfbafeca

// CPU architecture constants
#define CPU_ARCH_ABI64    0x01000000
#define CPU_TYPE_X86      7
#define CPU_TYPE_I386     CPU_TYPE_X86
#define CPU_TYPE_X86_64   (CPU_TYPE_X86 | CPU_ARCH_ABI64)
#define CPU_TYPE_ARM      12
#define CPU_TYPE_ARM64    (CPU_TYPE_ARM | CPU_ARCH_ABI64)
#define CPU_TYPE_POWERPC  18
#define CPU_TYPE_POWERPC64 (CPU_TYPE_POWERPC | CPU_ARCH_ABI64)

// CPU Subtypes and Capability Masks
#define CPU_SUBTYPE_MASK           0xff000000
#define CPU_SUBTYPE_LIB64          0x80000000

#define CPU_SUBTYPE_I386_ALL       3
#define CPU_SUBTYPE_386            3
#define CPU_SUBTYPE_486            4
#define CPU_SUBTYPE_586            5

#define CPU_SUBTYPE_X86_ALL        3
#define CPU_SUBTYPE_X86_64_ALL     3
#define CPU_SUBTYPE_X86_64_H       8

#define CPU_SUBTYPE_ARM_ALL        0
#define CPU_SUBTYPE_ARM_V4T        5
#define CPU_SUBTYPE_ARM_V6         6
#define CPU_SUBTYPE_ARM_V5TEJ      7
#define CPU_SUBTYPE_ARM_XSCALE     8
#define CPU_SUBTYPE_ARM_V7         9
#define CPU_SUBTYPE_ARM_V7F        10
#define CPU_SUBTYPE_ARM_V7S        11
#define CPU_SUBTYPE_ARM_V7K        12
#define CPU_SUBTYPE_ARM_V8         13
#define CPU_SUBTYPE_ARM_V6M        14
#define CPU_SUBTYPE_ARM_V7M        15
#define CPU_SUBTYPE_ARM_V7EM       16

#define CPU_SUBTYPE_ARM64_ALL      0
#define CPU_SUBTYPE_ARM64_V8       1
#define CPU_SUBTYPE_ARM64E         2

#define CPU_SUBTYPE_POWERPC_ALL    0

// Mach-O File Types
#define MH_OBJECT       0x1     // Relocatable object file
#define MH_EXECUTE      0x2     // Demand-paged executable file
#define MH_FVMLIB       0x3     // Fixed VM shared library file
#define MH_CORE         0x4     // Core file
#define MH_PREBOUND     0x5     // Prebound shared library file
#define MH_DYLIB        0x6     // Dynamically bound shared library
#define MH_DYLINKER     0x7     // Dynamic link editor
#define MH_BUNDLE       0x8     // Dynamically bound bundle file
#define MH_DYLIB_STUB   0x9     // Shared library stub for static linking only
#define MH_DSYM         0xa     // Companion file with only debug sections
#define MH_KEXT_BUNDLE  0xb     // x86_64 kernel extension bundle

// Mach-O Header Flags
#define MH_NOUNDEFS                0x1
#define MH_INCRLINK                0x2
#define MH_DYLDLINK                0x4
#define MH_BINDATLOAD              0x8
#define MH_PREBOUND_FLAG           0x10
#define MH_SPLIT_SEGS              0x20
#define MH_LAZY_INIT               0x40
#define MH_TWOLEVEL                0x80
#define MH_FORCE_FLAT              0x100
#define MH_NOMULTIDEFS             0x200
#define MH_NOFIXPREBINDING         0x400
#define MH_PREBINDABLE             0x800
#define MH_ALLMODSBOUND            0x1000
#define MH_SUBSECTIONS_VIA_SYMBOLS 0x2000
#define MH_CANONICAL               0x4000
#define MH_WEAK_DEFINES            0x8000
#define MH_BINDS_TO_WEAK           0x10000
#define MH_ALLOW_STACK_EXECUTION   0x20000
#define MH_ROOT_SAFE               0x40000
#define MH_SETUID_SAFE             0x80000
#define MH_NO_REEXPORTED_DYLIBS    0x100000
#define MH_PIE                     0x200000
#define MH_DEAD_STRIPPABLE_DYLIB   0x400000
#define MH_HAS_TLV_DESCRIPTORS     0x800000
#define MH_NO_HEAP_EXECUTION       0x1000000

// Mach-O Load Commands
#define LC_REQ_DYLD                0x80000000
#define LC_SEGMENT                 0x1
#define LC_SYMTAB                  0x2
#define LC_DYSYMTAB                0xb
#define LC_CODE_SIGNATURE          0x1d
#define LC_SEGMENT_64              0x19

// Mach-O Symbol Types and Masks (<mach-o/nlist.h>)
#define N_STAB                     0xe0
#define N_PEXT                     0x10
#define N_TYPE                     0x0e
#define N_EXT                      0x01
#define N_UNDF                     0x0
#define N_ABS                      0x2
#define N_SECT                     0xe
#define N_PBUD                     0xc
#define N_INDR                     0xa

// Code Signing SuperBlob Magic (cs_blobs.h)
#define CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0

// VM Protection Flags
#define VM_PROT_NONE               0x0
#define VM_PROT_READ               0x1
#define VM_PROT_WRITE              0x2
#define VM_PROT_EXECUTE            0x4

// Mach-O Section Types and Attributes
#define SECTION_TYPE               0x000000ff
#define SECTION_ATTRIBUTES         0xffffff00
#define S_REGULAR                  0x0
#define S_ZEROFILL                 0x1
#define S_CSTRING_LITERALS         0x2
#define S_4BYTE_LITERALS           0x3
#define S_8BYTE_LITERALS           0x4
#define S_LITERAL_POINTERS         0x5
#define S_NON_LAZY_SYMBOL_POINTERS 0x6
#define S_LAZY_SYMBOL_POINTERS     0x7
#define S_SYMBOL_STUBS             0x8
#define S_MOD_INIT_FUNC_POINTERS   0x9
#define S_MOD_TERM_FUNC_POINTERS   0xa
#define S_COALESCED                0xb
#define S_GB_ZEROFILL              0xc
#define S_INTERPOSING              0xd
#define S_16BYTE_LITERALS          0xe
#define S_DTRACE_DOF               0xf
#define S_LAZY_DYLIB_SYMBOL_POINTERS 0x10
#define S_THREAD_LOCAL_REGULAR     0x11
#define S_THREAD_LOCAL_ZEROFILL    0x12
#define S_THREAD_LOCAL_VARIABLES   0x13
#define S_THREAD_LOCAL_VARIABLE_POINTERS 0x14
#define S_THREAD_LOCAL_INIT_FUNCTION_POINTERS 0x15

#define S_ATTR_SOME_INSTRUCTIONS   0x00000400
#define S_ATTR_PURE_INSTRUCTIONS   0x80000000

namespace ropweaver {

#pragma pack(push, 1)

// Thin Mach-O 32-bit Header (28 bytes)
struct MachO_Header_32 {
    uint32_t magic;
    int32_t  cputype;
    int32_t  cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
};

// Thin Mach-O 64-bit Header (32 bytes)
struct MachO_Header_64 {
    uint32_t magic;
    int32_t  cputype;
    int32_t  cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};

// Base load_command (8 bytes)
struct load_command {
    uint32_t cmd;
    uint32_t cmdsize;
};

// 32-bit Segment Command (56 bytes)
struct segment_command {
    uint32_t cmd;
    uint32_t cmdsize;
    char     segname[16];
    uint32_t vmaddr;
    uint32_t vmsize;
    uint32_t fileoff;
    uint32_t filesize;
    int32_t  maxprot;
    int32_t  initprot;
    uint32_t nsects;
    uint32_t flags;
};

// 64-bit Segment Command (72 bytes)
struct segment_command_64 {
    uint32_t cmd;
    uint32_t cmdsize;
    char     segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    int32_t  maxprot;
    int32_t  initprot;
    uint32_t nsects;
    uint32_t flags;
};

// 32-bit Section (68 bytes)
struct section {
    char     sectname[16];
    char     segname[16];
    uint32_t addr;
    uint32_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
};

// 64-bit Section (80 bytes)
struct section_64 {
    char     sectname[16];
    char     segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
};

// Symbol Table Load Command (24 bytes)
struct symtab_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t symoff;
    uint32_t nsyms;
    uint32_t stroff;
    uint32_t strsize;
};

// Linkedit Data Command for LC_CODE_SIGNATURE (16 bytes)
struct linkedit_data_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dataoff;
    uint32_t datasize;
};

// 32-bit Symbol Table Entry (12 bytes)
struct nlist_32 {
    uint32_t n_strx;
    uint8_t  n_type;
    uint8_t  n_sect;
    uint16_t n_desc;
    uint32_t n_value;
};

// 64-bit Symbol Table Entry (16 bytes)
struct nlist_64 {
    uint32_t n_strx;
    uint8_t  n_type;
    uint8_t  n_sect;
    uint16_t n_desc;
    uint64_t n_value;
};

// Universal Fat Binary Header (8 bytes)
struct fat_header {
    uint32_t magic;
    uint32_t nfat_arch;
};

// 32-bit Architecture Record (20 bytes)
struct fat_arch {
    int32_t  cputype;
    int32_t  cpusubtype;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
};

// 64-bit Architecture Record (32 bytes)
struct fat_arch_64 {
    int32_t  cputype;
    int32_t  cpusubtype;
    uint64_t offset;
    uint64_t size;
    uint32_t align;
    uint32_t reserved;
};

#pragma pack(pop)

static_assert(sizeof(MachO_Header_32) == 28, "MachO_Header_32 must be exactly 28 bytes");
static_assert(sizeof(MachO_Header_64) == 32, "MachO_Header_64 must be exactly 32 bytes");
static_assert(sizeof(load_command) == 8, "load_command must be exactly 8 bytes");
static_assert(sizeof(segment_command) == 56, "segment_command must be exactly 56 bytes");
static_assert(sizeof(segment_command_64) == 72, "segment_command_64 must be exactly 72 bytes");
static_assert(sizeof(section) == 68, "section must be exactly 68 bytes");
static_assert(sizeof(section_64) == 80, "section_64 must be exactly 80 bytes");
static_assert(sizeof(fat_header) == 8, "fat_header must be exactly 8 bytes");
static_assert(sizeof(fat_arch) == 20, "fat_arch must be exactly 20 bytes");
static_assert(sizeof(fat_arch_64) == 32, "fat_arch_64 must be exactly 32 bytes");

// Helper struct representing a decoded fat slice
struct FatSlice {
    int32_t     cputype = 0;
    int32_t     cpusubtype = 0;
    uint64_t    offset = 0;
    uint64_t    size = 0;
    uint32_t    align = 0;
    std::string archName = "unknown";
};

inline bool isZeroFillSection(uint32_t flags) {
    uint32_t type = flags & SECTION_TYPE;
    return type == S_ZEROFILL || type == S_GB_ZEROFILL || type == S_THREAD_LOCAL_ZEROFILL;
}

using MachO_Header = MachO_Header_64;
using mach_header = MachO_Header_32;
using mach_header_64 = MachO_Header_64;

enum class MachOFormat {
    Invalid,
    MachO32_LE,
    MachO32_BE,
    MachO64_LE,
    MachO64_BE,
    Fat32_BE,
    Fat32_LE,
    Fat64_BE,
    Fat64_LE
};

inline MachOFormat detectMachOFormat(const uint8_t* p) {
    if (!p) return MachOFormat::Invalid;

    if (p[0] == 0xCE && p[1] == 0xFA && p[2] == 0xED && p[3] == 0xFE) {
        return MachOFormat::MachO32_LE;
    }
    if (p[0] == 0xFE && p[1] == 0xED && p[2] == 0xFA && p[3] == 0xCE) {
        return MachOFormat::MachO32_BE;
    }
    if (p[0] == 0xCF && p[1] == 0xFA && p[2] == 0xED && p[3] == 0xFE) {
        return MachOFormat::MachO64_LE;
    }
    if (p[0] == 0xFE && p[1] == 0xED && p[2] == 0xFA && p[3] == 0xCF) {
        return MachOFormat::MachO64_BE;
    }
    if (p[0] == 0xCA && p[1] == 0xFE && p[2] == 0xBA && p[3] == 0xBE) {
        return MachOFormat::Fat32_BE;
    }
    if (p[0] == 0xBE && p[1] == 0xBA && p[2] == 0xFE && p[3] == 0xCA) {
        return MachOFormat::Fat32_LE;
    }
    if (p[0] == 0xCA && p[1] == 0xFE && p[2] == 0xBA && p[3] == 0xBF) {
        return MachOFormat::Fat64_BE;
    }
    if (p[0] == 0xBF && p[1] == 0xBA && p[2] == 0xFE && p[3] == 0xCA) {
        return MachOFormat::Fat64_LE;
    }

    return MachOFormat::Invalid;
}

inline bool isMachO(MachOFormat fmt) {
    return fmt != MachOFormat::Invalid;
}

inline bool isThinMachO(MachOFormat fmt) {
    return fmt == MachOFormat::MachO32_LE || fmt == MachOFormat::MachO32_BE ||
           fmt == MachOFormat::MachO64_LE || fmt == MachOFormat::MachO64_BE;
}

inline bool isFatMachO(MachOFormat fmt) {
    return fmt == MachOFormat::Fat32_BE || fmt == MachOFormat::Fat32_LE ||
           fmt == MachOFormat::Fat64_BE || fmt == MachOFormat::Fat64_LE;
}

inline bool isMachO64(MachOFormat fmt) {
    return fmt == MachOFormat::MachO64_LE || fmt == MachOFormat::MachO64_BE ||
           fmt == MachOFormat::Fat64_BE   || fmt == MachOFormat::Fat64_LE;
}

inline bool isMachOBigEndian(MachOFormat fmt) {
    return fmt == MachOFormat::MachO32_BE || fmt == MachOFormat::MachO64_BE ||
           fmt == MachOFormat::Fat32_BE   || fmt == MachOFormat::Fat64_BE;
}

} // namespace ropweaver
