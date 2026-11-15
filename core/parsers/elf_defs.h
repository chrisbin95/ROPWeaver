#pragma once
#include <cstdint>

namespace ropweaver {

#pragma pack(push, 1)

// ELF Header 32-bit
struct Elf32_Ehdr {
  unsigned char e_ident[16]; // Magic number and other info
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint32_t e_entry;
  uint32_t e_phoff;
  uint32_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
};

// ELF Header 64-bit
struct Elf64_Ehdr {
  unsigned char e_ident[16];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint64_t e_entry;
  uint64_t e_phoff;
  uint64_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
};

// Section header 32-bit
struct Elf32_Shdr {
  uint32_t sh_name;
  uint32_t sh_type;
  uint32_t sh_flags;
  uint32_t sh_addr;
  uint32_t sh_offset;
  uint32_t sh_size;
  uint32_t sh_link;
  uint32_t sh_info;
  uint32_t sh_addralign;
  uint32_t sh_entsize;
};

// Section header 64-bit
struct Elf64_Shdr {
  uint32_t sh_name;
  uint32_t sh_type;
  uint64_t sh_flags;
  uint64_t sh_addr;
  uint64_t sh_offset;
  uint64_t sh_size;
  uint32_t sh_link;
  uint32_t sh_info;
  uint64_t sh_addralign;
  uint64_t sh_entsize;
};

// Program Header 32-bit
struct Elf32_Phdr {
  uint32_t p_type;
  uint32_t p_offset;
  uint32_t p_vaddr;
  uint32_t p_paddr;
  uint32_t p_filesz;
  uint32_t p_memsz;
  uint32_t p_flags;
  uint32_t p_align;
};

// Program Header 64-bit (note: p_flags position differs from 32-bit)
struct Elf64_Phdr {
  uint32_t p_type;
  uint32_t p_flags;
  uint64_t p_offset;
  uint64_t p_vaddr;
  uint64_t p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
  uint64_t p_align;
};

// Dynamic Array Tag 32-bit
struct Elf32_Dyn {
  int32_t d_tag;
  union {
    uint32_t d_val;
    uint32_t d_ptr;
  } d_un;
};

// Dynamic Array Tag 64-bit
struct Elf64_Dyn {
  int64_t d_tag;
  union {
    uint64_t d_val;
    uint64_t d_ptr;
  } d_un;
};

// Symbol table entry 32-bit (16 bytes)
struct Elf32_Sym {
  uint32_t st_name;
  uint32_t st_value;
  uint32_t st_size;
  uint8_t  st_info;
  uint8_t  st_other;
  uint16_t st_shndx;
};

// Symbol table entry 64-bit (24 bytes)
struct Elf64_Sym {
  uint32_t st_name;
  uint8_t  st_info;
  uint8_t  st_other;
  uint16_t st_shndx;
  uint64_t st_value;
  uint64_t st_size;
};

#pragma pack(pop)

// ELF Identification indexes
constexpr size_t EI_MAG0 = 0;
constexpr size_t EI_MAG1 = 1;
constexpr size_t EI_MAG2 = 2;
constexpr size_t EI_MAG3 = 3;
constexpr size_t EI_CLASS = 4;
constexpr size_t EI_DATA = 5;
constexpr size_t EI_VERSION = 6;
constexpr size_t EI_OSABI = 7;
constexpr size_t EI_ABIVERSION = 8;
constexpr size_t EI_PAD = 9;
constexpr size_t EI_NIDENT = 16;

constexpr unsigned char ELFMAG0 = 0x7f;
constexpr unsigned char ELFMAG1 = 'E';
constexpr unsigned char ELFMAG2 = 'L';
constexpr unsigned char ELFMAG3 = 'F';

// ELF Classes
constexpr uint8_t ELFCLASSNONE = 0;
constexpr uint8_t ELFCLASS32 = 1;
constexpr uint8_t ELFCLASS64 = 2;

// ELF Data Encodings
constexpr uint8_t ELFDATANONE = 0;
constexpr uint8_t ELFDATA2LSB = 1;
constexpr uint8_t ELFDATA2MSB = 2;

// OS ABI values (e_ident[EI_OSABI])
constexpr uint8_t ELFOSABI_NONE       = 0;   // System V / None (standard Linux default)
constexpr uint8_t ELFOSABI_SYSV       = 0;   // Alias for NONE
constexpr uint8_t ELFOSABI_HPUX       = 1;   // HP-UX
constexpr uint8_t ELFOSABI_NETBSD     = 2;   // NetBSD
constexpr uint8_t ELFOSABI_GNU        = 3;   // GNU / Linux extensions
constexpr uint8_t ELFOSABI_LINUX      = 3;   // Alias for GNU
constexpr uint8_t ELFOSABI_SOLARIS    = 6;   // Sun Solaris
constexpr uint8_t ELFOSABI_AIX        = 7;   // IBM AIX
constexpr uint8_t ELFOSABI_IRIX       = 8;   // SGI Irix
constexpr uint8_t ELFOSABI_FREEBSD    = 9;   // FreeBSD
constexpr uint8_t ELFOSABI_OPENBSD    = 12;  // OpenBSD
constexpr uint8_t ELFOSABI_ARM_AEABI  = 64;  // ARM EABI (used by some embedded/EABI compilers)
constexpr uint8_t ELFOSABI_ARM        = 97;  // ARM
constexpr uint8_t ELFOSABI_STANDALONE = 255; // Standalone / bare-metal embedded

// ARM-specific Flags (AAELF32 §4.3.4)
constexpr uint32_t EF_ARM_EABIMASK     = 0xFF000000;
constexpr uint32_t EF_ARM_EABI_UNKNOWN = 0x00000000; // Legacy OABI
constexpr uint32_t EF_ARM_EABI_VER1    = 0x01000000;
constexpr uint32_t EF_ARM_EABI_VER2    = 0x02000000;
constexpr uint32_t EF_ARM_EABI_VER3    = 0x03000000;
constexpr uint32_t EF_ARM_EABI_VER4    = 0x04000000;
constexpr uint32_t EF_ARM_EABI_VER5    = 0x05000000;
constexpr uint32_t EF_ARM_BE8          = 0x00800000;

// RISC-V specific Flags (RISC-V ELF psABI §8.1)
constexpr uint32_t EF_RISCV_RVC              = 0x0001; // Compressed instructions
constexpr uint32_t EF_RISCV_FLOAT_ABI_MASK   = 0x0006;
constexpr uint32_t EF_RISCV_FLOAT_ABI_SOFT   = 0x0000;
constexpr uint32_t EF_RISCV_FLOAT_ABI_SINGLE = 0x0002;
constexpr uint32_t EF_RISCV_FLOAT_ABI_DOUBLE = 0x0004;
constexpr uint32_t EF_RISCV_FLOAT_ABI_QUAD   = 0x0006;
constexpr uint32_t EF_RISCV_RVE              = 0x0008; // Embedded 16-register variant (A7/X17 does not exist)
constexpr uint32_t EF_RISCV_TSO              = 0x0010; // Total Store Ordering

// Safe endian-aware integer readers (bounds-checked by caller, safe on
// unaligned memory)
inline uint16_t read_u16(const uint8_t *p, bool is_be) {
  if (is_be) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) |
                                 static_cast<uint16_t>(p[1]));
  }
  return static_cast<uint16_t>(static_cast<uint16_t>(p[0]) |
                               (static_cast<uint16_t>(p[1]) << 8));
}

inline uint32_t read_u32(const uint8_t *p, bool is_be) {
  if (is_be) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | (static_cast<uint32_t>(p[3]));
  }
  return (static_cast<uint32_t>(p[0])) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}

inline uint64_t read_u64(const uint8_t *p, bool is_be) {
  if (is_be) {
    return (static_cast<uint64_t>(p[0]) << 56) |
           (static_cast<uint64_t>(p[1]) << 48) |
           (static_cast<uint64_t>(p[2]) << 40) |
           (static_cast<uint64_t>(p[3]) << 32) |
           (static_cast<uint64_t>(p[4]) << 24) |
           (static_cast<uint64_t>(p[5]) << 16) |
           (static_cast<uint64_t>(p[6]) << 8) | (static_cast<uint64_t>(p[7]));
  }
  return (static_cast<uint64_t>(p[0])) | (static_cast<uint64_t>(p[1]) << 8) |
         (static_cast<uint64_t>(p[2]) << 16) |
         (static_cast<uint64_t>(p[3]) << 24) |
         (static_cast<uint64_t>(p[4]) << 32) |
         (static_cast<uint64_t>(p[5]) << 40) |
         (static_cast<uint64_t>(p[6]) << 48) |
         (static_cast<uint64_t>(p[7]) << 56);
}

inline int32_t read_i32(const uint8_t *p, bool is_be) {
  uint32_t u = read_u32(p, is_be);
  if (u <= 0x7fffffffU) {
    return static_cast<int32_t>(u);
  }
  return -1 - static_cast<int32_t>(~u);
}

inline int64_t read_i64(const uint8_t *p, bool is_be) {
  uint64_t u = read_u64(p, is_be);
  if (u <= 0x7fffffffffffffffULL) {
    return static_cast<int64_t>(u);
  }
  return -1LL - static_cast<int64_t>(~u);
}

// Machine Architectures
constexpr uint16_t EM_386 = 3;
constexpr uint16_t EM_ARM = 40;
constexpr uint16_t EM_X86_64 = 62;
constexpr uint16_t EM_AARCH64 = 183;
constexpr uint16_t EM_RISCV = 243;

// Object file types
constexpr uint16_t ET_NONE = 0;
constexpr uint16_t ET_REL = 1;
constexpr uint16_t ET_EXEC = 2;
constexpr uint16_t ET_DYN = 3;
constexpr uint16_t ET_CORE = 4;

// Section types & flags
constexpr uint32_t SHN_UNDEF = 0;
constexpr uint32_t SHT_NULL = 0;
constexpr uint32_t SHT_PROGBITS = 1;
constexpr uint32_t SHT_SYMTAB = 2;
constexpr uint32_t SHT_STRTAB = 3;
constexpr uint32_t SHT_RELA = 4;
constexpr uint32_t SHT_HASH = 5;
constexpr uint32_t SHT_DYNAMIC = 6;
constexpr uint32_t SHT_NOTE = 7;
constexpr uint32_t SHT_NOBITS = 8;
constexpr uint32_t SHT_REL = 9;
constexpr uint32_t SHT_DYNSYM = 11;
constexpr uint64_t SHF_WRITE = 0x1;
constexpr uint64_t SHF_ALLOC = 0x2;
constexpr uint64_t SHF_EXECINSTR = 0x4;

// Segment types
constexpr uint32_t PT_NULL = 0;
constexpr uint32_t PT_LOAD = 1;
constexpr uint32_t PT_DYNAMIC = 2;
constexpr uint32_t PT_INTERP = 3;
constexpr uint32_t PT_NOTE = 4;
constexpr uint32_t PT_GNU_STACK = 0x6474e551;
constexpr uint32_t PT_GNU_RELRO = 0x6474e552;

// Segment flags
constexpr uint32_t PF_X = 1;
constexpr uint32_t PF_W = 2;
constexpr uint32_t PF_R = 4;

// Dynamic array tags
constexpr int64_t DT_NULL = 0;
constexpr int64_t DT_BIND_NOW = 24;
constexpr int64_t DT_FLAGS = 30;
constexpr int64_t DT_FLAGS_1 = 0x6ffffffb;

} // namespace ropweaver
