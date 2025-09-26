namespace ropweaver {
struct MachO_Header {
    uint32_t magic;
    int32_t  cputype;
    int32_t  cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};
} // namespace ropweaver

// Global constants
#define MH_MAGIC     0xfeedface
#define MH_MAGIC_64  0xfeedfacf
#define FAT_MAGIC    0xcafebabe
#define FAT_MAGIC_64 0xcafebabf

#define CPU_TYPE_X86     7
#define CPU_TYPE_X86_64  (CPU_TYPE_X86 | 0x01000000)
#define CPU_TYPE_ARM64   (CPU_TYPE_ARM | 0x01000000)
#define CPU_TYPE_ARM     12
