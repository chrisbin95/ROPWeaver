#include "core/parsers/elf_parser.h"
#include "core/parsers/elf_defs.h"
#include "core/gadget_finder.h"
#include <iostream>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>
#include <algorithm>

using ropweaver::ELFParser;

static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define ASSERT_TRUE(cond, msg) do { \
    if (cond) { \
        g_tests_passed++; \
    } else { \
        std::cerr << "[FAIL] Line " << __LINE__ << ": " << msg << std::endl; \
        g_tests_failed++; \
    } \
} while(0)

#define ASSERT_EQ(a, b, msg) do { \
    if ((a) == (b)) { \
        g_tests_passed++; \
    } else { \
        std::cerr << "[FAIL] Line " << __LINE__ << ": " << msg << " (expected " << (b) << ", got " << (a) << ")" << std::endl; \
        g_tests_failed++; \
    } \
} while(0)

struct TestSymDef {
    std::string name;
    uint32_t address;
};

// Helper: writes a valid synthetic 32-bit ARM ELF binary with complete headers and symbol tables
static void write_synthetic_arm_elf(const std::string& path,
                                    uint32_t symtab_type, // SHT_SYMTAB or SHT_DYNSYM
                                    const std::vector<TestSymDef>& sym_defs,
                                    const std::vector<uint8_t>& text_bytes,
                                    uint32_t text_va = 0x10000,
                                    bool is_be = false)
{
    std::vector<uint8_t> buf;

    // 1. ELF Header (52 bytes)
    ropweaver::Elf32_Ehdr ehdr{};
    ehdr.e_ident[ropweaver::EI_MAG0] = ropweaver::ELFMAG0;
    ehdr.e_ident[ropweaver::EI_MAG1] = ropweaver::ELFMAG1;
    ehdr.e_ident[ropweaver::EI_MAG2] = ropweaver::ELFMAG2;
    ehdr.e_ident[ropweaver::EI_MAG3] = ropweaver::ELFMAG3;
    ehdr.e_ident[ropweaver::EI_CLASS] = ropweaver::ELFCLASS32;
    ehdr.e_ident[ropweaver::EI_DATA] = is_be ? ropweaver::ELFDATA2MSB : ropweaver::ELFDATA2LSB;
    ehdr.e_ident[ropweaver::EI_VERSION] = 1;
    ehdr.e_ident[ropweaver::EI_OSABI] = ropweaver::ELFOSABI_NONE;

    auto put16 = [&](uint16_t v) {
        if (is_be) { buf.push_back(v >> 8); buf.push_back(v & 0xFF); }
        else       { buf.push_back(v & 0xFF); buf.push_back(v >> 8); }
    };
    auto put32 = [&](uint32_t v) {
        if (is_be) {
            buf.push_back(v >> 24); buf.push_back((v >> 16) & 0xFF);
            buf.push_back((v >> 8) & 0xFF); buf.push_back(v & 0xFF);
        } else {
            buf.push_back(v & 0xFF); buf.push_back((v >> 8) & 0xFF);
            buf.push_back((v >> 16) & 0xFF); buf.push_back(v >> 24);
        }
    };

    buf.insert(buf.end(), ehdr.e_ident, ehdr.e_ident + 16);
    put16(ropweaver::ET_EXEC);      // e_type
    put16(ropweaver::EM_ARM);       // e_machine = 40
    put32(1);                       // e_version
    put32(text_va);                 // e_entry
    put32(52);                      // e_phoff (immediately following Ehdr)
    put32(0);                       // e_shoff (patched later)
    put32(ropweaver::EF_ARM_EABI_VER5); // e_flags
    put16(52);                      // e_ehsize
    put16(32);                      // e_phentsize
    put16(1);                       // e_phnum
    put16(40);                      // e_shentsize
    put16(0);                       // e_shnum (patched later)
    put16(0);                       // e_shstrndx (patched later)

    // 2. Program Header (PT_LOAD covering text) (32 bytes)
    size_t phdr_pos = buf.size();
    put32(ropweaver::PT_LOAD);      // p_type
    put32(0x1000);                  // p_offset (text will start at 0x1000)
    put32(text_va);                 // p_vaddr
    put32(text_va);                 // p_paddr
    put32(text_bytes.size());       // p_filesz
    put32(text_bytes.size());       // p_memsz
    put32(ropweaver::PF_R | ropweaver::PF_X); // p_flags
    put32(0x1000);                  // p_align

    // Pad until offset 0x1000 for .text
    if (buf.size() < 0x1000) {
        buf.resize(0x1000, 0);
    }

    // 3. Section Data: .text
    size_t text_file_offset = buf.size();
    buf.insert(buf.end(), text_bytes.begin(), text_bytes.end());

    // 4. Section Data: .strtab (strings for symbols)
    std::vector<uint8_t> strtab;
    strtab.push_back('\0'); // string index 0 is always null
    std::vector<uint32_t> sym_name_offsets;
    for (const auto& s : sym_defs) {
        sym_name_offsets.push_back(strtab.size());
        strtab.insert(strtab.end(), s.name.begin(), s.name.end());
        strtab.push_back('\0');
    }

    // Pad to 4-byte alignment
    while (buf.size() % 4 != 0) buf.push_back(0);
    size_t strtab_file_offset = buf.size();
    buf.insert(buf.end(), strtab.begin(), strtab.end());

    // 5. Section Data: Symbol table (symtab or dynsym)
    while (buf.size() % 4 != 0) buf.push_back(0);
    size_t symtab_file_offset = buf.size();

    // Symbol 0 is STN_UNDEF
    for (size_t b = 0; b < 16; ++b) buf.push_back(0);

    for (size_t i = 0; i < sym_defs.size(); ++i) {
        put32(sym_name_offsets[i]);     // st_name
        put32(sym_defs[i].address);      // st_value
        put32(0);                       // st_size
        buf.push_back(0);               // st_info (STT_NOTYPE)
        buf.push_back(0);               // st_other
        put16(1);                       // st_shndx (section 1: .text)
    }
    size_t symtab_size = 16 * (sym_defs.size() + 1);

    // 6. Section Data: .shstrtab
    std::vector<uint8_t> shstrtab;
    shstrtab.push_back('\0');
    auto add_shstr = [&](const std::string& n) -> uint32_t {
        uint32_t off = shstrtab.size();
        shstrtab.insert(shstrtab.end(), n.begin(), n.end());
        shstrtab.push_back('\0');
        return off;
    };
    uint32_t off_text_name = add_shstr(".text");
    std::string sym_sec_name = (symtab_type == ropweaver::SHT_DYNSYM) ? ".dynsym" : ".symtab";
    std::string str_sec_name = (symtab_type == ropweaver::SHT_DYNSYM) ? ".dynstr" : ".strtab";
    uint32_t off_symtab_name = add_shstr(sym_sec_name);
    uint32_t off_strtab_name = add_shstr(str_sec_name);
    uint32_t off_shstrtab_name = add_shstr(".shstrtab");

    while (buf.size() % 4 != 0) buf.push_back(0);
    size_t shstrtab_file_offset = buf.size();
    buf.insert(buf.end(), shstrtab.begin(), shstrtab.end());

    // 7. Section Header Table
    while (buf.size() % 4 != 0) buf.push_back(0);
    size_t shoff = buf.size();

    auto emit_shdr = [&](uint32_t name, uint32_t type, uint32_t flags, uint32_t addr,
                         uint32_t offset, uint32_t sz, uint32_t link, uint32_t info,
                         uint32_t align, uint32_t entsz)
    {
        put32(name); put32(type); put32(flags); put32(addr);
        put32(offset); put32(sz); put32(link); put32(info);
        put32(align); put32(entsz);
    };

    // Shdr 0: NULL
    emit_shdr(0, ropweaver::SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0);

    // Shdr 1: .text
    emit_shdr(off_text_name, ropweaver::SHT_PROGBITS,
              ropweaver::SHF_ALLOC | ropweaver::SHF_EXECINSTR,
              text_va, text_file_offset, text_bytes.size(), 0, 0, 4, 0);

    // Shdr 2: Symbol table (.symtab / .dynsym) -> link to Shdr 3 (.strtab)
    emit_shdr(off_symtab_name, symtab_type,
              (symtab_type == ropweaver::SHT_DYNSYM ? ropweaver::SHF_ALLOC : 0),
              0, symtab_file_offset, symtab_size, 3, 1, 4, 16);

    // Shdr 3: String table (.strtab / .dynstr)
    emit_shdr(off_strtab_name, ropweaver::SHT_STRTAB,
              (symtab_type == ropweaver::SHT_DYNSYM ? ropweaver::SHF_ALLOC : 0),
              0, strtab_file_offset, strtab.size(), 0, 0, 1, 0);

    // Shdr 4: .shstrtab
    emit_shdr(off_shstrtab_name, ropweaver::SHT_STRTAB, 0,
              0, shstrtab_file_offset, shstrtab.size(), 0, 0, 1, 0);

    uint16_t num_shdrs = 5;
    uint16_t shstrndx = 4;

    // Patch ELF Header: e_shoff, e_shnum, e_shstrndx
    auto patch32 = [&](size_t offset, uint32_t val) {
        if (is_be) {
            buf[offset + 0] = val >> 24; buf[offset + 1] = (val >> 16) & 0xFF;
            buf[offset + 2] = (val >> 8) & 0xFF; buf[offset + 3] = val & 0xFF;
        } else {
            buf[offset + 0] = val & 0xFF; buf[offset + 1] = (val >> 8) & 0xFF;
            buf[offset + 2] = (val >> 16) & 0xFF; buf[offset + 3] = val >> 24;
        }
    };
    auto patch16 = [&](size_t offset, uint16_t val) {
        if (is_be) { buf[offset + 0] = val >> 8; buf[offset + 1] = val & 0xFF; }
        else       { buf[offset + 0] = val & 0xFF; buf[offset + 1] = val >> 8; }
    };

    patch32(32, shoff);
    patch16(48, num_shdrs);
    patch16(50, shstrndx);

    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(buf.data()), buf.size());
}

// Group 1: Basic Mapping Symbol Detection ($a, $t, $d in .symtab)
static void test_basic_mapping_symbols() {
    std::string path = "build-win/test_arm_basic_sym.elf";
    // 0x10000: ARM region (16 bytes)
    // 0x10010: Thumb region (16 bytes)
    // 0x10020: Data region (16 bytes)
    std::vector<uint8_t> code(48, 0x00);
    std::vector<TestSymDef> syms = {
        { "$a", 0x10000 },
        { "$t", 0x10010 },
        { "$d", 0x10020 }
    };
    write_synthetic_arm_elf(path, ropweaver::SHT_SYMTAB, syms, code, 0x10000);

    ELFParser parser(path);
    ASSERT_TRUE(parser.parse(path), "Parser must succeed on basic ARM ELF with mapping symbols");
    ASSERT_TRUE(parser.hasArmMappingSymbols(), "hasArmMappingSymbols must be true");

    const auto& map_syms = parser.getArmMappingSymbols();
    ASSERT_EQ(map_syms.size(), 3, "Must find exactly 3 mapping symbols");
    ASSERT_EQ(map_syms[0].address, 0x10000, "Sym 0 address == 0x10000");
    ASSERT_TRUE(map_syms[0].type == ArmRegionType::Arm, "Sym 0 type == Arm");
    ASSERT_EQ(map_syms[1].address, 0x10010, "Sym 1 address == 0x10010");
    ASSERT_TRUE(map_syms[1].type == ArmRegionType::Thumb, "Sym 1 type == Thumb");
    ASSERT_EQ(map_syms[2].address, 0x10020, "Sym 2 address == 0x10020");
    ASSERT_TRUE(map_syms[2].type == ArmRegionType::Data, "Sym 2 type == Data");

    const auto& regions = parser.getArmCodeRegions();
    ASSERT_EQ(regions.size(), 3, "Must construct 3 code regions");
    // Region 0: [0x10000, 0x10010) ARM
    ASSERT_EQ(regions[0].start_address, 0x10000, "Region 0 start == 0x10000");
    ASSERT_EQ(regions[0].end_address, 0x10010, "Region 0 end == 0x10010");
    ASSERT_EQ(regions[0].size, 16, "Region 0 size == 16");
    ASSERT_TRUE(regions[0].type == ArmRegionType::Arm, "Region 0 type == Arm");
    ASSERT_TRUE(regions[0].is_executable, "Region 0 is_executable == true");

    // Region 1: [0x10010, 0x10020) Thumb
    ASSERT_EQ(regions[1].start_address, 0x10010, "Region 1 start == 0x10010");
    ASSERT_EQ(regions[1].end_address, 0x10020, "Region 1 end == 0x10020");
    ASSERT_EQ(regions[1].size, 16, "Region 1 size == 16");
    ASSERT_TRUE(regions[1].type == ArmRegionType::Thumb, "Region 1 type == Thumb");
    ASSERT_TRUE(regions[1].is_executable, "Region 1 is_executable == true");

    // Region 2: [0x10020, 0x10030) Data
    ASSERT_EQ(regions[2].start_address, 0x10020, "Region 2 start == 0x10020");
    ASSERT_EQ(regions[2].end_address, 0x10030, "Region 2 end == 0x10030");
    ASSERT_EQ(regions[2].size, 16, "Region 2 size == 16");
    ASSERT_TRUE(regions[2].type == ArmRegionType::Data, "Region 2 type == Data");
    ASSERT_TRUE(!regions[2].is_executable, "Region 2 is_executable == false (Data excluded)");
}

// Group 2: Dotted suffix variants ($a.0, $t.sub, $d.pool) and non-mapping symbol filtering
static void test_suffix_and_filtering() {
    std::string path = "build-win/test_arm_suffix.elf";
    std::vector<uint8_t> code(32, 0x00);
    std::vector<TestSymDef> syms = {
        { "$a.0", 0x10000 },
        { "$data_var", 0x10008 }, // Should NOT match as a mapping symbol
        { "$t.1", 0x10010 },
        { "my_function", 0x10018 }, // Normal symbol, should NOT match
        { "$d.pool", 0x10018 }
    };
    write_synthetic_arm_elf(path, ropweaver::SHT_SYMTAB, syms, code, 0x10000);

    ELFParser parser(path);
    ASSERT_TRUE(parser.parse(path), "Parser must succeed on suffix ARM ELF");

    const auto& map_syms = parser.getArmMappingSymbols();
    ASSERT_EQ(map_syms.size(), 3, "Must only match valid mapping symbols ($a.0, $t.1, $d.pool)");
    ASSERT_EQ(map_syms[0].name, "$a.0", "Matches $a.0");
    ASSERT_EQ(map_syms[1].name, "$t.1", "Matches $t.1");
    ASSERT_EQ(map_syms[2].name, "$d.pool", "Matches $d.pool");
}

// Group 3: Multiple alternating ARM/Thumb/Data regions
static void test_alternating_regions() {
    std::string path = "build-win/test_arm_alternating.elf";
    // Section size: 64 bytes
    // 0x10000: $a (ARM)   len=12
    // 0x1000C: $d (Data)  len=8
    // 0x10014: $t (Thumb) len=16
    // 0x10024: $d (Data)  len=4
    // 0x10028: $a (ARM)   len=24 -> ends at 0x10040
    std::vector<uint8_t> code(64, 0x00);
    std::vector<TestSymDef> syms = {
        { "$a", 0x10000 },
        { "$d", 0x1000C },
        { "$t", 0x10014 },
        { "$d", 0x10024 },
        { "$a", 0x10028 }
    };
    write_synthetic_arm_elf(path, ropweaver::SHT_SYMTAB, syms, code, 0x10000);

    ELFParser parser(path);
    ASSERT_TRUE(parser.parse(path), "Parser must succeed on alternating regions");

    const auto& regions = parser.getArmCodeRegions();
    ASSERT_EQ(regions.size(), 5, "Must construct 5 alternating regions");

    ASSERT_TRUE(regions[0].type == ArmRegionType::Arm && regions[0].is_executable, "Region 0 is ARM executable");
    ASSERT_EQ(regions[0].size, 12, "Region 0 size == 12");

    ASSERT_TRUE(regions[1].type == ArmRegionType::Data && !regions[1].is_executable, "Region 1 is Data non-executable");
    ASSERT_EQ(regions[1].size, 8, "Region 1 size == 8");

    ASSERT_TRUE(regions[2].type == ArmRegionType::Thumb && regions[2].is_executable, "Region 2 is Thumb executable");
    ASSERT_EQ(regions[2].size, 16, "Region 2 size == 16");

    ASSERT_TRUE(regions[3].type == ArmRegionType::Data && !regions[3].is_executable, "Region 3 is Data non-executable");
    ASSERT_EQ(regions[3].size, 4, "Region 3 size == 4");

    ASSERT_TRUE(regions[4].type == ArmRegionType::Arm && regions[4].is_executable, "Region 4 is ARM executable");
    ASSERT_EQ(regions[4].size, 24, "Region 4 size == 24");
    ASSERT_EQ(regions[4].end_address, 0x10040, "Region 4 end == 0x10040 (section end)");
}

// Group 4: Mapping symbols in .dynsym
static void test_dynsym_mapping_symbols() {
    std::string path = "build-win/test_arm_dynsym.elf";
    std::vector<uint8_t> code(32, 0x00);
    std::vector<TestSymDef> syms = {
        { "$a", 0x10000 },
        { "$t", 0x10010 }
    };
    // Pass SHT_DYNSYM instead of SHT_SYMTAB
    write_synthetic_arm_elf(path, ropweaver::SHT_DYNSYM, syms, code, 0x10000);

    ELFParser parser(path);
    ASSERT_TRUE(parser.parse(path), "Parser must succeed on .dynsym ELF");
    ASSERT_TRUE(parser.hasArmMappingSymbols(), "Must detect mapping symbols from .dynsym");

    const auto& regions = parser.getArmCodeRegions();
    ASSERT_EQ(regions.size(), 2, "Must construct 2 regions from .dynsym");
    ASSERT_TRUE(regions[0].type == ArmRegionType::Arm, "Region 0 is Arm");
    ASSERT_TRUE(regions[1].type == ArmRegionType::Thumb, "Region 1 is Thumb");
}

// Group 5: Stripped ELF / Missing Symbol Table (Safely defaults to ARM mode, never guesses Thumb)
static void test_missing_and_stripped_symbols() {
    // 1. Existing stripped binary test_binaries/elf32_arm
    ELFParser parser1("test_binaries/elf32_arm");
    ASSERT_TRUE(parser1.parse("test_binaries/elf32_arm"), "Must parse test_binaries/elf32_arm");
    ASSERT_TRUE(!parser1.hasArmMappingSymbols(), "Stripped binary must have hasArmMappingSymbols() == false");
    ASSERT_TRUE(parser1.getArmMappingSymbols().empty(), "getArmMappingSymbols() must be empty");

    const auto& regions1 = parser1.getArmCodeRegions();
    ASSERT_TRUE(!regions1.empty(), "Must produce default region for .text");
    ASSERT_TRUE(regions1[0].type == ArmRegionType::Arm, "Default region must be ARM mode (never guessed as Thumb)");
    ASSERT_TRUE(regions1[0].is_executable, "Default region is executable");

    // 2. Synthetic binary with completely empty symbol table
    std::string path2 = "build-win/test_arm_no_syms.elf";
    std::vector<uint8_t> code(32, 0x00);
    write_synthetic_arm_elf(path2, ropweaver::SHT_SYMTAB, {}, code, 0x10000);

    ELFParser parser2(path2);
    ASSERT_TRUE(parser2.parse(path2), "Must parse unmapped ELF");
    ASSERT_TRUE(!parser2.hasArmMappingSymbols(), "No mapping symbols");
    const auto& regions2 = parser2.getArmCodeRegions();
    ASSERT_EQ(regions2.size(), 1, "Must construct single fallback region");
    ASSERT_TRUE(regions2[0].type == ArmRegionType::Arm, "Fallback region is ARM mode");
    ASSERT_EQ(regions2[0].size, 32, "Fallback region covers entire section");
}

// Group 6: Invalid and Out-of-Range Mapping Symbols
static void test_invalid_and_out_of_range_symbols() {
    std::string path = "build-win/test_arm_out_of_range.elf";
    // Section is at [0x10000, 0x10020) (32 bytes)
    std::vector<uint8_t> code(32, 0x00);
    std::vector<TestSymDef> syms = {
        { "$a", 0x5000 },  // Out of range (before .text)
        { "$t", 0x10008 }, // Valid
        { "$d", 0x10010 }, // Valid
        { "$a", 0x20000 }  // Out of range (after .text)
    };
    write_synthetic_arm_elf(path, ropweaver::SHT_SYMTAB, syms, code, 0x10000);

    ELFParser parser(path);
    ASSERT_TRUE(parser.parse(path), "Must parse ELF with out-of-range symbols");

    const auto& regions = parser.getArmCodeRegions();
    // Prefix [0x10000, 0x10008) is ARM default
    // [0x10008, 0x10010) is Thumb
    // [0x10010, 0x10020) is Data
    ASSERT_EQ(regions.size(), 3, "Out-of-range symbols must not create regions outside section bounds");
    ASSERT_EQ(regions[0].start_address, 0x10000, "Region 0 starts at section base 0x10000");
    ASSERT_EQ(regions[0].end_address, 0x10008, "Region 0 ends at first in-range symbol 0x10008");
    ASSERT_TRUE(regions[0].type == ArmRegionType::Arm, "Prefix region is ARM mode");
    ASSERT_EQ(regions.back().end_address, 0x10020, "Last region ends at section end 0x10020");
}

// Group 7: GadgetFinder Data-Region and Thumb Exclusion Verification
static void test_gadget_finder_data_exclusion() {
    // Construct buffer with 3 regions:
    // Region 0: 0x10000..0x10008 ARM code: contains valid bx lr (0x1E, 0xFF, 0x2F, 0xE1)
    // Region 1: 0x10008..0x10010 DATA pool: ALSO contains bytes 0x1E, 0xFF, 0x2F, 0xE1 (data literal)
    // Region 2: 0x10010..0x10018 THUMB code: contains dummy bytes
    std::vector<uint8_t> code = {
        // 0x10000: ARM code
        0x00, 0x00, 0xA0, 0xE3, // mov r0, #0
        0x1E, 0xFF, 0x2F, 0xE1, // bx lr (REAL GADGET at 0x10004)
        // 0x10008: DATA region ($d)
        0x1E, 0xFF, 0x2F, 0xE1, // bx lr bytes stored as literal constant (MUST BE EXCLUDED!)
        0x44, 0x41, 0x54, 0x41, // "DATA"
        // 0x10010: THUMB region ($t)
        0x70, 0x47, 0x00, 0xBF, // bx lr in thumb + nop
        0x00, 0x00, 0x00, 0x00
    };

    std::vector<ArmCodeRegion> regions = {
        { 0x10000, 0x10008, 0, 8, ArmRegionType::Arm, ".text", true },
        { 0x10008, 0x10010, 8, 8, ArmRegionType::Data, ".text", false },
        { 0x10010, 0x10018, 16, 8, ArmRegionType::Thumb, ".text", true }
    };

    GadgetFinder finder(code, 0x10000, "armv7", "", 10, Endianness::Little, false, regions);
    finder.findGadgets();

    const auto& gadgets = finder.getGadgets();
    // We expect gadgets ONLY from the ARM region [0x10000, 0x10008).
    // Specifically:
    // 0x10000: mov r0, #0 ; bx lr
    // 0x10004: bx lr
    // The data region at 0x10008 has IDENTICAL bx lr bytes, but MUST NEVER be found!
    // The thumb region at 0x10010 MUST NOT be decoded in ARM mode!
    ASSERT_TRUE(!gadgets.empty(), "Must find valid gadgets in ARM region");

    for (const auto& g : gadgets) {
        ASSERT_TRUE(g.address < 0x10008 || g.address >= 0x10010, "Data region [0x10008, 0x10010) must NEVER be decoded as a gadget");
        ASSERT_TRUE(g.address != 0x10008, "Data region at 0x10008 must NEVER be decoded as a gadget");
        if (g.address >= 0x10010) {
            ASSERT_TRUE(g.is_thumb, "Thumb region at 0x10010 must not be decoded in ARM mode (must have is_thumb == true)");
        }
    }
}

int main() {
    std::cout << "=== ROPWeaver Phase 2 Step 4.3: ARM Mapping Symbols Tests ===" << std::endl;

    test_basic_mapping_symbols();
    test_suffix_and_filtering();
    test_alternating_regions();
    test_dynsym_mapping_symbols();
    test_missing_and_stripped_symbols();
    test_invalid_and_out_of_range_symbols();
    test_gadget_finder_data_exclusion();

    std::cout << "Results: " << g_tests_passed << " passed, " << g_tests_failed << " failed." << std::endl;
    return (g_tests_failed == 0) ? 0 : 1;
}
