#include "core/parsers/elf_parser.h"
#include "core/parsers/elf_defs.h"
#include "core/gadget_finder.h"
#include "core/capstone_compat.h"
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

    // Shdr 2: .strtab / .dynstr
    emit_shdr(off_strtab_name, ropweaver::SHT_STRTAB, 0, 0,
              strtab_file_offset, strtab.size(), 0, 0, 1, 0);

    // Shdr 3: .symtab / .dynsym
    emit_shdr(off_symtab_name, symtab_type,
              (symtab_type == ropweaver::SHT_DYNSYM) ? ropweaver::SHF_ALLOC : 0,
              0, symtab_file_offset, symtab_size, 2, 1, 4, 16);

    // Shdr 4: .shstrtab
    emit_shdr(off_shstrtab_name, ropweaver::SHT_STRTAB, 0, 0,
              shstrtab_file_offset, shstrtab.size(), 0, 0, 1, 0);

    uint16_t shnum = 5;

    // Patch ELF Header: e_shoff (offset 32), e_shnum (offset 48), e_shstrndx (offset 50)
    auto patch32 = [&](size_t offset, uint32_t v) {
        if (is_be) {
            buf[offset]   = v >> 24; buf[offset+1] = (v >> 16) & 0xFF;
            buf[offset+2] = (v >> 8) & 0xFF; buf[offset+3] = v & 0xFF;
        } else {
            buf[offset]   = v & 0xFF; buf[offset+1] = (v >> 8) & 0xFF;
            buf[offset+2] = (v >> 16) & 0xFF; buf[offset+3] = v >> 24;
        }
    };
    auto patch16 = [&](size_t offset, uint16_t v) {
        if (is_be) { buf[offset] = v >> 8; buf[offset+1] = v & 0xFF; }
        else       { buf[offset] = v & 0xFF; buf[offset+1] = v >> 8; }
    };

    patch32(32, shoff);
    patch16(48, shnum);
    patch16(50, 4); // shstrndx is section 4

    std::ofstream out(path, std::ios::binary);
    if (!out) {
        std::cerr << "Failed to open file for writing: " << path << std::endl;
        return;
    }
    out.write(reinterpret_cast<const char*>(buf.data()), buf.size());
}

int main() {
    std::cout << "=== ROPWeaver Phase 2 Step 4.4: ARM Thumb Instruction Decoding and Gadget Scanning Tests ===" << std::endl;

    // ------------------------------------------------------------------------
    // Group 1: Capstone Thumb Mode Handle & Direct Opcode Decoding Verification
    // ------------------------------------------------------------------------
    std::cout << "\n[*] Group 1: Capstone Thumb Handle & Opcode Decoding..." << std::endl;
    {
        // GadgetFinder on armv7 initializes thumb_handle internally
        std::vector<uint8_t> code = {
            0x70, 0x47,             // bx lr (16-bit)
            0x10, 0xBD,             // pop {r4, pc} (16-bit)
            0x00, 0xBD,             // pop {pc} (16-bit)
            0x00, 0xDF,             // svc #0 (16-bit)
            0xBD, 0xE8, 0x10, 0x80, // pop.w {r4, pc} (32-bit Thumb-2)
            0x00, 0xBE              // bkpt #0 (trap - must NOT be accepted)
        };

        // When passed with ArmRegionType::Thumb
        ArmCodeRegion thumb_region;
        thumb_region.start_address = 0x1000;
        thumb_region.end_address = 0x1000 + code.size();
        thumb_region.size = code.size();
        thumb_region.buffer_offset = 0;
        thumb_region.type = ArmRegionType::Thumb;
        thumb_region.section_name = ".text";
        thumb_region.is_executable = true;

        GadgetFinder finder(code, 0x1000, "armv7", "", 10, Endianness::Little, false, { thumb_region });
        finder.findGadgets();
        const auto& gadgets = finder.getGadgets();

        // Check 16-bit bx lr
        bool found_bx_lr = false;
        for (const auto& g : gadgets) {
            if (g.address == 0x1000 && g.instructions.size() == 1 && g.assembly.find("bx lr") != std::string::npos) {
                found_bx_lr = true;
                ASSERT_EQ(g.terminator_type, "RET", "bx lr is classified as RET");
                ASSERT_TRUE(g.byte_verified, "bx lr byte_verified is true");
            }
        }
        ASSERT_TRUE(found_bx_lr, "Discovered 16-bit 'bx lr' Thumb gadget at 0x1000");

        // Check 16-bit pop {r4, pc}
        bool found_pop = false;
        for (const auto& g : gadgets) {
            if (g.address == 0x1002 && g.instructions.size() == 1 && (g.assembly.find("pop") != std::string::npos && g.assembly.find("pc") != std::string::npos)) {
                found_pop = true;
                ASSERT_EQ(g.terminator_type, "RET", "pop {r4, pc} is classified as RET");
                ASSERT_TRUE(g.byte_verified, "pop {r4, pc} byte_verified is true");
            }
        }
        ASSERT_TRUE(found_pop, "Discovered 16-bit 'pop {r4, pc}' Thumb gadget at 0x1002");

        // Check 16-bit pop {pc}
        bool found_pop_pc = false;
        for (const auto& g : gadgets) {
            if (g.address == 0x1004 && g.instructions.size() == 1 && g.assembly.find("pc") != std::string::npos) {
                found_pop_pc = true;
                ASSERT_EQ(g.terminator_type, "RET", "pop {pc} is classified as RET");
            }
        }
        ASSERT_TRUE(found_pop_pc, "Discovered 16-bit 'pop {pc}' Thumb gadget at 0x1004");

        // Check 16-bit svc #0
        bool found_svc = false;
        for (const auto& g : gadgets) {
            if (g.address == 0x1006 && g.instructions.size() == 1 && g.assembly.find("svc") != std::string::npos) {
                found_svc = true;
                ASSERT_EQ(g.terminator_type, "SYSCALL", "svc #0 is classified as SYSCALL");
            }
        }
        ASSERT_TRUE(found_svc, "Discovered 16-bit 'svc #0' Thumb gadget at 0x1006");

        // Check 32-bit pop.w {r4, pc}
        bool found_pop_w = false;
        for (const auto& g : gadgets) {
            if (g.address == 0x1008 && g.instructions.size() == 1 && (g.assembly.find("pop") != std::string::npos || g.assembly.find("ldm") != std::string::npos)) {
                found_pop_w = true;
                ASSERT_EQ(g.terminator_type, "RET", "pop.w {r4, pc} is classified as RET");
                ASSERT_TRUE(g.byte_verified, "pop.w byte_verified is true");
            }
        }
        ASSERT_TRUE(found_pop_w, "Discovered 32-bit Thumb-2 'pop.w {r4, pc}' gadget at 0x1008");

        // Check trap exclusion: bkpt #0 at 0x100C must NOT be accepted as a gadget
        bool found_bkpt = false;
        for (const auto& g : gadgets) {
            if (g.address == 0x100C || g.assembly.find("bkpt") != std::string::npos) {
                found_bkpt = true;
            }
        }
        ASSERT_TRUE(!found_bkpt, "Trap 'bkpt #0' is strictly rejected as a gadget");
    }

    // ------------------------------------------------------------------------
    // Group 2: ARM-only ELF Binary / Regions ($a only)
    // ------------------------------------------------------------------------
    std::cout << "\n[*] Group 2: ARM-only ELF Binary with $a mapping symbols..." << std::endl;
    {
        // 4-byte ARM instructions:
        // mov r0, #0: 0x00, 0x00, 0xA0, 0xE3
        // bx lr:      0x1E, 0xFF, 0x2F, 0xE1
        std::vector<uint8_t> text = {
            0x00, 0x00, 0xA0, 0xE3, // mov r0, #0
            0x1E, 0xFF, 0x2F, 0xE1  // bx lr
        };
        std::string elf_path = "build-win/test_arm_only.elf";
        write_synthetic_arm_elf(elf_path, ropweaver::SHT_SYMTAB, {
            { "$a", 0x10000 }
        }, text, 0x10000);

        ELFParser parser(elf_path);
        ASSERT_TRUE(parser.parse(elf_path), "Parsed ARM-only ELF");
        ASSERT_EQ(parser.getArmCodeRegions().size(), 1, "Has 1 ARM region");
        ASSERT_TRUE(parser.getArmCodeRegions()[0].type == ArmRegionType::Arm, "Region is ARM");

        GadgetFinder finder(parser.getTextSection(), 0, parser.getArchitecture(), elf_path,
                            parser.getExecBufferMappings(), 10, parser.getInstructionEndianness(),
                            parser.isRvcEnabled(), parser.getArmCodeRegions());
        finder.findGadgets();
        const auto& gadgets = finder.getGadgets();
        ASSERT_TRUE(!gadgets.empty(), "Found gadgets in ARM-only ELF");

        bool found_mov_bx = false;
        for (const auto& g : gadgets) {
            if (g.address == 0x10000 && g.instructions.size() == 2) {
                found_mov_bx = true;
                ASSERT_EQ(g.architecture, "armv7", "Architecture is armv7");
                ASSERT_EQ(g.terminator_type, "RET", "Terminator is RET");
            }
        }
        ASSERT_TRUE(found_mov_bx, "Discovered ARM gadget 'mov r0, #0 ; bx lr' at 0x10000");
    }

    // ------------------------------------------------------------------------
    // Group 3: Thumb-only ELF Binary with $t mapping symbols
    // ------------------------------------------------------------------------
    std::cout << "\n[*] Group 3: Thumb-only ELF Binary with $t mapping symbols..." << std::endl;
    {
        // 16-bit and 32-bit Thumb instructions:
        // 0x10000: movs r0, #1 (0x01, 0x20)
        // 0x10002: bx lr       (0x70, 0x47)
        // 0x10004: movs r1, #2 (0x02, 0x21)
        // 0x10006: pop {r4, pc}(0x10, 0xBD)
        // 0x10008: mov.w r2, #42 (0x4F, 0xF0, 0x2A, 0x00) (32-bit Thumb-2)
        // 0x1000C: pop.w {r4, pc} (0xBD, 0xE8, 0x10, 0x80) (32-bit Thumb-2)
        std::vector<uint8_t> text = {
            0x01, 0x20,             // movs r0, #1
            0x70, 0x47,             // bx lr
            0x02, 0x21,             // movs r1, #2
            0x10, 0xBD,             // pop {r4, pc}
            0x4F, 0xF0, 0x2A, 0x00, // mov.w r2, #42
            0xBD, 0xE8, 0x10, 0x80  // pop.w {r4, pc}
        };
        std::string elf_path = "build-win/test_thumb_only.elf";
        write_synthetic_arm_elf(elf_path, ropweaver::SHT_SYMTAB, {
            { "$t", 0x10000 }
        }, text, 0x10000);

        ELFParser parser(elf_path);
        ASSERT_TRUE(parser.parse(elf_path), "Parsed Thumb-only ELF");
        ASSERT_EQ(parser.getArmCodeRegions().size(), 1, "Has 1 region");
        ASSERT_TRUE(parser.getArmCodeRegions()[0].type == ArmRegionType::Thumb, "Region is Thumb");

        GadgetFinder finder(parser.getTextSection(), 0, parser.getArchitecture(), elf_path,
                            parser.getExecBufferMappings(), 10, parser.getInstructionEndianness(),
                            parser.isRvcEnabled(), parser.getArmCodeRegions());
        finder.findGadgets();
        const auto& gadgets = finder.getGadgets();

        // Gadget 1: movs r0, #1 ; bx lr at 0x10000
        bool found_g1 = false;
        for (const auto& g : gadgets) {
            if (g.address == 0x10000 && g.instructions.size() == 2 && g.assembly.find("bx lr") != std::string::npos) {
                found_g1 = true;
                ASSERT_EQ(g.terminator_type, "RET", "g1 terminator RET");
                ASSERT_TRUE(g.byte_verified, "g1 byte_verified");
            }
        }
        ASSERT_TRUE(found_g1, "Discovered Thumb 16-bit sequence 'movs r0, #1 ; bx lr' at 0x10000");

        // Gadget 2: movs r1, #2 ; pop {r4, pc} at 0x10004
        bool found_g2 = false;
        for (const auto& g : gadgets) {
            if (g.address == 0x10004 && g.instructions.size() == 2 && g.assembly.find("pc") != std::string::npos) {
                found_g2 = true;
                ASSERT_EQ(g.terminator_type, "RET", "g2 terminator RET");
                ASSERT_TRUE(g.byte_verified, "g2 byte_verified");
            }
        }
        ASSERT_TRUE(found_g2, "Discovered Thumb 16-bit pop sequence at 0x10004");

        // Gadget 3: mov.w r2, #42 ; pop.w {r4, pc} at 0x10008 (Thumb-2 32-bit instructions)
        bool found_g3 = false;
        for (const auto& g : gadgets) {
            if (g.address == 0x10008 && g.instructions.size() == 2) {
                found_g3 = true;
                ASSERT_EQ(g.terminator_type, "RET", "g3 terminator RET");
                ASSERT_TRUE(g.byte_verified, "g3 byte_verified");
            }
        }
        ASSERT_TRUE(found_g3, "Discovered Thumb-2 32-bit sequence at 0x10008");
    }

    // ------------------------------------------------------------------------
    // Group 4: 2-Byte Candidate Alignment for Thumb Code
    // ------------------------------------------------------------------------
    std::cout << "\n[*] Group 4: 2-Byte Candidate Alignment for Thumb Code..." << std::endl;
    {
        // Place a Thumb gadget starting at offset 2 (unaligned to 4, but aligned to 2):
        // 0x10000: nop (0x00, 0xBF)
        // 0x10002: adds r0, #1 (0x01, 0x30)
        // 0x10004: bx lr       (0x70, 0x47)
        std::vector<uint8_t> text = {
            0x00, 0xBF, // nop (2 bytes)
            0x01, 0x30, // adds r0, #1 (2 bytes) -> starts at 0x10002 (unaligned to 4!)
            0x70, 0x47  // bx lr (2 bytes)
        };
        std::string elf_path = "build-win/test_thumb_2byte_align.elf";
        write_synthetic_arm_elf(elf_path, ropweaver::SHT_SYMTAB, {
            { "$t", 0x10000 }
        }, text, 0x10000);

        ELFParser parser(elf_path);
        ASSERT_TRUE(parser.parse(elf_path), "Parsed 2-byte alignment test ELF");

        GadgetFinder finder(parser.getTextSection(), 0, parser.getArchitecture(), elf_path,
                            parser.getExecBufferMappings(), 10, parser.getInstructionEndianness(),
                            parser.isRvcEnabled(), parser.getArmCodeRegions());
        finder.findGadgets();
        const auto& gadgets = finder.getGadgets();

        bool found_2byte_aligned = false;
        for (const auto& g : gadgets) {
            if (g.address == 0x10002) {
                found_2byte_aligned = true;
                ASSERT_EQ(g.address % 2, 0, "Address is 2-byte aligned");
                ASSERT_EQ(g.address % 4, 2, "Address is not 4-byte aligned (offset 2)");
                ASSERT_EQ(g.instructions.size(), 2, "Gadget has 2 instructions");
                ASSERT_TRUE(g.byte_verified, "Gadget is byte-verified");
            }
        }
        ASSERT_TRUE(found_2byte_aligned, "Candidate scanner found gadget at 2-byte aligned address 0x10002");
    }

    // ------------------------------------------------------------------------
    // Group 5: Mixed ARM, Thumb, and Data ($d) Regions
    // ------------------------------------------------------------------------
    std::cout << "\n[*] Group 5: Mixed ARM, Thumb, and Data ($d) Regions..." << std::endl;
    {
        // 0x10000..0x10007: $a (ARM) -> mov r0, #0 ; bx lr (8 bytes)
        // 0x10008..0x1000F: $d (Data) -> bytes that would disassemble as 'bx lr' or 'pop {pc}' if decoded
        // 0x10010..0x10017: $t (Thumb) -> movs r0, #1 ; bx lr (4 bytes) + padding (4 bytes)
        std::vector<uint8_t> text = {
            // Region 1 ($a, ARM, 8 bytes)
            0x00, 0x00, 0xA0, 0xE3, // mov r0, #0
            0x1E, 0xFF, 0x2F, 0xE1, // bx lr
            // Region 2 ($d, Data, 8 bytes: trap / terminator lookalikes that must NEVER be decoded)
            0x70, 0x47, 0x10, 0xBD, 0x1E, 0xFF, 0x2F, 0xE1,
            // Region 3 ($t, Thumb, 8 bytes)
            0x01, 0x20,             // movs r0, #1
            0x70, 0x47,             // bx lr
            0x00, 0xBF, 0x00, 0xBF  // nop ; nop
        };

        std::string elf_path = "build-win/test_arm_mixed_regions.elf";
        write_synthetic_arm_elf(elf_path, ropweaver::SHT_SYMTAB, {
            { "$a", 0x10000 },
            { "$d", 0x10008 },
            { "$t", 0x10010 }
        }, text, 0x10000);

        ELFParser parser(elf_path);
        ASSERT_TRUE(parser.parse(elf_path), "Parsed mixed regions ELF");
        ASSERT_EQ(parser.getArmCodeRegions().size(), 3, "Constructed 3 regions");

        GadgetFinder finder(parser.getTextSection(), 0, parser.getArchitecture(), elf_path,
                            parser.getExecBufferMappings(), 10, parser.getInstructionEndianness(),
                            parser.isRvcEnabled(), parser.getArmCodeRegions());
        finder.findGadgets();
        const auto& gadgets = finder.getGadgets();

        // Check ARM gadget from Region 1
        bool found_arm = false;
        for (const auto& g : gadgets) {
            if (g.address == 0x10000) {
                found_arm = true;
                ASSERT_EQ(g.architecture, "armv7", "ARM gadget arch is armv7");
            }
        }
        ASSERT_TRUE(found_arm, "Discovered ARM gadget in $a region [0x10000, 0x10008)");

        // Check Thumb gadget from Region 3
        bool found_thumb = false;
        for (const auto& g : gadgets) {
            if (g.address == 0x10010) {
                found_thumb = true;
                ASSERT_EQ(g.architecture, "armv7", "Thumb gadget arch is armv7");
            }
        }
        ASSERT_TRUE(found_thumb, "Discovered Thumb gadget in $t region [0x10010, 0x10018)");

        // Check Data Region ($d) strictly excluded: NO gadget address in [0x10008, 0x10010)
        bool data_leak = false;
        for (const auto& g : gadgets) {
            if (g.address >= 0x10008 && g.address < 0x10010) {
                data_leak = true;
                std::cerr << "[LEAK] Gadget found in $d region: 0x" << std::hex << g.address << " " << g.assembly << std::endl;
            }
        }
        ASSERT_TRUE(!data_leak, "Strict data exclusion: Zero gadgets discovered in $d region [0x10008, 0x10010)");
    }

    // ------------------------------------------------------------------------
    // Group 6: Region Boundary Enforcement
    // ------------------------------------------------------------------------
    std::cout << "\n[*] Group 6: Region Boundary Enforcement..." << std::endl;
    {
        // Verify that candidate scanning backwards from a terminator does NOT cross
        // into the preceding region (e.g. data or ARM region).
        // Region 1 ($d, 4 bytes): 0x01, 0x20, 0x02, 0x21 (looks like Thumb movs)
        // Region 2 ($t, 4 bytes): 0x00, 0xBF (nop), 0x70, 0x47 (bx lr)
        std::vector<uint8_t> text = {
            0x01, 0x20, 0x02, 0x21, // $d data (4 bytes)
            0x00, 0xBF,             // $t nop
            0x70, 0x47              // $t bx lr
        };
        std::string elf_path = "build-win/test_boundary_enforce.elf";
        write_synthetic_arm_elf(elf_path, ropweaver::SHT_SYMTAB, {
            { "$d", 0x10000 },
            { "$t", 0x10004 }
        }, text, 0x10000);

        ELFParser parser(elf_path);
        ASSERT_TRUE(parser.parse(elf_path), "Parsed boundary test ELF");

        GadgetFinder finder(parser.getTextSection(), 0, parser.getArchitecture(), elf_path,
                            parser.getExecBufferMappings(), 10, parser.getInstructionEndianness(),
                            parser.isRvcEnabled(), parser.getArmCodeRegions());
        finder.findGadgets();
        const auto& gadgets = finder.getGadgets();

        // Every gadget found must have address >= 0x10004
        bool crossed_boundary = false;
        for (const auto& g : gadgets) {
            if (g.address < 0x10004) {
                crossed_boundary = true;
            }
        }
        ASSERT_TRUE(!crossed_boundary, "Thumb candidate scanning did not cross into preceding $d region");
    }

    // ------------------------------------------------------------------------
    // Group 7: Trap Rejection (`bkpt`)
    // ------------------------------------------------------------------------
    std::cout << "\n[*] Group 7: Trap Rejection (`bkpt`)..." << std::endl;
    {
        // 1. Thumb terminator bkpt #0 (0x00, 0xBE) -> must produce 0 gadgets
        std::vector<uint8_t> text1 = {
            0x00, 0x20, // movs r0, #0
            0x00, 0xBE  // bkpt #0
        };
        ArmCodeRegion r1{ 0x1000, 0x1004, 0, 4, ArmRegionType::Thumb, ".text", true };
        GadgetFinder f1(text1, 0x1000, "armv7", "", 10, Endianness::Little, false, { r1 });
        f1.findGadgets();
        ASSERT_EQ(f1.getGadgets().size(), 0, "bkpt #0 terminator produces 0 gadgets");

        // 2. Intermediate bkpt #0 before bx lr -> must reject gadget
        std::vector<uint8_t> text2 = {
            0x00, 0x20, // movs r0, #0
            0x00, 0xBE, // bkpt #0 (intermediate trap)
            0x70, 0x47  // bx lr
        };
        ArmCodeRegion r2{ 0x1000, 0x1006, 0, 6, ArmRegionType::Thumb, ".text", true };
        GadgetFinder f2(text2, 0x1000, "armv7", "", 10, Endianness::Little, false, { r2 });
        f2.findGadgets();
        bool found_with_bkpt = false;
        for (const auto& g : f2.getGadgets()) {
            if (g.assembly.find("bkpt") != std::string::npos) {
                found_with_bkpt = true;
            }
        }
        ASSERT_TRUE(!found_with_bkpt, "Intermediate bkpt #0 is strictly rejected from candidate gadgets");
    }

    // ------------------------------------------------------------------------
    // Group 8: Stripped ARM ELF Fallback (No mapping symbols)
    // ------------------------------------------------------------------------
    std::cout << "\n[*] Group 8: Stripped ARM ELF Fallback..." << std::endl;
    {
        // ELF with no symbols at all (no $a, $t, $d)
        std::vector<uint8_t> text = {
            0x00, 0x00, 0xA0, 0xE3, // mov r0, #0 (ARM)
            0x1E, 0xFF, 0x2F, 0xE1  // bx lr (ARM)
        };
        std::string elf_path = "build-win/test_stripped_arm.elf";
        write_synthetic_arm_elf(elf_path, ropweaver::SHT_SYMTAB, {}, text, 0x10000);

        ELFParser parser(elf_path);
        ASSERT_TRUE(parser.parse(elf_path), "Parsed stripped ARM ELF");
        ASSERT_TRUE(!parser.hasArmMappingSymbols(), "Stripped binary has no mapping symbols");
        ASSERT_EQ(parser.getArmMappingSymbols().size(), 0, "0 mapping symbols");
        ASSERT_EQ(parser.getArmCodeRegions().size(), 1, "Has 1 fallback ARM region");
        ASSERT_TRUE(parser.getArmCodeRegions()[0].type == ArmRegionType::Arm, "Fallback region is ARM");

        GadgetFinder finder(parser.getTextSection(), 0, parser.getArchitecture(), elf_path,
                            parser.getExecBufferMappings(), 10, parser.getInstructionEndianness(),
                            parser.isRvcEnabled(), parser.getArmCodeRegions());
        finder.findGadgets();
        const auto& gadgets = finder.getGadgets();
        ASSERT_TRUE(!gadgets.empty(), "Fallback to default ARM-mode scanning finds ARM gadgets");

        bool found_arm_gadget = false;
        for (const auto& g : gadgets) {
            if (g.address == 0x10000 && g.assembly.find("bx lr") != std::string::npos) {
                found_arm_gadget = true;
            }
        }
        ASSERT_TRUE(found_arm_gadget, "Stripped fallback successfully disassembled ARM gadget");
    }

    // ------------------------------------------------------------------------
    // Group 9: Address Handling (Physical VA without Bit 0 Modification)
    // ------------------------------------------------------------------------
    std::cout << "\n[*] Group 9: Address Handling (Physical VA)..." << std::endl;
    {
        std::vector<uint8_t> text = {
            0x01, 0x20, // movs r0, #1
            0x70, 0x47  // bx lr
        };
        ArmCodeRegion thumb_reg{ 0x10000, 0x10004, 0, 4, ArmRegionType::Thumb, ".text", true };
        GadgetFinder finder(text, 0x10000, "armv7", "", 10, Endianness::Little, false, { thumb_reg });
        finder.findGadgets();
        const auto& gadgets = finder.getGadgets();
        ASSERT_TRUE(!gadgets.empty(), "Found Thumb gadgets");

        for (const auto& g : gadgets) {
            ASSERT_EQ(g.address & 1, 0, "Gadget address does not set bit 0 (retains physical VA)");
            ASSERT_EQ(g.preferred_va & 1, 0, "Preferred VA does not set bit 0");
        }
    }

    std::cout << "\n============================================================" << std::endl;
    std::cout << "Step 4.4 Test Results: " << g_tests_passed << " Passed, " << g_tests_failed << " Failed" << std::endl;
    std::cout << "============================================================" << std::endl;

    return g_tests_failed == 0 ? 0 : 1;
}
