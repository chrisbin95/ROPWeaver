#include "core/parsers/elf_parser.h"
#include "core/parsers/elf_defs.h"
#include "core/gadget_finder.h"
#include "core/gadget.h"
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
                                    uint32_t symtab_type,
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
    put16(ropweaver::ET_EXEC);
    put16(ropweaver::EM_ARM);
    put32(1);
    put32(text_va);
    put32(52);
    put32(0);
    put32(ropweaver::EF_ARM_EABI_VER5);
    put16(52);
    put16(32);
    put16(1);
    put16(40);
    put16(0);
    put16(0);

    // 2. Program Header
    put32(ropweaver::PT_LOAD);
    put32(0x1000);
    put32(text_va);
    put32(text_va);
    put32(text_bytes.size());
    put32(text_bytes.size());
    put32(ropweaver::PF_R | ropweaver::PF_X);
    put32(0x1000);

    if (buf.size() < 0x1000) {
        buf.resize(0x1000, 0);
    }

    // 3. Section Data: .text
    size_t text_file_offset = buf.size();
    buf.insert(buf.end(), text_bytes.begin(), text_bytes.end());

    // 4. Section Data: .strtab
    std::vector<uint8_t> strtab;
    strtab.push_back('\0');
    std::vector<uint32_t> sym_name_offsets;
    for (const auto& s : sym_defs) {
        sym_name_offsets.push_back(strtab.size());
        strtab.insert(strtab.end(), s.name.begin(), s.name.end());
        strtab.push_back('\0');
    }

    while (buf.size() % 4 != 0) buf.push_back(0);
    size_t strtab_file_offset = buf.size();
    buf.insert(buf.end(), strtab.begin(), strtab.end());

    // 5. Section Data: Symbol table
    while (buf.size() % 4 != 0) buf.push_back(0);
    size_t symtab_file_offset = buf.size();

    for (size_t b = 0; b < 16; ++b) buf.push_back(0);

    for (size_t i = 0; i < sym_defs.size(); ++i) {
        put32(sym_name_offsets[i]);
        put32(sym_defs[i].address);
        put32(0);
        buf.push_back(0);
        buf.push_back(0);
        put16(1);
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

    emit_shdr(0, ropweaver::SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0);
    emit_shdr(off_text_name, ropweaver::SHT_PROGBITS,
              ropweaver::SHF_ALLOC | ropweaver::SHF_EXECINSTR,
              text_va, text_file_offset, text_bytes.size(), 0, 0, 4, 0);
    emit_shdr(off_strtab_name, ropweaver::SHT_STRTAB, 0, 0,
              strtab_file_offset, strtab.size(), 0, 0, 1, 0);
    emit_shdr(off_symtab_name, symtab_type,
              (symtab_type == ropweaver::SHT_DYNSYM) ? ropweaver::SHF_ALLOC : 0,
              0, symtab_file_offset, symtab_size, 2, 1, 4, 16);
    emit_shdr(off_shstrtab_name, ropweaver::SHT_STRTAB, 0, 0,
              shstrtab_file_offset, shstrtab.size(), 0, 0, 1, 0);

    uint16_t shnum = 5;

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
    patch16(50, 4);

    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(buf.data()), buf.size());
}

int main() {
    std::cout << "=== ROPWeaver Phase 2 Step 4.5: ARM Thumb Interworking and Address Handling Tests ===" << std::endl;

    // ------------------------------------------------------------------------
    // Group 1: Address Conversion Helpers & Idempotence
    // ------------------------------------------------------------------------
    std::cout << "\n[*] Group 1: Address Conversion Helpers & Idempotence..." << std::endl;
    {
        uint64_t even_addr = 0x00010040ULL;
        uint64_t odd_addr  = 0x00010041ULL;

        // Tagging an even address produces bit 0 set
        ASSERT_EQ(to_thumb_interwork_address(even_addr), odd_addr, "to_thumb_interwork_address sets bit 0");
        ASSERT_TRUE(is_thumb_interwork_address(odd_addr), "is_thumb_interwork_address is true for tagged address");
        ASSERT_TRUE(!is_thumb_interwork_address(even_addr), "is_thumb_interwork_address is false for even address");

        // Idempotence of tagging: tagging an already tagged address is a no-op
        ASSERT_EQ(to_thumb_interwork_address(odd_addr), odd_addr, "Tagging already tagged address is idempotent");
        ASSERT_EQ(to_thumb_interwork_address(to_thumb_interwork_address(even_addr)), odd_addr, "Double-tagging produces same tagged address");

        // Stripping bit 0 recovers original physical address
        ASSERT_EQ(to_physical_instruction_address(odd_addr), even_addr, "to_physical_instruction_address clears bit 0");
        ASSERT_EQ(to_physical_instruction_address(even_addr), even_addr, "Stripping even address is idempotent");
        ASSERT_EQ(to_physical_instruction_address(to_physical_instruction_address(odd_addr)), even_addr, "Double-stripping produces physical address");

        // Round-trip verification
        ASSERT_EQ(to_physical_instruction_address(to_thumb_interwork_address(even_addr)), even_addr, "Round-trip tag -> strip preserves physical address");
    }

    // ------------------------------------------------------------------------
    // Group 2: ARM-only Gadget Address Semantics
    // ------------------------------------------------------------------------
    std::cout << "\n[*] Group 2: ARM-only Gadget Address Semantics..." << std::endl;
    {
        std::vector<uint8_t> text = {
            0x00, 0x00, 0xA0, 0xE3, // mov r0, #0
            0x1E, 0xFF, 0x2F, 0xE1  // bx lr
        };
        std::string elf_path = "build-win/test_arm_interwork_arm_only.elf";
        write_synthetic_arm_elf(elf_path, ropweaver::SHT_SYMTAB, {
            { "$a", 0x10000 }
        }, text, 0x10000);

        ELFParser parser(elf_path);
        ASSERT_TRUE(parser.parse(elf_path), "Parsed ARM-only ELF");

        GadgetFinder finder(parser.getTextSection(), 0, parser.getArchitecture(), elf_path,
                            parser.getExecBufferMappings(), 10, parser.getInstructionEndianness(),
                            parser.isRvcEnabled(), parser.getArmCodeRegions());
        finder.findGadgets();
        const auto& gadgets = finder.getGadgets();
        ASSERT_TRUE(!gadgets.empty(), "Found ARM gadgets");

        for (const auto& g : gadgets) {
            // ARM gadgets must have is_thumb == false
            ASSERT_TRUE(!g.is_thumb, "ARM gadget has is_thumb == false");
            ASSERT_TRUE(!g.isThumb(), "g.isThumb() returns false");

            // Physical address must be even (bit 0 is 0)
            ASSERT_EQ(g.address & 1, 0, "ARM physical address has bit 0 == 0");
            ASSERT_EQ(g.preferred_va & 1, 0, "ARM preferred_va has bit 0 == 0");
            ASSERT_EQ(g.getPhysicalAddress(), g.address, "getPhysicalAddress() returns g.address");

            // Interworking entry address must retain ARM state (bit 0 == 0)
            ASSERT_EQ(g.entry_address & 1, 0, "ARM entry_address has bit 0 == 0");
            ASSERT_EQ(g.entry_address, g.address, "ARM entry_address equals physical address");
            ASSERT_EQ(g.getInterworkingAddress(), g.address, "getInterworkingAddress() equals physical address");
        }
    }

    // ------------------------------------------------------------------------
    // Group 3: Thumb-only Gadget Address Semantics
    // ------------------------------------------------------------------------
    std::cout << "\n[*] Group 3: Thumb-only Gadget Address Semantics..." << std::endl;
    {
        std::vector<uint8_t> text = {
            0x01, 0x20, // movs r0, #1
            0x70, 0x47  // bx lr
        };
        std::string elf_path = "build-win/test_arm_interwork_thumb_only.elf";
        write_synthetic_arm_elf(elf_path, ropweaver::SHT_SYMTAB, {
            { "$t", 0x10000 }
        }, text, 0x10000);

        ELFParser parser(elf_path);
        ASSERT_TRUE(parser.parse(elf_path), "Parsed Thumb-only ELF");

        GadgetFinder finder(parser.getTextSection(), 0, parser.getArchitecture(), elf_path,
                            parser.getExecBufferMappings(), 10, parser.getInstructionEndianness(),
                            parser.isRvcEnabled(), parser.getArmCodeRegions());
        finder.findGadgets();
        const auto& gadgets = finder.getGadgets();
        ASSERT_TRUE(!gadgets.empty(), "Found Thumb gadgets");

        for (const auto& g : gadgets) {
            // Thumb gadgets must have is_thumb == true
            ASSERT_TRUE(g.is_thumb, "Thumb gadget has is_thumb == true");
            ASSERT_TRUE(g.isThumb(), "g.isThumb() returns true");

            // Physical instruction address must remain even
            ASSERT_EQ(g.address & 1, 0, "Thumb physical address has bit 0 == 0 (even address)");
            ASSERT_EQ(g.preferred_va & 1, 0, "Thumb preferred_va has bit 0 == 0 (even address)");
            ASSERT_EQ(g.getPhysicalAddress(), g.address, "getPhysicalAddress() returns physical even address");

            // Thumb interworking entry address must have bit 0 set
            ASSERT_EQ(g.entry_address & 1, 1, "Thumb entry_address has bit 0 set");
            ASSERT_EQ(g.entry_address, g.address | 1ULL, "Thumb entry_address equals physical address | 1");
            ASSERT_EQ(g.getInterworkingAddress(), g.address | 1ULL, "getInterworkingAddress() equals physical address | 1");

            // Conversion round-trip
            ASSERT_EQ(to_physical_instruction_address(g.getInterworkingAddress()), g.getPhysicalAddress(),
                      "Stripping bit 0 from getInterworkingAddress() recovers physical address");
        }
    }

    // ------------------------------------------------------------------------
    // Group 4: Mixed ARM and Thumb ELF Binary
    // ------------------------------------------------------------------------
    std::cout << "\n[*] Group 4: Mixed ARM and Thumb ELF Binary..." << std::endl;
    {
        // 0x10000..0x10007: $a (ARM) -> mov r0, #0 ; bx lr
        // 0x10008..0x1000F: $t (Thumb) -> movs r0, #1 ; bx lr
        std::vector<uint8_t> text = {
            // ARM code at 0x10000
            0x00, 0x00, 0xA0, 0xE3, // mov r0, #0
            0x1E, 0xFF, 0x2F, 0xE1, // bx lr
            // Thumb code at 0x10008
            0x01, 0x20,             // movs r0, #1
            0x70, 0x47,             // bx lr
            0x00, 0xBF, 0x00, 0xBF  // nop ; nop
        };

        std::string elf_path = "build-win/test_arm_interwork_mixed.elf";
        write_synthetic_arm_elf(elf_path, ropweaver::SHT_SYMTAB, {
            { "$a", 0x10000 },
            { "$t", 0x10008 }
        }, text, 0x10000);

        ELFParser parser(elf_path);
        ASSERT_TRUE(parser.parse(elf_path), "Parsed mixed ELF");

        GadgetFinder finder(parser.getTextSection(), 0, parser.getArchitecture(), elf_path,
                            parser.getExecBufferMappings(), 10, parser.getInstructionEndianness(),
                            parser.isRvcEnabled(), parser.getArmCodeRegions());
        finder.findGadgets();
        const auto& gadgets = finder.getGadgets();

        bool found_arm = false;
        bool found_thumb = false;

        for (const auto& g : gadgets) {
            if (g.address == 0x10000) {
                found_arm = true;
                ASSERT_TRUE(!g.is_thumb, "ARM gadget has is_thumb == false");
                ASSERT_EQ(g.getPhysicalAddress(), 0x10000ULL, "ARM physical address is 0x10000");
                ASSERT_EQ(g.getInterworkingAddress(), 0x10000ULL, "ARM interworking address is 0x10000 (bit 0 = 0)");
            }
            if (g.address == 0x10008) {
                found_thumb = true;
                ASSERT_TRUE(g.is_thumb, "Thumb gadget has is_thumb == true");
                ASSERT_EQ(g.getPhysicalAddress(), 0x10008ULL, "Thumb physical address is 0x10008 (even)");
                ASSERT_EQ(g.getInterworkingAddress(), 0x10009ULL, "Thumb interworking address is 0x10009 (bit 0 = 1)");
            }
        }

        ASSERT_TRUE(found_arm, "Discovered ARM gadget with bit 0 = 0");
        ASSERT_TRUE(found_thumb, "Discovered Thumb gadget with bit 0 = 1");
    }

    // ------------------------------------------------------------------------
    // Group 5: Non-ARM Architectures (AArch64, RISC-V, x86) Are Never Modified
    // ------------------------------------------------------------------------
    std::cout << "\n[*] Group 5: Non-ARM Architectures Exclusion..." << std::endl;
    {
        // AArch64 gadget
        Gadget aarch64_g;
        aarch64_g.architecture = "aarch64";
        aarch64_g.address = 0x400040ULL;
        aarch64_g.preferred_va = 0x400040ULL;
        aarch64_g.is_thumb = false;
        aarch64_g.entry_address = aarch64_g.address;

        ASSERT_TRUE(!aarch64_g.isThumb(), "AArch64 is not Thumb");
        ASSERT_EQ(aarch64_g.getPhysicalAddress(), 0x400040ULL, "AArch64 physical address unchanged");
        ASSERT_EQ(aarch64_g.getInterworkingAddress(), 0x400040ULL, "AArch64 interworking address unchanged (bit 0 is 0)");

        // RISC-V gadget
        Gadget riscv_g;
        riscv_g.architecture = "riscv32";
        riscv_g.address = 0x80000002ULL;
        riscv_g.preferred_va = 0x80000002ULL;
        riscv_g.is_thumb = false;
        riscv_g.entry_address = riscv_g.address;

        ASSERT_TRUE(!riscv_g.isThumb(), "RISC-V is not Thumb");
        ASSERT_EQ(riscv_g.getPhysicalAddress(), 0x80000002ULL, "RISC-V physical address unchanged");
        ASSERT_EQ(riscv_g.getInterworkingAddress(), 0x80000002ULL, "RISC-V interworking address unchanged (bit 0 is 0)");

        // x86_64 gadget
        Gadget x64_g;
        x64_g.architecture = "x86_64";
        x64_g.address = 0x401000ULL;
        x64_g.preferred_va = 0x401000ULL;
        x64_g.is_thumb = false;
        x64_g.entry_address = x64_g.address;

        ASSERT_TRUE(!x64_g.isThumb(), "x86_64 is not Thumb");
        ASSERT_EQ(x64_g.getPhysicalAddress(), 0x401000ULL, "x86_64 physical address unchanged");
        ASSERT_EQ(x64_g.getInterworkingAddress(), 0x401000ULL, "x86_64 interworking address unchanged");
    }

    // ------------------------------------------------------------------------
    // Group 6: Deduplication & Sorting Consistency
    // ------------------------------------------------------------------------
    std::cout << "\n[*] Group 6: Deduplication & Sorting Consistency..." << std::endl;
    {
        std::vector<uint8_t> text = {
            0x01, 0x20, // 0x10000: movs r0, #1
            0x70, 0x47, // 0x10002: bx lr
            0x02, 0x20, // 0x10004: movs r0, #2
            0x70, 0x47  // 0x10006: bx lr
        };
        ArmCodeRegion thumb_reg{ 0x10000, 0x10008, 0, 8, ArmRegionType::Thumb, ".text", true };
        GadgetFinder finder(text, 0x10000, "armv7", "", 10, Endianness::Little, false, { thumb_reg });
        finder.findGadgets();
        const auto& gadgets = finder.getGadgets();

        // Check strictly ascending order by physical address
        for (size_t i = 1; i < gadgets.size(); ++i) {
            ASSERT_TRUE(gadgets[i-1].address <= gadgets[i].address, "Gadgets sorted by physical address ascending");
            ASSERT_TRUE(gadgets[i].is_thumb, "Every gadget has is_thumb == true");
            ASSERT_EQ(gadgets[i].entry_address, gadgets[i].address | 1ULL, "Entry address matches address | 1");
        }
    }

    std::cout << "\n============================================================" << std::endl;
    std::cout << "Step 4.5 Test Results: " << g_tests_passed << " Passed, " << g_tests_failed << " Failed" << std::endl;
    std::cout << "============================================================" << std::endl;

    return g_tests_failed == 0 ? 0 : 1;
}

