#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <cstdint>
#include <cstring>
#include <cassert>

#include "core/capstone_compat.h"
#include "core/parsers/file_parser.h"
#include "core/parsers/elf_parser.h"
#include "core/parsers/elf_defs.h"
#include "core/gadget_finder.h"

using namespace ropweaver;

// Dummy parser to verify FileParser base class virtual defaults
class DummyTestParser : public FileParser {
public:
    DummyTestParser() : FileParser("dummy") {}
    bool parse(const std::string&) override { return true; }
    const std::vector<uint8_t>& getTextSection() const override { static std::vector<uint8_t> v; return v; }
    uint64_t getTextSectionBaseAddress() const override { return 0; }
    std::string getArchitecture() const override { return "unknown"; }
    bool is64Bit() const override { return false; }
    std::string getBinaryType() const override { return "UNKNOWN"; }
    std::string getFilePath() const override { return m_filepath; }
};

// Helper to write complete, valid ELF32 with specific e_machine, e_flags, and executable .text section
static bool write_complete_test_elf32(const std::string& filepath, uint16_t machine, uint32_t flags,
                                      const std::vector<uint8_t>& code = { 0x13, 0x00, 0x00, 0x00 }) {
    std::ofstream out(filepath, std::ios::binary);
    if (!out) return false;

    // Layout:
    // 0x00: Ehdr (52 bytes)
    // 0x34: Phdr (32 bytes)
    // 0x60: Code (.text)
    // 0x80: shstrtab
    // 0xA0: Shdrs (3 * 40 = 120 bytes)
    uint32_t code_off = 0x60;
    uint32_t code_size = static_cast<uint32_t>(code.size());
    uint32_t shstrtab_off = 0x80;
    const char shstrtab_bytes[] = "\0.text\0.shstrtab\0";
    uint32_t shstrtab_size = sizeof(shstrtab_bytes); // 17 bytes
    uint32_t shoff = 0xA0;
    uint16_t num_shdrs = 3;
    uint16_t shstrndx = 2;

    uint32_t base_va = 0x10000;
    uint32_t code_va = base_va + code_off;

    // 1. Ehdr (52 bytes)
    uint8_t ehdr[52];
    std::memset(ehdr, 0, sizeof(ehdr));
    ehdr[0] = 0x7F; ehdr[1] = 'E'; ehdr[2] = 'L'; ehdr[3] = 'F';
    ehdr[4] = 1; // ELFCLASS32
    ehdr[5] = 1; // ELFDATA2LSB
    ehdr[6] = 1; // EV_CURRENT
    ehdr[16] = 2; // ET_EXEC
    ehdr[18] = static_cast<uint8_t>(machine & 0xFF);
    ehdr[19] = static_cast<uint8_t>((machine >> 8) & 0xFF);
    ehdr[20] = 1; // version
    ehdr[24] = static_cast<uint8_t>(code_va & 0xFF);
    ehdr[25] = static_cast<uint8_t>((code_va >> 8) & 0xFF);
    ehdr[26] = static_cast<uint8_t>((code_va >> 16) & 0xFF);
    ehdr[27] = static_cast<uint8_t>((code_va >> 24) & 0xFF);
    ehdr[28] = 52; // e_phoff
    ehdr[32] = static_cast<uint8_t>(shoff & 0xFF);
    ehdr[33] = static_cast<uint8_t>((shoff >> 8) & 0xFF);
    ehdr[36] = static_cast<uint8_t>(flags & 0xFF);
    ehdr[37] = static_cast<uint8_t>((flags >> 8) & 0xFF);
    ehdr[38] = static_cast<uint8_t>((flags >> 16) & 0xFF);
    ehdr[39] = static_cast<uint8_t>((flags >> 24) & 0xFF);
    ehdr[40] = 52; // e_ehsize
    ehdr[42] = 32; // e_phentsize
    ehdr[44] = 1;  // e_phnum
    ehdr[46] = 40; // e_shentsize
    ehdr[48] = static_cast<uint8_t>(num_shdrs & 0xFF);
    ehdr[50] = static_cast<uint8_t>(shstrndx & 0xFF);

    // 2. Phdr (32 bytes) PT_LOAD
    uint8_t phdr[32];
    std::memset(phdr, 0, sizeof(phdr));
    phdr[0] = 1; // PT_LOAD
    // p_vaddr = base_va
    phdr[4] = static_cast<uint8_t>(base_va & 0xFF);
    phdr[5] = static_cast<uint8_t>((base_va >> 8) & 0xFF);
    phdr[6] = static_cast<uint8_t>((base_va >> 16) & 0xFF);
    phdr[7] = static_cast<uint8_t>((base_va >> 24) & 0xFF);
    // p_paddr = base_va
    phdr[8] = phdr[4]; phdr[9] = phdr[5]; phdr[10] = phdr[6]; phdr[11] = phdr[7];
    // p_filesz = 0xA0 + 120
    uint32_t total_sz = shoff + (num_shdrs * 40);
    phdr[12] = static_cast<uint8_t>(total_sz & 0xFF);
    phdr[13] = static_cast<uint8_t>((total_sz >> 8) & 0xFF);
    phdr[16] = phdr[12]; phdr[17] = phdr[13]; // p_memsz
    phdr[24] = 7; // PF_R | PF_W | PF_X
    phdr[28] = 0x00; phdr[29] = 0x10; // p_align = 0x1000

    std::vector<uint8_t> buffer(total_sz, 0);
    std::memcpy(buffer.data(), ehdr, sizeof(ehdr));
    std::memcpy(buffer.data() + 52, phdr, sizeof(phdr));
    std::memcpy(buffer.data() + code_off, code.data(), code.size());
    std::memcpy(buffer.data() + shstrtab_off, shstrtab_bytes, shstrtab_size);

    // Shdr 1: .text (sh_name = 1, sh_type = 1, sh_flags = 6)
    uint8_t* sh1 = buffer.data() + shoff + 40;
    sh1[0] = 1; // name = 1 (.text)
    sh1[4] = 1; // type = SHT_PROGBITS
    sh1[8] = 6; // flags = SHF_ALLOC | SHF_EXECINSTR
    sh1[12] = static_cast<uint8_t>(code_va & 0xFF);
    sh1[13] = static_cast<uint8_t>((code_va >> 8) & 0xFF);
    sh1[14] = static_cast<uint8_t>((code_va >> 16) & 0xFF);
    sh1[15] = static_cast<uint8_t>((code_va >> 24) & 0xFF);
    sh1[16] = static_cast<uint8_t>(code_off & 0xFF);
    sh1[20] = static_cast<uint8_t>(code_size & 0xFF);
    sh1[32] = 4; // addralign = 4

    // Shdr 2: .shstrtab (sh_name = 7, sh_type = 3, sh_flags = 0)
    uint8_t* sh2 = buffer.data() + shoff + 80;
    sh2[0] = 7; // name = 7 (.shstrtab)
    sh2[4] = 3; // type = SHT_STRTAB
    sh2[16] = static_cast<uint8_t>(shstrtab_off & 0xFF);
    sh2[20] = static_cast<uint8_t>(shstrtab_size & 0xFF);
    sh2[32] = 1; // addralign = 1

    out.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    return out.good();
}

// Helper to write complete, valid ELF64 with specific e_machine, e_flags, and executable .text section
static bool write_complete_test_elf64(const std::string& filepath, uint16_t machine, uint32_t flags,
                                      const std::vector<uint8_t>& code = { 0x13, 0x00, 0x00, 0x00 }) {
    std::ofstream out(filepath, std::ios::binary);
    if (!out) return false;

    // Layout:
    // 0x00: Ehdr (64 bytes)
    // 0x40: Phdr (56 bytes)
    // 0x80: Code (.text)
    // 0xA0: shstrtab
    // 0xC0: Shdrs (3 * 64 = 192 bytes)
    uint32_t code_off = 0x80;
    uint32_t code_size = static_cast<uint32_t>(code.size());
    uint32_t shstrtab_off = 0xA0;
    const char shstrtab_bytes[] = "\0.text\0.shstrtab\0";
    uint32_t shstrtab_size = sizeof(shstrtab_bytes); // 17 bytes
    uint32_t shoff = 0xC0;
    uint16_t num_shdrs = 3;
    uint16_t shstrndx = 2;

    uint64_t base_va = 0x400000;
    uint64_t code_va = base_va + code_off;

    // 1. Ehdr (64 bytes)
    uint8_t ehdr[64];
    std::memset(ehdr, 0, sizeof(ehdr));
    ehdr[0] = 0x7F; ehdr[1] = 'E'; ehdr[2] = 'L'; ehdr[3] = 'F';
    ehdr[4] = 2; // ELFCLASS64
    ehdr[5] = 1; // ELFDATA2LSB
    ehdr[6] = 1; // EV_CURRENT
    ehdr[16] = 2; // ET_EXEC
    ehdr[18] = static_cast<uint8_t>(machine & 0xFF);
    ehdr[19] = static_cast<uint8_t>((machine >> 8) & 0xFF);
    ehdr[20] = 1; // version
    ehdr[24] = static_cast<uint8_t>(code_va & 0xFF);
    ehdr[25] = static_cast<uint8_t>((code_va >> 8) & 0xFF);
    ehdr[26] = static_cast<uint8_t>((code_va >> 16) & 0xFF);
    ehdr[27] = static_cast<uint8_t>((code_va >> 24) & 0xFF);
    ehdr[32] = 64; // e_phoff
    ehdr[40] = static_cast<uint8_t>(shoff & 0xFF);
    ehdr[41] = static_cast<uint8_t>((shoff >> 8) & 0xFF);
    ehdr[48] = static_cast<uint8_t>(flags & 0xFF);
    ehdr[49] = static_cast<uint8_t>((flags >> 8) & 0xFF);
    ehdr[50] = static_cast<uint8_t>((flags >> 16) & 0xFF);
    ehdr[51] = static_cast<uint8_t>((flags >> 24) & 0xFF);
    ehdr[52] = 64; // e_ehsize
    ehdr[54] = 56; // e_phentsize
    ehdr[56] = 1;  // e_phnum
    ehdr[58] = 64; // e_shentsize
    ehdr[60] = static_cast<uint8_t>(num_shdrs & 0xFF);
    ehdr[62] = static_cast<uint8_t>(shstrndx & 0xFF);

    // 2. Phdr (56 bytes) PT_LOAD
    uint8_t phdr[56];
    std::memset(phdr, 0, sizeof(phdr));
    phdr[0] = 1; // PT_LOAD
    phdr[4] = 7; // p_flags = PF_R | PF_W | PF_X
    // p_vaddr = base_va
    phdr[16] = static_cast<uint8_t>(base_va & 0xFF);
    phdr[17] = static_cast<uint8_t>((base_va >> 8) & 0xFF);
    phdr[18] = static_cast<uint8_t>((base_va >> 16) & 0xFF);
    phdr[19] = static_cast<uint8_t>((base_va >> 24) & 0xFF);
    // p_paddr = base_va
    phdr[24] = phdr[16]; phdr[25] = phdr[17]; phdr[26] = phdr[18]; phdr[27] = phdr[19];
    // p_filesz = 0xC0 + 192 = 384
    uint32_t total_sz = shoff + (num_shdrs * 64);
    phdr[32] = static_cast<uint8_t>(total_sz & 0xFF);
    phdr[33] = static_cast<uint8_t>((total_sz >> 8) & 0xFF);
    phdr[40] = phdr[32]; phdr[41] = phdr[33]; // p_memsz
    phdr[48] = 0x00; phdr[49] = 0x10; // p_align = 0x1000

    std::vector<uint8_t> buffer(total_sz, 0);
    std::memcpy(buffer.data(), ehdr, sizeof(ehdr));
    std::memcpy(buffer.data() + 64, phdr, sizeof(phdr));
    std::memcpy(buffer.data() + code_off, code.data(), code.size());
    std::memcpy(buffer.data() + shstrtab_off, shstrtab_bytes, shstrtab_size);

    // Shdr 1: .text (sh_name = 1, sh_type = 1, sh_flags = 6)
    uint8_t* sh1 = buffer.data() + shoff + 64;
    sh1[0] = 1; // name = 1 (.text)
    sh1[4] = 1; // type = SHT_PROGBITS
    sh1[8] = 6; // flags = SHF_ALLOC | SHF_EXECINSTR
    sh1[16] = static_cast<uint8_t>(code_va & 0xFF);
    sh1[17] = static_cast<uint8_t>((code_va >> 8) & 0xFF);
    sh1[18] = static_cast<uint8_t>((code_va >> 16) & 0xFF);
    sh1[19] = static_cast<uint8_t>((code_va >> 24) & 0xFF);
    sh1[24] = static_cast<uint8_t>(code_off & 0xFF);
    sh1[32] = static_cast<uint8_t>(code_size & 0xFF);
    sh1[48] = 4; // addralign = 4

    // Shdr 2: .shstrtab (sh_name = 7, sh_type = 3, sh_flags = 0)
    uint8_t* sh2 = buffer.data() + shoff + 128;
    sh2[0] = 7; // name = 7 (.shstrtab)
    sh2[4] = 3; // type = SHT_STRTAB
    sh2[24] = static_cast<uint8_t>(shstrtab_off & 0xFF);
    sh2[32] = static_cast<uint8_t>(shstrtab_size & 0xFF);
    sh2[48] = 1; // addralign = 1

    out.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    return out.good();
}

int main() {
    int total_tests = 0;
    int passed_tests = 0;
    int failures = 0;

    auto assertCond = [&](const std::string& name, bool cond, const std::string& detail = "") {
        total_tests++;
        if (cond) {
            passed_tests++;
            std::cout << "  [PASS] " << name << "\n";
        } else {
            failures++;
            std::cerr << "  [FAIL] " << name;
            if (!detail.empty()) std::cerr << " (" << detail << ")";
            std::cerr << "\n";
        }
    };

    std::cout << "=== Running ROPWeaver Phase 2 Step 4.1 RVC Groundwork Tests ===\n\n";

    // -------------------------------------------------------------
    // Group 1: Capstone Compatibility Foundation
    // -------------------------------------------------------------
    std::cout << "[*] Group 1: Capstone Compatibility Foundation...\n";
    {
        assertCond("CS_API_MAJOR is defined and >= 4", CS_API_MAJOR >= 4);
        assertCond("ROPW_CAPSTONE_HAS_RVC is true", ROPW_CAPSTONE_HAS_RVC == true);
        assertCond("ROPW_CS_MODE_RISCVC is non-zero (1 << 2 = 4)", static_cast<int>(ROPW_CS_MODE_RISCVC) == 4);
        assertCond("CS_MODE_RISCVC equals ROPW_CS_MODE_RISCVC", CS_MODE_RISCVC == ROPW_CS_MODE_RISCVC);

        // Capstone handle initialization with RVC mode flag
        csh handle32 = 0;
        cs_err err32 = cs_open(CS_ARCH_RISCV, static_cast<cs_mode>(CS_MODE_RISCV32 | ROPW_CS_MODE_RISCVC), &handle32);
        assertCond("cs_open succeeds for RISCV32 + RVC", err32 == CS_ERR_OK && handle32 != 0);

        csh handle64 = 0;
        cs_err err64 = cs_open(CS_ARCH_RISCV, static_cast<cs_mode>(CS_MODE_RISCV64 | ROPW_CS_MODE_RISCVC), &handle64);
        assertCond("cs_open succeeds for RISCV64 + RVC", err64 == CS_ERR_OK && handle64 != 0);

        // Disassemble 16-bit compressed instruction c.jr ra (0x8082 = 0x82, 0x80)
        uint8_t c_jr_ra_bytes[] = { 0x82, 0x80 };
        cs_insn *insns = nullptr;
        size_t count = cs_disasm(handle64, c_jr_ra_bytes, sizeof(c_jr_ra_bytes), 0x1000, 1, &insns);
        assertCond("Disassembles 16-bit c.jr ra opcode (0x8082)", count == 1);
        if (count == 1) {
            std::string mnem = insns[0].mnemonic ? insns[0].mnemonic : "";
            std::string ops  = insns[0].op_str ? insns[0].op_str : "";
            assertCond("c.jr mnemonic is 'c.jr'", mnem == "c.jr", "got: " + mnem);
            assertCond("c.jr operand is 'ra'", ops.find("ra") != std::string::npos, "got: " + ops);
            cs_free(insns, count);
        }

        // Disassemble 16-bit c.ebreak opcode (0x9002 = 0x02, 0x90)
        uint8_t c_ebreak_bytes[] = { 0x02, 0x90 };
        insns = nullptr;
        count = cs_disasm(handle64, c_ebreak_bytes, sizeof(c_ebreak_bytes), 0x1002, 1, &insns);
        assertCond("Disassembles 16-bit c.ebreak opcode (0x9002)", count == 1);
        if (count == 1) {
            std::string mnem = insns[0].mnemonic ? insns[0].mnemonic : "";
            assertCond("c.ebreak mnemonic is 'c.ebreak'", mnem == "c.ebreak", "got: " + mnem);
            cs_free(insns, count);
        }

        // Disassemble 16-bit c.jalr ra opcode (0x9082 = 0x82, 0x90)
        uint8_t c_jalr_bytes[] = { 0x82, 0x90 };
        insns = nullptr;
        count = cs_disasm(handle64, c_jalr_bytes, sizeof(c_jalr_bytes), 0x1004, 1, &insns);
        assertCond("Disassembles 16-bit c.jalr ra opcode (0x9082)", count == 1);
        if (count == 1) {
            std::string mnem = insns[0].mnemonic ? insns[0].mnemonic : "";
            assertCond("c.jalr mnemonic is 'c.jalr'", mnem == "c.jalr", "got: " + mnem);
            cs_free(insns, count);
        }

        if (handle32) cs_close(&handle32);
        if (handle64) cs_close(&handle64);
    }

    // -------------------------------------------------------------
    // Group 2: Parser Base Virtual Defaults & Interface
    // -------------------------------------------------------------
    std::cout << "\n[*] Group 2: Parser Base Virtual Defaults & Interface...\n";
    {
        DummyTestParser dummy;
        assertCond("FileParser base default isRvcEnabled() == false", dummy.isRvcEnabled() == false);
    }

    // -------------------------------------------------------------
    // Group 3: Non-RVC ELF Binary Metadata Verification
    // -------------------------------------------------------------
    std::cout << "\n[*] Group 3: Non-RVC ELF Binary Metadata Verification...\n";
    {
        // 1. Standard 32-bit RISC-V binary (no EF_RISCV_RVC in e_flags)
        ELFParser elf32("test_binaries/elf32_riscv");
        bool p32 = elf32.parse("test_binaries/elf32_riscv");
        assertCond("Parsed test_binaries/elf32_riscv", p32);
        assertCond("elf32_riscv arch is 'riscv32'", elf32.getArchitecture() == "riscv32");
        assertCond("elf32_riscv (e_flags = 0) has isRvcEnabled() == false", elf32.isRvcEnabled() == false);
        assertCond("elf32_riscv e_flags has no EF_RISCV_RVC", (elf32.getElfFlags() & EF_RISCV_RVC) == 0);

        // 2. Standard 64-bit RISC-V binary (no EF_RISCV_RVC in e_flags)
        ELFParser elf64("test_binaries/elf64_riscv");
        bool p64 = elf64.parse("test_binaries/elf64_riscv");
        assertCond("Parsed test_binaries/elf64_riscv", p64);
        assertCond("elf64_riscv arch is 'riscv64'", elf64.getArchitecture() == "riscv64");
        assertCond("elf64_riscv (e_flags = 0) has isRvcEnabled() == false", elf64.isRvcEnabled() == false);
        assertCond("elf64_riscv e_flags has no EF_RISCV_RVC", (elf64.getElfFlags() & EF_RISCV_RVC) == 0);

        // 3. Non-RISC-V binaries: x86, ARM, AArch64 must report isRvcEnabled() == false
        ELFParser elfX86("test_binaries/elf32_x86");
        if (elfX86.parse("test_binaries/elf32_x86")) {
            assertCond("elf32_x86 has isRvcEnabled() == false", elfX86.isRvcEnabled() == false);
        }
        ELFParser elfArm("test_binaries/elf32_arm");
        if (elfArm.parse("test_binaries/elf32_arm")) {
            assertCond("elf32_arm has isRvcEnabled() == false", elfArm.isRvcEnabled() == false);
        }
        ELFParser elfAarch64("test_binaries/elf64_aarch64");
        if (elfAarch64.parse("test_binaries/elf64_aarch64")) {
            assertCond("elf64_aarch64 has isRvcEnabled() == false", elfAarch64.isRvcEnabled() == false);
        }
    }

    // -------------------------------------------------------------
    // Group 4: RVC-Enabled ELF Binary Metadata Detection
    // -------------------------------------------------------------
    std::cout << "\n[*] Group 4: RVC-Enabled ELF Binary Metadata Detection...\n";
    {
        std::string tmpRv32Rvc = "build-win/test_elf32_riscv_rvc";
        std::string tmpRv64Rvc = "build-win/test_elf64_riscv_rvc";
        std::string tmpRv32MultiFlag = "build-win/test_elf32_riscv_multi_flag";
        std::string tmpNonRiscvFlag = "build-win/test_elf32_non_riscv_rvc_flag";

        // 1. Generate complete ELF32 with EF_RISCV_RVC (0x0001)
        bool w1 = write_complete_test_elf32(tmpRv32Rvc, EM_RISCV, EF_RISCV_RVC);
        assertCond("Generated complete ELF32 with EF_RISCV_RVC", w1);
        ELFParser pRv32Rvc(tmpRv32Rvc);
        bool parsed1 = pRv32Rvc.parse(tmpRv32Rvc);
        assertCond("Parsed ELF32 with EF_RISCV_RVC", parsed1);
        assertCond("pRv32Rvc architecture is 'riscv32'", pRv32Rvc.getArchitecture() == "riscv32");
        assertCond("pRv32Rvc has isRvcEnabled() == true", pRv32Rvc.isRvcEnabled() == true);
        assertCond("pRv32Rvc getElfFlags() == EF_RISCV_RVC", pRv32Rvc.getElfFlags() == EF_RISCV_RVC);

        // 2. Generate complete ELF64 with EF_RISCV_RVC (0x0001)
        // Include c.jr ra opcode (0x82, 0x80) in .text section
        bool w2 = write_complete_test_elf64(tmpRv64Rvc, EM_RISCV, EF_RISCV_RVC, { 0x82, 0x80, 0x00, 0x00 });
        assertCond("Generated complete ELF64 with EF_RISCV_RVC", w2);
        ELFParser pRv64Rvc(tmpRv64Rvc);
        bool parsed2 = pRv64Rvc.parse(tmpRv64Rvc);
        assertCond("Parsed ELF64 with EF_RISCV_RVC", parsed2);
        assertCond("pRv64Rvc architecture is 'riscv64'", pRv64Rvc.getArchitecture() == "riscv64");
        assertCond("pRv64Rvc has isRvcEnabled() == true", pRv64Rvc.isRvcEnabled() == true);
        assertCond("pRv64Rvc getElfFlags() == EF_RISCV_RVC", pRv64Rvc.getElfFlags() == EF_RISCV_RVC);

        // 3. Generate complete ELF32 with EF_RISCV_RVC + Float ABI double flag (0x0001 | 0x0004 = 0x0005)
        uint32_t multi_flags = EF_RISCV_RVC | EF_RISCV_FLOAT_ABI_DOUBLE;
        bool w3 = write_complete_test_elf32(tmpRv32MultiFlag, EM_RISCV, multi_flags);
        assertCond("Generated complete ELF32 with RVC + Float ABI flags", w3);
        ELFParser pMulti(tmpRv32MultiFlag);
        bool parsed3 = pMulti.parse(tmpRv32MultiFlag);
        assertCond("Parsed ELF32 with multiple flags", parsed3);
        assertCond("pMulti has isRvcEnabled() == true", pMulti.isRvcEnabled() == true);
        assertCond("pMulti preserves complete e_flags bitmask", pMulti.getElfFlags() == multi_flags);

        // 4. Non-RISC-V machine (EM_386 = 3) with flag 0x0001: must NOT enable RVC
        bool w4 = write_complete_test_elf32(tmpNonRiscvFlag, EM_386, 0x0001);
        assertCond("Generated complete x86 ELF32 with flag 0x0001", w4);
        ELFParser pNonRiscv(tmpNonRiscvFlag);
        bool parsed4 = pNonRiscv.parse(tmpNonRiscvFlag);
        assertCond("Parsed x86 ELF32 with flag 0x0001", parsed4);
        assertCond("pNonRiscv architecture is 'x86'", pNonRiscv.getArchitecture() == "x86");
        assertCond("Non-RISC-V with flag 0x0001 has isRvcEnabled() == false", pNonRiscv.isRvcEnabled() == false);
    }

    // -------------------------------------------------------------
    // Group 5: Control-Flow Terminators vs. Traps Classification
    // -------------------------------------------------------------
    std::cout << "\n[*] Group 5: Control-Flow Terminators vs. Traps Classification...\n";
    {
        std::string rvcBinary = "build-win/test_elf64_riscv_rvc";
        std::string nonRvcBinary = "test_binaries/elf64_riscv";

        auto checkGadgetFinder = [&](const std::string& testName,
                                     const std::vector<uint8_t>& codeBytes,
                                     const std::string& binPath,
                                     bool expectGadgetFound,
                                     const std::string& expectedMnem = "") {
            GadgetFinder finder(codeBytes, 0x400080, "riscv64", binPath, 10);
            finder.findGadgets();
            const auto& gadgets = finder.getGadgets();
            if (expectGadgetFound) {
                assertCond(testName + " produces accepted gadget", !gadgets.empty());
                if (!gadgets.empty() && !expectedMnem.empty()) {
                    assertCond(testName + " contains expected mnemonic " + expectedMnem,
                               gadgets[0].assembly.find(expectedMnem) != std::string::npos,
                               "assembly: " + gadgets[0].assembly);
                }
            } else {
                assertCond(testName + " is strictly rejected (0 gadgets found)", gadgets.empty(),
                           gadgets.empty() ? "" : "found: " + gadgets[0].assembly);
            }
        };

        // 1. Standard 32-bit ret (jalr x0, 0(ra) = 0x67, 0x80, 0x00, 0x00): Valid terminator
        std::vector<uint8_t> std_ret = { 0x67, 0x80, 0x00, 0x00 };
        checkGadgetFinder("Standard 32-bit ret (non-RVC)", std_ret, nonRvcBinary, true, "ret");

        // 2. 16-bit c.jr ra (0x82, 0x80): Valid RVC return terminator when binary is RVC-enabled
        std::vector<uint8_t> c_jr_ra = { 0x82, 0x80, 0x00, 0x00 };
        checkGadgetFinder("16-bit c.jr ra in RVC binary", c_jr_ra, rvcBinary, true, "c.jr");

        // 3. 16-bit c.jalr ra (0x82, 0x90): Strictly NOT a return gadget (it links ra and behaves as call)
        std::vector<uint8_t> c_jalr_ra = { 0x82, 0x90, 0x00, 0x00 };
        checkGadgetFinder("16-bit c.jalr ra (indirect call)", c_jalr_ra, rvcBinary, false);

        // 4. 16-bit c.ebreak (0x02, 0x90): Strictly NOT a return terminator (debug trap / SIGTRAP)
        std::vector<uint8_t> c_ebreak = { 0x02, 0x90, 0x00, 0x00 };
        checkGadgetFinder("16-bit c.ebreak trap", c_ebreak, rvcBinary, false);

        // 5. 32-bit ebreak (0x73, 0x00, 0x10, 0x00): Strictly NOT a return terminator (trap)
        std::vector<uint8_t> std_ebreak = { 0x73, 0x00, 0x10, 0x00 };
        checkGadgetFinder("32-bit ebreak trap (non-RVC)", std_ebreak, nonRvcBinary, false);

        // 6. Non-RVC binary does NOT decode 16-bit compressed c.jr ra
        checkGadgetFinder("16-bit c.jr ra in non-RVC binary is ignored", c_jr_ra, nonRvcBinary, false);

        // 7. Traps as intermediate instructions in multi-instruction sequence: must be rejected
        std::vector<uint8_t> trap_interleaved = { 0x02, 0x90, 0x67, 0x80, 0x00, 0x00 };
        GadgetFinder finderTrap(trap_interleaved, 0x400080, "riscv64", rvcBinary, 10);
        finderTrap.findGadgets();
        for (const auto& g : finderTrap.getGadgets()) {
            assertCond("Intermediate c.ebreak is not included in accepted gadget",
                       g.assembly.find("c.ebreak") == std::string::npos,
                       "assembly: " + g.assembly);
        }
    }

    std::cout << "\n============================================================\n";
    std::cout << "Step 4.1 Test Results: " << passed_tests << " Passed, " << failures << " Failed\n";
    std::cout << "============================================================\n";

    return (failures == 0) ? 0 : 1;
}
