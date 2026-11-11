#include <iostream>
#include <string>
#include <cassert>
#include "core/parsers/file_parser.h"
#include "core/parsers/elf_parser.h"
#include "core/parsers/pe_parser.h"

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

static const char* endianStr(Endianness e) {
    switch (e) {
        case Endianness::Little: return "Little";
        case Endianness::Big: return "Big";
        case Endianness::Unknown: return "Unknown";
        case Endianness::Unsupported: return "Unsupported";
    }
    return "Invalid";
}

int main() {
    int failures = 0;

    auto assertEndian = [&](const std::string& testName,
                            Endianness actualMeta, Endianness expectedMeta,
                            Endianness actualInst, Endianness expectedInst) {
        bool ok = (actualMeta == expectedMeta) && (actualInst == expectedInst);
        if (ok) {
            std::cout << "  [PASS] " << testName << ": Meta=" << endianStr(actualMeta)
                      << ", Inst=" << endianStr(actualInst) << "\n";
        } else {
            std::cerr << "  [FAIL] " << testName << ": Expected Meta=" << endianStr(expectedMeta)
                      << ", Inst=" << endianStr(expectedInst)
                      << " but got Meta=" << endianStr(actualMeta)
                      << ", Inst=" << endianStr(actualInst) << "\n";
            failures++;
        }
    };

    std::cout << "[*] Running Endianness Classification Unit Tests...\n";

    // 1. FileParser base class defaults
    DummyTestParser dummy;
    assertEndian("FileParser default unestablished",
                 dummy.getMetadataEndianness(), Endianness::Unknown,
                 dummy.getInstructionEndianness(), Endianness::Unknown);

    // 2. PEParser: classic_bof.exe
    PEParser peParser("test_binaries/classic_bof.exe");
    if (peParser.parse("test_binaries/classic_bof.exe")) {
        assertEndian("PE64 (classic_bof.exe)",
                     peParser.getMetadataEndianness(), Endianness::Little,
                     peParser.getInstructionEndianness(), Endianness::Little);
    } else {
        std::cerr << "  [FAIL] Failed to parse classic_bof.exe\n";
        failures++;
    }

    // 3. x86 32-bit ELF
    ELFParser elfX86("test_binaries/elf32_x86");
    if (elfX86.parse("test_binaries/elf32_x86")) {
        assertEndian("ELF32 x86",
                     elfX86.getMetadataEndianness(), Endianness::Little,
                     elfX86.getInstructionEndianness(), Endianness::Little);
    } else {
        std::cerr << "  [FAIL] Failed to parse elf32_x86\n";
        failures++;
    }

    // 4. ARMv7 Little-Endian ELF
    ELFParser elfArmLe("test_binaries/elf32_arm");
    if (elfArmLe.parse("test_binaries/elf32_arm")) {
        assertEndian("ELF32 ARMv7 LE",
                     elfArmLe.getMetadataEndianness(), Endianness::Little,
                     elfArmLe.getInstructionEndianness(), Endianness::Little);
    } else {
        std::cerr << "  [FAIL] Failed to parse elf32_arm\n";
        failures++;
    }

    // 5. ARMv7 BE-8 ELF (EF_ARM_BE8 set)
    ELFParser elfArmBe8("test_binaries/elf32_arm_be8");
    if (elfArmBe8.parse("test_binaries/elf32_arm_be8")) {
        assertEndian("ELF32 ARMv7 BE-8",
                     elfArmBe8.getMetadataEndianness(), Endianness::Big,
                     elfArmBe8.getInstructionEndianness(), Endianness::Little);
    } else {
        std::cerr << "  [FAIL] Failed to parse elf32_arm_be8\n";
        failures++;
    }

    // 6. ARMv7 BE Ambiguous ELF (EF_ARM_BE8 clear)
    ELFParser elfArmBeAmb("test_binaries/elf32_arm_be_ambiguous");
    if (elfArmBeAmb.parse("test_binaries/elf32_arm_be_ambiguous")) {
        assertEndian("ELF32 ARMv7 BE Ambiguous (EF_ARM_BE8 clear)",
                     elfArmBeAmb.getMetadataEndianness(), Endianness::Big,
                     elfArmBeAmb.getInstructionEndianness(), Endianness::Unsupported);
    } else {
        std::cerr << "  [FAIL] Failed to parse elf32_arm_be_ambiguous\n";
        failures++;
    }

    // 7. AArch64 Little-Endian ELF
    ELFParser elfAaLe("test_binaries/elf64_aarch64");
    if (elfAaLe.parse("test_binaries/elf64_aarch64")) {
        assertEndian("ELF64 AArch64 LE",
                     elfAaLe.getMetadataEndianness(), Endianness::Little,
                     elfAaLe.getInstructionEndianness(), Endianness::Little);
    } else {
        std::cerr << "  [FAIL] Failed to parse elf64_aarch64\n";
        failures++;
    }

    // 8. AArch64 Big-Endian ELF (EI_DATA = 2, LE instructions)
    ELFParser elfAaBe("test_binaries/elf64_aarch64_be");
    if (elfAaBe.parse("test_binaries/elf64_aarch64_be")) {
        assertEndian("ELF64 AArch64 BE (AAELF64)",
                     elfAaBe.getMetadataEndianness(), Endianness::Big,
                     elfAaBe.getInstructionEndianness(), Endianness::Little);
    } else {
        std::cerr << "  [FAIL] Failed to parse elf64_aarch64_be\n";
        failures++;
    }

    // 9. RISC-V 32 Little-Endian ELF
    ELFParser elfRv32Le("test_binaries/elf32_riscv");
    if (elfRv32Le.parse("test_binaries/elf32_riscv")) {
        assertEndian("ELF32 RISC-V LE",
                     elfRv32Le.getMetadataEndianness(), Endianness::Little,
                     elfRv32Le.getInstructionEndianness(), Endianness::Little);
    } else {
        std::cerr << "  [FAIL] Failed to parse elf32_riscv\n";
        failures++;
    }

    // 10. RISC-V 64 Little-Endian ELF
    ELFParser elfRv64Le("test_binaries/elf64_riscv");
    if (elfRv64Le.parse("test_binaries/elf64_riscv")) {
        assertEndian("ELF64 RISC-V LE",
                     elfRv64Le.getMetadataEndianness(), Endianness::Little,
                     elfRv64Le.getInstructionEndianness(), Endianness::Little);
    } else {
        std::cerr << "  [FAIL] Failed to parse elf64_riscv\n";
        failures++;
    }

    // 11. RISC-V 32 Big-Endian ELF (Capstone cannot decode)
    ELFParser elfRv32Be("test_binaries/elf32_riscv_be");
    if (elfRv32Be.parse("test_binaries/elf32_riscv_be")) {
        assertEndian("ELF32 RISC-V BE",
                     elfRv32Be.getMetadataEndianness(), Endianness::Big,
                     elfRv32Be.getInstructionEndianness(), Endianness::Unsupported);
    } else {
        std::cerr << "  [FAIL] Failed to parse elf32_riscv_be\n";
        failures++;
    }

    // 12. RISC-V 64 Big-Endian ELF (Capstone cannot decode)
    ELFParser elfRv64Be("test_binaries/elf64_riscv_be");
    if (elfRv64Be.parse("test_binaries/elf64_riscv_be")) {
        assertEndian("ELF64 RISC-V BE",
                     elfRv64Be.getMetadataEndianness(), Endianness::Big,
                     elfRv64Be.getInstructionEndianness(), Endianness::Unsupported);
    } else {
        std::cerr << "  [FAIL] Failed to parse elf64_riscv_be\n";
        failures++;
    }

    return failures == 0 ? 0 : 1;
}

