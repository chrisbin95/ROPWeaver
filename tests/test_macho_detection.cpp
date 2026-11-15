#include "core/parsers/macho_defs.h"
#include "core/parsers/macho_parser.h"
#include "core/parsers/file_parser.h"
#include "core/arch_detector.h"
#include "core/payload_gen.h"
#include "core/gadget_finder.h"
#include "nlohmann/json.hpp"
#include <iostream>
#include <vector>
#include <fstream>
#include <cstring>
#include <filesystem>

using namespace ropweaver;
namespace fs = std::filesystem;

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
        std::cerr << "[FAIL] Line " << __LINE__ << ": " << msg << std::endl; \
        g_tests_failed++; \
    } \
} while(0)

// Helper: writes synthetic 32-bit Mach-O header bytes to buffer
static std::vector<uint8_t> make_macho32_buf(uint32_t magic, int32_t cputype, int32_t cpusubtype,
                                             uint32_t filetype, uint32_t ncmds, uint32_t sizeofcmds,
                                             uint32_t flags, bool is_be)
{
    std::vector<uint8_t> buf(sizeof(MachO_Header_32), 0);
    auto write_u32 = [&](size_t offset, uint32_t val) {
        if (is_be) {
            buf[offset + 0] = static_cast<uint8_t>((val >> 24) & 0xFF);
            buf[offset + 1] = static_cast<uint8_t>((val >> 16) & 0xFF);
            buf[offset + 2] = static_cast<uint8_t>((val >> 8) & 0xFF);
            buf[offset + 3] = static_cast<uint8_t>(val & 0xFF);
        } else {
            buf[offset + 0] = static_cast<uint8_t>(val & 0xFF);
            buf[offset + 1] = static_cast<uint8_t>((val >> 8) & 0xFF);
            buf[offset + 2] = static_cast<uint8_t>((val >> 16) & 0xFF);
            buf[offset + 3] = static_cast<uint8_t>((val >> 24) & 0xFF);
        }
    };

    write_u32(0,  magic);
    write_u32(4,  static_cast<uint32_t>(cputype));
    write_u32(8,  static_cast<uint32_t>(cpusubtype));
    write_u32(12, filetype);
    write_u32(16, ncmds);
    write_u32(20, sizeofcmds);
    write_u32(24, flags);
    return buf;
}

// Helper: writes synthetic 64-bit Mach-O header bytes to buffer
static std::vector<uint8_t> make_macho64_buf(uint32_t magic, int32_t cputype, int32_t cpusubtype,
                                             uint32_t filetype, uint32_t ncmds, uint32_t sizeofcmds,
                                             uint32_t flags, uint32_t reserved, bool is_be)
{
    std::vector<uint8_t> buf(sizeof(MachO_Header_64), 0);
    auto write_u32 = [&](size_t offset, uint32_t val) {
        if (is_be) {
            buf[offset + 0] = static_cast<uint8_t>((val >> 24) & 0xFF);
            buf[offset + 1] = static_cast<uint8_t>((val >> 16) & 0xFF);
            buf[offset + 2] = static_cast<uint8_t>((val >> 8) & 0xFF);
            buf[offset + 3] = static_cast<uint8_t>(val & 0xFF);
        } else {
            buf[offset + 0] = static_cast<uint8_t>(val & 0xFF);
            buf[offset + 1] = static_cast<uint8_t>((val >> 8) & 0xFF);
            buf[offset + 2] = static_cast<uint8_t>((val >> 16) & 0xFF);
            buf[offset + 3] = static_cast<uint8_t>((val >> 24) & 0xFF);
        }
    };

    write_u32(0,  magic);
    write_u32(4,  static_cast<uint32_t>(cputype));
    write_u32(8,  static_cast<uint32_t>(cpusubtype));
    write_u32(12, filetype);
    write_u32(16, ncmds);
    write_u32(20, sizeofcmds);
    write_u32(24, flags);
    write_u32(28, reserved);
    return buf;
}

static void write_file(const std::string& path, const std::vector<uint8_t>& bytes) {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs.is_open()) {
        std::cerr << "Failed to open " << path << " for writing\n";
        return;
    }
    ofs.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

static void test_thin_magic_and_endianness() {
    std::cout << "\n[*] Group 1: Thin Mach-O Magic Detection & Format Classification...\n";

    // 1. 32-bit Little-Endian (MH_MAGIC on LE disk: 0xCE, 0xFA, 0xED, 0xFE)
    const uint8_t le32[4] = {0xCE, 0xFA, 0xED, 0xFE};
    MachOFormat fmt1 = detectMachOFormat(le32);
    ASSERT_EQ(fmt1, MachOFormat::MachO32_LE, "32-bit LE magic correctly detected");
    ASSERT_TRUE(isMachO(fmt1), "isMachO is true for 32-bit LE");
    ASSERT_TRUE(isThinMachO(fmt1), "isThinMachO is true for 32-bit LE");
    ASSERT_TRUE(!isFatMachO(fmt1), "isFatMachO is false for 32-bit LE");
    ASSERT_TRUE(!isMachO64(fmt1), "isMachO64 is false for 32-bit LE");
    ASSERT_TRUE(!isMachOBigEndian(fmt1), "isMachOBigEndian is false for 32-bit LE");

    // 2. 32-bit Big-Endian (MH_CIGAM / MH_MAGIC on BE disk: 0xFE, 0xED, 0xFA, 0xCE)
    const uint8_t be32[4] = {0xFE, 0xED, 0xFA, 0xCE};
    MachOFormat fmt2 = detectMachOFormat(be32);
    ASSERT_EQ(fmt2, MachOFormat::MachO32_BE, "32-bit BE magic correctly detected");
    ASSERT_TRUE(isMachO(fmt2), "isMachO is true for 32-bit BE");
    ASSERT_TRUE(isThinMachO(fmt2), "isThinMachO is true for 32-bit BE");
    ASSERT_TRUE(!isFatMachO(fmt2), "isFatMachO is false for 32-bit BE");
    ASSERT_TRUE(!isMachO64(fmt2), "isMachO64 is false for 32-bit BE");
    ASSERT_TRUE(isMachOBigEndian(fmt2), "isMachOBigEndian is true for 32-bit BE");

    // 3. 64-bit Little-Endian (MH_MAGIC_64 on LE disk: 0xCF, 0xFA, 0xED, 0xFE)
    const uint8_t le64[4] = {0xCF, 0xFA, 0xED, 0xFE};
    MachOFormat fmt3 = detectMachOFormat(le64);
    ASSERT_EQ(fmt3, MachOFormat::MachO64_LE, "64-bit LE magic (0xCF...) correctly detected");
    ASSERT_TRUE(isMachO(fmt3), "isMachO is true for 64-bit LE");
    ASSERT_TRUE(isThinMachO(fmt3), "isThinMachO is true for 64-bit LE");
    ASSERT_TRUE(!isFatMachO(fmt3), "isFatMachO is false for 64-bit LE");
    ASSERT_TRUE(isMachO64(fmt3), "isMachO64 is true for 64-bit LE");
    ASSERT_TRUE(!isMachOBigEndian(fmt3), "isMachOBigEndian is false for 64-bit LE");

    // 4. 64-bit Big-Endian (MH_CIGAM_64 / MH_MAGIC_64 on BE disk: 0xFE, 0xED, 0xFA, 0xCF)
    const uint8_t be64[4] = {0xFE, 0xED, 0xFA, 0xCF};
    MachOFormat fmt4 = detectMachOFormat(be64);
    ASSERT_EQ(fmt4, MachOFormat::MachO64_BE, "64-bit BE magic correctly detected");
    ASSERT_TRUE(isMachO(fmt4), "isMachO is true for 64-bit BE");
    ASSERT_TRUE(isThinMachO(fmt4), "isThinMachO is true for 64-bit BE");
    ASSERT_TRUE(!isFatMachO(fmt4), "isFatMachO is false for 64-bit BE");
    ASSERT_TRUE(isMachO64(fmt4), "isMachO64 is true for 64-bit BE");
    ASSERT_TRUE(isMachOBigEndian(fmt4), "isMachOBigEndian is true for 64-bit BE");
}

static void test_fat_universal_magic() {
    std::cout << "\n[*] Group 2: Fat / Universal Binary Magic Recognition...\n";
    ArchDetector detector;

    // 1. FAT_MAGIC Big-Endian (0xCA, 0xFE, 0xBA, 0xBE)
    const uint8_t fat_be32[4] = {0xCA, 0xFE, 0xBA, 0xBE};
    MachOFormat f1 = detectMachOFormat(fat_be32);
    ASSERT_EQ(f1, MachOFormat::Fat32_BE, "FAT_MAGIC BE correctly detected");
    ASSERT_TRUE(isFatMachO(f1), "isFatMachO is true for FAT_MAGIC BE");
    ASSERT_TRUE(!isThinMachO(f1), "isThinMachO is false for FAT_MAGIC BE");
    std::vector<uint8_t> f1_buf(fat_be32, fat_be32 + 4);
    ASSERT_EQ(detector.detectMachOArchitecture(f1_buf), "fat", "detectMachOArchitecture returns 'fat' for FAT_MAGIC BE");

    // 2. FAT_CIGAM Little-Endian (0xBE, 0xBA, 0xFE, 0xCA)
    const uint8_t fat_le32[4] = {0xBE, 0xBA, 0xFE, 0xCA};
    MachOFormat f2 = detectMachOFormat(fat_le32);
    ASSERT_EQ(f2, MachOFormat::Fat32_LE, "FAT_CIGAM LE correctly detected");
    ASSERT_TRUE(isFatMachO(f2), "isFatMachO is true for FAT_CIGAM LE");
    ASSERT_TRUE(!isThinMachO(f2), "isThinMachO is false for FAT_CIGAM LE");
    std::vector<uint8_t> f2_buf(fat_le32, fat_le32 + 4);
    ASSERT_EQ(detector.detectMachOArchitecture(f2_buf), "fat", "detectMachOArchitecture returns 'fat' for FAT_CIGAM LE");

    // 3. FAT_MAGIC_64 Big-Endian (0xCA, 0xFE, 0xBA, 0xBF)
    const uint8_t fat_be64[4] = {0xCA, 0xFE, 0xBA, 0xBF};
    MachOFormat f3 = detectMachOFormat(fat_be64);
    ASSERT_EQ(f3, MachOFormat::Fat64_BE, "FAT_MAGIC_64 BE correctly detected");
    ASSERT_TRUE(isFatMachO(f3), "isFatMachO is true for FAT_MAGIC_64 BE");
    ASSERT_TRUE(!isThinMachO(f3), "isThinMachO is false for FAT_MAGIC_64 BE");
    std::vector<uint8_t> f3_buf(fat_be64, fat_be64 + 4);
    ASSERT_EQ(detector.detectMachOArchitecture(f3_buf), "fat", "detectMachOArchitecture returns 'fat' for FAT_MAGIC_64 BE");

    // 4. FAT_CIGAM_64 Little-Endian (0xBF, 0xBA, 0xFE, 0xCA)
    const uint8_t fat_le64[4] = {0xBF, 0xBA, 0xFE, 0xCA};
    MachOFormat f4 = detectMachOFormat(fat_le64);
    ASSERT_EQ(f4, MachOFormat::Fat64_LE, "FAT_CIGAM_64 LE correctly detected");
    ASSERT_TRUE(isFatMachO(f4), "isFatMachO is true for FAT_CIGAM_64 LE");
    ASSERT_TRUE(!isThinMachO(f4), "isThinMachO is false for FAT_CIGAM_64 LE");
    std::vector<uint8_t> f4_buf(fat_le64, fat_le64 + 4);
    ASSERT_EQ(detector.detectMachOArchitecture(f4_buf), "fat", "detectMachOArchitecture returns 'fat' for FAT_CIGAM_64 LE");
}

static void test_cpu_architecture_extraction() {
    std::cout << "\n[*] Group 3: CPU Architecture Extraction...\n";
    ArchDetector detector;

    // 1. 32-bit LE x86
    auto x86_le = make_macho32_buf(MH_MAGIC, CPU_TYPE_X86, 3, MH_EXECUTE, 1, 56, 0, false);
    ASSERT_EQ(detector.detectMachOArchitecture(x86_le), "x86", "32-bit LE x86 detected as 'x86'");

    // 2. 32-bit BE x86
    auto x86_be = make_macho32_buf(MH_MAGIC, CPU_TYPE_X86, 3, MH_EXECUTE, 1, 56, 0, true);
    ASSERT_EQ(detector.detectMachOArchitecture(x86_be), "x86", "32-bit BE x86 detected as 'x86'");

    // 3. 64-bit LE x86_64
    auto x64_le = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, 72, MH_PIE, 0, false);
    ASSERT_EQ(detector.detectMachOArchitecture(x64_le), "x86_64", "64-bit LE x86_64 detected as 'x86_64'");

    // 4. 64-bit BE x86_64
    auto x64_be = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, 72, MH_PIE, 0, true);
    ASSERT_EQ(detector.detectMachOArchitecture(x64_be), "x86_64", "64-bit BE x86_64 detected as 'x86_64'");

    // 5. 32-bit LE ARM (armv7)
    auto arm_le = make_macho32_buf(MH_MAGIC, CPU_TYPE_ARM, 9, MH_EXECUTE, 1, 56, 0, false);
    ASSERT_EQ(detector.detectMachOArchitecture(arm_le), "armv7", "32-bit LE ARM detected as 'armv7'");

    // 6. 32-bit BE ARM (armv7)
    auto arm_be = make_macho32_buf(MH_MAGIC, CPU_TYPE_ARM, 9, MH_EXECUTE, 1, 56, 0, true);
    ASSERT_EQ(detector.detectMachOArchitecture(arm_be), "armv7", "32-bit BE ARM detected as 'armv7'");

    // 7. 64-bit LE ARM64 (aarch64)
    auto arm64_le = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_ARM64, 0, MH_EXECUTE, 1, 72, MH_PIE, 0, false);
    ASSERT_EQ(detector.detectMachOArchitecture(arm64_le), "aarch64", "64-bit LE ARM64 detected as 'aarch64'");

    // 8. 64-bit BE ARM64 (aarch64)
    auto arm64_be = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_ARM64, 0, MH_EXECUTE, 1, 72, MH_PIE, 0, true);
    ASSERT_EQ(detector.detectMachOArchitecture(arm64_be), "aarch64", "64-bit BE ARM64 detected as 'aarch64'");
}

static void test_negative_cases() {
    std::cout << "\n[*] Group 4: Negative Detection Tests (Invalid, Truncated, Unsupported)...\n";
    ArchDetector detector;

    // 1. Invalid magic: random bytes
    const uint8_t random_bytes[4] = {0x11, 0x22, 0x33, 0x44};
    ASSERT_EQ(detectMachOFormat(random_bytes), MachOFormat::Invalid, "Random bytes produce MachOFormat::Invalid");
    std::vector<uint8_t> rand_vec(random_bytes, random_bytes + 4);
    ASSERT_EQ(detector.detectMachOArchitecture(rand_vec), "unknown", "Random bytes return 'unknown'");

    // 2. Invalid magic: ELF magic
    const uint8_t elf_magic[4] = {0x7F, 'E', 'L', 'F'};
    ASSERT_EQ(detectMachOFormat(elf_magic), MachOFormat::Invalid, "ELF magic produces MachOFormat::Invalid");

    // 3. Invalid magic: PE magic
    const uint8_t pe_magic[4] = {'M', 'Z', 0x90, 0x00};
    ASSERT_EQ(detectMachOFormat(pe_magic), MachOFormat::Invalid, "PE magic produces MachOFormat::Invalid");

    // 4. Truncated buffers
    std::vector<uint8_t> empty_buf;
    ASSERT_EQ(detector.detectMachOArchitecture(empty_buf), "unknown", "0-byte buffer returns 'unknown'");

    std::vector<uint8_t> short_buf = {0xCF, 0xFA};
    ASSERT_EQ(detector.detectMachOArchitecture(short_buf), "unknown", "2-byte buffer returns 'unknown'");

    std::vector<uint8_t> short4_buf = {0xCF, 0xFA, 0xED, 0xFE};
    ASSERT_EQ(detector.detectMachOArchitecture(short4_buf), "unknown", "4-byte thin Mach-O (< 8 bytes) returns 'unknown'");

    std::vector<uint8_t> short7_buf = {0xCF, 0xFA, 0xED, 0xFE, 0x07, 0x00, 0x00};
    ASSERT_EQ(detector.detectMachOArchitecture(short7_buf), "unknown", "7-byte thin Mach-O (< 8 bytes) returns 'unknown'");

    // 5. Unsupported CPU types
    auto ppc32 = make_macho32_buf(MH_MAGIC, CPU_TYPE_POWERPC, 0, MH_EXECUTE, 1, 56, 0, false);
    ASSERT_EQ(detector.detectMachOArchitecture(ppc32), "unknown", "PowerPC 32 returns 'unknown'");

    auto ppc64 = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_POWERPC64, 0, MH_EXECUTE, 1, 72, 0, 0, false);
    ASSERT_EQ(detector.detectMachOArchitecture(ppc64), "unknown", "PowerPC 64 returns 'unknown'");

    auto bad_cpu = make_macho64_buf(MH_MAGIC_64, 0x9999, 0, MH_EXECUTE, 1, 72, 0, 0, false);
    ASSERT_EQ(detector.detectMachOArchitecture(bad_cpu), "unknown", "Arbitrary CPU 0x9999 returns 'unknown'");
}

static void test_thin_header_parsing() {
    std::cout << "\n[*] Group 5: MachOParser Thin Header Parsing...\n";

    fs::path temp_dir = fs::temp_directory_path();

    // 1. 64-bit LE x86_64
    {
        std::string test_file = (temp_dir / "test_macho_x86_64.bin").string();
        auto bytes = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 16, 1024, MH_PIE | MH_DYLDLINK, 0x0, false);
        write_file(test_file, bytes);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "64-bit LE x86_64 parse succeeds");
        ASSERT_TRUE(parser.is64Bit(), "is64Bit() is true");
        ASSERT_TRUE(!parser.isBigEndian(), "isBigEndian() is false");
        ASSERT_EQ(parser.getArchitecture(), "x86_64", "getArchitecture() is 'x86_64'");
        ASSERT_EQ(parser.getBinaryType(), "Mach-O", "getBinaryType() is 'Mach-O'");
        ASSERT_EQ(parser.getMetadataEndianness(), Endianness::Little, "getMetadataEndianness() is Little");
        ASSERT_EQ(parser.getInstructionEndianness(), Endianness::Little, "getInstructionEndianness() is Little");
        ASSERT_EQ(parser.getCpuType(), static_cast<uint32_t>(CPU_TYPE_X86_64), "getCpuType() matches");
        ASSERT_EQ(parser.getCpuSubType(), 3u, "getCpuSubType() is 3");
        ASSERT_EQ(parser.getFileType(), static_cast<uint32_t>(MH_EXECUTE), "getFileType() is MH_EXECUTE");
        ASSERT_EQ(parser.getNumCmds(), 16u, "getNumCmds() is 16");
        ASSERT_EQ(parser.getSizeOfCmds(), 1024u, "getSizeOfCmds() is 1024");
        ASSERT_EQ(parser.getFlags(), static_cast<uint32_t>(MH_PIE | MH_DYLDLINK), "getFlags() matches");
        ASSERT_EQ(parser.getHeader64().reserved, 0u, "reserved is 0");
        ASSERT_TRUE(parser.getTextSection().empty(), "textSection is empty in Step 5.2 (no fake gadgets)");
        ASSERT_EQ(parser.getTextSectionBaseAddress(), 0ULL, "textBaseAddr is 0");

        fs::remove(test_file);
    }

    // 2. 64-bit LE ARM64 (aarch64)
    {
        std::string test_file = (temp_dir / "test_macho_arm64.bin").string();
        auto bytes = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_ARM64, 0, MH_EXECUTE, 12, 800, MH_PIE, 0x0, false);
        write_file(test_file, bytes);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "64-bit LE ARM64 parse succeeds");
        ASSERT_TRUE(parser.is64Bit(), "is64Bit() is true for ARM64");
        ASSERT_TRUE(!parser.isBigEndian(), "isBigEndian() is false for ARM64");
        ASSERT_EQ(parser.getArchitecture(), "aarch64", "getArchitecture() is 'aarch64'");
        ASSERT_EQ(parser.getCpuType(), static_cast<uint32_t>(CPU_TYPE_ARM64), "getCpuType() is CPU_TYPE_ARM64");
        ASSERT_EQ(parser.getMetadataEndianness(), Endianness::Little, "getMetadataEndianness() is Little");
        ASSERT_EQ(parser.getInstructionEndianness(), Endianness::Little, "getInstructionEndianness() is Little");

        fs::remove(test_file);
    }

    // 3. 32-bit LE x86
    {
        std::string test_file = (temp_dir / "test_macho_x86_32.bin").string();
        auto bytes = make_macho32_buf(MH_MAGIC, CPU_TYPE_X86, 3, MH_EXECUTE, 8, 400, 0, false);
        write_file(test_file, bytes);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "32-bit LE x86 parse succeeds");
        ASSERT_TRUE(!parser.is64Bit(), "is64Bit() is false for x86 32-bit");
        ASSERT_TRUE(!parser.isBigEndian(), "isBigEndian() is false for x86 LE");
        ASSERT_EQ(parser.getArchitecture(), "x86", "getArchitecture() is 'x86'");
        ASSERT_EQ(parser.getCpuType(), static_cast<uint32_t>(CPU_TYPE_X86), "getCpuType() is CPU_TYPE_X86");
        ASSERT_EQ(parser.getMetadataEndianness(), Endianness::Little, "getMetadataEndianness() is Little");

        fs::remove(test_file);
    }

    // 4. 32-bit LE ARM (armv7)
    {
        std::string test_file = (temp_dir / "test_macho_armv7.bin").string();
        auto bytes = make_macho32_buf(MH_MAGIC, CPU_TYPE_ARM, 9, MH_EXECUTE, 6, 300, 0, false);
        write_file(test_file, bytes);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "32-bit LE ARM parse succeeds");
        ASSERT_TRUE(!parser.is64Bit(), "is64Bit() is false for ARMv7");
        ASSERT_TRUE(!parser.isBigEndian(), "isBigEndian() is false for ARMv7 LE");
        ASSERT_EQ(parser.getArchitecture(), "armv7", "getArchitecture() is 'armv7'");
        ASSERT_EQ(parser.getCpuType(), static_cast<uint32_t>(CPU_TYPE_ARM), "getCpuType() is CPU_TYPE_ARM");
        ASSERT_EQ(parser.getMetadataEndianness(), Endianness::Little, "getMetadataEndianness() is Little");

        fs::remove(test_file);
    }

    // 5. 64-bit BE x86_64 (big-endian metadata test)
    {
        std::string test_file = (temp_dir / "test_macho_be64.bin").string();
        auto bytes = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 4, 200, 0, 0, true);
        write_file(test_file, bytes);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "64-bit BE parse succeeds");
        ASSERT_TRUE(parser.is64Bit(), "is64Bit() is true for 64-bit BE");
        ASSERT_TRUE(parser.isBigEndian(), "isBigEndian() is true for 64-bit BE");
        ASSERT_EQ(parser.getArchitecture(), "x86_64", "getArchitecture() is 'x86_64'");
        ASSERT_EQ(parser.getMetadataEndianness(), Endianness::Big, "getMetadataEndianness() is Big");
        ASSERT_EQ(parser.getInstructionEndianness(), Endianness::Unsupported, "BE x86 instruction endianness is Unsupported");

        fs::remove(test_file);
    }
}

static void test_macho_parser_errors() {
    std::cout << "\n[*] Group 6: MachOParser Error Handling & Truncation Rejection...\n";

    fs::path temp_dir = fs::temp_directory_path();

    // 1. Non-existent file
    {
        MachOParser parser("non_existent_file_xyz_1234.bin");
        ASSERT_TRUE(!parser.parse("non_existent_file_xyz_1234.bin"), "Non-existent file fails to parse");
    }

    // 2. Truncated magic (< 4 bytes)
    {
        std::string test_file = (temp_dir / "test_trunc_magic.bin").string();
        std::vector<uint8_t> short_bytes = {0xCF, 0xFA};
        write_file(test_file, short_bytes);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "File with < 4 bytes fails to parse");
        fs::remove(test_file);
    }

    // 3. Truncated 32-bit header (20 bytes < 28 bytes)
    {
        std::string test_file = (temp_dir / "test_trunc_32.bin").string();
        auto bytes = make_macho32_buf(MH_MAGIC, CPU_TYPE_X86, 3, MH_EXECUTE, 1, 56, 0, false);
        bytes.resize(20);
        write_file(test_file, bytes);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "Truncated 32-bit header (< 28 bytes) fails to parse");
        fs::remove(test_file);
    }

    // 4. Truncated 64-bit header (28 bytes < 32 bytes)
    {
        std::string test_file = (temp_dir / "test_trunc_64.bin").string();
        auto bytes = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, 72, 0, 0, false);
        bytes.resize(28);
        write_file(test_file, bytes);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "Truncated 64-bit header (< 32 bytes) fails to parse");
        fs::remove(test_file);
    }

    // 5. Fat binary passed to MachOParser (thin-only parser in this step)
    {
        std::string test_file = (temp_dir / "test_fat_to_macho_parser.bin").string();
        std::vector<uint8_t> fat_bytes = {0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02};
        write_file(test_file, fat_bytes);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "Fat binary fails in thin MachOParser (not thin)");
        fs::remove(test_file);
    }

    // 6. Unsupported CPU type in header
    {
        std::string test_file = (temp_dir / "test_unsupported_cpu.bin").string();
        auto bytes = make_macho64_buf(MH_MAGIC_64, 0x7777, 0, MH_EXECUTE, 1, 72, 0, 0, false);
        write_file(test_file, bytes);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "Unsupported CPU type fails to parse");
        ASSERT_EQ(parser.getArchitecture(), "unknown", "Architecture is set to 'unknown'");
        fs::remove(test_file);
    }
}

static void test_factory_routing() {
    std::cout << "\n[*] Group 7: Factory Routing via ArchDetector::createFileParser()...\n";
    ArchDetector detector;
    fs::path temp_dir = fs::temp_directory_path();

    // 1. 64-bit LE x86_64
    {
        std::string test_file = (temp_dir / "test_factory_x86_64.bin").string();
        auto bytes = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, 72, 0, 0, false);
        write_file(test_file, bytes);

        auto parser = detector.createFileParser(test_file);
        ASSERT_TRUE(parser != nullptr, "createFileParser returns non-null for x86_64 Mach-O");
        if (parser) {
            ASSERT_EQ(parser->getBinaryType(), "Mach-O", "Parser binary type is 'Mach-O'");
            ASSERT_TRUE(parser->parse(test_file), "Parser successfully parses the file");
            ASSERT_EQ(parser->getArchitecture(), "x86_64", "Parser architecture is 'x86_64'");
        }
        fs::remove(test_file);
    }

    // 2. 64-bit LE ARM64 (aarch64)
    {
        std::string test_file = (temp_dir / "test_factory_arm64.bin").string();
        auto bytes = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_ARM64, 0, MH_EXECUTE, 1, 72, 0, 0, false);
        write_file(test_file, bytes);

        auto parser = detector.createFileParser(test_file);
        ASSERT_TRUE(parser != nullptr, "createFileParser returns non-null for ARM64 Mach-O");
        if (parser) {
            ASSERT_EQ(parser->getBinaryType(), "Mach-O", "Parser binary type is 'Mach-O'");
            ASSERT_TRUE(parser->parse(test_file), "Parser successfully parses ARM64 Mach-O");
            ASSERT_EQ(parser->getArchitecture(), "aarch64", "Parser architecture is 'aarch64'");
        }
        fs::remove(test_file);
    }

    // 3. 32-bit LE x86
    {
        std::string test_file = (temp_dir / "test_factory_x86.bin").string();
        auto bytes = make_macho32_buf(MH_MAGIC, CPU_TYPE_X86, 3, MH_EXECUTE, 1, 56, 0, false);
        write_file(test_file, bytes);

        auto parser = detector.createFileParser(test_file);
        ASSERT_TRUE(parser != nullptr, "createFileParser returns non-null for x86 32-bit Mach-O");
        if (parser) {
            ASSERT_EQ(parser->getBinaryType(), "Mach-O", "Parser binary type is 'Mach-O'");
            ASSERT_TRUE(parser->parse(test_file), "Parser successfully parses x86 32-bit Mach-O");
            ASSERT_EQ(parser->getArchitecture(), "x86", "Parser architecture is 'x86'");
        }
        fs::remove(test_file);
    }

    // 4. 32-bit LE ARM (armv7)
    {
        std::string test_file = (temp_dir / "test_factory_armv7.bin").string();
        auto bytes = make_macho32_buf(MH_MAGIC, CPU_TYPE_ARM, 9, MH_EXECUTE, 1, 56, 0, false);
        write_file(test_file, bytes);

        auto parser = detector.createFileParser(test_file);
        ASSERT_TRUE(parser != nullptr, "createFileParser returns non-null for ARMv7 Mach-O");
        if (parser) {
            ASSERT_EQ(parser->getBinaryType(), "Mach-O", "Parser binary type is 'Mach-O'");
            ASSERT_TRUE(parser->parse(test_file), "Parser successfully parses ARMv7 Mach-O");
            ASSERT_EQ(parser->getArchitecture(), "armv7", "Parser architecture is 'armv7'");
        }
        fs::remove(test_file);
    }

    // 5. Fat binary (Step 5.5: factory returns non-null MachOParser for universal binary)
    {
        std::string test_file = (temp_dir / "test_factory_fat.bin").string();
        std::vector<uint8_t> fat_bytes = {0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02,
                                          0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x03};
        write_file(test_file, fat_bytes);

        auto parser = detector.createFileParser(test_file);
        ASSERT_TRUE(parser != nullptr, "createFileParser returns non-null MachOParser for fat binary");
        if (parser) {
            ASSERT_EQ(parser->getBinaryType(), "Mach-O", "Parser binary type is 'Mach-O'");
        }
        fs::remove(test_file);
    }

    // 6. Unsupported CPU Mach-O
    {
        std::string test_file = (temp_dir / "test_factory_unsupported.bin").string();
        auto bytes = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_POWERPC64, 0, MH_EXECUTE, 1, 72, 0, 0, false);
        write_file(test_file, bytes);

        auto parser = detector.createFileParser(test_file);
        ASSERT_TRUE(parser == nullptr, "createFileParser returns nullptr for unsupported CPU type");
        fs::remove(test_file);
    }
}

static void test_bitness_cpu_mismatch() {
    std::cout << "\n[*] Group 8: Header Bitness vs. CPU Type Mismatch Rejection...\n";
    ArchDetector detector;
    fs::path temp_dir = fs::temp_directory_path();

    // 1. 32-bit Header + CPU_TYPE_X86_64 (must reject)
    {
        std::string test_file = (temp_dir / "test_mismatch_32_x86_64.bin").string();
        auto bytes = make_macho32_buf(MH_MAGIC, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, 56, 0, false);
        ASSERT_EQ(detector.detectMachOArchitecture(bytes), "unknown", "32-bit header + CPU_TYPE_X86_64 detected as 'unknown'");
        write_file(test_file, bytes);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "32-bit header + CPU_TYPE_X86_64 parse() returns false");
        ASSERT_EQ(parser.getArchitecture(), "unknown", "32-bit header + CPU_TYPE_X86_64 architecture set to 'unknown'");

        auto factory_parser = detector.createFileParser(test_file);
        ASSERT_TRUE(factory_parser == nullptr, "createFileParser returns nullptr for 32-bit header + CPU_TYPE_X86_64");

        fs::remove(test_file);
    }

    // 2. 32-bit Header + CPU_TYPE_ARM64 (must reject)
    {
        std::string test_file = (temp_dir / "test_mismatch_32_arm64.bin").string();
        auto bytes = make_macho32_buf(MH_MAGIC, CPU_TYPE_ARM64, 0, MH_EXECUTE, 1, 56, 0, false);
        ASSERT_EQ(detector.detectMachOArchitecture(bytes), "unknown", "32-bit header + CPU_TYPE_ARM64 detected as 'unknown'");
        write_file(test_file, bytes);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "32-bit header + CPU_TYPE_ARM64 parse() returns false");
        ASSERT_EQ(parser.getArchitecture(), "unknown", "32-bit header + CPU_TYPE_ARM64 architecture set to 'unknown'");

        auto factory_parser = detector.createFileParser(test_file);
        ASSERT_TRUE(factory_parser == nullptr, "createFileParser returns nullptr for 32-bit header + CPU_TYPE_ARM64");

        fs::remove(test_file);
    }

    // 3. 64-bit Header + CPU_TYPE_X86 (must reject)
    {
        std::string test_file = (temp_dir / "test_mismatch_64_x86.bin").string();
        auto bytes = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86, 3, MH_EXECUTE, 1, 72, 0, 0, false);
        ASSERT_EQ(detector.detectMachOArchitecture(bytes), "unknown", "64-bit header + CPU_TYPE_X86 detected as 'unknown'");
        write_file(test_file, bytes);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "64-bit header + CPU_TYPE_X86 parse() returns false");
        ASSERT_EQ(parser.getArchitecture(), "unknown", "64-bit header + CPU_TYPE_X86 architecture set to 'unknown'");

        auto factory_parser = detector.createFileParser(test_file);
        ASSERT_TRUE(factory_parser == nullptr, "createFileParser returns nullptr for 64-bit header + CPU_TYPE_X86");

        fs::remove(test_file);
    }

    // 4. 64-bit Header + CPU_TYPE_ARM (must reject)
    {
        std::string test_file = (temp_dir / "test_mismatch_64_arm.bin").string();
        auto bytes = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_ARM, 9, MH_EXECUTE, 1, 72, 0, 0, false);
        ASSERT_EQ(detector.detectMachOArchitecture(bytes), "unknown", "64-bit header + CPU_TYPE_ARM detected as 'unknown'");
        write_file(test_file, bytes);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "64-bit header + CPU_TYPE_ARM parse() returns false");
        ASSERT_EQ(parser.getArchitecture(), "unknown", "64-bit header + CPU_TYPE_ARM architecture set to 'unknown'");

        auto factory_parser = detector.createFileParser(test_file);
        ASSERT_TRUE(factory_parser == nullptr, "createFileParser returns nullptr for 64-bit header + CPU_TYPE_ARM");

        fs::remove(test_file);
    }
}

// Helpers for Step 5.3 Load Command and Section synthetic testing
static void write_u32_to(std::vector<uint8_t>& buf, size_t offset, uint32_t val, bool is_be) {
    if (offset + 4 > buf.size()) buf.resize(offset + 4, 0);
    if (is_be) {
        buf[offset + 0] = static_cast<uint8_t>((val >> 24) & 0xFF);
        buf[offset + 1] = static_cast<uint8_t>((val >> 16) & 0xFF);
        buf[offset + 2] = static_cast<uint8_t>((val >> 8) & 0xFF);
        buf[offset + 3] = static_cast<uint8_t>(val & 0xFF);
    } else {
        buf[offset + 0] = static_cast<uint8_t>(val & 0xFF);
        buf[offset + 1] = static_cast<uint8_t>((val >> 8) & 0xFF);
        buf[offset + 2] = static_cast<uint8_t>((val >> 16) & 0xFF);
        buf[offset + 3] = static_cast<uint8_t>((val >> 24) & 0xFF);
    }
}

static void write_u64_to(std::vector<uint8_t>& buf, size_t offset, uint64_t val, bool is_be) {
    if (offset + 8 > buf.size()) buf.resize(offset + 8, 0);
    if (is_be) {
        for (int i = 7; i >= 0; --i) {
            buf[offset + (7 - i)] = static_cast<uint8_t>((val >> (i * 8)) & 0xFF);
        }
    } else {
        for (int i = 0; i < 8; ++i) {
            buf[offset + i] = static_cast<uint8_t>((val >> (i * 8)) & 0xFF);
        }
    }
}

struct TestSection64Desc {
    std::string sectname;
    std::string segname;
    uint64_t addr = 0;
    uint64_t size = 0;
    uint32_t offset = 0;
    uint32_t align = 0;
    uint32_t reloff = 0;
    uint32_t nreloc = 0;
    uint32_t flags = 0;
    uint32_t reserved1 = 0;
    uint32_t reserved2 = 0;
    uint32_t reserved3 = 0;
};

struct TestSection32Desc {
    std::string sectname;
    std::string segname;
    uint32_t addr = 0;
    uint32_t size = 0;
    uint32_t offset = 0;
    uint32_t align = 0;
    uint32_t reloff = 0;
    uint32_t nreloc = 0;
    uint32_t flags = 0;
    uint32_t reserved1 = 0;
    uint32_t reserved2 = 0;
};

static void append_segment64_desc(std::vector<uint8_t>& buf,
                                  uint32_t cmd,
                                  const std::string& segname,
                                  uint64_t vmaddr, uint64_t vmsize,
                                  uint64_t fileoff, uint64_t filesize,
                                  int32_t maxprot, int32_t initprot,
                                  uint32_t segflags,
                                  const std::vector<TestSection64Desc>& sections,
                                  bool is_be,
                                  uint32_t override_cmdsize = 0,
                                  uint32_t override_nsects = 0xFFFFFFFF)
{
    size_t base = buf.size();
    uint32_t cmdsize = override_cmdsize != 0 ? override_cmdsize : static_cast<uint32_t>(72 + sections.size() * 80);
    buf.resize(base + 72 + sections.size() * 80, 0);

    write_u32_to(buf, base + 0, cmd, is_be);
    write_u32_to(buf, base + 4, cmdsize, is_be);
    std::memcpy(&buf[base + 8], segname.data(), std::min<size_t>(16, segname.size()));
    write_u64_to(buf, base + 24, vmaddr, is_be);
    write_u64_to(buf, base + 32, vmsize, is_be);
    write_u64_to(buf, base + 40, fileoff, is_be);
    write_u64_to(buf, base + 48, filesize, is_be);
    write_u32_to(buf, base + 56, static_cast<uint32_t>(maxprot), is_be);
    write_u32_to(buf, base + 60, static_cast<uint32_t>(initprot), is_be);
    uint32_t nsects_val = (override_nsects != 0xFFFFFFFF) ? override_nsects : static_cast<uint32_t>(sections.size());
    write_u32_to(buf, base + 64, nsects_val, is_be);
    write_u32_to(buf, base + 68, segflags, is_be);

    size_t sec_offset = base + 72;
    for (const auto& sec : sections) {
        std::memcpy(&buf[sec_offset + 0], sec.sectname.data(), std::min<size_t>(16, sec.sectname.size()));
        std::memcpy(&buf[sec_offset + 16], sec.segname.data(), std::min<size_t>(16, sec.segname.size()));
        write_u64_to(buf, sec_offset + 32, sec.addr, is_be);
        write_u64_to(buf, sec_offset + 40, sec.size, is_be);
        write_u32_to(buf, sec_offset + 48, sec.offset, is_be);
        write_u32_to(buf, sec_offset + 52, sec.align, is_be);
        write_u32_to(buf, sec_offset + 56, sec.reloff, is_be);
        write_u32_to(buf, sec_offset + 60, sec.nreloc, is_be);
        write_u32_to(buf, sec_offset + 64, sec.flags, is_be);
        write_u32_to(buf, sec_offset + 68, sec.reserved1, is_be);
        write_u32_to(buf, sec_offset + 72, sec.reserved2, is_be);
        write_u32_to(buf, sec_offset + 76, sec.reserved3, is_be);
        sec_offset += 80;
    }
}

static void append_segment32_desc(std::vector<uint8_t>& buf,
                                  uint32_t cmd,
                                  const std::string& segname,
                                  uint32_t vmaddr, uint32_t vmsize,
                                  uint32_t fileoff, uint32_t filesize,
                                  int32_t maxprot, int32_t initprot,
                                  uint32_t segflags,
                                  const std::vector<TestSection32Desc>& sections,
                                  bool is_be,
                                  uint32_t override_cmdsize = 0,
                                  uint32_t override_nsects = 0xFFFFFFFF)
{
    size_t base = buf.size();
    uint32_t cmdsize = override_cmdsize != 0 ? override_cmdsize : static_cast<uint32_t>(56 + sections.size() * 68);
    buf.resize(base + 56 + sections.size() * 68, 0);

    write_u32_to(buf, base + 0, cmd, is_be);
    write_u32_to(buf, base + 4, cmdsize, is_be);
    std::memcpy(&buf[base + 8], segname.data(), std::min<size_t>(16, segname.size()));
    write_u32_to(buf, base + 24, vmaddr, is_be);
    write_u32_to(buf, base + 28, vmsize, is_be);
    write_u32_to(buf, base + 32, fileoff, is_be);
    write_u32_to(buf, base + 36, filesize, is_be);
    write_u32_to(buf, base + 40, static_cast<uint32_t>(maxprot), is_be);
    write_u32_to(buf, base + 44, static_cast<uint32_t>(initprot), is_be);
    uint32_t nsects_val = (override_nsects != 0xFFFFFFFF) ? override_nsects : static_cast<uint32_t>(sections.size());
    write_u32_to(buf, base + 48, nsects_val, is_be);
    write_u32_to(buf, base + 52, segflags, is_be);

    size_t sec_offset = base + 56;
    for (const auto& sec : sections) {
        std::memcpy(&buf[sec_offset + 0], sec.sectname.data(), std::min<size_t>(16, sec.sectname.size()));
        std::memcpy(&buf[sec_offset + 16], sec.segname.data(), std::min<size_t>(16, sec.segname.size()));
        write_u32_to(buf, sec_offset + 32, sec.addr, is_be);
        write_u32_to(buf, sec_offset + 36, sec.size, is_be);
        write_u32_to(buf, sec_offset + 40, sec.offset, is_be);
        write_u32_to(buf, sec_offset + 44, sec.align, is_be);
        write_u32_to(buf, sec_offset + 48, sec.reloff, is_be);
        write_u32_to(buf, sec_offset + 52, sec.nreloc, is_be);
        write_u32_to(buf, sec_offset + 56, sec.flags, is_be);
        write_u32_to(buf, sec_offset + 60, sec.reserved1, is_be);
        write_u32_to(buf, sec_offset + 64, sec.reserved2, is_be);
        sec_offset += 68;
    }
}

static void append_symtab_desc(std::vector<uint8_t>& buf,
                               uint32_t symoff, uint32_t nsyms,
                               uint32_t stroff, uint32_t strsize,
                               bool is_be, uint32_t override_cmdsize = 0)
{
    size_t base = buf.size();
    uint32_t cmdsize = override_cmdsize != 0 ? override_cmdsize : 24;
    buf.resize(base + 24, 0);
    write_u32_to(buf, base + 0, LC_SYMTAB, is_be);
    write_u32_to(buf, base + 4, cmdsize, is_be);
    write_u32_to(buf, base + 8, symoff, is_be);
    write_u32_to(buf, base + 12, nsyms, is_be);
    write_u32_to(buf, base + 16, stroff, is_be);
    write_u32_to(buf, base + 20, strsize, is_be);
}

static void append_code_signature_desc(std::vector<uint8_t>& buf,
                                      uint32_t dataoff, uint32_t datasize,
                                      bool is_be, uint32_t override_cmdsize = 0)
{
    size_t base = buf.size();
    uint32_t cmdsize = override_cmdsize != 0 ? override_cmdsize : 16;
    buf.resize(base + cmdsize, 0);
    write_u32_to(buf, base + 0, LC_CODE_SIGNATURE, is_be);
    write_u32_to(buf, base + 4, cmdsize, is_be);
    if (cmdsize >= 12) {
        write_u32_to(buf, base + 8, dataoff, is_be);
    }
    if (cmdsize >= 16) {
        write_u32_to(buf, base + 12, datasize, is_be);
    }
}

static void append_nlist64(std::vector<uint8_t>& buf, uint32_t strx, uint8_t type, uint8_t sect, uint16_t desc, uint64_t value, bool is_be) {
    size_t base = buf.size();
    buf.resize(base + 16, 0);
    write_u32_to(buf, base + 0, strx, is_be);
    buf[base + 4] = type;
    buf[base + 5] = sect;
    if (is_be) {
        buf[base + 6] = static_cast<uint8_t>((desc >> 8) & 0xFF);
        buf[base + 7] = static_cast<uint8_t>(desc & 0xFF);
    } else {
        buf[base + 6] = static_cast<uint8_t>(desc & 0xFF);
        buf[base + 7] = static_cast<uint8_t>((desc >> 8) & 0xFF);
    }
    write_u64_to(buf, base + 8, value, is_be);
}

static void append_nlist32(std::vector<uint8_t>& buf, uint32_t strx, uint8_t type, uint8_t sect, uint16_t desc, uint32_t value, bool is_be) {
    size_t base = buf.size();
    buf.resize(base + 12, 0);
    write_u32_to(buf, base + 0, strx, is_be);
    buf[base + 4] = type;
    buf[base + 5] = sect;
    if (is_be) {
        buf[base + 6] = static_cast<uint8_t>((desc >> 8) & 0xFF);
        buf[base + 7] = static_cast<uint8_t>(desc & 0xFF);
    } else {
        buf[base + 6] = static_cast<uint8_t>(desc & 0xFF);
        buf[base + 7] = static_cast<uint8_t>((desc >> 8) & 0xFF);
    }
    write_u32_to(buf, base + 8, value, is_be);
}

static void test_step53_load_command_64_parsing() {
    std::cout << "\n[*] Group 9: 64-bit LC_SEGMENT_64 and Section Parsing...\n";
    fs::path temp_dir = fs::temp_directory_path();
    std::string test_file = (temp_dir / "test_step53_x86_64.bin").string();

    uint32_t cmdsize = 72 + 80; // 152 bytes
    auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, cmdsize, MH_PIE, 0, false);

    TestSection64Desc sec;
    sec.sectname = "__text";
    sec.segname = "__TEXT";
    sec.addr = 0x100001000ULL;
    sec.size = 16;
    sec.offset = 512;
    sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;

    append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x2000ULL, 0, 1024,
                          VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ | VM_PROT_EXECUTE, 0,
                          {sec}, false);

    if (buf.size() < 1024) buf.resize(1024, 0x90);
    // Write x86_64 machine code at offset 512: push rbp; mov rbp, rsp; nop; ret
    const uint8_t opcodes[16] = {0x55, 0x48, 0x89, 0xe5, 0x90, 0xc3, 0x90, 0x90,
                                 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
    std::memcpy(&buf[512], opcodes, 16);
    write_file(test_file, buf);

    MachOParser parser(test_file);
    ASSERT_TRUE(parser.parse(test_file), "64-bit Mach-O with LC_SEGMENT_64 parsed successfully");
    ASSERT_TRUE(parser.is64Bit(), "parser reports 64-bit");
    ASSERT_EQ(parser.getArchitecture(), "x86_64", "parser reports x86_64");
    ASSERT_EQ(parser.getImageBase(), 0x100000000ULL, "imageBase is __TEXT.vmaddr (0x100000000)");
    ASSERT_TRUE(parser.isPieEnabled(), "isPieEnabled is true for MH_PIE");
    ASSERT_EQ(parser.getTextSectionBaseAddress(), 0x100001000ULL, "textBaseAddr matches section virtual address");
    ASSERT_EQ(parser.getTextSection().size(), 16u, "textSection size is 16 bytes");
    ASSERT_EQ(parser.getTextSection()[0], 0x55, "first opcode is 0x55 (push rbp)");
    ASSERT_EQ(parser.getTextSection()[5], 0xc3, "opcode at offset 5 is 0xc3 (ret)");

    // Section table check
    const auto& secs = parser.getSections();
    ASSERT_EQ(secs.size(), 1u, "sections count is 1");
    if (!secs.empty()) {
        ASSERT_EQ(secs[0].name, "__TEXT,__text", "section name is '__TEXT,__text'");
        ASSERT_EQ(secs[0].virtual_address, 0x100001000ULL, "section virtual_address matches");
        ASSERT_EQ(secs[0].virtual_size, 16ULL, "section virtual_size is 16");
        ASSERT_EQ(secs[0].raw_offset, 512ULL, "section raw_offset is 512");
        ASSERT_EQ(secs[0].raw_size, 16ULL, "section raw_size is 16");
        ASSERT_TRUE(secs[0].is_executable, "section is marked executable");
    }

    // Exec buffer mapping check
    const auto& mappings = parser.getExecBufferMappings();
    ASSERT_EQ(mappings.size(), 1u, "exec mappings count is 1");
    if (!mappings.empty()) {
        ASSERT_EQ(mappings[0].virtual_address, 0x100001000ULL, "mapping virtual_address matches");
        ASSERT_EQ(mappings[0].buffer_offset, 0u, "buffer_offset is 0");
        ASSERT_EQ(mappings[0].size, 16u, "mapping size is 16");
        ASSERT_EQ(mappings[0].raw_offset, 512ULL, "mapping raw_offset is 512");
        ASSERT_EQ(mappings[0].section_name, "__TEXT,__text", "mapping section_name matches");
    }

    // Address translation test via vaToOffsets
    uint64_t fo = 0, rva = 0;
    ASSERT_TRUE(parser.vaToOffsets(0x100001005ULL, fo, rva), "vaToOffsets succeeds for VA in __text");
    ASSERT_EQ(fo, 517ULL, "file offset correctly calculated as 517");
    ASSERT_EQ(rva, 0x1005ULL, "RVA correctly calculated as 0x1005");

    fs::remove(test_file);
}

static void test_step53_load_command_32_parsing() {
    std::cout << "\n[*] Group 10: 32-bit LC_SEGMENT and Section Parsing...\n";
    fs::path temp_dir = fs::temp_directory_path();
    std::string test_file = (temp_dir / "test_step53_x86_32.bin").string();

    uint32_t cmdsize = 56 + 68; // 124 bytes
    auto buf = make_macho32_buf(MH_MAGIC, CPU_TYPE_X86, 3, MH_EXECUTE, 1, cmdsize, 0, false);

    TestSection32Desc sec;
    sec.sectname = "__text";
    sec.segname = "__TEXT";
    sec.addr = 0x2000;
    sec.size = 8;
    sec.offset = 256;
    sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;

    append_segment32_desc(buf, LC_SEGMENT, "__TEXT", 0x1000, 0x2000, 0, 512,
                          VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ | VM_PROT_EXECUTE, 0,
                          {sec}, false);

    if (buf.size() < 512) buf.resize(512, 0x90);
    const uint8_t opcodes[8] = {0x90, 0x58, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90};
    std::memcpy(&buf[256], opcodes, 8);
    write_file(test_file, buf);

    MachOParser parser(test_file);
    ASSERT_TRUE(parser.parse(test_file), "32-bit Mach-O with LC_SEGMENT parsed successfully");
    ASSERT_TRUE(!parser.is64Bit(), "parser reports 32-bit");
    ASSERT_EQ(parser.getArchitecture(), "x86", "parser reports x86");
    ASSERT_EQ(parser.getImageBase(), 0x1000ULL, "imageBase is __TEXT.vmaddr (0x1000)");
    ASSERT_EQ(parser.getTextSectionBaseAddress(), 0x2000ULL, "textBaseAddr matches section virtual address");
    ASSERT_EQ(parser.getTextSection().size(), 8u, "textSection size is 8 bytes");
    ASSERT_EQ(parser.getTextSection()[2], 0xc3, "opcode at offset 2 is 0xc3 (ret)");

    uint64_t fo = 0, rva = 0;
    ASSERT_TRUE(parser.vaToOffsets(0x2002ULL, fo, rva), "vaToOffsets succeeds for VA 0x2002");
    ASSERT_EQ(fo, 258ULL, "file offset is 258");
    ASSERT_EQ(rva, 0x1002ULL, "RVA is 0x1002");

    fs::remove(test_file);
}

static void test_step53_multiple_sections_and_ordering() {
    std::cout << "\n[*] Group 11: Non-First Section Ordering & Multiple Segments...\n";
    fs::path temp_dir = fs::temp_directory_path();
    std::string test_file = (temp_dir / "test_step53_multi_sec.bin").string();

    // 2 segment commands: __PAGEZERO (72 bytes) and __TEXT with 2 sections (72 + 160 = 232 bytes)
    uint32_t sizeofcmds = 72 + 232;
    auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 2, sizeofcmds, 0, 0, false);

    // 1. __PAGEZERO segment (no sections)
    append_segment64_desc(buf, LC_SEGMENT_64, "__PAGEZERO", 0x0, 0x100000000ULL, 0, 0,
                          VM_PROT_NONE, VM_PROT_NONE, 0, {}, false);

    // 2. __TEXT segment with __cstring (non-executable metadata) placed BEFORE __text
    TestSection64Desc sec_cstring;
    sec_cstring.sectname = "__cstring";
    sec_cstring.segname = "__TEXT";
    sec_cstring.addr = 0x100001000ULL;
    sec_cstring.size = 32;
    sec_cstring.offset = 400;
    sec_cstring.flags = S_CSTRING_LITERALS;

    TestSection64Desc sec_text;
    sec_text.sectname = "__text";
    sec_text.segname = "__TEXT";
    sec_text.addr = 0x100001020ULL;
    sec_text.size = 16;
    sec_text.offset = 432;
    sec_text.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;

    append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x2000ULL, 0, 1024,
                          VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ | VM_PROT_EXECUTE, 0,
                          {sec_cstring, sec_text}, false);

    if (buf.size() < 1024) buf.resize(1024, 0);
    const uint8_t opcodes[16] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3};
    std::memcpy(&buf[432], opcodes, 16);
    write_file(test_file, buf);

    MachOParser parser(test_file);
    ASSERT_TRUE(parser.parse(test_file), "Multi-segment binary with __text as second section parses");
    ASSERT_EQ(parser.getTextSectionBaseAddress(), 0x100001020ULL, "textBaseAddr matches __text (0x100001020), not __cstring");
    ASSERT_EQ(parser.getTextSection().size(), 16u, "textSection size is 16");
    ASSERT_EQ(parser.getSections().size(), 2u, "parser records both sections in getSections()");
    ASSERT_EQ(parser.getSections()[0].name, "__TEXT,__cstring", "first section is __cstring");
    ASSERT_TRUE(!parser.getSections()[0].is_executable, "__cstring is not executable");
    ASSERT_EQ(parser.getSections()[1].name, "__TEXT,__text", "second section is __text");
    ASSERT_TRUE(parser.getSections()[1].is_executable, "__text is executable");

    fs::remove(test_file);
}

static void test_step53_zero_fill_sections() {
    std::cout << "\n[*] Group 12: Zero-Fill Section Handling...\n";
    fs::path temp_dir = fs::temp_directory_path();
    std::string test_file = (temp_dir / "test_step53_zerofill.bin").string();

    // 2 segments: __TEXT with __text (72+80=152 bytes) and __DATA with __data and __bss (72+160=232 bytes)
    uint32_t sizeofcmds = 152 + 232;
    auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 2, sizeofcmds, 0, 0, false);

    TestSection64Desc sec_text;
    sec_text.sectname = "__text";
    sec_text.segname = "__TEXT";
    sec_text.addr = 0x100001000ULL;
    sec_text.size = 16;
    sec_text.offset = 512;
    sec_text.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;

    append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x2000ULL, 0, 600,
                          VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ | VM_PROT_EXECUTE, 0,
                          {sec_text}, false);

    TestSection64Desc sec_data;
    sec_data.sectname = "__data";
    sec_data.segname = "__DATA";
    sec_data.addr = 0x100002000ULL;
    sec_data.size = 32;
    sec_data.offset = 600;
    sec_data.flags = S_REGULAR;

    TestSection64Desc sec_bss;
    sec_bss.sectname = "__bss";
    sec_bss.segname = "__DATA";
    sec_bss.addr = 0x100002020ULL;
    sec_bss.size = 0x20000ULL; // 128 KB virtual size!
    sec_bss.offset = 0;
    sec_bss.flags = S_ZEROFILL;

    // Segment filesize is only 32 bytes (only __data is in file), while vmsize is 0x30000
    append_segment64_desc(buf, LC_SEGMENT_64, "__DATA", 0x100002000ULL, 0x30000ULL, 600, 32,
                          VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, 0,
                          {sec_data, sec_bss}, false);

    // Total file size on disk is ~640 bytes (much smaller than __bss virtual size)
    if (buf.size() < 600 + 32) buf.resize(600 + 32, 0);
    const uint8_t opcodes[16] = {0x90, 0xc3};
    std::memcpy(&buf[512], opcodes, 2);
    write_file(test_file, buf);

    MachOParser parser(test_file);
    ASSERT_TRUE(parser.parse(test_file), "Mach-O with 128KB __bss zero-fill section parses without file size bounds error");
    const auto& secs = parser.getSections();
    ASSERT_EQ(secs.size(), 3u, "parser records 3 sections");
    bool found_bss = false;
    for (const auto& s : secs) {
        if (s.name == "__DATA,__bss") {
            found_bss = true;
            ASSERT_EQ(s.virtual_size, 0x20000ULL, "__bss virtual_size is 128KB");
            ASSERT_EQ(s.raw_size, 0ULL, "__bss raw_size is 0 (not file-backed)");
            ASSERT_EQ(s.raw_offset, 0ULL, "__bss raw_offset is 0");
        }
    }
    ASSERT_TRUE(found_bss, "__DATA,__bss section was found and validated");

    fs::remove(test_file);
}

static void test_step53_big_endian_load_commands() {
    std::cout << "\n[*] Group 13: Big-Endian Command & Section Field Decoding...\n";
    fs::path temp_dir = fs::temp_directory_path();
    std::string test_file = (temp_dir / "test_step53_be64.bin").string();

    uint32_t cmdsize = 72 + 80;
    auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, cmdsize, 0, 0, true);

    TestSection64Desc sec;
    sec.sectname = "__text";
    sec.segname = "__TEXT";
    sec.addr = 0x100001000ULL;
    sec.size = 8;
    sec.offset = 512;
    sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;

    append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x2000ULL, 0, 1024,
                          VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ | VM_PROT_EXECUTE, 0,
                          {sec}, true);

    if (buf.size() < 1024) buf.resize(1024, 0);
    const uint8_t opcodes[8] = {0x90, 0x90, 0x90, 0xc3, 0x00, 0x00, 0x00, 0x00};
    std::memcpy(&buf[512], opcodes, 8);
    write_file(test_file, buf);

    MachOParser parser(test_file);
    ASSERT_TRUE(parser.parse(test_file), "Big-endian 64-bit Mach-O with load commands parses successfully");
    ASSERT_TRUE(parser.isBigEndian(), "parser isBigEndian is true");
    ASSERT_EQ(parser.getTextSectionBaseAddress(), 0x100001000ULL, "textBaseAddr matches BE decoded addr");
    ASSERT_EQ(parser.getTextSection().size(), 8u, "textSection size is 8");
    ASSERT_EQ(parser.getTextSection()[3], 0xc3, "opcode at offset 3 is 0xc3");

    fs::remove(test_file);
}

static void test_step53_security_and_malformed_inputs() {
    std::cout << "\n[*] Group 14: Security, Malformed Inputs & Boundary Validation...\n";
    fs::path temp_dir = fs::temp_directory_path();

    // 1. Missing __TEXT,__text section
    {
        std::string test_file = (temp_dir / "test_missing_text.bin").string();
        uint32_t cmdsize = 72 + 80;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, cmdsize, 0, 0, false);
        TestSection64Desc sec;
        sec.sectname = "__data";
        sec.segname = "__DATA";
        sec.addr = 0x1000;
        sec.size = 16;
        sec.offset = 200;
        append_segment64_desc(buf, LC_SEGMENT_64, "__DATA", 0x1000, 0x1000, 0, 500, 3, 3, 0, {sec}, false);
        buf.resize(400, 0);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "Missing __TEXT,__text section causes parse() to fail");
        fs::remove(test_file);
    }

    // 2. Empty __TEXT,__text section (size == 0)
    {
        std::string test_file = (temp_dir / "test_empty_text.bin").string();
        uint32_t cmdsize = 72 + 80;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, cmdsize, 0, 0, false);
        TestSection64Desc sec;
        sec.sectname = "__text";
        sec.segname = "__TEXT";
        sec.addr = 0x1000;
        sec.size = 0; // Empty!
        sec.offset = 200;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x1000, 0x1000, 0, 500, 5, 5, 0, {sec}, false);
        buf.resize(400, 0);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "Empty __TEXT,__text (size 0) causes parse() to fail");
        fs::remove(test_file);
    }

    // 3. sizeofcmds extends past file size
    {
        std::string test_file = (temp_dir / "test_trunc_sizeofcmds.bin").string();
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, 5000, 0, 0, false);
        buf.resize(100, 0); // Only 100 bytes on disk, but claims 5000 bytes
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "sizeofcmds extending past EOF causes parse() to fail");
        fs::remove(test_file);
    }

    // 4. Invalid load command size: cmdsize < sizeof(load_command) (e.g. 4 bytes)
    {
        std::string test_file = (temp_dir / "test_bad_cmdsize.bin").string();
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, 4, 0, 0, false);
        write_u32_to(buf, 32, LC_SEGMENT_64, false);
        write_u32_to(buf, 36, 4, false); // cmdsize < 8
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "cmdsize < 8 causes parse() to fail");
        fs::remove(test_file);
    }

    // 5. Unaligned cmdsize (not multiple of 4)
    {
        std::string test_file = (temp_dir / "test_unaligned_cmdsize.bin").string();
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, 75, 0, 0, false);
        buf.resize(32 + 75, 0);
        write_u32_to(buf, 32, LC_SEGMENT_64, false);
        write_u32_to(buf, 36, 75, false); // Not multiple of 4
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "Unaligned cmdsize (not multiple of 4) causes parse() to fail");
        fs::remove(test_file);
    }

    // 6. Section count overflow: nsects claims 100 sections, but cmdsize is only 72
    {
        std::string test_file = (temp_dir / "test_nsects_overflow.bin").string();
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, 72, 0, 0, false);
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x1000, 0x1000, 0, 500, 5, 5, 0, {}, false, 72, 100);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "nsects exceeding declared cmdsize causes parse() to fail");
        fs::remove(test_file);
    }

    // 7. Section offset + size exceeds total file size
    {
        std::string test_file = (temp_dir / "test_sec_out_of_bounds.bin").string();
        uint32_t cmdsize = 72 + 80;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, cmdsize, 0, 0, false);
        TestSection64Desc sec;
        sec.sectname = "__text";
        sec.segname = "__TEXT";
        sec.addr = 0x1000;
        sec.size = 1000; // Exceeds file size
        sec.offset = 500;
        sec.flags = S_REGULAR;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x1000, 0x2000, 0, 2000, 5, 5, 0, {sec}, false);
        buf.resize(600, 0); // File is only 600 bytes, but offset+size is 1500
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "Section offset + size past EOF causes parse() to fail");
        fs::remove(test_file);
    }

    // 8. 32-bit LC_SEGMENT inside 64-bit Mach-O container
    {
        std::string test_file = (temp_dir / "test_mismatch_segment32_in_64.bin").string();
        uint32_t cmdsize = 56 + 68;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, cmdsize, 0, 0, false);
        TestSection32Desc sec;
        sec.sectname = "__text";
        sec.segname = "__TEXT";
        sec.addr = 0x1000;
        sec.size = 16;
        sec.offset = 200;
        append_segment32_desc(buf, LC_SEGMENT, "__TEXT", 0x1000, 0x1000, 0, 500, 5, 5, 0, {sec}, false);
        buf.resize(400, 0);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "32-bit LC_SEGMENT in 64-bit binary rejected");
        fs::remove(test_file);
    }

    // 9. 64-bit LC_SEGMENT_64 inside 32-bit Mach-O container
    {
        std::string test_file = (temp_dir / "test_mismatch_segment64_in_32.bin").string();
        uint32_t cmdsize = 72 + 80;
        auto buf = make_macho32_buf(MH_MAGIC, CPU_TYPE_X86, 3, MH_EXECUTE, 1, cmdsize, 0, false);
        TestSection64Desc sec;
        sec.sectname = "__text";
        sec.segname = "__TEXT";
        sec.addr = 0x1000;
        sec.size = 16;
        sec.offset = 200;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x1000, 0x1000, 0, 500, 5, 5, 0, {sec}, false);
        buf.resize(400, 0);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "64-bit LC_SEGMENT_64 in 32-bit binary rejected");
        fs::remove(test_file);
    }

    // 10. Section segname does not match containing segment
    {
        std::string test_file = (temp_dir / "test_segname_mismatch.bin").string();
        uint32_t cmdsize = 72 + 80;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, cmdsize, 0, 0, false);
        TestSection64Desc sec;
        sec.sectname = "__text";
        sec.segname = "__DATA"; // Mismatch! Containing segment is __TEXT
        sec.addr = 0x1000;
        sec.size = 16;
        sec.offset = 200;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x1000, 0x1000, 0, 500, 5, 5, 0, {sec}, false);
        buf.resize(400, 0);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "Section segname mismatch causes parse() to fail");
        fs::remove(test_file);
    }
}

// ============================================================================
// Phase 2 Step 5.4 Test Suites: Universal / Fat Mach-O Binary Support
// ============================================================================

struct TestFatSlice32 {
    int32_t cputype;
    int32_t cpusubtype;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
    std::vector<uint8_t> slice_data;
};

struct TestFatSlice64 {
    int32_t cputype;
    int32_t cpusubtype;
    uint64_t offset;
    uint64_t size;
    uint32_t align;
    uint32_t reserved = 0;
    std::vector<uint8_t> slice_data;
};

static std::vector<uint8_t> make_valid_thin64_slice(int32_t cputype, int32_t cpusubtype,
                                                    uint64_t text_addr, size_t text_size,
                                                    bool is_be, const std::vector<uint8_t>& code = {})
{
    uint32_t cmdsize = 72 + 80;
    auto buf = make_macho64_buf(MH_MAGIC_64, cputype, cpusubtype, MH_EXECUTE, 1, cmdsize, 0, 0, is_be);
    TestSection64Desc sec;
    sec.sectname = "__text";
    sec.segname = "__TEXT";
    sec.addr = text_addr;
    sec.size = text_size;
    sec.offset = 32 + cmdsize;
    sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;

    append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", text_addr, 0x1000, 0, sec.offset + text_size,
                          VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ | VM_PROT_EXECUTE, 0, {sec}, is_be);
    if (buf.size() < sec.offset + text_size) {
        buf.resize(sec.offset + text_size, 0x90);
    }
    if (!code.empty()) {
        std::memcpy(&buf[sec.offset], code.data(), std::min(code.size(), static_cast<size_t>(text_size)));
    }
    return buf;
}

static std::vector<uint8_t> make_valid_thin32_slice(int32_t cputype, int32_t cpusubtype,
                                                    uint32_t text_addr, size_t text_size,
                                                    bool is_be, const std::vector<uint8_t>& code = {})
{
    uint32_t cmdsize = 56 + 68;
    auto buf = make_macho32_buf(MH_MAGIC, cputype, cpusubtype, MH_EXECUTE, 1, cmdsize, 0, is_be);
    TestSection32Desc sec;
    sec.sectname = "__text";
    sec.segname = "__TEXT";
    sec.addr = text_addr;
    sec.size = static_cast<uint32_t>(text_size);
    sec.offset = 28 + cmdsize;
    sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;

    append_segment32_desc(buf, LC_SEGMENT, "__TEXT", text_addr, 0x1000, 0, sec.offset + text_size,
                          VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ | VM_PROT_EXECUTE, 0, {sec}, is_be);
    if (buf.size() < sec.offset + text_size) {
        buf.resize(sec.offset + text_size, 0x90);
    }
    if (!code.empty()) {
        std::memcpy(&buf[sec.offset], code.data(), std::min(code.size(), static_cast<size_t>(text_size)));
    }
    return buf;
}

static std::vector<uint8_t> make_fat32_file(uint32_t magic, const std::vector<TestFatSlice32>& slices, bool is_be) {
    std::vector<uint8_t> buf(8 + slices.size() * 20, 0);
    write_u32_to(buf, 0, magic, is_be);
    write_u32_to(buf, 4, static_cast<uint32_t>(slices.size()), is_be);

    for (size_t i = 0; i < slices.size(); ++i) {
        size_t off = 8 + i * 20;
        write_u32_to(buf, off + 0, static_cast<uint32_t>(slices[i].cputype), is_be);
        write_u32_to(buf, off + 4, static_cast<uint32_t>(slices[i].cpusubtype), is_be);
        write_u32_to(buf, off + 8, slices[i].offset, is_be);
        write_u32_to(buf, off + 12, slices[i].size, is_be);
        write_u32_to(buf, off + 16, slices[i].align, is_be);

        if (!slices[i].slice_data.empty()) {
            if (slices[i].offset + slices[i].slice_data.size() > buf.size()) {
                buf.resize(slices[i].offset + slices[i].slice_data.size(), 0);
            }
            std::memcpy(&buf[slices[i].offset], slices[i].slice_data.data(), slices[i].slice_data.size());
        }
    }
    return buf;
}

static std::vector<uint8_t> make_fat64_file(uint32_t magic, const std::vector<TestFatSlice64>& slices, bool is_be) {
    std::vector<uint8_t> buf(8 + slices.size() * 32, 0);
    write_u32_to(buf, 0, magic, is_be);
    write_u32_to(buf, 4, static_cast<uint32_t>(slices.size()), is_be);

    for (size_t i = 0; i < slices.size(); ++i) {
        size_t off = 8 + i * 32;
        write_u32_to(buf, off + 0, static_cast<uint32_t>(slices[i].cputype), is_be);
        write_u32_to(buf, off + 4, static_cast<uint32_t>(slices[i].cpusubtype), is_be);
        write_u64_to(buf, off + 8, slices[i].offset, is_be);
        write_u64_to(buf, off + 16, slices[i].size, is_be);
        write_u32_to(buf, off + 24, slices[i].align, is_be);
        write_u32_to(buf, off + 28, slices[i].reserved, is_be);

        if (!slices[i].slice_data.empty()) {
            if (slices[i].offset + slices[i].slice_data.size() > buf.size()) {
                buf.resize(slices[i].offset + slices[i].slice_data.size(), 0);
            }
            std::memcpy(&buf[slices[i].offset], slices[i].slice_data.data(), slices[i].slice_data.size());
        }
    }
    return buf;
}

static void write_sparse_file(const std::string& path, const std::vector<uint8_t>& header_and_table,
                              uint64_t slice_offset, const std::vector<uint8_t>& slice_data)
{
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs.is_open()) return;
    ofs.write(reinterpret_cast<const char*>(header_and_table.data()), header_and_table.size());
    ofs.seekp(static_cast<std::streamoff>(slice_offset), std::ios::beg);
    ofs.write(reinterpret_cast<const char*>(slice_data.data()), slice_data.size());
}

static void test_step54_universal_binaries() {
    std::cout << "\n[*] Group 15: Step 5.4 Universal / Fat Mach-O Binary Parsing...\n";
    fs::path temp_dir = fs::temp_directory_path();

    // 1. All four universal magic variants
    {
        // 1.1 FAT_MAGIC (BE container) with x86_64 slice
        auto slice_x64 = make_valid_thin64_slice(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0x100000000, 32, false);
        TestFatSlice32 s1;
        s1.cputype = CPU_TYPE_X86_64;
        s1.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
        s1.offset = 4096;
        s1.size = static_cast<uint32_t>(slice_x64.size());
        s1.align = 12; // 2^12 = 4096
        s1.slice_data = slice_x64;

        std::string test_file1 = (temp_dir / "test_fat_magic_be.bin").string();
        auto fat_bytes1 = make_fat32_file(FAT_MAGIC, {s1}, true);
        write_file(test_file1, fat_bytes1);

        MachOParser parser1(test_file1);
        ASSERT_TRUE(parser1.parse(test_file1), "FAT_MAGIC (BE container) parses successfully");
        ASSERT_TRUE(parser1.isFat(), "isFat() is true for FAT_MAGIC container");
        ASSERT_EQ(parser1.getArchitecture(), "x86_64", "Selected architecture is x86_64");
        ASSERT_EQ(parser1.getSliceOffset(), 4096ULL, "Slice offset is 4096");
        ASSERT_EQ(parser1.getSliceSize(), slice_x64.size(), "Slice size matches slice data");
        fs::remove(test_file1);

        // 1.2 FAT_CIGAM (LE container) with x86_64 slice
        std::string test_file2 = (temp_dir / "test_fat_cigam_le.bin").string();
        auto fat_bytes2 = make_fat32_file(FAT_MAGIC, {s1}, false); // write with is_be = false creates 0xbebafeca
        write_file(test_file2, fat_bytes2);

        MachOParser parser2(test_file2);
        ASSERT_TRUE(parser2.parse(test_file2), "FAT_CIGAM (LE container) parses successfully");
        ASSERT_TRUE(parser2.isFat(), "isFat() is true for FAT_CIGAM container");
        ASSERT_EQ(parser2.getArchitecture(), "x86_64", "Selected architecture is x86_64");
        ASSERT_EQ(parser2.getSliceOffset(), 4096ULL, "Slice offset is 4096");
        fs::remove(test_file2);

        // 1.3 FAT_MAGIC_64 (BE 64-bit container) with x86_64 slice
        TestFatSlice64 s64_1;
        s64_1.cputype = CPU_TYPE_X86_64;
        s64_1.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
        s64_1.offset = 4096;
        s64_1.size = slice_x64.size();
        s64_1.align = 12;
        s64_1.slice_data = slice_x64;

        std::string test_file3 = (temp_dir / "test_fat_magic64_be.bin").string();
        auto fat_bytes3 = make_fat64_file(FAT_MAGIC_64, {s64_1}, true);
        write_file(test_file3, fat_bytes3);

        MachOParser parser3(test_file3);
        ASSERT_TRUE(parser3.parse(test_file3), "FAT_MAGIC_64 (BE container) parses successfully");
        ASSERT_TRUE(parser3.isFat(), "isFat() is true for FAT_MAGIC_64 container");
        ASSERT_EQ(parser3.getArchitecture(), "x86_64", "Selected architecture is x86_64");
        ASSERT_EQ(parser3.getSliceOffset(), 4096ULL, "Slice offset is 4096");
        fs::remove(test_file3);

        // 1.4 FAT_CIGAM_64 (LE 64-bit container) with x86_64 slice
        std::string test_file4 = (temp_dir / "test_fat_cigam64_le.bin").string();
        auto fat_bytes4 = make_fat64_file(FAT_MAGIC_64, {s64_1}, false);
        write_file(test_file4, fat_bytes4);

        MachOParser parser4(test_file4);
        ASSERT_TRUE(parser4.parse(test_file4), "FAT_CIGAM_64 (LE container) parses successfully");
        ASSERT_TRUE(parser4.isFat(), "isFat() is true for FAT_CIGAM_64 container");
        ASSERT_EQ(parser4.getArchitecture(), "x86_64", "Selected architecture is x86_64");
        ASSERT_EQ(parser4.getSliceOffset(), 4096ULL, "Slice offset is 4096");
        fs::remove(test_file4);
    }

    // 2. Multiple slices and deterministic default selection
    {
        auto slice_x64 = make_valid_thin64_slice(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0x100000000, 32, false);
        auto slice_arm64 = make_valid_thin64_slice(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, 0x200000000, 32, false);
        auto slice_x86 = make_valid_thin32_slice(CPU_TYPE_X86, CPU_SUBTYPE_I386_ALL, 0x1000, 32, false);
        auto slice_armv7 = make_valid_thin32_slice(CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7, 0x2000, 32, false);

        // 2.1 Dual slice: ARM64 at 4096, x86_64 at 8192 -> deterministic default selects x86_64!
        TestFatSlice32 s_arm64;
        s_arm64.cputype = CPU_TYPE_ARM64;
        s_arm64.cpusubtype = CPU_SUBTYPE_ARM64_ALL;
        s_arm64.offset = 4096;
        s_arm64.size = static_cast<uint32_t>(slice_arm64.size());
        s_arm64.align = 12;
        s_arm64.slice_data = slice_arm64;

        TestFatSlice32 s_x64;
        s_x64.cputype = CPU_TYPE_X86_64;
        s_x64.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
        s_x64.offset = 8192;
        s_x64.size = static_cast<uint32_t>(slice_x64.size());
        s_x64.align = 12;
        s_x64.slice_data = slice_x64;

        std::string test_file = (temp_dir / "test_multi_arm_first.bin").string();
        auto fat_bytes = make_fat32_file(FAT_MAGIC, {s_arm64, s_x64}, true);
        write_file(test_file, fat_bytes);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "Multi-slice universal binary parses successfully");
        ASSERT_EQ(parser.getArchitecture(), "x86_64", "Default precedence selects x86_64 even when ARM64 is earlier");
        ASSERT_EQ(parser.getSliceOffset(), 8192ULL, "Selected slice offset is 8192");
        fs::remove(test_file);

        // 2.2 Dual slice: ARM64 and ARMv7 -> selects ARM64
        TestFatSlice32 s_armv7;
        s_armv7.cputype = CPU_TYPE_ARM;
        s_armv7.cpusubtype = CPU_SUBTYPE_ARM_V7;
        s_armv7.offset = 8192;
        s_armv7.size = static_cast<uint32_t>(slice_armv7.size());
        s_armv7.align = 12;
        s_armv7.slice_data = slice_armv7;

        test_file = (temp_dir / "test_multi_arm64_armv7.bin").string();
        fat_bytes = make_fat32_file(FAT_MAGIC, {s_arm64, s_armv7}, true);
        write_file(test_file, fat_bytes);

        MachOParser parser_arm(test_file);
        ASSERT_TRUE(parser_arm.parse(test_file), "ARM64 + ARMv7 container parses successfully");
        ASSERT_EQ(parser_arm.getArchitecture(), "aarch64", "Default precedence selects aarch64 over armv7");
        ASSERT_EQ(parser_arm.getSliceOffset(), 4096ULL, "Selected slice offset is 4096");
        fs::remove(test_file);

        // 2.3 Dual slice: x86 and ARMv7 -> selects x86
        TestFatSlice32 s_x86;
        s_x86.cputype = CPU_TYPE_X86;
        s_x86.cpusubtype = CPU_SUBTYPE_I386_ALL;
        s_x86.offset = 4096;
        s_x86.size = static_cast<uint32_t>(slice_x86.size());
        s_x86.align = 12;
        s_x86.slice_data = slice_x86;

        test_file = (temp_dir / "test_multi_x86_armv7.bin").string();
        fat_bytes = make_fat32_file(FAT_MAGIC, {s_x86, s_armv7}, true);
        write_file(test_file, fat_bytes);

        MachOParser parser_x86(test_file);
        ASSERT_TRUE(parser_x86.parse(test_file), "x86 + ARMv7 container parses successfully");
        ASSERT_EQ(parser_x86.getArchitecture(), "x86", "Default precedence selects x86 over armv7");
        ASSERT_EQ(parser_x86.getSliceOffset(), 4096ULL, "Selected slice offset is 4096");
        fs::remove(test_file);
    }

    // 3. Explicit architecture selection and missing architecture (NO silent fallback)
    {
        auto slice_x64 = make_valid_thin64_slice(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0x100000000, 32, false);
        auto slice_arm64 = make_valid_thin64_slice(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, 0x200000000, 32, false);

        TestFatSlice32 s_x64;
        s_x64.cputype = CPU_TYPE_X86_64;
        s_x64.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
        s_x64.offset = 4096;
        s_x64.size = static_cast<uint32_t>(slice_x64.size());
        s_x64.align = 12;
        s_x64.slice_data = slice_x64;

        TestFatSlice32 s_arm64;
        s_arm64.cputype = CPU_TYPE_ARM64;
        s_arm64.cpusubtype = CPU_SUBTYPE_ARM64_ALL;
        s_arm64.offset = 8192;
        s_arm64.size = static_cast<uint32_t>(slice_arm64.size());
        s_arm64.align = 12;
        s_arm64.slice_data = slice_arm64;

        std::string test_file = (temp_dir / "test_explicit_selection.bin").string();
        auto fat_bytes = make_fat32_file(FAT_MAGIC, {s_x64, s_arm64}, true);
        write_file(test_file, fat_bytes);

        // 3.1 Explicitly request "arm64"
        MachOParser parser_req_arm64(test_file);
        ASSERT_TRUE(parser_req_arm64.parse(test_file, "arm64"), "Explicit 'arm64' request succeeds");
        ASSERT_EQ(parser_req_arm64.getArchitecture(), "aarch64", "Architecture is aarch64");
        ASSERT_EQ(parser_req_arm64.getSliceOffset(), 8192ULL, "Slice offset is 8192");

        // 3.2 Explicitly request "aarch64"
        MachOParser parser_req_aarch64(test_file);
        ASSERT_TRUE(parser_req_aarch64.parse(test_file, "aarch64"), "Explicit 'aarch64' request succeeds");
        ASSERT_EQ(parser_req_aarch64.getArchitecture(), "aarch64", "Architecture is aarch64");
        ASSERT_EQ(parser_req_aarch64.getSliceOffset(), 8192ULL, "Slice offset is 8192");

        // 3.3 Explicitly request "x86_64"
        MachOParser parser_req_x64(test_file);
        ASSERT_TRUE(parser_req_x64.parse(test_file, "x86_64"), "Explicit 'x86_64' request succeeds");
        ASSERT_EQ(parser_req_x64.getArchitecture(), "x86_64", "Architecture is x86_64");
        ASSERT_EQ(parser_req_x64.getSliceOffset(), 4096ULL, "Slice offset is 4096");

        // 3.4 Explicitly request missing architecture "x86" (MUST fail, no fallback!)
        MachOParser parser_req_missing(test_file);
        ASSERT_TRUE(!parser_req_missing.parse(test_file, "x86"), "Missing architecture 'x86' fails to parse without fallback");

        // 3.5 Explicitly request missing architecture "armv7" (MUST fail)
        MachOParser parser_req_missing2(test_file);
        ASSERT_TRUE(!parser_req_missing2.parse(test_file, "armv7"), "Missing architecture 'armv7' fails to parse without fallback");

        fs::remove(test_file);
    }

    // 4. Big-endian universal header with little-endian thin slice
    {
        std::vector<uint8_t> expected_code = {0x48, 0x89, 0xC3, 0xC3}; // mov rbx, rax; ret
        auto slice_x64 = make_valid_thin64_slice(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0x100000000, 32, false, expected_code);

        TestFatSlice32 s1;
        s1.cputype = CPU_TYPE_X86_64;
        s1.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
        s1.offset = 4096;
        s1.size = static_cast<uint32_t>(slice_x64.size());
        s1.align = 12;
        s1.slice_data = slice_x64;

        std::string test_file = (temp_dir / "test_be_fat_le_slice.bin").string();
        auto fat_bytes = make_fat32_file(FAT_MAGIC, {s1}, true); // Container is Big-Endian
        write_file(test_file, fat_bytes);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "BE container + LE thin slice parses successfully");
        ASSERT_TRUE(!parser.isBigEndian(), "Thin slice is recognized as Little-Endian despite BE fat header");
        ASSERT_EQ(parser.getMetadataEndianness(), Endianness::Little, "Metadata endianness is Little");
        ASSERT_EQ(parser.getInstructionEndianness(), Endianness::Little, "Instruction endianness is Little");

        const auto& code = parser.getTextSection();
        ASSERT_TRUE(code.size() >= 4, "Extracted text section is at least 4 bytes");
        ASSERT_EQ(code[0], 0x48, "Opcode byte 0 matches expected");
        ASSERT_EQ(code[1], 0x89, "Opcode byte 1 matches expected");
        ASSERT_EQ(code[2], 0xC3, "Opcode byte 2 matches expected");
        ASSERT_EQ(code[3], 0xC3, "Opcode byte 3 matches expected");

        fs::remove(test_file);
    }

    // 5. Nonzero slice offsets and absolute file-offset resolution (vaToOffsets)
    {
        auto slice_x64 = make_valid_thin64_slice(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0x100001000, 64, false);
        TestFatSlice32 s1;
        s1.cputype = CPU_TYPE_X86_64;
        s1.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
        s1.offset = 4096;
        s1.size = static_cast<uint32_t>(slice_x64.size());
        s1.align = 12;
        s1.slice_data = slice_x64;

        std::string test_file = (temp_dir / "test_slice_offset_resolution.bin").string();
        auto fat_bytes = make_fat32_file(FAT_MAGIC, {s1}, true);
        write_file(test_file, fat_bytes);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "Slice offset resolution test parses successfully");

        const auto& sections = parser.getSections();
        ASSERT_TRUE(!sections.empty(), "Sections vector is non-empty");

        // In slice_x64, section offset relative to slice is 32 + (72 + 80) = 184 (0xB8)
        // With slice offset = 4096, section raw_offset MUST be 4096 + 184 = 4280!
        ASSERT_EQ(sections[0].raw_offset, 4096ULL + 184ULL, "Section raw_offset is correctly translated to absolute file offset");

        const auto& mappings = parser.getExecBufferMappings();
        ASSERT_TRUE(!mappings.empty(), "Exec mappings vector is non-empty");
        ASSERT_EQ(mappings[0].raw_offset, 4096ULL + 184ULL, "Mapping raw_offset is correctly translated to absolute file offset");

        // Test vaToOffsets: virtual address 0x100001008 should map to file offset 4280 + 8 = 4288
        uint64_t fo = 0, rva = 0;
        ASSERT_TRUE(parser.vaToOffsets(0x100001008, fo, rva), "vaToOffsets succeeds for valid section VA");
        ASSERT_EQ(fo, 4280ULL + 8ULL, "vaToOffsets maps to correct absolute container file offset");
        ASSERT_EQ(rva, 8ULL, "vaToOffsets maps to correct RVA");

        fs::remove(test_file);
    }

    // 6. CPU subtype compatibility and capability masking
    {
        // 6.1 x86_64h (Haswell) with CPU_SUBTYPE_LIB64 capability bit
        auto slice_x64h = make_valid_thin64_slice(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_H | CPU_SUBTYPE_LIB64, 0x100000000, 32, false);
        TestFatSlice32 s_x64h;
        s_x64h.cputype = CPU_TYPE_X86_64;
        s_x64h.cpusubtype = CPU_SUBTYPE_X86_64_H | CPU_SUBTYPE_LIB64;
        s_x64h.offset = 4096;
        s_x64h.size = static_cast<uint32_t>(slice_x64h.size());
        s_x64h.align = 12;
        s_x64h.slice_data = slice_x64h;

        std::string test_file1 = (temp_dir / "test_subtype_x86_64h.bin").string();
        auto fat_bytes1 = make_fat32_file(FAT_MAGIC, {s_x64h}, true);
        write_file(test_file1, fat_bytes1);

        MachOParser parser1(test_file1);
        ASSERT_TRUE(parser1.parse(test_file1), "x86_64h slice with LIB64 mask parses successfully");
        ASSERT_EQ(parser1.getArchitecture(), "x86_64", "x86_64h is accepted as x86_64 compatible");
        fs::remove(test_file1);

        // 6.2 arm64e (PAC) with CPU_SUBTYPE_LIB64 capability bit
        auto slice_arm64e = make_valid_thin64_slice(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_LIB64, 0x200000000, 32, false);
        TestFatSlice32 s_arm64e;
        s_arm64e.cputype = CPU_TYPE_ARM64;
        s_arm64e.cpusubtype = CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_LIB64;
        s_arm64e.offset = 4096;
        s_arm64e.size = static_cast<uint32_t>(slice_arm64e.size());
        s_arm64e.align = 12;
        s_arm64e.slice_data = slice_arm64e;

        std::string test_file2 = (temp_dir / "test_subtype_arm64e.bin").string();
        auto fat_bytes2 = make_fat32_file(FAT_MAGIC, {s_arm64e}, true);
        write_file(test_file2, fat_bytes2);

        MachOParser parser2(test_file2);
        ASSERT_TRUE(parser2.parse(test_file2), "arm64e slice with LIB64 mask parses successfully");
        ASSERT_EQ(parser2.getArchitecture(), "aarch64", "arm64e is accepted as aarch64 compatible");
        fs::remove(test_file2);

        // 6.3 Unsupported legacy subtype: ARMv4T
        auto slice_v4t = make_valid_thin32_slice(CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V4T, 0x1000, 32, false);
        TestFatSlice32 s_v4t;
        s_v4t.cputype = CPU_TYPE_ARM;
        s_v4t.cpusubtype = CPU_SUBTYPE_ARM_V4T;
        s_v4t.offset = 4096;
        s_v4t.size = static_cast<uint32_t>(slice_v4t.size());
        s_v4t.align = 12;
        s_v4t.slice_data = slice_v4t;

        std::string test_file3 = (temp_dir / "test_subtype_arm_v4t.bin").string();
        auto fat_bytes3 = make_fat32_file(FAT_MAGIC, {s_v4t}, true);
        write_file(test_file3, fat_bytes3);

        MachOParser parser3(test_file3);
        ASSERT_TRUE(!parser3.parse(test_file3), "Unsupported ARMv4T subtype is rejected by default selection");
        fs::remove(test_file3);
    }

    // 7. Security validations and malformed container rejection
    {
        // 7.1 Zero architecture count (nfat_arch == 0)
        {
            std::string test_file = (temp_dir / "test_malformed_zero_arch.bin").string();
            std::vector<uint8_t> bytes(8, 0);
            write_u32_to(bytes, 0, FAT_MAGIC, true);
            write_u32_to(bytes, 4, 0, true); // nfat_arch = 0
            write_file(test_file, bytes);

            MachOParser parser(test_file);
            ASSERT_TRUE(!parser.parse(test_file), "Zero architecture count is rejected");
            fs::remove(test_file);
        }

        // 7.2 Truncated architecture table
        {
            std::string test_file = (temp_dir / "test_malformed_trunc_table.bin").string();
            std::vector<uint8_t> bytes(16, 0);
            write_u32_to(bytes, 0, FAT_MAGIC, true);
            write_u32_to(bytes, 4, 2, true); // declares 2 slices (needs 8 + 40 = 48 bytes)
            write_file(test_file, bytes);

            MachOParser parser(test_file);
            ASSERT_TRUE(!parser.parse(test_file), "Truncated architecture table is rejected");
            fs::remove(test_file);
        }

        // 7.3 Slice offset + size integer overflow
        {
            std::string test_file = (temp_dir / "test_malformed_overflow.bin").string();
            TestFatSlice64 s;
            s.cputype = CPU_TYPE_X86_64;
            s.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
            s.offset = 0xFFFFFFFFFFFF0000ULL;
            s.size = 0x20000ULL; // offset + size wraps around
            s.align = 0;

            auto bytes = make_fat64_file(FAT_MAGIC_64, {s}, true);
            write_file(test_file, bytes);

            MachOParser parser(test_file);
            ASSERT_TRUE(!parser.parse(test_file), "Slice offset + size 64-bit integer overflow is rejected");
            fs::remove(test_file);
        }

        // 7.4 Slice containment within file
        {
            std::string test_file = (temp_dir / "test_malformed_past_eof.bin").string();
            TestFatSlice32 s;
            s.cputype = CPU_TYPE_X86_64;
            s.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
            s.offset = 4096;
            s.size = 8192; // requires 12288 bytes, but file is smaller
            s.align = 12;

            auto bytes = make_fat32_file(FAT_MAGIC, {s}, true);
            bytes.resize(5000); // truncate file past offset
            write_file(test_file, bytes);

            MachOParser parser(test_file);
            ASSERT_TRUE(!parser.parse(test_file), "Slice exceeding file size is rejected");
            fs::remove(test_file);
        }

        // 7.5 Slice / header / table overlap
        {
            std::string test_file = (temp_dir / "test_malformed_table_overlap.bin").string();
            TestFatSlice32 s;
            s.cputype = CPU_TYPE_X86_64;
            s.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
            s.offset = 16; // Table extends to 8 + 20 = 28 bytes! Offset 16 overlaps table.
            s.size = 100;
            s.align = 0;

            auto bytes = make_fat32_file(FAT_MAGIC, {s}, true);
            bytes.resize(200, 0);
            write_file(test_file, bytes);

            MachOParser parser(test_file);
            ASSERT_TRUE(!parser.parse(test_file), "Slice overlapping architecture table is rejected");
            fs::remove(test_file);
        }

        // 7.6 Slice-to-slice overlap
        {
            std::string test_file = (temp_dir / "test_malformed_slice_overlap.bin").string();
            auto slice_x64 = make_valid_thin64_slice(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0x100000000, 32, false);

            TestFatSlice32 s1;
            s1.cputype = CPU_TYPE_X86_64;
            s1.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
            s1.offset = 4096;
            s1.size = 4096; // [4096, 8192)
            s1.align = 12;
            s1.slice_data = slice_x64;

            TestFatSlice32 s2;
            s2.cputype = CPU_TYPE_ARM64;
            s2.cpusubtype = CPU_SUBTYPE_ARM64_ALL;
            s2.offset = 6144; // [6144, 10240) overlaps s1!
            s2.size = 4096;
            s2.align = 11; // 2^11 = 2048, divides 6144
            s2.slice_data = slice_x64;

            auto bytes = make_fat32_file(FAT_MAGIC, {s1, s2}, true);
            bytes.resize(16384, 0);
            write_file(test_file, bytes);

            MachOParser parser(test_file);
            ASSERT_TRUE(!parser.parse(test_file), "Mutually overlapping slices in container are rejected");
            fs::remove(test_file);
        }

        // 7.7 FAT32 and FAT64 Alignment Exponent Tests
        // 7.7.1 FAT32 exponent 32 is rejected
        {
            std::string test_file = (temp_dir / "test_fat32_align_32_rejected.bin").string();
            auto slice_x64 = make_valid_thin64_slice(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0x100000000, 32, false);

            TestFatSlice32 s;
            s.cputype = CPU_TYPE_X86_64;
            s.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
            s.offset = 4096;
            s.size = static_cast<uint32_t>(slice_x64.size());
            s.align = 32; // Invalid exponent >= 32 for FAT32
            s.slice_data = slice_x64;

            auto bytes = make_fat32_file(FAT_MAGIC, {s}, true);
            write_file(test_file, bytes);

            MachOParser parser(test_file);
            ASSERT_TRUE(!parser.parse(test_file), "FAT32 alignment exponent >= 32 is rejected");
            fs::remove(test_file);
        }

        // 7.7.2 FAT64 exponent 31 is handled correctly
        {
            std::string test_file = (temp_dir / "test_fat64_align_31.bin").string();
            auto slice_x64 = make_valid_thin64_slice(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0x100000000, 32, false);

            TestFatSlice64 s;
            s.cputype = CPU_TYPE_X86_64;
            s.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
            s.offset = 0x80000000ULL; // 2GB satisfies 2^31 alignment
            s.size = slice_x64.size();
            s.align = 31;

            auto hdr = make_fat64_file(FAT_MAGIC_64, {s}, true);
            write_sparse_file(test_file, hdr, s.offset, slice_x64);

            MachOParser parser(test_file);
            ASSERT_TRUE(parser.parse(test_file), "FAT64 exponent 31 with 2GB offset is handled correctly");
            ASSERT_EQ(parser.getSliceOffset(), 0x80000000ULL, "FAT64 slice offset is 2GB");
            ASSERT_EQ(parser.getArchitecture(), "x86_64", "FAT64 slice architecture is x86_64");
            fs::remove(test_file);
        }

        // 7.7.3 FAT64 exponent 32 is accepted when offset satisfies alignment requirement
        {
            std::string test_file = (temp_dir / "test_fat64_align_32.bin").string();
            auto slice_x64 = make_valid_thin64_slice(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0x100000000, 32, false);

            TestFatSlice64 s;
            s.cputype = CPU_TYPE_X86_64;
            s.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
            s.offset = 0x100000000ULL; // 4GB satisfies 2^32 alignment
            s.size = slice_x64.size();
            s.align = 32;

            auto hdr = make_fat64_file(FAT_MAGIC_64, {s}, true);
            write_sparse_file(test_file, hdr, s.offset, slice_x64);

            MachOParser parser(test_file);
            ASSERT_TRUE(parser.parse(test_file), "FAT64 exponent 32 is accepted when offset satisfies alignment");
            ASSERT_EQ(parser.getSliceOffset(), 0x100000000ULL, "FAT64 slice offset is 4GB");
            ASSERT_EQ(parser.getArchitecture(), "x86_64", "FAT64 slice architecture is x86_64");
            fs::remove(test_file);
        }

        // 7.7.4 FAT64 exponent 63 is handled safely when offset satisfies alignment requirement
        {
            std::string test_file = (temp_dir / "test_fat64_align_63.bin").string();
            TestFatSlice64 s;
            s.cputype = CPU_TYPE_X86_64;
            s.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
            s.offset = 0x8000000000000000ULL; // Satisfies 2^63 alignment
            s.size = 100;
            s.align = 63; // Exponent 63 is valid in 64-bit space (1ULL << 63)

            auto bytes = make_fat64_file(FAT_MAGIC_64, {s}, true);
            write_file(test_file, bytes);

            MachOParser parser(test_file);
            ASSERT_TRUE(!parser.parse(test_file), "FAT64 exponent 63 is handled safely without shift overflow");
            fs::remove(test_file);
        }

        // 7.7.5 FAT64 exponent 64 is rejected without performing a shift
        {
            std::string test_file = (temp_dir / "test_fat64_align_64_rejected.bin").string();
            TestFatSlice64 s;
            s.cputype = CPU_TYPE_X86_64;
            s.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
            s.offset = 4096;
            s.size = 100;
            s.align = 64; // Exponent >= 64 is invalid

            auto bytes = make_fat64_file(FAT_MAGIC_64, {s}, true);
            bytes.resize(5000, 0);
            write_file(test_file, bytes);

            MachOParser parser(test_file);
            ASSERT_TRUE(!parser.parse(test_file), "FAT64 exponent 64 is rejected without performing a shift");
            fs::remove(test_file);
        }

        // 7.7.6 Misaligned FAT64 offsets are rejected
        {
            std::string test_file = (temp_dir / "test_fat64_misaligned.bin").string();
            TestFatSlice64 s;
            s.cputype = CPU_TYPE_X86_64;
            s.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
            s.offset = 4096; // 4096 is NOT aligned to 2^32
            s.size = 100;
            s.align = 32;

            auto bytes = make_fat64_file(FAT_MAGIC_64, {s}, true);
            bytes.resize(5000, 0);
            write_file(test_file, bytes);

            MachOParser parser(test_file);
            ASSERT_TRUE(!parser.parse(test_file), "Misaligned FAT64 offset is rejected");
            fs::remove(test_file);
        }

        // 7.8 Slice offset not aligned to declared align
        {
            std::string test_file = (temp_dir / "test_malformed_misaligned_offset.bin").string();
            auto slice_x64 = make_valid_thin64_slice(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0x100000000, 32, false);

            TestFatSlice32 s;
            s.cputype = CPU_TYPE_X86_64;
            s.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
            s.offset = 4097; // Not aligned to 2^12 = 4096
            s.size = static_cast<uint32_t>(slice_x64.size());
            s.align = 12;
            s.slice_data = slice_x64;

            auto bytes = make_fat32_file(FAT_MAGIC, {s}, true);
            write_file(test_file, bytes);

            MachOParser parser(test_file);
            ASSERT_TRUE(!parser.parse(test_file), "Slice offset violating declared power-of-two alignment is rejected");
            fs::remove(test_file);
        }

        // 7.9 Slice with align == 0 (byte aligned, naturally valid)
        {
            std::string test_file = (temp_dir / "test_valid_align_zero.bin").string();
            auto slice_x64 = make_valid_thin64_slice(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0x100000000, 32, false);

            TestFatSlice32 s;
            s.cputype = CPU_TYPE_X86_64;
            s.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
            s.offset = 100; // Byte aligned (align == 0)
            s.size = static_cast<uint32_t>(slice_x64.size());
            s.align = 0; // 2^0 = 1 byte
            s.slice_data = slice_x64;

            auto bytes = make_fat32_file(FAT_MAGIC, {s}, true);
            write_file(test_file, bytes);

            MachOParser parser(test_file);
            ASSERT_TRUE(parser.parse(test_file), "Slice with align == 0 parses successfully");
            fs::remove(test_file);
        }

        // 7.10 Slice size smaller than thin header (< 28 bytes)
        {
            std::string test_file = (temp_dir / "test_malformed_slice_too_small.bin").string();
            TestFatSlice32 s;
            s.cputype = CPU_TYPE_X86_64;
            s.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
            s.offset = 4096;
            s.size = 20; // < 28 bytes
            s.align = 12;

            auto bytes = make_fat32_file(FAT_MAGIC, {s}, true);
            bytes.resize(5000, 0);
            write_file(test_file, bytes);

            MachOParser parser(test_file);
            ASSERT_TRUE(!parser.parse(test_file), "Slice size smaller than minimum header (< 28 bytes) is rejected");
            fs::remove(test_file);
        }

        // 7.11 Unsupported architecture entry with malformed bounds (rejected uniformly)
        {
            std::string test_file = (temp_dir / "test_malformed_unsupported_slice.bin").string();
            auto slice_x64 = make_valid_thin64_slice(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0x100000000, 32, false);

            TestFatSlice32 s_valid;
            s_valid.cputype = CPU_TYPE_X86_64;
            s_valid.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
            s_valid.offset = 4096;
            s_valid.size = static_cast<uint32_t>(slice_x64.size());
            s_valid.align = 12;
            s_valid.slice_data = slice_x64;

            TestFatSlice32 s_ppc_bad;
            s_ppc_bad.cputype = CPU_TYPE_POWERPC; // Unsupported architecture
            s_ppc_bad.cpusubtype = CPU_SUBTYPE_POWERPC_ALL;
            s_ppc_bad.offset = 999999; // Malformed bounds extending far past EOF
            s_ppc_bad.size = 5000;
            s_ppc_bad.align = 12;

            auto bytes = make_fat32_file(FAT_MAGIC, {s_valid, s_ppc_bad}, true);
            write_file(test_file, bytes);

            MachOParser parser(test_file);
            ASSERT_TRUE(!parser.parse(test_file), "Unsupported architecture entry with malformed bounds causes container rejection");
            fs::remove(test_file);
        }

        // 7.12 Slice boundaries prevent segment from reading into adjacent slice
        {
            std::string test_file = (temp_dir / "test_slice_boundary_enforcement.bin").string();
            // Create a slice where segment command claims filesize = 1000, but slice size is only 300
            uint32_t cmdsize = 72 + 80;
            auto slice_buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_EXECUTE, 1, cmdsize, 0, 0, false);
            TestSection64Desc sec;
            sec.sectname = "__text";
            sec.segname = "__TEXT";
            sec.addr = 0x100000000;
            sec.size = 32;
            sec.offset = 32 + cmdsize;
            sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;

            // filesize = 1000 (exceeds slice size 300)
            append_segment64_desc(slice_buf, LC_SEGMENT_64, "__TEXT", 0x100000000, 0x1000, 0, 1000,
                                  VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ | VM_PROT_EXECUTE, 0, {sec}, false);
            slice_buf.resize(300, 0);

            TestFatSlice32 s;
            s.cputype = CPU_TYPE_X86_64;
            s.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
            s.offset = 4096;
            s.size = 300; // slice size is 300
            s.align = 12;
            s.slice_data = slice_buf;

            auto bytes = make_fat32_file(FAT_MAGIC, {s}, true);
            bytes.resize(8192, 0);
            write_file(test_file, bytes);

            MachOParser parser(test_file);
            ASSERT_TRUE(!parser.parse(test_file), "Segment filesize exceeding slice size is rejected by bounded slice parser");
            fs::remove(test_file);
        }
    }
}

static void test_step55_factory_integration() {
    std::cout << "\n[*] Group 16: Step 5.5 Parser Factory Integration & Architecture Propagation...\n";
    ArchDetector detector;
    fs::path temp_dir = fs::temp_directory_path();

    // 16.1 FAT32 factory creation and successful parsing
    {
        std::string test_file = (temp_dir / "test_step55_fat32_factory.bin").string();
        auto slice_x64 = make_valid_thin64_slice(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0x100000000, 32, false);
        auto slice_arm64 = make_valid_thin64_slice(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, 0x200000000, 32, false);

        TestFatSlice32 s1, s2;
        s1.cputype = CPU_TYPE_X86_64;
        s1.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
        s1.offset = 4096;
        s1.size = static_cast<uint32_t>(slice_x64.size());
        s1.align = 12;
        s1.slice_data = slice_x64;

        s2.cputype = CPU_TYPE_ARM64;
        s2.cpusubtype = CPU_SUBTYPE_ARM64_ALL;
        s2.offset = 8192;
        s2.size = static_cast<uint32_t>(slice_arm64.size());
        s2.align = 12;
        s2.slice_data = slice_arm64;

        auto fat_bytes = make_fat32_file(FAT_MAGIC, {s1, s2}, true);
        write_file(test_file, fat_bytes);

        auto parser = detector.createFileParser(test_file);
        ASSERT_TRUE(parser != nullptr, "FAT32 binary creates non-null FileParser via factory");
        if (parser) {
            ASSERT_EQ(parser->getBinaryType(), "Mach-O", "FAT32 parser reports binary type 'Mach-O'");
            ASSERT_TRUE(parser->parse(test_file), "FAT32 parser parses successfully");
        }
        fs::remove(test_file);
    }

    // 16.2 FAT64 factory creation and successful parsing
    {
        std::string test_file = (temp_dir / "test_step55_fat64_factory.bin").string();
        auto slice_x64 = make_valid_thin64_slice(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0x100000000, 32, false);

        TestFatSlice64 s;
        s.cputype = CPU_TYPE_X86_64;
        s.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
        s.offset = 4096;
        s.size = slice_x64.size();
        s.align = 12;
        s.slice_data = slice_x64;

        auto fat_bytes = make_fat64_file(FAT_MAGIC_64, {s}, true);
        write_file(test_file, fat_bytes);

        auto parser = detector.createFileParser(test_file);
        ASSERT_TRUE(parser != nullptr, "FAT64 binary creates non-null FileParser via factory");
        if (parser) {
            ASSERT_EQ(parser->getBinaryType(), "Mach-O", "FAT64 parser reports binary type 'Mach-O'");
            ASSERT_TRUE(parser->parse(test_file), "FAT64 parser parses successfully");
            ASSERT_EQ(parser->getArchitecture(), "x86_64", "FAT64 parser reports x86_64 architecture");
        }
        fs::remove(test_file);
    }

    // 16.3 Default slice selection using established priority (x86_64 -> aarch64 -> x86 -> armv7)
    {
        // 16.3.1 Priority x86_64 over aarch64 (slice order in file: aarch64 first, x86_64 second)
        {
            std::string test_file = (temp_dir / "test_step55_prio_x64_arm64.bin").string();
            auto slice_arm64 = make_valid_thin64_slice(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, 0x200000000, 32, false);
            auto slice_x64 = make_valid_thin64_slice(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0x100000000, 32, false);

            TestFatSlice32 s_arm64, s_x64;
            s_arm64.cputype = CPU_TYPE_ARM64;
            s_arm64.cpusubtype = CPU_SUBTYPE_ARM64_ALL;
            s_arm64.offset = 4096;
            s_arm64.size = static_cast<uint32_t>(slice_arm64.size());
            s_arm64.align = 12;
            s_arm64.slice_data = slice_arm64;

            s_x64.cputype = CPU_TYPE_X86_64;
            s_x64.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
            s_x64.offset = 8192;
            s_x64.size = static_cast<uint32_t>(slice_x64.size());
            s_x64.align = 12;
            s_x64.slice_data = slice_x64;

            auto fat_bytes = make_fat32_file(FAT_MAGIC, {s_arm64, s_x64}, true);
            write_file(test_file, fat_bytes);

            auto parser = detector.createFileParser(test_file);
            ASSERT_TRUE(parser != nullptr, "Factory creates parser for arm64+x64 binary");
            if (parser) {
                ASSERT_TRUE(parser->parse(test_file), "Parser parses arm64+x64 binary");
                ASSERT_EQ(parser->getArchitecture(), "x86_64", "Default priority selects x86_64 over aarch64");
            }
            fs::remove(test_file);
        }

        // 16.3.2 Priority aarch64 over armv7
        {
            std::string test_file = (temp_dir / "test_step55_prio_arm64_armv7.bin").string();
            auto slice_arm64 = make_valid_thin64_slice(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, 0x200000000, 32, false);
            auto slice_armv7 = make_valid_thin32_slice(CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7, 0x2000, 32, false);

            TestFatSlice32 s_arm64, s_armv7;
            s_arm64.cputype = CPU_TYPE_ARM64;
            s_arm64.cpusubtype = CPU_SUBTYPE_ARM64_ALL;
            s_arm64.offset = 4096;
            s_arm64.size = static_cast<uint32_t>(slice_arm64.size());
            s_arm64.align = 12;
            s_arm64.slice_data = slice_arm64;

            s_armv7.cputype = CPU_TYPE_ARM;
            s_armv7.cpusubtype = CPU_SUBTYPE_ARM_V7;
            s_armv7.offset = 8192;
            s_armv7.size = static_cast<uint32_t>(slice_armv7.size());
            s_armv7.align = 12;
            s_armv7.slice_data = slice_armv7;

            auto fat_bytes = make_fat32_file(FAT_MAGIC, {s_arm64, s_armv7}, true);
            write_file(test_file, fat_bytes);

            auto parser = detector.createFileParser(test_file);
            ASSERT_TRUE(parser != nullptr, "Factory creates parser for arm64+armv7 binary");
            if (parser) {
                ASSERT_TRUE(parser->parse(test_file), "Parser parses arm64+armv7 binary");
                ASSERT_EQ(parser->getArchitecture(), "aarch64", "Default priority selects aarch64 over armv7");
            }
            fs::remove(test_file);
        }

        // 16.3.3 Priority x86 over armv7
        {
            std::string test_file = (temp_dir / "test_step55_prio_x86_armv7.bin").string();
            auto slice_x86 = make_valid_thin32_slice(CPU_TYPE_X86, CPU_SUBTYPE_I386_ALL, 0x1000, 32, false);
            auto slice_armv7 = make_valid_thin32_slice(CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7, 0x2000, 32, false);

            TestFatSlice32 s_x86, s_armv7;
            s_x86.cputype = CPU_TYPE_X86;
            s_x86.cpusubtype = CPU_SUBTYPE_I386_ALL;
            s_x86.offset = 4096;
            s_x86.size = static_cast<uint32_t>(slice_x86.size());
            s_x86.align = 12;
            s_x86.slice_data = slice_x86;

            s_armv7.cputype = CPU_TYPE_ARM;
            s_armv7.cpusubtype = CPU_SUBTYPE_ARM_V7;
            s_armv7.offset = 8192;
            s_armv7.size = static_cast<uint32_t>(slice_armv7.size());
            s_armv7.align = 12;
            s_armv7.slice_data = slice_armv7;

            auto fat_bytes = make_fat32_file(FAT_MAGIC, {s_x86, s_armv7}, true);
            write_file(test_file, fat_bytes);

            auto parser = detector.createFileParser(test_file);
            ASSERT_TRUE(parser != nullptr, "Factory creates parser for x86+armv7 binary");
            if (parser) {
                ASSERT_TRUE(parser->parse(test_file), "Parser parses x86+armv7 binary");
                ASSERT_EQ(parser->getArchitecture(), "x86", "Default priority selects x86 over armv7");
            }
            fs::remove(test_file);
        }
    }

    // 16.4 Explicit aarch64 selection
    {
        std::string test_file = (temp_dir / "test_step55_explicit_aarch64.bin").string();
        auto slice_x64 = make_valid_thin64_slice(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0x100000000, 32, false);
        auto slice_arm64 = make_valid_thin64_slice(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, 0x200000000, 32, false);

        TestFatSlice32 s_x64, s_arm64;
        s_x64.cputype = CPU_TYPE_X86_64;
        s_x64.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
        s_x64.offset = 4096;
        s_x64.size = static_cast<uint32_t>(slice_x64.size());
        s_x64.align = 12;
        s_x64.slice_data = slice_x64;

        s_arm64.cputype = CPU_TYPE_ARM64;
        s_arm64.cpusubtype = CPU_SUBTYPE_ARM64_ALL;
        s_arm64.offset = 8192;
        s_arm64.size = static_cast<uint32_t>(slice_arm64.size());
        s_arm64.align = 12;
        s_arm64.slice_data = slice_arm64;

        auto fat_bytes = make_fat32_file(FAT_MAGIC, {s_x64, s_arm64}, true);
        write_file(test_file, fat_bytes);

        auto parser = detector.createFileParser(test_file, "aarch64");
        ASSERT_TRUE(parser != nullptr, "Factory creates parser with targetArch='aarch64'");
        if (parser) {
            ASSERT_TRUE(parser->parse(test_file), "Parser successfully parses requested aarch64 slice");
            ASSERT_EQ(parser->getArchitecture(), "aarch64", "Parser architecture is 'aarch64'");
        }
        fs::remove(test_file);
    }

    // 16.5 Explicit alias arm64 and amd64 selection with canonical reporting
    {
        std::string test_file = (temp_dir / "test_step55_alias_selection.bin").string();
        auto slice_x64 = make_valid_thin64_slice(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0x100000000, 32, false);
        auto slice_arm64 = make_valid_thin64_slice(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, 0x200000000, 32, false);

        TestFatSlice32 s_x64, s_arm64;
        s_x64.cputype = CPU_TYPE_X86_64;
        s_x64.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
        s_x64.offset = 4096;
        s_x64.size = static_cast<uint32_t>(slice_x64.size());
        s_x64.align = 12;
        s_x64.slice_data = slice_x64;

        s_arm64.cputype = CPU_TYPE_ARM64;
        s_arm64.cpusubtype = CPU_SUBTYPE_ARM64_ALL;
        s_arm64.offset = 8192;
        s_arm64.size = static_cast<uint32_t>(slice_arm64.size());
        s_arm64.align = 12;
        s_arm64.slice_data = slice_arm64;

        auto fat_bytes = make_fat32_file(FAT_MAGIC, {s_x64, s_arm64}, true);
        write_file(test_file, fat_bytes);

        // 16.5.1 Alias "arm64" normalizes to canonical "aarch64"
        {
            auto parser = detector.createFileParser(test_file, "arm64");
            ASSERT_TRUE(parser != nullptr, "Factory creates parser with targetArch='arm64'");
            if (parser) {
                ASSERT_TRUE(parser->parse(test_file), "Parser parses slice requested via 'arm64' alias");
                ASSERT_EQ(parser->getArchitecture(), "aarch64", "Parser architecture reports canonical 'aarch64'");
            }
        }

        // 16.5.2 Alias "amd64" normalizes to canonical "x86_64"
        {
            auto parser = detector.createFileParser(test_file, "amd64");
            ASSERT_TRUE(parser != nullptr, "Factory creates parser with targetArch='amd64'");
            if (parser) {
                ASSERT_TRUE(parser->parse(test_file), "Parser parses slice requested via 'amd64' alias");
                ASSERT_EQ(parser->getArchitecture(), "x86_64", "Parser architecture reports canonical 'x86_64'");
            }
        }
        fs::remove(test_file);
    }

    // 16.6 Explicit architecture not present in FAT binary must fail without silent fallback
    {
        std::string test_file = (temp_dir / "test_step55_missing_arch.bin").string();
        auto slice_x64 = make_valid_thin64_slice(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0x100000000, 32, false);
        auto slice_arm64 = make_valid_thin64_slice(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, 0x200000000, 32, false);

        TestFatSlice32 s_x64, s_arm64;
        s_x64.cputype = CPU_TYPE_X86_64;
        s_x64.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
        s_x64.offset = 4096;
        s_x64.size = static_cast<uint32_t>(slice_x64.size());
        s_x64.align = 12;
        s_x64.slice_data = slice_x64;

        s_arm64.cputype = CPU_TYPE_ARM64;
        s_arm64.cpusubtype = CPU_SUBTYPE_ARM64_ALL;
        s_arm64.offset = 8192;
        s_arm64.size = static_cast<uint32_t>(slice_arm64.size());
        s_arm64.align = 12;
        s_arm64.slice_data = slice_arm64;

        auto fat_bytes = make_fat32_file(FAT_MAGIC, {s_x64, s_arm64}, true);
        write_file(test_file, fat_bytes);

        auto parser = detector.createFileParser(test_file, "armv7");
        ASSERT_TRUE(parser != nullptr, "Factory creates parser when missing arch requested");
        if (parser) {
            ASSERT_TRUE(!parser->parse(test_file), "Parser fails when requested architecture is not in container");
            ASSERT_EQ(parser->getArchitecture(), "unknown", "Architecture remains 'unknown' after failed parse");
        }
        fs::remove(test_file);
    }

    // 16.7 Existing thin Mach-O factory behavior with matching, alias, and conflicting architectures
    {
        std::string test_file = (temp_dir / "test_step55_thin_factory.bin").string();
        auto bytes = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, 72, 0, 0, false);
        write_file(test_file, bytes);

        // Matching architecture
        {
            auto parser = detector.createFileParser(test_file, "x86_64");
            ASSERT_TRUE(parser != nullptr, "Factory creates parser for thin x86_64 with targetArch='x86_64'");
            if (parser) {
                ASSERT_TRUE(parser->parse(test_file), "Thin x86_64 parses when matching arch requested");
                ASSERT_EQ(parser->getArchitecture(), "x86_64", "Thin x86_64 reports x86_64");
            }
        }

        // Matching alias "amd64"
        {
            auto parser = detector.createFileParser(test_file, "amd64");
            ASSERT_TRUE(parser != nullptr, "Factory creates parser for thin x86_64 with targetArch='amd64'");
            if (parser) {
                ASSERT_TRUE(parser->parse(test_file), "Thin x86_64 parses when matching alias 'amd64' requested");
                ASSERT_EQ(parser->getArchitecture(), "x86_64", "Thin x86_64 reports canonical 'x86_64'");
            }
        }

        // Conflicting architecture "aarch64"
        {
            auto parser = detector.createFileParser(test_file, "aarch64");
            ASSERT_TRUE(parser != nullptr, "Factory creates parser for thin x86_64 with targetArch='aarch64'");
            if (parser) {
                ASSERT_TRUE(!parser->parse(test_file), "Thin x86_64 parse fails when conflicting arch requested");
            }
        }
        fs::remove(test_file);
    }

    // 16.8 Existing one-argument factory calls still compile and behave correctly
    {
        std::string test_file = (temp_dir / "test_step55_onearg.bin").string();
        auto bytes = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, 72, 0, 0, false);
        write_file(test_file, bytes);

        auto parser = detector.createFileParser(test_file);
        ASSERT_TRUE(parser != nullptr, "1-arg createFileParser compiles and returns non-null");
        if (parser) {
            ASSERT_TRUE(parser->parse(test_file), "1-arg parser parses thin binary");
            ASSERT_EQ(parser->getArchitecture(), "x86_64", "1-arg parser reports x86_64");
        }
        fs::remove(test_file);
    }

    // 16.9 ELF and PE factory behavior remains unchanged with targetArch parameter
    {
        // 16.9.1 ELF 64-bit x86_64 factory creation with and without targetArch
        {
            std::string test_file = (temp_dir / "test_step55_elf.bin").string();
            std::vector<uint8_t> elf_bytes(64, 0);
            elf_bytes[0] = 0x7F;
            elf_bytes[1] = 'E';
            elf_bytes[2] = 'L';
            elf_bytes[3] = 'F';
            elf_bytes[4] = 0x02; // ELFCLASS64
            elf_bytes[5] = 0x01; // ELFDATA2LSB
            elf_bytes[6] = 0x01; // EV_CURRENT
            elf_bytes[18] = 0x3E; // e_machine = EM_X86_64 (62)
            elf_bytes[19] = 0x00;
            write_file(test_file, elf_bytes);

            // 1-arg call
            auto parser1 = detector.createFileParser(test_file);
            ASSERT_TRUE(parser1 != nullptr, "Factory creates non-null parser for 64-bit ELF (1-arg)");
            if (parser1) {
                ASSERT_EQ(parser1->getBinaryType(), "ELF", "Binary type is ELF (1-arg)");
            }

            // 2-arg call with targetArch (safely ignored)
            auto parser2 = detector.createFileParser(test_file, "x86_64");
            ASSERT_TRUE(parser2 != nullptr, "Factory creates non-null parser for 64-bit ELF (2-arg)");
            if (parser2) {
                ASSERT_EQ(parser2->getBinaryType(), "ELF", "Binary type is ELF (2-arg)");
            }
            fs::remove(test_file);
        }

        // 16.9.2 PE 64-bit x86_64 factory creation with and without targetArch
        {
            std::string test_file = (temp_dir / "test_step55_pe.bin").string();
            std::vector<uint8_t> pe_bytes(512, 0);
            pe_bytes[0] = 'M';
            pe_bytes[1] = 'Z';
            // e_lfanew at 0x3C
            pe_bytes[0x3C] = 0x80;
            pe_bytes[0x3D] = 0x00;
            pe_bytes[0x3E] = 0x00;
            pe_bytes[0x3F] = 0x00;
            // PE signature at 0x80
            pe_bytes[0x80] = 'P';
            pe_bytes[0x81] = 'E';
            pe_bytes[0x82] = 0x00;
            pe_bytes[0x83] = 0x00;
            // Machine field at 0x84: IMAGE_FILE_MACHINE_AMD64 = 0x8664
            pe_bytes[0x84] = 0x64;
            pe_bytes[0x85] = 0x86;
            write_file(test_file, pe_bytes);

            // 1-arg call
            auto parser1 = detector.createFileParser(test_file);
            ASSERT_TRUE(parser1 != nullptr, "Factory creates non-null parser for PE (1-arg)");
            if (parser1) {
                ASSERT_EQ(parser1->getBinaryType(), "PE", "Binary type is PE (1-arg)");
            }

            // 2-arg call with targetArch (safely ignored)
            auto parser2 = detector.createFileParser(test_file, "x86_64");
            ASSERT_TRUE(parser2 != nullptr, "Factory creates non-null parser for PE (2-arg)");
            if (parser2) {
                ASSERT_EQ(parser2->getBinaryType(), "PE", "Binary type is PE (2-arg)");
            }
            fs::remove(test_file);
        }
    }

    // 16.10 Selected slice section and executable mapping exposure
    {
        std::string test_file = (temp_dir / "test_step55_section_exposure.bin").string();
        std::vector<uint8_t> expected_code = {0x55, 0x48, 0x89, 0xE5, 0x90, 0xC3};
        auto slice_x64 = make_valid_thin64_slice(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0x100000000, expected_code.size(), false, expected_code);
        auto slice_arm64 = make_valid_thin64_slice(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, 0x200000000, 32, false);

        TestFatSlice32 s_x64, s_arm64;
        s_x64.cputype = CPU_TYPE_X86_64;
        s_x64.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
        s_x64.offset = 4096;
        s_x64.size = static_cast<uint32_t>(slice_x64.size());
        s_x64.align = 12;
        s_x64.slice_data = slice_x64;

        s_arm64.cputype = CPU_TYPE_ARM64;
        s_arm64.cpusubtype = CPU_SUBTYPE_ARM64_ALL;
        s_arm64.offset = 8192;
        s_arm64.size = static_cast<uint32_t>(slice_arm64.size());
        s_arm64.align = 12;
        s_arm64.slice_data = slice_arm64;

        auto fat_bytes = make_fat32_file(FAT_MAGIC, {s_x64, s_arm64}, true);
        write_file(test_file, fat_bytes);

        auto parser = detector.createFileParser(test_file, "x86_64");
        ASSERT_TRUE(parser != nullptr, "Factory creates parser for section exposure test");
        if (parser) {
            ASSERT_TRUE(parser->parse(test_file), "Parser parses selected slice");
            ASSERT_EQ(parser->getArchitecture(), "x86_64", "Architecture is x86_64");
            ASSERT_EQ(parser->getTextSectionBaseAddress(), 0x100000000ULL, "Base text address is 0x100000000");
            ASSERT_EQ(parser->getImageBase(), 0x100000000ULL, "Image base is 0x100000000");
            ASSERT_EQ(parser->getTextSection().size(), expected_code.size(), "Text section size matches code");
            ASSERT_TRUE(parser->getTextSection() == expected_code, "Text section bytes match injected code");
            ASSERT_EQ(parser->getSections().size(), 1, "Exactly 1 section registered");
            if (!parser->getSections().empty()) {
                ASSERT_EQ(parser->getSections()[0].name, "__TEXT,__text", "Section name is __TEXT,__text");
                ASSERT_TRUE(parser->getSections()[0].is_executable, "Section is marked executable");
            }
            ASSERT_EQ(parser->getExecBufferMappings().size(), 1, "Exactly 1 exec mapping registered");
            if (!parser->getExecBufferMappings().empty()) {
                ASSERT_EQ(parser->getExecBufferMappings()[0].section_name, "__TEXT,__text", "Exec mapping section name is __TEXT,__text");
                ASSERT_EQ(parser->getExecBufferMappings()[0].virtual_address, 0x100000000ULL, "Exec mapping VA matches text address");
            }
            ASSERT_TRUE(parser->getInstructionEndianness() == Endianness::Little, "Instruction endianness is Little");
        }
        fs::remove(test_file);
    }
}

static void test_step56_mitigations() {
    std::cout << "\n[*] Group 17: Step 5.6 Mach-O Mitigations & Platform Reporting Tests...\n";
    fs::path temp_dir = fs::temp_directory_path();

    // 17.1 NX Detection (Stack NX, Heap NX, PIE, RELRO)
    {
        std::string test_file = (temp_dir / "test_step56_nx_default.bin").string();
        uint32_t cmdsize = 72 + 80;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, cmdsize, 0, 0, false);
        TestSection64Desc sec;
        sec.sectname = "__text";
        sec.segname = "__TEXT";
        sec.addr = 0x100001000ULL;
        sec.size = 16;
        sec.offset = 32 + cmdsize;
        sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x2000, 0, 32 + cmdsize + 16, 5, 5, 0, {sec}, false);
        buf.resize(buf.size() + 16, 0x90);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "Parse default flags Mach-O");
        ASSERT_TRUE(parser.isNxEnabled(), "Default flags: Stack NX enabled");
        const auto& mit = parser.getMachOMitigations();
        ASSERT_TRUE(mit.stack_nx, "mit.stack_nx == true");
        ASSERT_TRUE(mit.heap_nx == HeapNxStatus::Unknown, "Absent MH_NO_HEAP_EXECUTION => HeapNxStatus::Unknown");
        ASSERT_TRUE(!mit.pie, "mit.pie == false");
        ASSERT_TRUE(parser.getRelro() == "NOT_APPLICABLE", "Mach-O RELRO is NOT_APPLICABLE");
        fs::remove(test_file);
    }

    // 17.2 MH_ALLOW_STACK_EXECUTION disables Stack NX
    {
        std::string test_file = (temp_dir / "test_step56_stack_exec.bin").string();
        uint32_t cmdsize = 72 + 80;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, cmdsize, MH_ALLOW_STACK_EXECUTION, 0, false);
        TestSection64Desc sec;
        sec.sectname = "__text";
        sec.segname = "__TEXT";
        sec.addr = 0x100001000ULL;
        sec.size = 16;
        sec.offset = 32 + cmdsize;
        sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x2000, 0, 32 + cmdsize + 16, 7, 7, 0, {sec}, false);
        buf.resize(buf.size() + 16, 0x90);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "Parse MH_ALLOW_STACK_EXECUTION Mach-O");
        ASSERT_TRUE(!parser.isNxEnabled(), "MH_ALLOW_STACK_EXECUTION: isNxEnabled() is false");
        ASSERT_TRUE(!parser.getMachOMitigations().stack_nx, "mit.stack_nx is false");
        fs::remove(test_file);
    }

    // 17.3 MH_NO_HEAP_EXECUTION and MH_PIE
    {
        std::string test_file = (temp_dir / "test_step56_heap_pie.bin").string();
        uint32_t cmdsize = 72 + 80;
        uint32_t flags = MH_NO_HEAP_EXECUTION | MH_PIE;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, cmdsize, flags, 0, false);
        TestSection64Desc sec;
        sec.sectname = "__text";
        sec.segname = "__TEXT";
        sec.addr = 0x100001000ULL;
        sec.size = 16;
        sec.offset = 32 + cmdsize;
        sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x2000, 0, 32 + cmdsize + 16, 5, 5, 0, {sec}, false);
        buf.resize(buf.size() + 16, 0x90);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "Parse MH_NO_HEAP_EXECUTION | MH_PIE");
        const auto& mit = parser.getMachOMitigations();
        ASSERT_TRUE(mit.heap_nx == HeapNxStatus::ExplicitEnabled, "HeapNxStatus::ExplicitEnabled");
        ASSERT_TRUE(mit.pie, "mit.pie == true");
        ASSERT_TRUE(parser.isPieEnabled(), "parser.isPieEnabled() == true");
        fs::remove(test_file);
    }

    // 17.4 Segment W^X Compliance & Precedence
    {
        // Case A: Clean segments -> Compliant
        std::string test_file = (temp_dir / "test_step56_wx_clean.bin").string();
        uint32_t seg1_size = 72 + 80;
        uint32_t seg2_size = 72 + 80;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 2, seg1_size + seg2_size, 0, 0, false);

        TestSection64Desc sec1;
        sec1.sectname = "__text";
        sec1.segname = "__TEXT";
        sec1.addr = 0x100001000ULL;
        sec1.size = 16;
        sec1.offset = 32 + seg1_size + seg2_size;
        sec1.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x2000, 0, 32 + seg1_size + seg2_size + 16, 5, 5, 0, {sec1}, false);

        TestSection64Desc sec2;
        sec2.sectname = "__data";
        sec2.segname = "__DATA";
        sec2.addr = 0x100002000ULL;
        sec2.size = 16;
        sec2.offset = 32 + seg1_size + seg2_size + 16;
        sec2.flags = S_REGULAR;
        append_segment64_desc(buf, LC_SEGMENT_64, "__DATA", 0x100002000ULL, 0x1000, 32 + seg1_size + seg2_size + 16, 16, 3, 3, 0, {sec2}, false);

        buf.resize(buf.size() + 32, 0x90);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "Parse clean 2-segment binary");
        const auto& mit = parser.getMachOMitigations();
        ASSERT_EQ(mit.total_declared_segments, 2, "total_declared_segments == 2");
        ASSERT_EQ(mit.inspected_segments, 2, "inspected_segments == 2");
        ASSERT_TRUE(mit.segment_stream_complete, "segment_stream_complete == true");
        ASSERT_TRUE(mit.segment_wx_status == SegmentWxStatus::Compliant, "Segment W^X is Compliant");
        fs::remove(test_file);
    }
    {
        // Case B: Segment with initprot W+X -> InitViolation
        std::string test_file = (temp_dir / "test_step56_wx_init_violation.bin").string();
        uint32_t cmdsize = 72 + 80;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, cmdsize, 0, 0, false);
        TestSection64Desc sec;
        sec.sectname = "__text";
        sec.segname = "__TEXT";
        sec.addr = 0x100001000ULL;
        sec.size = 16;
        sec.offset = 32 + cmdsize;
        sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x2000, 0, 32 + cmdsize + 16, 7, 7, 0, {sec}, false);
        buf.resize(buf.size() + 16, 0x90);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "Parse initprot W+X binary");
        const auto& mit = parser.getMachOMitigations();
        ASSERT_TRUE(mit.has_wx_initprot, "has_wx_initprot == true");
        ASSERT_TRUE(mit.segment_wx_status == SegmentWxStatus::InitViolation, "segment_wx_status == InitViolation");
        fs::remove(test_file);
    }
    {
        // Case C: Segment with maxprot W+X (initprot r-x) -> MaxprotPermissive
        std::string test_file = (temp_dir / "test_step56_wx_maxprot.bin").string();
        uint32_t cmdsize = 72 + 80;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, cmdsize, 0, 0, false);
        TestSection64Desc sec;
        sec.sectname = "__text";
        sec.segname = "__TEXT";
        sec.addr = 0x100001000ULL;
        sec.size = 16;
        sec.offset = 32 + cmdsize;
        sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x2000, 0, 32 + cmdsize + 16, 7, 5, 0, {sec}, false);
        buf.resize(buf.size() + 16, 0x90);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "Parse maxprot W+X binary");
        const auto& mit = parser.getMachOMitigations();
        ASSERT_TRUE(!mit.has_wx_initprot, "has_wx_initprot == false");
        ASSERT_TRUE(mit.has_wx_maxprot, "has_wx_maxprot == true");
        ASSERT_TRUE(mit.segment_wx_status == SegmentWxStatus::MaxprotPermissive, "segment_wx_status == MaxprotPermissive");
        fs::remove(test_file);
    }

    // 17.5 Stack Canary Detection (64-bit, 32-bit, Clean, Precedence, Malformed)
    {
        // Case A: 64-bit with ___stack_chk_fail -> SYMBOL_DETECTED
        std::string test_file = (temp_dir / "test_step56_canary_found.bin").string();
        uint32_t seg_cmdsize = 72 + 80;
        uint32_t sym_cmdsize = 24;
        uint32_t sizeofcmds = seg_cmdsize + sym_cmdsize;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 2, sizeofcmds, 0, 0, false);

        uint32_t text_off = 32 + sizeofcmds;
        uint32_t text_sz = 16;
        TestSection64Desc sec;
        sec.sectname = "__text";
        sec.segname = "__TEXT";
        sec.addr = 0x100001000ULL;
        sec.size = text_sz;
        sec.offset = text_off;
        sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;

        uint32_t sym_off = text_off + text_sz;
        uint32_t nsyms = 2;
        uint32_t sym_sz = nsyms * 16;
        uint32_t str_off = sym_off + sym_sz;

        // String table: [0]='\0', [1]='m','a','i','n','\0', [6]='_','_','_','s','t','a','c','k','_','c','h','k','_','f','a','i','l','\0'
        std::vector<uint8_t> strtab = {'\0', 'm', 'a', 'i', 'n', '\0'};
        uint32_t canary_strx = static_cast<uint32_t>(strtab.size());
        std::string canary_str = "___stack_chk_fail";
        strtab.insert(strtab.end(), canary_str.begin(), canary_str.end());
        strtab.push_back('\0');
        uint32_t str_sz = static_cast<uint32_t>(strtab.size());

        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x2000, 0, str_off + str_sz, 5, 5, 0, {sec}, false);
        append_symtab_desc(buf, sym_off, nsyms, str_off, str_sz, false);

        // Append text code
        buf.resize(text_off + text_sz, 0x90);

        // Append symbol table
        append_nlist64(buf, 1, N_SECT | N_EXT, 1, 0, 0x100001000ULL, false); // main
        append_nlist64(buf, canary_strx, N_UNDF | N_EXT, 0, 0, 0, false);    // ___stack_chk_fail

        // Append string table
        buf.insert(buf.end(), strtab.begin(), strtab.end());
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "Parse 64-bit Mach-O with ___stack_chk_fail");
        const auto& mit = parser.getMachOMitigations();
        ASSERT_TRUE(mit.canary_status == CanaryStatus::SymbolDetected, "CanaryStatus::SymbolDetected");
        ASSERT_EQ(mit.canary_symbol_name, "___stack_chk_fail", "Canary symbol name matches");
        ASSERT_TRUE(parser.isCanaryEnabled(), "parser.isCanaryEnabled() == true");
        fs::remove(test_file);
    }
    {
        // Case B: 32-bit with ___stack_chk_guard -> SYMBOL_DETECTED
        std::string test_file = (temp_dir / "test_step56_canary_32.bin").string();
        uint32_t seg_cmdsize = 56 + 68;
        uint32_t sym_cmdsize = 24;
        uint32_t sizeofcmds = seg_cmdsize + sym_cmdsize;
        auto buf = make_macho32_buf(MH_MAGIC, CPU_TYPE_X86, 3, MH_EXECUTE, 2, sizeofcmds, 0, false);

        uint32_t text_off = 28 + sizeofcmds;
        uint32_t text_sz = 16;
        TestSection32Desc sec;
        sec.sectname = "__text";
        sec.segname = "__TEXT";
        sec.addr = 0x1000;
        sec.size = text_sz;
        sec.offset = text_off;
        sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;

        uint32_t sym_off = text_off + text_sz;
        uint32_t nsyms = 1;
        uint32_t sym_sz = nsyms * 12; // 32-bit nlist
        uint32_t str_off = sym_off + sym_sz;

        std::vector<uint8_t> strtab = {'\0'};
        uint32_t canary_strx = static_cast<uint32_t>(strtab.size());
        std::string canary_str = "___stack_chk_guard";
        strtab.insert(strtab.end(), canary_str.begin(), canary_str.end());
        strtab.push_back('\0');
        uint32_t str_sz = static_cast<uint32_t>(strtab.size());

        append_segment32_desc(buf, LC_SEGMENT, "__TEXT", 0x1000, 0x2000, 0, str_off + str_sz, 5, 5, 0, {sec}, false);
        append_symtab_desc(buf, sym_off, nsyms, str_off, str_sz, false);

        buf.resize(text_off + text_sz, 0x90);
        append_nlist32(buf, canary_strx, N_UNDF | N_EXT, 0, 0, 0, false);
        buf.insert(buf.end(), strtab.begin(), strtab.end());
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "Parse 32-bit Mach-O with ___stack_chk_guard");
        ASSERT_TRUE(parser.getMachOMitigations().canary_status == CanaryStatus::SymbolDetected, "32-bit Canary detected");
        fs::remove(test_file);
    }
    {
        // Case C: Clean symbol table without canary -> NOT_DETECTED
        std::string test_file = (temp_dir / "test_step56_canary_not_detected.bin").string();
        uint32_t seg_cmdsize = 72 + 80;
        uint32_t sym_cmdsize = 24;
        uint32_t sizeofcmds = seg_cmdsize + sym_cmdsize;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 2, sizeofcmds, 0, 0, false);

        uint32_t text_off = 32 + sizeofcmds;
        uint32_t text_sz = 16;
        TestSection64Desc sec;
        sec.sectname = "__text";
        sec.segname = "__TEXT";
        sec.addr = 0x100001000ULL;
        sec.size = text_sz;
        sec.offset = text_off;
        sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;

        uint32_t sym_off = text_off + text_sz;
        uint32_t nsyms = 2;
        uint32_t sym_sz = nsyms * 16;
        uint32_t str_off = sym_off + sym_sz;

        std::vector<uint8_t> strtab = {'\0', 'm', 'a', 'i', 'n', '\0', 'f', 'o', 'o', '\0'};
        uint32_t str_sz = static_cast<uint32_t>(strtab.size());

        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x2000, 0, str_off + str_sz, 5, 5, 0, {sec}, false);
        append_symtab_desc(buf, sym_off, nsyms, str_off, str_sz, false);

        buf.resize(text_off + text_sz, 0x90);
        append_nlist64(buf, 0, N_SECT, 1, 0, 0x100001000ULL, false); // empty string (n_strx == 0)
        append_nlist64(buf, 1, N_SECT | N_EXT, 1, 0, 0x100001000ULL, false); // "main"
        buf.insert(buf.end(), strtab.begin(), strtab.end());
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "Parse clean symbol table without canary");
        ASSERT_TRUE(parser.getMachOMitigations().canary_status == CanaryStatus::NotDetected, "CanaryStatus::NotDetected");
        ASSERT_TRUE(!parser.isCanaryEnabled(), "isCanaryEnabled() == false");
        fs::remove(test_file);
    }
    {
        // Case D: Positive evidence precedence (valid canary followed by corrupt entry)
        std::string test_file = (temp_dir / "test_step56_canary_precedence.bin").string();
        uint32_t seg_cmdsize = 72 + 80;
        uint32_t sym_cmdsize = 24;
        uint32_t sizeofcmds = seg_cmdsize + sym_cmdsize;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 2, sizeofcmds, 0, 0, false);

        uint32_t text_off = 32 + sizeofcmds;
        uint32_t text_sz = 16;
        TestSection64Desc sec;
        sec.sectname = "__text";
        sec.segname = "__TEXT";
        sec.addr = 0x100001000ULL;
        sec.size = text_sz;
        sec.offset = text_off;
        sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;

        uint32_t sym_off = text_off + text_sz;
        uint32_t nsyms = 2;
        uint32_t sym_sz = nsyms * 16;
        uint32_t str_off = sym_off + sym_sz;

        std::vector<uint8_t> strtab = {'\0', '_', '_', '_', 's', 't', 'a', 'c', 'k', '_', 'c', 'h', 'k', '_', 'f', 'a', 'i', 'l', '\0'};
        uint32_t str_sz = static_cast<uint32_t>(strtab.size());

        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x2000, 0, str_off + str_sz, 5, 5, 0, {sec}, false);
        append_symtab_desc(buf, sym_off, nsyms, str_off, str_sz, false);

        buf.resize(text_off + text_sz, 0x90);
        append_nlist64(buf, 1, N_UNDF | N_EXT, 0, 0, 0, false); // canary
        append_nlist64(buf, 99999, N_UNDF | N_EXT, 0, 0, 0, false); // corrupt n_strx
        buf.insert(buf.end(), strtab.begin(), strtab.end());
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "Parse canary followed by corrupt entry");
        ASSERT_TRUE(parser.getMachOMitigations().canary_status == CanaryStatus::SymbolDetected, "Precedence 1: Positive canary evidence wins");
        fs::remove(test_file);
    }
    {
        // Case E: Corrupt entry without canary -> UNKNOWN
        std::string test_file = (temp_dir / "test_step56_canary_corrupt_unknown.bin").string();
        uint32_t seg_cmdsize = 72 + 80;
        uint32_t sym_cmdsize = 24;
        uint32_t sizeofcmds = seg_cmdsize + sym_cmdsize;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 2, sizeofcmds, 0, 0, false);

        uint32_t text_off = 32 + sizeofcmds;
        uint32_t text_sz = 16;
        TestSection64Desc sec;
        sec.sectname = "__text";
        sec.segname = "__TEXT";
        sec.addr = 0x100001000ULL;
        sec.size = text_sz;
        sec.offset = text_off;
        sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;

        uint32_t sym_off = text_off + text_sz;
        uint32_t nsyms = 1;
        uint32_t sym_sz = nsyms * 16;
        uint32_t str_off = sym_off + sym_sz;

        std::vector<uint8_t> strtab = {'\0', 'm', 'a', 'i', 'n', '\0'};
        uint32_t str_sz = static_cast<uint32_t>(strtab.size());

        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x2000, 0, str_off + str_sz, 5, 5, 0, {sec}, false);
        append_symtab_desc(buf, sym_off, nsyms, str_off, str_sz, false);

        buf.resize(text_off + text_sz, 0x90);
        append_nlist64(buf, 99999, N_UNDF | N_EXT, 0, 0, 0, false); // corrupt n_strx
        buf.insert(buf.end(), strtab.begin(), strtab.end());
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "Parse corrupt entry without canary");
        ASSERT_TRUE(parser.getMachOMitigations().canary_status == CanaryStatus::Unknown, "Precedence 2: Corruption without canary yields Unknown");
        fs::remove(test_file);
    }

    // 17.6 Code Signature Structural Validation
    {
        // Case A: Valid LC_CODE_SIGNATURE with 12-byte SuperBlob header
        std::string test_file = (temp_dir / "test_step56_cs_valid.bin").string();
        uint32_t seg_cmdsize = 72 + 80;
        uint32_t cs_cmdsize = 16;
        uint32_t sizeofcmds = seg_cmdsize + cs_cmdsize;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 2, sizeofcmds, 0, 0, false);

        uint32_t text_off = 32 + sizeofcmds;
        uint32_t text_sz = 16;
        TestSection64Desc sec;
        sec.sectname = "__text";
        sec.segname = "__TEXT";
        sec.addr = 0x100001000ULL;
        sec.size = text_sz;
        sec.offset = text_off;
        sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;

        uint32_t cs_off = text_off + text_sz;
        uint32_t cs_sz = 20; // 12-byte header + 8-byte index entry

        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x2000, 0, cs_off + cs_sz, 5, 5, 0, {sec}, false);
        append_code_signature_desc(buf, cs_off, cs_sz, false);

        buf.resize(text_off + text_sz, 0x90);

        // SuperBlob: magic=0xfade0cc0 (BE), length=20 (BE), count=1 (BE)
        size_t sb_base = buf.size();
        buf.resize(sb_base + cs_sz, 0);
        write_u32_to(buf, sb_base + 0, CSMAGIC_EMBEDDED_SIGNATURE, true);
        write_u32_to(buf, sb_base + 4, 20, true);
        write_u32_to(buf, sb_base + 8, 1, true); // count=1: 12 + 1*8 = 20 <= 20
        write_u32_to(buf, sb_base + 12, 0, true); // slot 0
        write_u32_to(buf, sb_base + 16, 20, true); // offset

        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "Parse valid LC_CODE_SIGNATURE");
        const auto& mit = parser.getMachOMitigations();
        ASSERT_TRUE(mit.has_code_signature_cmd, "has_code_signature_cmd == true");
        ASSERT_TRUE(mit.data_range_valid, "data_range_valid == true");
        ASSERT_TRUE(mit.superblob_header_valid, "superblob_header_valid == true");
        ASSERT_TRUE(!mit.cryptographically_verified, "cryptographically_verified == false (offline static analysis)");
        fs::remove(test_file);
    }
    {
        // Case B: SuperBlob index count overflow (count=5 when length=20)
        std::string test_file = (temp_dir / "test_step56_cs_count_overflow.bin").string();
        uint32_t seg_cmdsize = 72 + 80;
        uint32_t cs_cmdsize = 16;
        uint32_t sizeofcmds = seg_cmdsize + cs_cmdsize;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 2, sizeofcmds, 0, 0, false);

        uint32_t text_off = 32 + sizeofcmds;
        uint32_t text_sz = 16;
        TestSection64Desc sec;
        sec.sectname = "__text";
        sec.segname = "__TEXT";
        sec.addr = 0x100001000ULL;
        sec.size = text_sz;
        sec.offset = text_off;
        sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;

        uint32_t cs_off = text_off + text_sz;
        uint32_t cs_sz = 20;

        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x2000, 0, cs_off + cs_sz, 5, 5, 0, {sec}, false);
        append_code_signature_desc(buf, cs_off, cs_sz, false);

        buf.resize(text_off + text_sz, 0x90);
        size_t sb_base = buf.size();
        buf.resize(sb_base + cs_sz, 0);
        write_u32_to(buf, sb_base + 0, CSMAGIC_EMBEDDED_SIGNATURE, true);
        write_u32_to(buf, sb_base + 4, 20, true);
        write_u32_to(buf, sb_base + 8, 5, true); // count=5: 12 + 5*8 = 52 > 20

        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "Parse SuperBlob with index count overflow");
        const auto& mit = parser.getMachOMitigations();
        ASSERT_TRUE(mit.has_code_signature_cmd, "has_code_signature_cmd == true");
        ASSERT_TRUE(mit.data_range_valid, "data_range_valid == true");
        ASSERT_TRUE(!mit.superblob_header_valid, "superblob_header_valid == false (count exceeds length)");
        fs::remove(test_file);
    }
    {
        // Case C: Duplicate LC_CODE_SIGNATURE command
        std::string test_file = (temp_dir / "test_step56_cs_duplicate.bin").string();
        uint32_t seg_cmdsize = 72 + 80;
        uint32_t cs_cmdsize = 16;
        uint32_t sizeofcmds = seg_cmdsize + cs_cmdsize + cs_cmdsize;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 3, sizeofcmds, 0, 0, false);

        uint32_t text_off = 32 + sizeofcmds;
        uint32_t text_sz = 16;
        TestSection64Desc sec;
        sec.sectname = "__text";
        sec.segname = "__TEXT";
        sec.addr = 0x100001000ULL;
        sec.size = text_sz;
        sec.offset = text_off;
        sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;

        uint32_t cs_off = text_off + text_sz;
        uint32_t cs_sz = 16;

        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x2000, 0, cs_off + cs_sz, 5, 5, 0, {sec}, false);
        append_code_signature_desc(buf, cs_off, cs_sz, false);
        append_code_signature_desc(buf, cs_off, cs_sz, false); // duplicate!

        buf.resize(text_off + text_sz + cs_sz, 0);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "Parse duplicate LC_CODE_SIGNATURE");
        const auto& mit = parser.getMachOMitigations();
        ASSERT_TRUE(mit.has_code_signature_cmd, "has_code_signature_cmd == true");
        ASSERT_TRUE(!mit.data_range_valid, "data_range_valid == false due to duplicate ambiguity");
        ASSERT_TRUE(!mit.superblob_header_valid, "superblob_header_valid == false");
        fs::remove(test_file);
    }

    // 17.7 PayloadGenerator JSON Telemetry & Platform Isolation (In-Memory / Safe Temp Path)
    {
        std::string test_bin = (temp_dir / "test_step56_payloadgen.bin").string();
        uint32_t seg_cmdsize = 72 + 80;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, seg_cmdsize, MH_PIE, 0, false);
        TestSection64Desc sec;
        sec.sectname = "__text";
        sec.segname = "__TEXT";
        sec.addr = 0x100001000ULL;
        sec.size = 16;
        sec.offset = 32 + seg_cmdsize;
        sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x2000, 0, 32 + seg_cmdsize + 16, 5, 5, 0, {sec}, false);
        buf.resize(buf.size() + 16, 0x90);
        write_file(test_bin, buf);

        MachOParser parser(test_bin);
        ASSERT_TRUE(parser.parse(test_bin), "Parse binary for payload_gen test");

        // Safe temporary output paths to protect reports/output.json
        fs::path temp_test_dir = temp_dir / "temp_step56_report_dir";
        fs::create_directories(temp_test_dir);
        std::string temp_report_json = (temp_test_dir / "test_macho_report.json").string();
        std::string temp_payload_bin = (temp_test_dir / "test_macho_payload.bin").string();
        std::string temp_payload_rep = (temp_test_dir / "test_macho_payload_rep.bin").string();

        ROPChain emptyChain;
        PayloadGenerator payloadGen;
        payloadGen.generate(emptyChain, 104, test_bin, {}, "x86_64", "Mach-O", {},
                            "TEST_REPORT_ID", "TEST_FILE_HASH", &parser,
                            temp_report_json, temp_payload_bin, temp_payload_rep);

        // Parse and assert on generated JSON
        ASSERT_TRUE(fs::exists(temp_report_json), "Temporary report JSON generated");
        std::ifstream jf(temp_report_json);
        nlohmann::json reportJson;
        jf >> reportJson;
        jf.close();

        ASSERT_EQ(reportJson["rop_chain_generation"]["platform"], "macOS Mach-O", "Platform is macOS Mach-O");
        ASSERT_EQ(
            reportJson["rop_chain_generation"]["status"],
            "Failed: Required gadgets missing for Darwin execve chain synthesis",
            "Empty Mach-O chain reports missing Darwin chain requirements"
        );

        ASSERT_EQ(
            reportJson["rop_chain_generation"]["target_syscall"],
            "execve (0x200003B)",
            "Mach-O target syscall identifies Darwin execve"
        );
        ASSERT_EQ(reportJson["protections"]["RELRO"], "NOT_APPLICABLE", "Protections RELRO is NOT_APPLICABLE");
        ASSERT_TRUE(reportJson["protections"]["Stack_NX"] == true, "Protections Stack_NX is true");
        ASSERT_TRUE(reportJson["protections"]["PIE"] == true, "Protections PIE is true");

        // Cleanup temporary report
        fs::remove_all(temp_test_dir);
        fs::remove(test_bin);
    }

    // 17.8 Segment Declaration Accounting & Malformed Stream Safety
    {
        // Case A: Truncated LC_SEGMENT_64 command (cmdsize < 72)
        std::string test_file = (temp_dir / "test_step56_seg_decl_trunc.bin").string();
        uint32_t bad_cmdsize = 32; // < sizeof(segment_command_64) = 72
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, bad_cmdsize, 0, 0, false);
        size_t base = buf.size();
        buf.resize(base + bad_cmdsize, 0);
        write_u32_to(buf, base + 0, LC_SEGMENT_64, false);
        write_u32_to(buf, base + 4, bad_cmdsize, false);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "Truncated LC_SEGMENT_64 command fails parsing");
        const auto& mit = parser.getMachOMitigations();
        ASSERT_EQ(mit.total_declared_segments, 1, "Malformed segment counted in declared segments");
        ASSERT_EQ(mit.inspected_segments, 0, "inspected_segments == 0 for truncated segment");
        ASSERT_TRUE(!mit.segment_stream_complete, "segment_stream_complete == false");
        ASSERT_TRUE(mit.segment_wx_status == SegmentWxStatus::IncompleteOrUnavailable, "segment_wx_status == IncompleteOrUnavailable");
        fs::remove(test_file);
    }
    {
        // Case B: Section failure prevents segment inspection
        std::string test_file = (temp_dir / "test_step56_sec_fail_insp.bin").string();
        uint32_t seg_cmdsize = 72 + 80;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, seg_cmdsize, 0, 0, false);
        TestSection64Desc bad_sec;
        bad_sec.sectname = "__text";
        bad_sec.segname = "__TEXT";
        bad_sec.addr = 0x500; // Invalid VA: addr < vmaddr (0x100000000)
        bad_sec.size = 16;
        bad_sec.offset = 32 + seg_cmdsize;
        bad_sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x2000, 0, 32 + seg_cmdsize + 16, 5, 5, 0, {bad_sec}, false);
        buf.resize(buf.size() + 16, 0x90);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "Section VA out of bounds fails parsing");
        const auto& mit = parser.getMachOMitigations();
        ASSERT_EQ(mit.total_declared_segments, 1, "total_declared_segments == 1");
        ASSERT_EQ(mit.inspected_segments, 0, "Section failure prevents segment inspection (inspected_segments == 0)");
        ASSERT_TRUE(!mit.segment_stream_complete, "segment_stream_complete == false");
        ASSERT_TRUE(mit.segment_wx_status == SegmentWxStatus::IncompleteOrUnavailable, "segment_wx_status == IncompleteOrUnavailable");
        fs::remove(test_file);
    }
    {
        // Case C1: Width mismatch - 32-bit LC_SEGMENT in 64-bit Mach-O
        std::string test_file = (temp_dir / "test_step56_width_mismatch_32in64.bin").string();
        uint32_t seg_cmdsize = 56 + 68;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 1, seg_cmdsize, 0, 0, false);
        TestSection32Desc sec32;
        sec32.sectname = "__text";
        sec32.segname = "__TEXT";
        sec32.addr = 0x1000;
        sec32.size = 16;
        sec32.offset = 32 + seg_cmdsize;
        sec32.flags = S_REGULAR;
        append_segment32_desc(buf, LC_SEGMENT, "__TEXT", 0x1000, 0x2000, 0, 32 + seg_cmdsize + 16, 5, 5, 0, {sec32}, false);
        buf.resize(buf.size() + 16, 0x90);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "32-bit LC_SEGMENT in 64-bit Mach-O fails parsing");
        const auto& mit = parser.getMachOMitigations();
        ASSERT_EQ(mit.total_declared_segments, 1, "Width mismatch: declared segment counted");
        ASSERT_EQ(mit.inspected_segments, 0, "Width mismatch: inspected_segments == 0");
        ASSERT_TRUE(!mit.segment_stream_complete, "segment_stream_complete == false");
        ASSERT_TRUE(mit.segment_wx_status == SegmentWxStatus::IncompleteOrUnavailable, "segment_wx_status == IncompleteOrUnavailable");
        fs::remove(test_file);
    }
    {
        // Case C2: Width mismatch - 64-bit LC_SEGMENT_64 in 32-bit Mach-O
        std::string test_file = (temp_dir / "test_step56_width_mismatch_64in32.bin").string();
        uint32_t seg_cmdsize = 72 + 80;
        auto buf = make_macho32_buf(MH_MAGIC, CPU_TYPE_X86, 3, MH_EXECUTE, 1, seg_cmdsize, 0, false);
        TestSection64Desc sec64;
        sec64.sectname = "__text";
        sec64.segname = "__TEXT";
        sec64.addr = 0x1000;
        sec64.size = 16;
        sec64.offset = 28 + seg_cmdsize;
        sec64.flags = S_REGULAR;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x1000, 0x2000, 0, 28 + seg_cmdsize + 16, 5, 5, 0, {sec64}, false);
        buf.resize(buf.size() + 16, 0x90);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "64-bit LC_SEGMENT_64 in 32-bit Mach-O fails parsing");
        const auto& mit = parser.getMachOMitigations();
        ASSERT_EQ(mit.total_declared_segments, 1, "Width mismatch: declared segment counted");
        ASSERT_EQ(mit.inspected_segments, 0, "Width mismatch: inspected_segments == 0");
        ASSERT_TRUE(!mit.segment_stream_complete, "segment_stream_complete == false");
        ASSERT_TRUE(mit.segment_wx_status == SegmentWxStatus::IncompleteOrUnavailable, "segment_wx_status == IncompleteOrUnavailable");
        fs::remove(test_file);
    }

    // 17.9 LC_CODE_SIGNATURE Command Size Exact 16-Byte Enforcement
    {
        // Case A: cmdsize = 12 (too small, < 16)
        std::string test_file = (temp_dir / "test_step56_cs_cmdsize_small.bin").string();
        uint32_t seg_cmdsize = 72 + 80;
        uint32_t cs_cmdsize = 12; // invalid cmdsize
        uint32_t sizeofcmds = seg_cmdsize + cs_cmdsize;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 2, sizeofcmds, 0, 0, false);
        TestSection64Desc sec;
        sec.sectname = "__text";
        sec.segname = "__TEXT";
        sec.addr = 0x100001000ULL;
        sec.size = 16;
        sec.offset = 32 + sizeofcmds;
        sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x2000, 0, 32 + sizeofcmds + 16, 5, 5, 0, {sec}, false);
        append_code_signature_desc(buf, 32 + sizeofcmds, 16, false, cs_cmdsize);
        buf.resize(buf.size() + 16, 0x90);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "Parse succeeds for non-segment command size violation");
        const auto& mit = parser.getMachOMitigations();
        ASSERT_TRUE(mit.has_code_signature_cmd, "has_code_signature_cmd == true");
        ASSERT_TRUE(!mit.data_range_valid, "data_range_valid == false when cmdsize == 12");
        ASSERT_TRUE(!mit.superblob_header_valid, "superblob_header_valid == false when cmdsize == 12");
        fs::remove(test_file);
    }
    {
        // Case B: cmdsize = 20 (too large, > 16)
        std::string test_file = (temp_dir / "test_step56_cs_cmdsize_large.bin").string();
        uint32_t seg_cmdsize = 72 + 80;
        uint32_t cs_cmdsize = 20; // invalid cmdsize
        uint32_t sizeofcmds = seg_cmdsize + cs_cmdsize;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 2, sizeofcmds, 0, 0, false);
        TestSection64Desc sec;
        sec.sectname = "__text";
        sec.segname = "__TEXT";
        sec.addr = 0x100001000ULL;
        sec.size = 16;
        sec.offset = 32 + sizeofcmds;
        sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x2000, 0, 32 + sizeofcmds + 16, 5, 5, 0, {sec}, false);
        append_code_signature_desc(buf, 32 + sizeofcmds, 16, false, cs_cmdsize);
        buf.resize(buf.size() + 16, 0x90);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "Parse succeeds for non-segment command size violation");
        const auto& mit = parser.getMachOMitigations();
        ASSERT_TRUE(mit.has_code_signature_cmd, "has_code_signature_cmd == true");
        ASSERT_TRUE(!mit.data_range_valid, "data_range_valid == false when cmdsize == 20");
        ASSERT_TRUE(!mit.superblob_header_valid, "superblob_header_valid == false when cmdsize == 20");
        fs::remove(test_file);
    }

    // 17.10 SuperBlob Index Count Boundary Conditions
    {
        // Case A: Exact index count boundary (length = 20, count = 1: (20-12)/8 = 1, count <= 1 is valid)
        std::string test_file = (temp_dir / "test_step56_cs_boundary_exact.bin").string();
        uint32_t seg_cmdsize = 72 + 80;
        uint32_t cs_cmdsize = 16;
        uint32_t sizeofcmds = seg_cmdsize + cs_cmdsize;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 2, sizeofcmds, 0, 0, false);
        uint32_t text_off = 32 + sizeofcmds;
        uint32_t text_sz = 16;
        TestSection64Desc sec;
        sec.sectname = "__text";
        sec.segname = "__TEXT";
        sec.addr = 0x100001000ULL;
        sec.size = text_sz;
        sec.offset = text_off;
        sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;
        uint32_t cs_off = text_off + text_sz;
        uint32_t cs_sz = 20;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x2000, 0, cs_off + cs_sz, 5, 5, 0, {sec}, false);
        append_code_signature_desc(buf, cs_off, cs_sz, false);
        buf.resize(text_off + text_sz, 0x90);
        size_t sb_base = buf.size();
        buf.resize(sb_base + cs_sz, 0);
        write_u32_to(buf, sb_base + 0, CSMAGIC_EMBEDDED_SIGNATURE, true);
        write_u32_to(buf, sb_base + 4, 20, true);
        write_u32_to(buf, sb_base + 8, 1, true); // count = 1: exact boundary
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "Parse SuperBlob exact boundary");
        const auto& mit = parser.getMachOMitigations();
        ASSERT_TRUE(mit.superblob_header_valid, "superblob_header_valid == true on exact count boundary");
        fs::remove(test_file);
    }
    {
        // Case B: Off-by-one count overflow (length = 20, count = 2: (20-12)/8 = 1, count=2 exceeds length)
        std::string test_file = (temp_dir / "test_step56_cs_boundary_overflow.bin").string();
        uint32_t seg_cmdsize = 72 + 80;
        uint32_t cs_cmdsize = 16;
        uint32_t sizeofcmds = seg_cmdsize + cs_cmdsize;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 2, sizeofcmds, 0, 0, false);
        uint32_t text_off = 32 + sizeofcmds;
        uint32_t text_sz = 16;
        TestSection64Desc sec;
        sec.sectname = "__text";
        sec.segname = "__TEXT";
        sec.addr = 0x100001000ULL;
        sec.size = text_sz;
        sec.offset = text_off;
        sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;
        uint32_t cs_off = text_off + text_sz;
        uint32_t cs_sz = 20;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x2000, 0, cs_off + cs_sz, 5, 5, 0, {sec}, false);
        append_code_signature_desc(buf, cs_off, cs_sz, false);
        buf.resize(text_off + text_sz, 0x90);
        size_t sb_base = buf.size();
        buf.resize(sb_base + cs_sz, 0);
        write_u32_to(buf, sb_base + 0, CSMAGIC_EMBEDDED_SIGNATURE, true);
        write_u32_to(buf, sb_base + 4, 20, true);
        write_u32_to(buf, sb_base + 8, 2, true); // count = 2: 12 + 2*8 = 28 > 20
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "Parse SuperBlob off-by-one count overflow");
        const auto& mit = parser.getMachOMitigations();
        ASSERT_TRUE(!mit.superblob_header_valid, "superblob_header_valid == false on off-by-one count overflow");
        fs::remove(test_file);
    }
    {
        // Case C: Zero count boundary (length = 12, count = 0: (12-12)/8 = 0, count <= 0 is valid)
        std::string test_file = (temp_dir / "test_step56_cs_boundary_zero.bin").string();
        uint32_t seg_cmdsize = 72 + 80;
        uint32_t cs_cmdsize = 16;
        uint32_t sizeofcmds = seg_cmdsize + cs_cmdsize;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE, 2, sizeofcmds, 0, 0, false);
        uint32_t text_off = 32 + sizeofcmds;
        uint32_t text_sz = 16;
        TestSection64Desc sec;
        sec.sectname = "__text";
        sec.segname = "__TEXT";
        sec.addr = 0x100001000ULL;
        sec.size = text_sz;
        sec.offset = text_off;
        sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;
        uint32_t cs_off = text_off + text_sz;
        uint32_t cs_sz = 12;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x2000, 0, cs_off + cs_sz, 5, 5, 0, {sec}, false);
        append_code_signature_desc(buf, cs_off, cs_sz, false);
        buf.resize(text_off + text_sz, 0x90);
        size_t sb_base = buf.size();
        buf.resize(sb_base + cs_sz, 0);
        write_u32_to(buf, sb_base + 0, CSMAGIC_EMBEDDED_SIGNATURE, true);
        write_u32_to(buf, sb_base + 4, 12, true);
        write_u32_to(buf, sb_base + 8, 0, true); // count = 0: valid empty index
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "Parse SuperBlob with count=0");
        const auto& mit = parser.getMachOMitigations();
        ASSERT_TRUE(mit.superblob_header_valid, "superblob_header_valid == true with count=0");
        fs::remove(test_file);
    }

    // 17.11 Big-Endian Symbol Table Decoding
    {
        std::string test_file = (temp_dir / "test_step56_canary_be32.bin").string();
        uint32_t seg_cmdsize = 56 + 68;
        uint32_t sym_cmdsize = 24;
        uint32_t sizeofcmds = seg_cmdsize + sym_cmdsize;
        // 32-bit Big-Endian Mach-O
        auto buf = make_macho32_buf(MH_MAGIC, CPU_TYPE_X86, 3, MH_EXECUTE, 2, sizeofcmds, 0, true);

        uint32_t text_off = 28 + sizeofcmds;
        uint32_t text_sz = 16;
        TestSection32Desc sec;
        sec.sectname = "__text";
        sec.segname = "__TEXT";
        sec.addr = 0x1000;
        sec.size = text_sz;
        sec.offset = text_off;
        sec.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;

        uint32_t sym_off = text_off + text_sz;
        uint32_t nsyms = 1;
        uint32_t sym_sz = nsyms * 12; // 32-bit nlist
        uint32_t str_off = sym_off + sym_sz;

        std::vector<uint8_t> strtab = {'\0'};
        uint32_t canary_strx = static_cast<uint32_t>(strtab.size());
        std::string canary_str = "___stack_chk_fail";
        strtab.insert(strtab.end(), canary_str.begin(), canary_str.end());
        strtab.push_back('\0');
        uint32_t str_sz = static_cast<uint32_t>(strtab.size());

        append_segment32_desc(buf, LC_SEGMENT, "__TEXT", 0x1000, 0x2000, 0, str_off + str_sz, 5, 5, 0, {sec}, true);
        append_symtab_desc(buf, sym_off, nsyms, str_off, str_sz, true);

        buf.resize(text_off + text_sz, 0x60); // NOP for PowerPC
        append_nlist32(buf, canary_strx, N_UNDF | N_EXT, 0, 0, 0, true); // Big-endian nlist_32
        buf.insert(buf.end(), strtab.begin(), strtab.end());
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "Parse 32-bit Big-Endian Mach-O with canary");
        const auto& mit = parser.getMachOMitigations();
        ASSERT_TRUE(mit.canary_status == CanaryStatus::SymbolDetected, "Big-endian canary detected");
        ASSERT_EQ(mit.canary_symbol_name, "___stack_chk_fail", "Canary symbol name matches in big-endian");
        fs::remove(test_file);
    }
}

static void test_step6_gadget_discovery() {
    std::cout << "\n[*] Group 18: Step 6 Multi-Section Mach-O Executable Aggregation & Gadget Discovery Tests...\n";
    fs::path temp_dir = fs::temp_directory_path();

    // T6.1: Multi-Section Non-Contiguous VAs
    {
        std::string test_file = (temp_dir / "test_step6_t61_multisec.bin").string();
        uint32_t seg_cmdsize = 72 + 2 * 80; // 2 sections
        uint32_t sizeofcmds = seg_cmdsize;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_EXECUTE, 1, sizeofcmds, 0, 0, false);

        uint32_t sec1_off = 0x200;
        uint32_t sec1_sz = 16;
        uint32_t sec2_off = 0x400;
        uint32_t sec2_sz = 16;

        TestSection64Desc s1;
        s1.sectname = "__text";
        s1.segname = "__TEXT";
        s1.addr = 0x100001000ULL;
        s1.size = sec1_sz;
        s1.offset = sec1_off;
        s1.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;

        TestSection64Desc s2;
        s2.sectname = "__stubs";
        s2.segname = "__TEXT";
        s2.addr = 0x100004000ULL;
        s2.size = sec2_sz;
        s2.offset = sec2_off;
        s2.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;

        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x10000ULL, 0, sec2_off + sec2_sz, 7, 5, 0, {s1, s2}, false);

        buf.resize(sec1_off, 0x90);
        std::vector<uint8_t> s1_bytes = {0x5f, 0xc3}; // pop rdi; ret
        s1_bytes.resize(sec1_sz, 0x90);
        buf.insert(buf.end(), s1_bytes.begin(), s1_bytes.end());

        buf.resize(sec2_off, 0x90);
        std::vector<uint8_t> s2_bytes = {0x58, 0xc3}; // pop rax; ret
        s2_bytes.resize(sec2_sz, 0x90);
        buf.insert(buf.end(), s2_bytes.begin(), s2_bytes.end());

        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "T6.1: Parse multi-section 64-bit Mach-O");
        const auto& maps = parser.getExecBufferMappings();
        ASSERT_EQ(maps.size(), static_cast<size_t>(2), "T6.1: Exactly 2 exec buffer mappings");
        ASSERT_EQ(maps[0].virtual_address, 0x100001000ULL, "T6.1: Mapping 0 VA matches sec1");
        ASSERT_EQ(maps[0].buffer_offset, static_cast<size_t>(0), "T6.1: Mapping 0 buffer offset is 0");
        ASSERT_EQ(maps[0].size, static_cast<size_t>(16), "T6.1: Mapping 0 size is 16");

        ASSERT_EQ(maps[1].virtual_address, 0x100004000ULL, "T6.1: Mapping 1 VA matches sec2");
        ASSERT_EQ(maps[1].buffer_offset, static_cast<size_t>(20), "T6.1: Mapping 1 buffer offset accounts for 4-byte 0xCC fence (16 + 4 = 20)");
        ASSERT_EQ(maps[1].size, static_cast<size_t>(16), "T6.1: Mapping 1 size is 16");

        const auto& code = parser.getTextSection();
        ASSERT_EQ(code.size(), static_cast<size_t>(36), "T6.1: Aggregated code buffer size is 16 + 4 + 16 = 36");
        ASSERT_EQ(code[16], 0xCC, "T6.1: Fence byte 0 is 0xCC");
        ASSERT_EQ(code[17], 0xCC, "T6.1: Fence byte 1 is 0xCC");
        ASSERT_EQ(code[18], 0xCC, "T6.1: Fence byte 2 is 0xCC");
        ASSERT_EQ(code[19], 0xCC, "T6.1: Fence byte 3 is 0xCC");

        GadgetFinder gf(code, parser.getTextSectionBaseAddress(), "x86_64", test_file, maps, 10, Endianness::Little);
        gf.findGadgets();
        const auto& gadgets = gf.getGadgets();
        ASSERT_TRUE(gadgets.size() >= 2, "T6.1: Found gadgets across both non-contiguous sections");

        bool found_s1_gadget = false;
        bool found_s2_gadget = false;
        for (const auto& g : gadgets) {
            if (g.address == 0x100001000ULL && g.assembly == "pop rdi ; ret") found_s1_gadget = true;
            if (g.address == 0x100004000ULL && g.assembly == "pop rax ; ret") found_s2_gadget = true;
        }
        ASSERT_TRUE(found_s1_gadget, "T6.1: Discovered gadget in sec1 with actual VA 0x100001000");
        ASSERT_TRUE(found_s2_gadget, "T6.1: Discovered gadget in sec2 with actual VA 0x100004000");

        uint64_t fo1 = 0, rva1 = 0;
        ASSERT_TRUE(parser.vaToOffsets(0x100001000ULL, fo1, rva1), "T6.1: vaToOffsets for sec1");
        ASSERT_EQ(fo1, static_cast<uint64_t>(sec1_off), "T6.1: Sec1 file offset resolved accurately");
        ASSERT_EQ(rva1, static_cast<uint64_t>(0x1000), "T6.1: Sec1 RVA resolved accurately");

        uint64_t fo2 = 0, rva2 = 0;
        ASSERT_TRUE(parser.vaToOffsets(0x100004000ULL, fo2, rva2), "T6.1: vaToOffsets for sec2");
        ASSERT_EQ(fo2, static_cast<uint64_t>(sec2_off), "T6.1: Sec2 file offset resolved accurately");
        ASSERT_EQ(rva2, static_cast<uint64_t>(0x4000), "T6.1: Sec2 RVA resolved accurately");

        fs::remove(test_file);
    }

    // T6.2: Boundary Fence Isolation
    {
        std::string test_file = (temp_dir / "test_step6_t62_fence_isolation.bin").string();
        uint32_t seg_cmdsize = 72 + 2 * 80;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_EXECUTE, 1, seg_cmdsize, 0, 0, false);

        uint32_t sec1_off = 0x200;
        uint32_t sec1_sz = 16;
        uint32_t sec2_off = 0x400;
        uint32_t sec2_sz = 16;

        TestSection64Desc s1;
        s1.sectname = "__text"; s1.segname = "__TEXT";
        s1.addr = 0x100001000ULL; s1.size = sec1_sz; s1.offset = sec1_off;
        s1.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;

        TestSection64Desc s2;
        s2.sectname = "__stubs"; s2.segname = "__TEXT";
        s2.addr = 0x100004000ULL; s2.size = sec2_sz; s2.offset = sec2_off;
        s2.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;

        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x10000ULL, 0, sec2_off + sec2_sz, 7, 5, 0, {s1, s2}, false);

        // Section 1 ends with 0x5f (pop rdi) at byte 15, no ret
        buf.resize(sec1_off, 0x90);
        std::vector<uint8_t> s1_bytes(sec1_sz, 0x90);
        s1_bytes[sec1_sz - 1] = 0x5f;
        buf.insert(buf.end(), s1_bytes.begin(), s1_bytes.end());

        // Section 2 starts with 0xc3 (ret) at byte 0
        buf.resize(sec2_off, 0x90);
        std::vector<uint8_t> s2_bytes(sec2_sz, 0x90);
        s2_bytes[0] = 0xc3;
        buf.insert(buf.end(), s2_bytes.begin(), s2_bytes.end());

        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "T6.2: Parse boundary isolation fixture");
        const auto& maps = parser.getExecBufferMappings();
        GadgetFinder gf(parser.getTextSection(), parser.getTextSectionBaseAddress(), "x86_64", test_file, maps, 10, Endianness::Little);
        gf.findGadgets();
        const auto& gadgets = gf.getGadgets();

        bool cross_section_gadget = false;
        for (const auto& g : gadgets) {
            if (g.assembly == "pop rdi ; ret") cross_section_gadget = true;
        }
        ASSERT_TRUE(!cross_section_gadget, "T6.2: Boundary fence prevents cross-section gadget synthesis");
        fs::remove(test_file);
    }

    // T6.3: Universal Binary with Selected Slice at Non-Zero Offset
    {
        std::string test_file = (temp_dir / "test_step6_t63_fat_slice.bin").string();
        uint64_t slice_off = 0x4000;
        uint32_t seg_cmdsize = 72 + 2 * 80;
        uint32_t sec1_off = 0x200;
        uint32_t sec2_off = 0x400;
        uint32_t sec_sz = 16;
        uint64_t slice_sz = sec2_off + sec_sz;

        std::vector<uint8_t> fat_buf(8, 0);
        write_u32_to(fat_buf, 0, 0xCAFEBABE, true);
        write_u32_to(fat_buf, 4, 1, true);

        std::vector<uint8_t> arch_entry(20, 0);
        write_u32_to(arch_entry, 0, CPU_TYPE_X86_64, true);
        write_u32_to(arch_entry, 4, CPU_SUBTYPE_X86_64_ALL, true);
        write_u32_to(arch_entry, 8, static_cast<uint32_t>(slice_off), true);
        write_u32_to(arch_entry, 12, static_cast<uint32_t>(slice_sz), true);
        write_u32_to(arch_entry, 16, 12, true);
        fat_buf.insert(fat_buf.end(), arch_entry.begin(), arch_entry.end());

        fat_buf.resize(static_cast<size_t>(slice_off), 0);

        auto slice_buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_EXECUTE, 1, seg_cmdsize, 0, 0, false);
        TestSection64Desc s1;
        s1.sectname = "__text"; s1.segname = "__TEXT";
        s1.addr = 0x100001000ULL; s1.size = sec_sz; s1.offset = sec1_off;
        s1.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;

        TestSection64Desc s2;
        s2.sectname = "__stubs"; s2.segname = "__TEXT";
        s2.addr = 0x100004000ULL; s2.size = sec_sz; s2.offset = sec2_off;
        s2.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;

        append_segment64_desc(slice_buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x10000ULL, 0, slice_sz, 7, 5, 0, {s1, s2}, false);

        slice_buf.resize(sec1_off, 0x90);
        std::vector<uint8_t> s1_bytes = {0x5f, 0xc3}; s1_bytes.resize(sec_sz, 0x90);
        slice_buf.insert(slice_buf.end(), s1_bytes.begin(), s1_bytes.end());

        slice_buf.resize(sec2_off, 0x90);
        std::vector<uint8_t> s2_bytes = {0x58, 0xc3}; s2_bytes.resize(sec_sz, 0x90);
        slice_buf.insert(slice_buf.end(), s2_bytes.begin(), s2_bytes.end());

        fat_buf.insert(fat_buf.end(), slice_buf.begin(), slice_buf.end());
        write_file(test_file, fat_buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "T6.3: Parse universal binary with slice offset 0x4000");
        const auto& maps = parser.getExecBufferMappings();
        ASSERT_EQ(maps.size(), static_cast<size_t>(2), "T6.3: 2 mappings parsed from universal slice");
        ASSERT_EQ(maps[0].raw_offset, slice_off + sec1_off, "T6.3: Map 0 raw_offset incorporates sliceOffset_ exactly once");
        ASSERT_EQ(maps[1].raw_offset, slice_off + sec2_off, "T6.3: Map 1 raw_offset incorporates sliceOffset_ exactly once");

        uint64_t fo2 = 0, rva2 = 0;
        ASSERT_TRUE(parser.vaToOffsets(0x100004000ULL, fo2, rva2), "T6.3: vaToOffsets for sec2 gadget");
        ASSERT_EQ(fo2, slice_off + sec2_off, "T6.3: Resolved file offset is exactly slice_off + sec2_off");
        ASSERT_EQ(rva2, static_cast<uint64_t>(0x4000), "T6.3: RVA is relative to imageBase");

        fs::remove(test_file);
    }

    // T6.4: Zero-Fill Section Exclusion
    {
        std::string test_file = (temp_dir / "test_step6_t64_zerofill_exclusion.bin").string();
        uint32_t seg_cmdsize = 72 + 4 * 80;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_EXECUTE, 1, seg_cmdsize, 0, 0, false);
        uint32_t sec1_off = 0x200;
        uint32_t sec1_sz = 16;

        TestSection64Desc s1;
        s1.sectname = "__text"; s1.segname = "__TEXT";
        s1.addr = 0x100001000ULL; s1.size = sec1_sz; s1.offset = sec1_off;
        s1.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;

        TestSection64Desc s2;
        s2.sectname = "__zerofill"; s2.segname = "__TEXT";
        s2.addr = 0x100002000ULL; s2.size = 0x1000; s2.offset = 0;
        s2.flags = S_ZEROFILL | S_ATTR_SOME_INSTRUCTIONS;

        TestSection64Desc s3;
        s3.sectname = "__gb_zero"; s3.segname = "__TEXT";
        s3.addr = 0x100003000ULL; s3.size = 0x1000; s3.offset = 0;
        s3.flags = S_GB_ZEROFILL | S_ATTR_SOME_INSTRUCTIONS;

        TestSection64Desc s4;
        s4.sectname = "__tl_zero"; s4.segname = "__TEXT";
        s4.addr = 0x100004000ULL; s4.size = 0x1000; s4.offset = 0;
        s4.flags = S_THREAD_LOCAL_ZEROFILL | S_ATTR_SOME_INSTRUCTIONS;

        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x10000ULL, 0, sec1_off + sec1_sz, 7, 5, 0, {s1, s2, s3, s4}, false);
        buf.resize(sec1_off + sec1_sz, 0x90);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "T6.4: Parse Mach-O with zero-fill sections succeeds");
        const auto& maps = parser.getExecBufferMappings();
        ASSERT_EQ(maps.size(), static_cast<size_t>(1), "T6.4: Only file-backed text section is aggregated into execMappings");
        ASSERT_EQ(maps[0].section_name, "__TEXT,__text", "T6.4: Single mapping is __TEXT,__text");

        const auto& all_secs = parser.getSections();
        ASSERT_EQ(all_secs.size(), static_cast<size_t>(4), "T6.4: Exactly 4 sections in parsed metadata");
        for (const auto& sec : all_secs) {
            if (sec.name == "__TEXT,__zerofill" || sec.name == "__TEXT,__gb_zero" || sec.name == "__TEXT,__tl_zero") {
                ASSERT_EQ(sec.raw_offset, static_cast<uint64_t>(0), "T6.4: Zero-fill raw_offset must be 0");
                ASSERT_EQ(sec.raw_size, static_cast<uint64_t>(0), "T6.4: Zero-fill raw_size must be 0");
                ASSERT_TRUE(!sec.is_executable, "T6.4: Zero-fill is_executable must be false");
            }
        }
        fs::remove(test_file);
    }

    // T6.5: x86_64 Gadget Discovery
    {
        std::string test_file = (temp_dir / "test_step6_t65_x86_64_gadgets.bin").string();
        uint32_t seg_cmdsize = 72 + 80;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_EXECUTE, 1, seg_cmdsize, 0, 0, false);
        uint32_t sec_off = 0x200;
        uint32_t sec_sz = 32;

        TestSection64Desc s;
        s.sectname = "__text"; s.segname = "__TEXT";
        s.addr = 0x100001000ULL; s.size = sec_sz; s.offset = sec_off;
        s.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;

        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x10000ULL, 0, sec_off + sec_sz, 7, 5, 0, {s}, false);
        buf.resize(sec_off, 0x90);
        std::vector<uint8_t> code_bytes = {0x5f, 0xc3, 0x48, 0xc7, 0xc0, 0x3b, 0x00, 0x00, 0x00, 0x0f, 0x05};
        code_bytes.resize(sec_sz, 0x90);
        buf.insert(buf.end(), code_bytes.begin(), code_bytes.end());
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "T6.5: Parse x86_64 binary");
        GadgetFinder gf(parser.getTextSection(), parser.getTextSectionBaseAddress(), "x86_64", test_file, parser.getExecBufferMappings(), 10, Endianness::Little);
        gf.findGadgets();
        const auto& gadgets = gf.getGadgets();
        ASSERT_TRUE(!gadgets.empty(), "T6.5: Discovered x86_64 gadgets");
        bool found_pop_rdi = false;
        bool found_mov_rax = false;
        for (const auto& g : gadgets) {
            ASSERT_TRUE(g.byte_verified, "T6.5: Discovered gadget is byte_verified");
            if (g.address == 0x100001000ULL && g.assembly == "pop rdi ; ret") {
                found_pop_rdi = true;
            }
            if (g.address == 0x100001002ULL && g.assembly == "mov rax, 0x3b ; syscall") {
                found_mov_rax = true;
            }
        }
        ASSERT_TRUE(found_pop_rdi, "T6.5: Discovered expected 'pop rdi ; ret' gadget at 0x100001000");
        ASSERT_TRUE(found_mov_rax, "T6.5: Discovered expected 'mov rax, 0x3b ; syscall' gadget at 0x100001002");
        fs::remove(test_file);
    }

    // T6.6: x86 32-bit Gadget Discovery
    {
        std::string test_file = (temp_dir / "test_step6_t66_x86_32_gadgets.bin").string();
        uint32_t seg_cmdsize = 56 + 68;
        auto buf = make_macho32_buf(MH_MAGIC, CPU_TYPE_X86, CPU_SUBTYPE_I386_ALL, MH_EXECUTE, 1, seg_cmdsize, 0, false);
        uint32_t sec_off = 0x200;
        uint32_t sec_sz = 16;

        TestSection32Desc s;
        s.sectname = "__text"; s.segname = "__TEXT";
        s.addr = 0x1000; s.size = sec_sz; s.offset = sec_off;
        s.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;

        append_segment32_desc(buf, LC_SEGMENT, "__TEXT", 0x1000, 0x1000, 0, sec_off + sec_sz, 7, 5, 0, {s}, false);
        buf.resize(sec_off, 0x90);
        std::vector<uint8_t> code_bytes = {0x58, 0xc3}; // pop eax; ret
        code_bytes.resize(sec_sz, 0x90);
        buf.insert(buf.end(), code_bytes.begin(), code_bytes.end());
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "T6.6: Parse x86 32-bit binary");
        GadgetFinder gf(parser.getTextSection(), parser.getTextSectionBaseAddress(), "x86", test_file, parser.getExecBufferMappings(), 10, Endianness::Little);
        gf.findGadgets();
        const auto& gadgets = gf.getGadgets();
        ASSERT_TRUE(!gadgets.empty(), "T6.6: Discovered x86 32-bit gadgets");
        ASSERT_EQ(gadgets[0].address, static_cast<uint64_t>(0x1000), "T6.6: Gadget address is 32-bit 0x1000");
        fs::remove(test_file);
    }

    // T6.7: AArch64 Gadget Discovery
    {
        std::string test_file = (temp_dir / "test_step6_t67_aarch64_gadgets.bin").string();
        uint32_t seg_cmdsize = 72 + 80;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE, 1, seg_cmdsize, 0, 0, false);
        uint32_t sec_off = 0x200;
        uint32_t sec_sz = 16;

        TestSection64Desc s;
        s.sectname = "__text"; s.segname = "__TEXT";
        s.addr = 0x100001000ULL; s.size = sec_sz; s.offset = sec_off;
        s.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;

        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x10000ULL, 0, sec_off + sec_sz, 7, 5, 0, {s}, false);
        buf.resize(sec_off, 0x00);
        // mov x0, x1 (\xe0\x03\x01\xaa), ret (\xc0\x03\x5f\xd6)
        std::vector<uint8_t> code_bytes = {0xe0, 0x03, 0x01, 0xaa, 0xc0, 0x03, 0x5f, 0xd6};
        code_bytes.resize(sec_sz, 0x1f);
        code_bytes[8] = 0x1f; code_bytes[9] = 0x20; code_bytes[10] = 0x03; code_bytes[11] = 0xd5;
        code_bytes[12] = 0x1f; code_bytes[13] = 0x20; code_bytes[14] = 0x03; code_bytes[15] = 0xd5;
        buf.insert(buf.end(), code_bytes.begin(), code_bytes.end());
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "T6.7: Parse AArch64 binary");
        GadgetFinder gf(parser.getTextSection(), parser.getTextSectionBaseAddress(), "aarch64", test_file, parser.getExecBufferMappings(), 10, Endianness::Little);
        gf.findGadgets();
        const auto& gadgets = gf.getGadgets();
        ASSERT_TRUE(!gadgets.empty(), "T6.7: Discovered AArch64 gadget");
        bool found_ret = false;
        bool found_expected_aarch64 = false;
        for (const auto& g : gadgets) {
            if (g.assembly.find("ret") != std::string::npos) found_ret = true;
            if (g.address == 0x100001000ULL && g.assembly == "mov x0, x1 ; ret") {
                found_expected_aarch64 = true;
            }
        }
        ASSERT_TRUE(found_ret, "T6.7: AArch64 ret terminator identified");
        ASSERT_TRUE(found_expected_aarch64, "T6.7: Found expected AArch64 'mov x0, x1 ; ret' gadget at 0x100001000");
        fs::remove(test_file);
    }

    // T6.8: Section Gating & Permissions
    {
        std::string test_file = (temp_dir / "test_step6_t68_gating.bin").string();
        uint32_t seg1_cmdsize = 72 + 3 * 80;
        uint32_t seg2_cmdsize = 72 + 1 * 80;
        uint32_t sizeofcmds = seg1_cmdsize + seg2_cmdsize;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_EXECUTE, 2, sizeofcmds, 0, 0, false);
        uint32_t sec_off = 0x200;

        TestSection64Desc s1;
        s1.sectname = "__text"; s1.segname = "__TEXT";
        s1.addr = 0x100001000ULL; s1.size = 16; s1.offset = sec_off;
        s1.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;

        TestSection64Desc s2; // Data section (no instructions)
        s2.sectname = "__data"; s2.segname = "__TEXT";
        s2.addr = 0x100002000ULL; s2.size = 16; s2.offset = sec_off + 16;
        s2.flags = S_REGULAR;

        TestSection64Desc s3; // Empty section (s_size = 0)
        s3.sectname = "__empty"; s3.segname = "__TEXT";
        s3.addr = 0x100003000ULL; s3.size = 0; s3.offset = sec_off + 32;
        s3.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;

        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x4000ULL, 0, sec_off + 32, 7, 5, 0, {s1, s2, s3}, false);

        // Segment 2: __DATA with initprot = 3 (VM_PROT_READ | VM_PROT_WRITE, non-executable)
        TestSection64Desc s_data_code;
        s_data_code.sectname = "__data_code"; s_data_code.segname = "__DATA";
        s_data_code.addr = 0x100010000ULL; s_data_code.size = 16; s_data_code.offset = sec_off + 32;
        s_data_code.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;

        append_segment64_desc(buf, LC_SEGMENT_64, "__DATA", 0x100010000ULL, 0x1000ULL, sec_off + 32, 16, 7, 3, 0, {s_data_code}, false);

        buf.resize(sec_off + 48, 0x90);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(parser.parse(test_file), "T6.8: Parse gating test fixture");
        const auto& maps = parser.getExecBufferMappings();
        ASSERT_EQ(maps.size(), static_cast<size_t>(1), "T6.8: Only s1 (executable instruction section) is aggregated");
        ASSERT_EQ(maps[0].section_name, "__TEXT,__text", "T6.8: Aggregated section is __TEXT,__text");

        const auto& all_secs = parser.getSections();
        bool found_empty_sec = false;
        bool found_data_code = false;
        for (const auto& sec : all_secs) {
            if (sec.name == "__TEXT,__empty") {
                found_empty_sec = true;
                ASSERT_EQ(sec.raw_size, static_cast<uint64_t>(0), "T6.8: Zero-sized instruction section raw_size == 0");
                ASSERT_TRUE(!sec.is_executable, "T6.8: Zero-sized instruction section has is_executable == false");
            }
            if (sec.name == "__DATA,__data_code") {
                found_data_code = true;
                ASSERT_TRUE(!sec.is_executable, "T6.8: Section in non-executable segment has is_executable == false");
            }
        }
        ASSERT_TRUE(found_empty_sec, "T6.8: Zero-sized instruction section exists in parsed sections");
        ASSERT_TRUE(found_data_code, "T6.8: Section in non-executable segment was evaluated");

        for (const auto& map : maps) {
            ASSERT_TRUE(map.section_name != "__TEXT,__empty", "T6.8: Zero-sized section is absent from executable mappings");
        }
        fs::remove(test_file);
    }

    // T6.M1: Section Offset Before Segment fileoff
    {
        std::string test_file = (temp_dir / "test_step6_t6m1_sec_before_fileoff.bin").string();
        uint32_t seg_cmdsize = 72 + 80;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_EXECUTE, 1, seg_cmdsize, 0, 0, false);
        TestSection64Desc s;
        s.sectname = "__text"; s.segname = "__TEXT";
        s.addr = 0x100002000ULL; s.size = 0x100; s.offset = 0x1000; // < fileoff (0x2000)
        s.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x10000ULL, 0x2000, 0x1000, 7, 5, 0, {s}, false);
        buf.resize(0x3000, 0);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "T6.M1: Section offset before segment fileoff fails parse");
        ASSERT_TRUE(!parser.getMachOMitigations().segment_stream_complete, "T6.M1: segment_stream_complete is false");
        fs::remove(test_file);
    }

    // T6.M2: Section Extending Beyond Segment filesize
    {
        std::string test_file = (temp_dir / "test_step6_t6m2_sec_exceeds_filesize.bin").string();
        uint32_t seg_cmdsize = 72 + 80;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_EXECUTE, 1, seg_cmdsize, 0, 0, false);
        TestSection64Desc s;
        s.sectname = "__text"; s.segname = "__TEXT";
        s.addr = 0x100001000ULL; s.size = 0x1000; s.offset = 0x1800; // 0x1800 + 0x1000 = 0x2800 > 0x2000
        s.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x10000ULL, 0x1000, 0x1000, 7, 5, 0, {s}, false);
        buf.resize(0x3000, 0);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "T6.M2: Section extending beyond segment filesize fails parse");
        ASSERT_TRUE(!parser.getMachOMitigations().segment_stream_complete, "T6.M2: segment_stream_complete is false");
        fs::remove(test_file);
    }

    // T6.M3: Section Extending Beyond Slice Bounds
    {
        std::string test_file = (temp_dir / "test_step6_t6m3_sec_exceeds_slice.bin").string();
        uint32_t seg_cmdsize = 72 + 80;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_EXECUTE, 1, seg_cmdsize, 0, 0, false);
        TestSection64Desc s;
        s.sectname = "__text"; s.segname = "__TEXT";
        s.addr = 0x100001000ULL; s.size = 0x1000; s.offset = 0x3800; // 0x3800 + 0x1000 = 0x4800 > sliceSize (0x4000)
        s.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x10000ULL, 0, 0x4800, 7, 5, 0, {s}, false);
        buf.resize(0x4000, 0); // File size is 0x4000, so sliceSize is 0x4000
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "T6.M3: Section extending beyond slice size fails parse");
        ASSERT_TRUE(!parser.getMachOMitigations().segment_stream_complete, "T6.M3: segment_stream_complete is false");
        fs::remove(test_file);
    }

    // T6.M4: Section Extending Beyond Container Bounds
    {
        std::string test_file = (temp_dir / "test_step6_t6m4_sec_exceeds_container.bin").string();
        uint64_t slice_off = 0x4000;
        uint64_t slice_sz = 0x4000;
        uint32_t seg_cmdsize = 72 + 80;

        std::vector<uint8_t> fat_buf(8, 0);
        write_u32_to(fat_buf, 0, 0xCAFEBABE, true);
        write_u32_to(fat_buf, 4, 1, true);

        std::vector<uint8_t> arch_entry(20, 0);
        write_u32_to(arch_entry, 0, CPU_TYPE_X86_64, true);
        write_u32_to(arch_entry, 4, CPU_SUBTYPE_X86_64_ALL, true);
        write_u32_to(arch_entry, 8, static_cast<uint32_t>(slice_off), true);
        write_u32_to(arch_entry, 12, static_cast<uint32_t>(slice_sz), true);
        write_u32_to(arch_entry, 16, 12, true);
        fat_buf.insert(fat_buf.end(), arch_entry.begin(), arch_entry.end());
        fat_buf.resize(static_cast<size_t>(slice_off), 0);

        auto slice_buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_EXECUTE, 1, seg_cmdsize, 0, 0, false);
        TestSection64Desc s;
        s.sectname = "__text"; s.segname = "__TEXT";
        s.addr = 0x100001000ULL; s.size = 0x1800; s.offset = 0x2000; // 0x4000 + 0x2000 + 0x1800 = 0x7800 > totalFileSize (0x7000)
        s.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;
        append_segment64_desc(slice_buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x10000ULL, 0, 0x3800, 7, 5, 0, {s}, false);

        fat_buf.insert(fat_buf.end(), slice_buf.begin(), slice_buf.end());
        fat_buf.resize(0x7000, 0); // truncate container to 0x7000
        write_file(test_file, fat_buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "T6.M4: Section extending beyond container bounds fails parse");
        ASSERT_TRUE(!parser.getMachOMitigations().segment_stream_complete, "T6.M4: segment_stream_complete is false");
        fs::remove(test_file);
    }

    // T6.M5: Section Virtual Address Before Segment vmaddr
    {
        std::string test_file = (temp_dir / "test_step6_t6m5_sec_va_before_vmaddr.bin").string();
        uint32_t seg_cmdsize = 72 + 80;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_EXECUTE, 1, seg_cmdsize, 0, 0, false);
        TestSection64Desc s;
        s.sectname = "__text"; s.segname = "__TEXT";
        s.addr = 0x100001000ULL; s.size = 0x100; s.offset = 0x200; // addr < vmaddr (0x100002000)
        s.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100002000ULL, 0x10000ULL, 0, 0x1000, 7, 5, 0, {s}, false);
        buf.resize(0x2000, 0);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "T6.M5: Section VA before segment vmaddr fails parse");
        ASSERT_TRUE(!parser.getMachOMitigations().segment_stream_complete, "T6.M5: segment_stream_complete is false");
        fs::remove(test_file);
    }

    // T6.M6: Section Extending Beyond Segment vmsize
    {
        std::string test_file = (temp_dir / "test_step6_t6m6_sec_exceeds_vmsize.bin").string();
        uint32_t seg_cmdsize = 72 + 80;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_EXECUTE, 1, seg_cmdsize, 0, 0, false);
        TestSection64Desc s;
        s.sectname = "__text"; s.segname = "__TEXT";
        s.addr = 0x100001800ULL; s.size = 0x1000; s.offset = 0x200; // 0x1800 + 0x1000 = 0x2800 > vmsize (0x1000)
        s.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100001000ULL, 0x1000ULL, 0, 0x1000, 7, 5, 0, {s}, false);
        buf.resize(0x2000, 0);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "T6.M6: Section extending beyond segment vmsize fails parse");
        ASSERT_TRUE(!parser.getMachOMitigations().segment_stream_complete, "T6.M6: segment_stream_complete is false");
        fs::remove(test_file);
    }

    // T6.M7: Section Virtual Range Overflow
    {
        std::string test_file = (temp_dir / "test_step6_t6m7_sec_va_overflow.bin").string();
        uint32_t seg_cmdsize = 72 + 80;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_EXECUTE, 1, seg_cmdsize, 0, 0, false);
        TestSection64Desc s;
        s.sectname = "__text"; s.segname = "__TEXT";
        s.addr = 0xFFFFFFFFFFFFFF00ULL; s.size = 0x200; s.offset = 0x200; // addr + size overflows
        s.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0xFFFFFFFFFFFFFF00ULL, 0x1000ULL, 0, 0x1000, 7, 5, 0, {s}, false);
        buf.resize(0x2000, 0);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "T6.M7: Section virtual range overflow fails parse");
        ASSERT_TRUE(!parser.getMachOMitigations().segment_stream_complete, "T6.M7: segment_stream_complete is false");
        fs::remove(test_file);
    }

    // T6.M8: Zero-Sized Segment with Non-Zero Section
    {
        std::string test_file = (temp_dir / "test_step6_t6m8_zero_segment_nonzero_sec.bin").string();
        uint32_t seg_cmdsize = 72 + 80;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_EXECUTE, 1, seg_cmdsize, 0, 0, false);
        TestSection64Desc s;
        s.sectname = "__text"; s.segname = "__TEXT";
        s.addr = 0x100000000ULL; s.size = 0x100; s.offset = 0; // size > 0 in zero-size segment
        s.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS;
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0, 0, 0, 7, 5, 0, {s}, false);
        buf.resize(0x2000, 0);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "T6.M8: Zero-sized segment with non-zero section fails parse");
        ASSERT_TRUE(!parser.getMachOMitigations().segment_stream_complete, "T6.M8: segment_stream_complete is false");
        fs::remove(test_file);
    }

    // T6.M9: Segment Virtual Range Overflow (64-bit and 32-bit)
    {
        // 64-bit segment virtual overflow
        std::string test_file64 = (temp_dir / "test_step6_t6m9_seg_va_overflow_64.bin").string();
        uint32_t seg_cmdsize = 72;
        auto buf64 = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_EXECUTE, 1, seg_cmdsize, 0, 0, false);
        append_segment64_desc(buf64, LC_SEGMENT_64, "__TEXT", 0xFFFFFFFFFFFFF000ULL, 0x2000ULL, 0, 0x100, 7, 5, 0, {}, false);
        buf64.resize(0x1000, 0);
        write_file(test_file64, buf64);

        MachOParser parser64(test_file64);
        ASSERT_TRUE(!parser64.parse(test_file64), "T6.M9: 64-bit segment virtual range overflow fails parse");
        ASSERT_TRUE(!parser64.getMachOMitigations().segment_stream_complete, "T6.M9: 64-bit segment_stream_complete is false");
        fs::remove(test_file64);

        // 32-bit segment virtual overflow
        std::string test_file32 = (temp_dir / "test_step6_t6m9_seg_va_overflow_32.bin").string();
        uint32_t seg_cmdsize32 = 56;
        auto buf32 = make_macho32_buf(MH_MAGIC, CPU_TYPE_X86, CPU_SUBTYPE_I386_ALL, MH_EXECUTE, 1, seg_cmdsize32, 0, false);
        append_segment32_desc(buf32, LC_SEGMENT, "__TEXT", 0xFFFFF000, 0x2000, 0, 0x100, 7, 5, 0, {}, false);
        buf32.resize(0x1000, 0);
        write_file(test_file32, buf32);

        MachOParser parser32(test_file32);
        ASSERT_TRUE(!parser32.parse(test_file32), "T6.M9: 32-bit segment virtual range overflow fails parse");
        ASSERT_TRUE(!parser32.getMachOMitigations().segment_stream_complete, "T6.M9: 32-bit segment_stream_complete is false");
        fs::remove(test_file32);
    }

    // T6.M10: Segment Fileoff Exceeds Slice Bounds
    {
        std::string test_file = (temp_dir / "test_step6_t6m10_seg_fileoff_exceeds_slice.bin").string();
        uint32_t seg_cmdsize = 72;
        auto buf = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_EXECUTE, 1, seg_cmdsize, 0, 0, false);
        // fileoff = 0x8000, filesize = 0, but total file size = 0x4000 (sliceSize_ = 0x4000)
        append_segment64_desc(buf, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x1000ULL, 0x8000, 0, 7, 5, 0, {}, false);
        buf.resize(0x4000, 0);
        write_file(test_file, buf);

        MachOParser parser(test_file);
        ASSERT_TRUE(!parser.parse(test_file), "T6.M10: Segment fileoff exceeding slice size fails parse even when filesize is zero");
        ASSERT_TRUE(!parser.getMachOMitigations().segment_stream_complete, "T6.M10: segment_stream_complete is false");
        fs::remove(test_file);
    }

    // T6.M11: Segment File Range Overflow (64-bit and 32-bit)
    {
        // 64-bit segment file range overflow
        std::string test_file64 = (temp_dir / "test_step6_t6m11_seg_file_overflow_64.bin").string();
        uint32_t seg_cmdsize = 72;
        auto buf64 = make_macho64_buf(MH_MAGIC_64, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_EXECUTE, 1, seg_cmdsize, 0, 0, false);
        append_segment64_desc(buf64, LC_SEGMENT_64, "__TEXT", 0x100000000ULL, 0x1000ULL, 0xFFFFFFFFFFFFF000ULL, 0x2000ULL, 7, 5, 0, {}, false);
        buf64.resize(0x1000, 0);
        write_file(test_file64, buf64);

        MachOParser parser64(test_file64);
        ASSERT_TRUE(!parser64.parse(test_file64), "T6.M11: 64-bit segment file range overflow fails parse");
        ASSERT_TRUE(!parser64.getMachOMitigations().segment_stream_complete, "T6.M11: 64-bit segment_stream_complete is false");
        fs::remove(test_file64);

        // 32-bit segment file range overflow
        std::string test_file32 = (temp_dir / "test_step6_t6m11_seg_file_overflow_32.bin").string();
        uint32_t seg_cmdsize32 = 56;
        auto buf32 = make_macho32_buf(MH_MAGIC, CPU_TYPE_X86, CPU_SUBTYPE_I386_ALL, MH_EXECUTE, 1, seg_cmdsize32, 0, false);
        append_segment32_desc(buf32, LC_SEGMENT, "__TEXT", 0x1000, 0x1000, 0xFFFFF000, 0x2000, 7, 5, 0, {}, false);
        buf32.resize(0x1000, 0);
        write_file(test_file32, buf32);

        MachOParser parser32(test_file32);
        ASSERT_TRUE(!parser32.parse(test_file32), "T6.M11: 32-bit segment file range overflow fails parse");
        ASSERT_TRUE(!parser32.getMachOMitigations().segment_stream_complete, "T6.M11: 32-bit segment_stream_complete is false");
        fs::remove(test_file32);
    }
}

int main() {
    std::cout << "=== ROPWeaver Phase 2 Step 5.2/5.3/5.6/6: Mach-O Detection, Parsing & Discovery Tests ===\n";

    test_thin_magic_and_endianness();
    test_fat_universal_magic();
    test_cpu_architecture_extraction();
    test_negative_cases();
    test_thin_header_parsing();
    test_macho_parser_errors();
    test_factory_routing();
    test_bitness_cpu_mismatch();

    // Step 5.3 Test Suites
    test_step53_load_command_64_parsing();
    test_step53_load_command_32_parsing();
    test_step53_multiple_sections_and_ordering();
    test_step53_zero_fill_sections();
    test_step53_big_endian_load_commands();
    test_step53_security_and_malformed_inputs();

    // Step 5.4 Test Suites
    test_step54_universal_binaries();

    // Step 5.5 Test Suites
    test_step55_factory_integration();

    // Step 5.6 Test Suites
    test_step56_mitigations();

    // Step 6 Test Suites
    test_step6_gadget_discovery();

    std::cout << "\n============================================================\n";
    std::cout << "Mach-O Test Results: " << g_tests_passed << " Passed, " << g_tests_failed << " Failed\n";
    std::cout << "============================================================\n";

    return (g_tests_failed == 0) ? 0 : 1;
}

