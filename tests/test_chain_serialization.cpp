#include <iostream>
#include <vector>
#include <iomanip>
#include <stdexcept>
#include <cstdint>
#include <sstream>
#include <fstream>
#include <filesystem>
#include "core/rop_chain.h"
#include "core/gadget.h"
#include "core/parsers/elf_defs.h"
#include "core/parsers/file_parser.h"
#include "core/payload_gen.h"
#include "core/chain_builder.h"
#include "core/parsers/macho_defs.h"
#include "core/parsers/macho_parser.h"
#include "core/gadget_finder.h"

// Helper to format byte vector as hex string
static std::string bytes_to_hex(const std::vector<char>& bytes) {
    std::ostringstream oss;
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i > 0) oss << " ";
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(static_cast<unsigned char>(bytes[i]));
    }
    return oss.str();
}

int main() {
    int failures = 0;
    int passed = 0;

    auto assertCond = [&](const std::string& testName, bool condition, const std::string& details = "") {
        if (condition) {
            std::cout << "  [PASS] " << testName << "\n";
            passed++;
        } else {
            std::cerr << "  [FAIL] " << testName << ": " << details << "\n";
            failures++;
        }
    };

    std::cout << "=== Running ROP Chain Architecture-Aware Serialization Unit Tests ===\n\n";

    // -------------------------------------------------------------
    // Test 1: 32-bit Little-Endian Serialization
    // -------------------------------------------------------------
    {
        ROPChain chain;
        Gadget g1; g1.address = 0x11223344ULL;
        chain.add_step(g1, "step 1: pop eax; ret");
        Gadget g2; g2.address = 0x55667788ULL;
        chain.add_step(g2, 0x01020304ULL, "step 2: pop ebx with value");

        std::vector<char> bytes = chain.getPayloadBytes(4, Endianness::Little);
        std::vector<unsigned char> expected = {
            0x44, 0x33, 0x22, 0x11,  // addr1 = 0x11223344 LE
            0x88, 0x77, 0x66, 0x55,  // addr2 = 0x55667788 LE
            0x04, 0x03, 0x02, 0x01   // val2  = 0x01020304 LE
        };

        bool match = (bytes.size() == expected.size());
        if (match) {
            for (size_t i = 0; i < expected.size(); ++i) {
                if (static_cast<unsigned char>(bytes[i]) != expected[i]) {
                    match = false;
                    break;
                }
            }
        }
        assertCond("32-bit Little-Endian byte count is 12", bytes.size() == 12, "Got " + std::to_string(bytes.size()));
        assertCond("32-bit Little-Endian byte sequence matches expected", match,
                   "Got: " + bytes_to_hex(bytes));
    }

    // -------------------------------------------------------------
    // Test 2: 32-bit Big-Endian Serialization
    // -------------------------------------------------------------
    {
        ROPChain chain;
        Gadget g1; g1.address = 0x11223344ULL;
        chain.add_step(g1, "step 1: pop eax; ret");
        Gadget g2; g2.address = 0x55667788ULL;
        chain.add_step(g2, 0x01020304ULL, "step 2: pop ebx with value");

        std::vector<char> bytes = chain.getPayloadBytes(4, Endianness::Big);
        std::vector<unsigned char> expected = {
            0x11, 0x22, 0x33, 0x44,  // addr1 = 0x11223344 BE
            0x55, 0x66, 0x77, 0x88,  // addr2 = 0x55667788 BE
            0x01, 0x02, 0x03, 0x04   // val2  = 0x01020304 BE
        };

        bool match = (bytes.size() == expected.size());
        if (match) {
            for (size_t i = 0; i < expected.size(); ++i) {
                if (static_cast<unsigned char>(bytes[i]) != expected[i]) {
                    match = false;
                    break;
                }
            }
        }
        assertCond("32-bit Big-Endian byte count is 12", bytes.size() == 12, "Got " + std::to_string(bytes.size()));
        assertCond("32-bit Big-Endian byte sequence matches expected", match,
                   "Got: " + bytes_to_hex(bytes));
    }

    // -------------------------------------------------------------
    // Test 3: 64-bit Little-Endian Serialization
    // -------------------------------------------------------------
    {
        ROPChain chain;
        Gadget g1; g1.address = 0x0102030405060708ULL;
        chain.add_step(g1, "step 1: pop rdi; ret");
        Gadget g2; g2.address = 0x1112131415161718ULL;
        chain.add_step(g2, 0x2122232425262728ULL, "step 2: pop rsi with value");

        std::vector<char> bytes = chain.getPayloadBytes(8, Endianness::Little);
        std::vector<unsigned char> expected = {
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,  // addr1 LE
            0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,  // addr2 LE
            0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21   // val2 LE
        };

        bool match = (bytes.size() == expected.size());
        if (match) {
            for (size_t i = 0; i < expected.size(); ++i) {
                if (static_cast<unsigned char>(bytes[i]) != expected[i]) {
                    match = false;
                    break;
                }
            }
        }
        assertCond("64-bit Little-Endian byte count is 24", bytes.size() == 24, "Got " + std::to_string(bytes.size()));
        assertCond("64-bit Little-Endian byte sequence matches expected", match,
                   "Got: " + bytes_to_hex(bytes));
    }

    // -------------------------------------------------------------
    // Test 4: 64-bit Big-Endian Serialization
    // -------------------------------------------------------------
    {
        ROPChain chain;
        Gadget g1; g1.address = 0x0102030405060708ULL;
        chain.add_step(g1, "step 1: pop rdi; ret");
        Gadget g2; g2.address = 0x1112131415161718ULL;
        chain.add_step(g2, 0x2122232425262728ULL, "step 2: pop rsi with value");

        std::vector<char> bytes = chain.getPayloadBytes(8, Endianness::Big);
        std::vector<unsigned char> expected = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,  // addr1 BE
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,  // addr2 BE
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28   // val2 BE
        };

        bool match = (bytes.size() == expected.size());
        if (match) {
            for (size_t i = 0; i < expected.size(); ++i) {
                if (static_cast<unsigned char>(bytes[i]) != expected[i]) {
                    match = false;
                    break;
                }
            }
        }
        assertCond("64-bit Big-Endian byte count is 24", bytes.size() == 24, "Got " + std::to_string(bytes.size()));
        assertCond("64-bit Big-Endian byte sequence matches expected", match,
                   "Got: " + bytes_to_hex(bytes));
    }

    // -------------------------------------------------------------
    // Test 5: 32-bit Overflow Rejection
    // -------------------------------------------------------------
    {
        // 5a. Address exceeds 32 bits
        ROPChain chain_overflow_addr;
        Gadget g_overflow; g_overflow.address = 0x100000000ULL; // 4GB
        chain_overflow_addr.add_step(g_overflow, "exceeds 32-bit addr");

        bool caught_addr = false;
        std::string err_addr;
        try {
            chain_overflow_addr.getPayloadBytes(4, Endianness::Little);
        } catch (const std::runtime_error& e) {
            caught_addr = true;
            err_addr = e.what();
        }
        assertCond("32-bit rejects address exceeding 32-bit range", caught_addr, "Error: " + err_addr);
        assertCond("32-bit address overflow error message identifies condition",
                   err_addr.find("exceeds 32-bit range") != std::string::npos, "Error: " + err_addr);

        // 5b. Value exceeds 32 bits
        ROPChain chain_overflow_val;
        Gadget g_valid; g_valid.address = 0x8048000ULL;
        chain_overflow_val.add_step(g_valid, 0x1FFFFFFFFULL, "exceeds 32-bit value");

        bool caught_val = false;
        std::string err_val;
        try {
            chain_overflow_val.getPayloadBytes(4, Endianness::Big);
        } catch (const std::runtime_error& e) {
            caught_val = true;
            err_val = e.what();
        }
        assertCond("32-bit rejects value exceeding 32-bit range", caught_val, "Error: " + err_val);
        assertCond("32-bit value overflow error message identifies condition",
                   err_val.find("exceeds 32-bit range") != std::string::npos, "Error: " + err_val);

        // 5c. Boundary: 0xFFFFFFFF exactly succeeds for 32-bit
        ROPChain chain_max32;
        Gadget g_max; g_max.address = 0xFFFFFFFFULL;
        chain_max32.add_step(g_max, 0xFFFFFFFFULL, "max 32-bit");
        std::vector<char> bytes_max = chain_max32.getPayloadBytes(4, Endianness::Little);
        assertCond("32-bit accepts boundary 0xFFFFFFFF", bytes_max.size() == 8);
    }

    // -------------------------------------------------------------
    // Test 6: Invalid Word-Size Rejection
    // -------------------------------------------------------------
    {
        ROPChain chain;
        Gadget g; g.address = 0x1000;
        chain.add_step(g, "gadget");

        size_t invalid_sizes[] = { 0, 1, 2, 3, 5, 6, 7, 9, 16 };
        for (size_t sz : invalid_sizes) {
            bool caught = false;
            try {
                chain.getPayloadBytes(sz, Endianness::Little);
            } catch (const std::invalid_argument&) {
                caught = true;
            }
            assertCond("Rejects invalid word size " + std::to_string(sz), caught);
        }
    }

    // -------------------------------------------------------------
    // Test 7: Unknown and Unsupported Endianness Rejection
    // -------------------------------------------------------------
    {
        ROPChain chain;
        Gadget g; g.address = 0x1000;
        chain.add_step(g, "gadget");

        bool caught_unknown = false;
        try {
            chain.getPayloadBytes(8, Endianness::Unknown);
        } catch (const std::invalid_argument&) {
            caught_unknown = true;
        }
        assertCond("Rejects Endianness::Unknown", caught_unknown);

        bool caught_unsupported = false;
        try {
            chain.getPayloadBytes(4, Endianness::Unsupported);
        } catch (const std::invalid_argument&) {
            caught_unsupported = true;
        }
        assertCond("Rejects Endianness::Unsupported", caught_unsupported);
    }

    // -------------------------------------------------------------
    // Test 8: Backward-Compatible No-Argument Overload
    // -------------------------------------------------------------
    {
        ROPChain chain;
        Gadget g1; g1.address = 0x0102030405060708ULL;
        chain.add_step(g1, "step 1");
        Gadget g2; g2.address = 0x1112131415161718ULL;
        chain.add_step(g2, 0x2122232425262728ULL, "step 2");

        std::vector<char> bytes_no_arg = chain.getPayloadBytes();
        std::vector<char> bytes_explicit = chain.getPayloadBytes(8, Endianness::Little);

        assertCond("No-argument overload matches explicit 64-bit Little-Endian",
                   bytes_no_arg == bytes_explicit);
        assertCond("No-argument overload produces 24 bytes", bytes_no_arg.size() == 24);
    }

    // -------------------------------------------------------------
    // Test 9: Empty-Chain Behavior
    // -------------------------------------------------------------
    {
        ROPChain empty;

        assertCond("Empty chain (4, LE) returns empty vector", empty.getPayloadBytes(4, Endianness::Little).empty());
        assertCond("Empty chain (4, BE) returns empty vector", empty.getPayloadBytes(4, Endianness::Big).empty());
        assertCond("Empty chain (8, LE) returns empty vector", empty.getPayloadBytes(8, Endianness::Little).empty());
        assertCond("Empty chain (8, BE) returns empty vector", empty.getPayloadBytes(8, Endianness::Big).empty());
        assertCond("Empty chain no-arg returns empty vector", empty.getPayloadBytes().empty());

        // Parameter validation still occurs on empty chain
        bool caught_empty_inv_size = false;
        try {
            empty.getPayloadBytes(5, Endianness::Little);
        } catch (const std::invalid_argument&) {
            caught_empty_inv_size = true;
        }
        assertCond("Empty chain still validates word size", caught_empty_inv_size);

        bool caught_empty_inv_endian = false;
        try {
            empty.getPayloadBytes(4, Endianness::Unknown);
        } catch (const std::invalid_argument&) {
            caught_empty_inv_endian = true;
        }
        assertCond("Empty chain still validates endianness", caught_empty_inv_endian);
    }

    // -------------------------------------------------------------
    // Test 10: FileParser Integration (MockParser)
    // -------------------------------------------------------------
    {
        class MockFileParser : public FileParser {
            bool m_is64;
            Endianness m_endianness;
            std::string m_arch;
            uint8_t m_osabi = 0;
            uint32_t m_elf_flags = 0;
        public:
            MockFileParser(bool is64, Endianness endian, const std::string& arch,
                           uint8_t osabi = 0, uint32_t elf_flags = 0)
                : FileParser("dummy"), m_is64(is64), m_endianness(endian), m_arch(arch),
                  m_osabi(osabi), m_elf_flags(elf_flags) {}
            bool parse(const std::string&) override { return true; }
            const std::vector<uint8_t>& getTextSection() const override { static std::vector<uint8_t> d; return d; }
            uint64_t getTextSectionBaseAddress() const override { return 0; }
            std::string getArchitecture() const override { return m_arch; }
            bool is64Bit() const override { return m_is64; }
            std::string getBinaryType() const override { return "ELF"; }
            std::string getFilePath() const override { return "dummy"; }
            Endianness getMetadataEndianness() const override { return m_endianness; }
            uint8_t getOsAbi() const override { return m_osabi; }
            uint32_t getElfFlags() const override { return m_elf_flags; }
            void setOsAbi(uint8_t osabi) { m_osabi = osabi; }
            void setElfFlags(uint32_t flags) { m_elf_flags = flags; }
        };

        ROPChain chain32;
        Gadget g1; g1.address = 0x12345678ULL;
        chain32.add_step(g1, 0x0A0B0C0DULL, "step");

        // 10a. 32-bit LE parser (e.g. ARMv7 / x86)
        MockFileParser parser_arm_le(false, Endianness::Little, "armv7");
        std::vector<char> bytes_arm_le = chain32.getPayloadBytes(
            parser_arm_le.is64Bit() ? 8 : 4,
            parser_arm_le.getMetadataEndianness()
        );
        std::vector<unsigned char> exp_arm_le = { 0x78, 0x56, 0x34, 0x12, 0x0D, 0x0C, 0x0B, 0x0A };
        bool match_arm_le = (bytes_arm_le.size() == exp_arm_le.size());
        for (size_t i = 0; match_arm_le && i < exp_arm_le.size(); ++i) {
            if (static_cast<unsigned char>(bytes_arm_le[i]) != exp_arm_le[i]) match_arm_le = false;
        }
        assertCond("MockParser 32-bit LE (ARMv7) produces correct bytes", match_arm_le, "Got: " + bytes_to_hex(bytes_arm_le));

        // 10b. 32-bit BE parser (e.g. ARM BE-8 data endianness)
        MockFileParser parser_arm_be(false, Endianness::Big, "armv7");
        std::vector<char> bytes_arm_be = chain32.getPayloadBytes(
            parser_arm_be.is64Bit() ? 8 : 4,
            parser_arm_be.getMetadataEndianness()
        );
        std::vector<unsigned char> exp_arm_be = { 0x12, 0x34, 0x56, 0x78, 0x0A, 0x0B, 0x0C, 0x0D };
        bool match_arm_be = (bytes_arm_be.size() == exp_arm_be.size());
        for (size_t i = 0; match_arm_be && i < exp_arm_be.size(); ++i) {
            if (static_cast<unsigned char>(bytes_arm_be[i]) != exp_arm_be[i]) match_arm_be = false;
        }
        assertCond("MockParser 32-bit BE (ARMv7 BE-8 data) produces correct bytes", match_arm_be, "Got: " + bytes_to_hex(bytes_arm_be));

        // 10c. 64-bit LE parser (e.g. x86_64)
        ROPChain chain64;
        Gadget g64; g64.address = 0x0102030405060708ULL;
        chain64.add_step(g64, "step");
        MockFileParser parser_x64(true, Endianness::Little, "x86_64");
        std::vector<char> bytes_x64 = chain64.getPayloadBytes(
            parser_x64.is64Bit() ? 8 : 4,
            parser_x64.getMetadataEndianness()
        );
        assertCond("MockParser 64-bit LE (x86_64) produces 8 bytes", bytes_x64.size() == 8);

        // 10d. Unknown endianness parser rejection
        MockFileParser parser_unknown(false, Endianness::Unknown, "unknown");
        bool caught_parser_unknown = false;
        try {
            chain32.getPayloadBytes(
                parser_unknown.is64Bit() ? 8 : 4,
                parser_unknown.getMetadataEndianness()
            );
        } catch (const std::invalid_argument&) {
            caught_parser_unknown = true;
        }
        assertCond("MockParser with Endianness::Unknown is rejected", caught_parser_unknown);
    }

    // -------------------------------------------------------------
    // Test 11: PayloadGenerator Rejection Without Parser Metadata
    // -------------------------------------------------------------
    {
        PayloadGenerator generator;
        ROPChain chain;
        Gadget g; g.address = 0x400000ULL;
        chain.add_step(g, "pop rdi; ret");

        std::string testReportPath = "build-win/test_null_parser_report.json";
        std::string testPayloadBin = "build-win/test_null_parser_payload.bin";
        std::string testPayloadBinReports = "build-win/test_null_parser_reports_payload.bin";

        std::error_code ec;
        std::filesystem::remove(testReportPath, ec);
        std::filesystem::remove(testPayloadBin, ec);
        std::filesystem::remove(testPayloadBinReports, ec);

        // Nonempty chain with parser = nullptr (using isolated temporary test paths)
        generator.generate(chain, 104, "test_binary", {}, "x86_64", "ELF", {}, "TEST-REPORT-ID", "", nullptr,
                           testReportPath, testPayloadBin, testPayloadBinReports);

        // Verify neither payload binary was created on serialization failure
        assertCond("Serialization failure does NOT create test payload.bin",
                   !std::filesystem::exists(testPayloadBin));
        assertCond("Serialization failure does NOT create test reports/payload.bin",
                   !std::filesystem::exists(testPayloadBinReports));

        // Read generated test report to verify serialization failure is recorded accurately
        std::ifstream f(testReportPath);
        assertCond("PayloadGenerator writes report to specified test path", f.is_open());
        if (f.is_open()) {
            nlohmann::json reportJson;
            f >> reportJson;
            f.close();

            std::string rawStatus = reportJson["raw_payload"]["status"].get<std::string>();
            assertCond("PayloadGenerator raw_payload status indicates serialization failure",
                       rawStatus.find("Serialization Failed") != std::string::npos, "Got: " + rawStatus);
            assertCond("PayloadGenerator raw_payload status explains missing parser metadata",
                       rawStatus.find("Target parser metadata is required") != std::string::npos, "Got: " + rawStatus);
            assertCond("PayloadGenerator raw_payload data is null on serialization failure",
                       reportJson["raw_payload"]["data"].is_null());

            std::string chainStatus = reportJson["rop_chain_generation"]["status"].get<std::string>();
            assertCond("PayloadGenerator rop_chain_generation status indicates failure",
                       chainStatus.find("Failed: Payload serialization error") != std::string::npos, "Got: " + chainStatus);

            // Clean up temporary test report
            std::filesystem::remove(testReportPath, ec);
        }
    }

    // -------------------------------------------------------------
    // Test 12: PayloadGenerator reportPath Handling Without Parent Directory
    // -------------------------------------------------------------
    {
        PayloadGenerator generator;
        ROPChain emptyChain;
        std::string simpleName = "test_temp_root_report.json";
        std::error_code ec;
        std::filesystem::remove(simpleName, ec);

        // Generate report with simple filename having no parent directory (suppress binary payload files)
        generator.generate(emptyChain, 104, "test_binary", {}, "x86_64", "ELF", {},
                           "TEST-ID", "", nullptr, simpleName, "", "");

        assertCond("PayloadGenerator handles reportPath with no parent directory",
                   std::filesystem::exists(simpleName));
        std::filesystem::remove(simpleName, ec);
    }

    // -------------------------------------------------------------
    // Test 13: Explicit Chain Step Categories and String Conversion
    // -------------------------------------------------------------
    {
        assertCond("ROPStepType::Unknown string is 'Unknown'",
                   std::string(stepTypeToString(ROPStepType::Unknown)) == "Unknown");
        assertCond("ROPStepType::GadgetExecution string is 'GadgetExecution'",
                   std::string(stepTypeToString(ROPStepType::GadgetExecution)) == "GadgetExecution");
        assertCond("ROPStepType::RegisterAssignment string is 'RegisterAssignment'",
                   std::string(stepTypeToString(ROPStepType::RegisterAssignment)) == "RegisterAssignment");
        assertCond("ROPStepType::SystemCallSetup string is 'SystemCallSetup'",
                   std::string(stepTypeToString(ROPStepType::SystemCallSetup)) == "SystemCallSetup");
        assertCond("ROPStepType::SystemCallExecution string is 'SystemCallExecution'",
                   std::string(stepTypeToString(ROPStepType::SystemCallExecution)) == "SystemCallExecution");
        assertCond("ROPStepType::StackAdjustment string is 'StackAdjustment'",
                   std::string(stepTypeToString(ROPStepType::StackAdjustment)) == "StackAdjustment");
        assertCond("to_string() matches stepTypeToString()",
                   std::string(to_string(ROPStepType::RegisterAssignment)) == "RegisterAssignment");
    }

    // -------------------------------------------------------------
    // Test 14: Overload Compatibility and Deliberate Defaults
    // -------------------------------------------------------------
    {
        ROPChain chain;
        Gadget g1; g1.address = 0x401000ULL;
        Gadget g2; g2.address = 0x402000ULL;

        // Legacy 2-arg call without value
        chain.add_step(g1, "legacy step without value");
        // Legacy 3-arg call with value
        chain.add_step(g2, 0x12345678ULL, "legacy step with value");

        const auto& steps = chain.get_steps();
        assertCond("Chain has 2 steps from legacy calls", steps.size() == 2);
        if (steps.size() == 2) {
            // Check step 1: deliberate default must be GadgetExecution, NOT inferred from has_value
            assertCond("Legacy step without value defaults to GadgetExecution",
                       steps[0].type == ROPStepType::GadgetExecution);
            assertCond("Legacy step without value has has_value == false",
                       !steps[0].has_value);
            assertCond("Legacy step without value preserves comment",
                       steps[0].comment == "legacy step without value");

            // Check step 2: deliberate default must be GadgetExecution, NOT inferred from has_value
            assertCond("Legacy step with value defaults to GadgetExecution",
                       steps[1].type == ROPStepType::GadgetExecution);
            assertCond("Legacy step with value has has_value == true",
                       steps[1].has_value);
            assertCond("Legacy step with value preserves value",
                       steps[1].value == 0x12345678ULL);
            assertCond("Legacy step with value preserves comment",
                       steps[1].comment == "legacy step with value");
        }
    }

    // -------------------------------------------------------------
    // Test 15: Explicit Step Category Overloads
    // -------------------------------------------------------------
    {
        ROPChain chain;
        Gadget gSyscall; gSyscall.address = 0x403000ULL; gSyscall.assembly = "syscall";
        Gadget gStack; gStack.address = 0x404000ULL; gStack.assembly = "add rsp, 0x20; ret";
        Gadget gPopRdi; gPopRdi.address = 0x405000ULL; gPopRdi.assembly = "pop rdi; ret"; gPopRdi.target_register = "rdi";
        Gadget gPopRax; gPopRax.address = 0x406000ULL; gPopRax.assembly = "pop rax; ret"; gPopRax.target_register = "rax";
        Gadget gValExec; gValExec.address = 0x407000ULL; gValExec.assembly = "pop rcx; jmp rax";
        Gadget gUnknown; gUnknown.address = 0x408000ULL; gUnknown.assembly = "nop";

        // add_step(gadget, comment, type)
        chain.add_step(gSyscall, "invoke execve", ROPStepType::SystemCallExecution);

        // add_step(gadget, type, comment)
        chain.add_step(gStack, ROPStepType::StackAdjustment, "shadow space cleanup");

        // add_step(gadget, value, comment, type)
        chain.add_step(gPopRdi, 0x601000ULL, "set rdi to /bin/sh", ROPStepType::RegisterAssignment);

        // add_step(gadget, value, type, comment)
        chain.add_step(gPopRax, 59, ROPStepType::SystemCallSetup, "set rax to sys_execve");

        // Value-bearing GadgetExecution
        chain.add_step(gValExec, 0xdeadbeefULL, "value-bearing gadget execution", ROPStepType::GadgetExecution);

        // Explicit Unknown step
        chain.add_step(gUnknown, "unclassified gadget", ROPStepType::Unknown);

        const auto& steps = chain.get_steps();
        assertCond("Chain has 6 explicitly typed steps", steps.size() == 6);
        if (steps.size() == 6) {
            assertCond("Step 0 type is SystemCallExecution",
                       steps[0].type == ROPStepType::SystemCallExecution && !steps[0].has_value);
            assertCond("Step 1 type is StackAdjustment",
                       steps[1].type == ROPStepType::StackAdjustment && !steps[1].has_value);
            assertCond("Step 2 type is RegisterAssignment",
                       steps[2].type == ROPStepType::RegisterAssignment && steps[2].has_value && steps[2].value == 0x601000ULL);
            assertCond("Step 3 type is SystemCallSetup",
                       steps[3].type == ROPStepType::SystemCallSetup && steps[3].has_value && steps[3].value == 59);
            assertCond("Step 4 type is GadgetExecution with value",
                       steps[4].type == ROPStepType::GadgetExecution && steps[4].has_value && steps[4].value == 0xdeadbeefULL);
            assertCond("Step 5 type is Unknown",
                       steps[5].type == ROPStepType::Unknown && !steps[5].has_value);
        }
    }

    // -------------------------------------------------------------
    // Test 16: JSON Reporting with Explicit Categories
    // -------------------------------------------------------------
    {
        ROPChain chain;
        Gadget gReg; gReg.address = 0x401000ULL; gReg.assembly = "pop rdi; ret"; gReg.target_register = "rdi";
        Gadget gSysSetup; gSysSetup.address = 0x402000ULL; gSysSetup.assembly = "pop rax; ret"; gSysSetup.target_register = "rax";
        Gadget gSysExec; gSysExec.address = 0x403000ULL; gSysExec.assembly = "syscall";
        Gadget gStack; gStack.address = 0x404000ULL; gStack.assembly = "add rsp, 0x20; ret";
        Gadget gGadgetNoVal; gGadgetNoVal.address = 0x405000ULL; gGadgetNoVal.assembly = "xor eax, eax; ret";
        Gadget gGadgetWithVal; gGadgetWithVal.address = 0x406000ULL; gGadgetWithVal.assembly = "pop rcx; ret";
        Gadget gUnk; gUnk.address = 0x407000ULL; gUnk.assembly = "nop";

        chain.add_step(gReg, 0x601000ULL, "set rdi arg", ROPStepType::RegisterAssignment);
        chain.add_step(gSysSetup, 59, "set rax syscall nr", ROPStepType::SystemCallSetup);
        chain.add_step(gSysExec, "trigger syscall", ROPStepType::SystemCallExecution);
        chain.add_step(gStack, "adjust stack", ROPStepType::StackAdjustment);
        chain.add_step(gGadgetNoVal, "generic gadget without value", ROPStepType::GadgetExecution);
        chain.add_step(gGadgetWithVal, 0x1234ULL, "generic gadget with value", ROPStepType::GadgetExecution);
        chain.add_step(gUnk, "unknown gadget", ROPStepType::Unknown);

        nlohmann::json jsonReport = chain.toJson();
        assertCond("JSON report is an array of 7 elements",
                   jsonReport.is_array() && jsonReport.size() == 7);

        if (jsonReport.is_array() && jsonReport.size() == 7) {
            // Check exact "type" string representations
            assertCond("JSON step 0 type is 'RegisterAssignment'",
                       jsonReport[0]["type"].get<std::string>() == "RegisterAssignment");
            assertCond("JSON step 0 semantic_type is 'RegisterAssignment'",
                       jsonReport[0]["semantic_type"].get<std::string>() == "RegisterAssignment");
            assertCond("JSON step 0 value_loaded is hex formatted",
                       jsonReport[0]["value_loaded"].get<std::string>() == "0x0000000000601000");

            assertCond("JSON step 1 type is 'SystemCallSetup'",
                       jsonReport[1]["type"].get<std::string>() == "SystemCallSetup");
            assertCond("JSON step 1 semantic_type is 'SystemCallSetup'",
                       jsonReport[1]["semantic_type"].get<std::string>() == "SystemCallSetup");

            assertCond("JSON step 2 type is 'SystemCallExecution'",
                       jsonReport[2]["type"].get<std::string>() == "SystemCallExecution");
            assertCond("JSON step 2 semantic_type is 'SystemCallExecution'",
                       jsonReport[2]["semantic_type"].get<std::string>() == "SystemCallExecution");
            assertCond("JSON step 2 value_loaded is 'N/A' when no value",
                       jsonReport[2]["value_loaded"].get<std::string>() == "N/A");

            assertCond("JSON step 3 type is 'StackAdjustment'",
                       jsonReport[3]["type"].get<std::string>() == "StackAdjustment");
            assertCond("JSON step 3 semantic_type is 'StackAdjustment'",
                       jsonReport[3]["semantic_type"].get<std::string>() == "StackAdjustment");

            // Step 4: GadgetExecution without value NOT mistakenly labeled "Syscall_Execution"
            assertCond("JSON step 4 (GadgetExecution, no value) type is 'GadgetExecution'",
                       jsonReport[4]["type"].get<std::string>() == "GadgetExecution");

            // Step 5: GadgetExecution with value NOT mistakenly labeled "Register_Load"
            assertCond("JSON step 5 (GadgetExecution, with value) type is 'GadgetExecution'",
                       jsonReport[5]["type"].get<std::string>() == "GadgetExecution");

            // Step 6: Unknown NOT mistakenly labeled "Syscall_Execution"
            assertCond("JSON step 6 (Unknown) type is 'Unknown'",
                       jsonReport[6]["type"].get<std::string>() == "Unknown");

            // Verify standard fields are preserved on every step
            bool allFieldsPresent = true;
            for (size_t i = 0; i < jsonReport.size(); ++i) {
                const auto& item = jsonReport[i];
                if (!item.contains("index") || !item.contains("type") || !item.contains("semantic_type") ||
                    !item.contains("gadget_address") || !item.contains("assembly") ||
                    !item.contains("value_loaded") || !item.contains("register") || !item.contains("comment")) {
                    allFieldsPresent = false;
                    break;
                }
            }
            assertCond("All JSON steps preserve required standard fields", allFieldsPresent);
        }
    }

    // -------------------------------------------------------------
    // Test 17: Serialization Invariance Under Explicit Categories
    // -------------------------------------------------------------
    {
        Gadget g1; g1.address = 0x401000ULL;
        Gadget g2; g2.address = 0x402000ULL;

        // Chain with default category
        ROPChain legacyChain;
        legacyChain.add_step(g1, "step 1");
        legacyChain.add_step(g2, 0x1122334455667788ULL, "step 2");

        // Chain with explicit categories
        ROPChain explicitChain;
        explicitChain.add_step(g1, "step 1", ROPStepType::GadgetExecution);
        explicitChain.add_step(g2, 0x1122334455667788ULL, "step 2", ROPStepType::RegisterAssignment);

        std::vector<char> legacyBytes = legacyChain.getPayloadBytes(8, Endianness::Little);
        std::vector<char> explicitBytes = explicitChain.getPayloadBytes(8, Endianness::Little);

        assertCond("Payload serialization is invariant to explicit step categories",
                   legacyBytes == explicitBytes);
    }

    // -------------------------------------------------------------
    // Test 18: ChainBuilder Explicit Step Category Assignment
    // -------------------------------------------------------------
    {
        auto makePop = [](uint64_t addr, const std::string& reg) {
            Gadget g;
            g.address = addr;
            g.preferred_va = addr;
            g.target_register = reg;
            g.assembly = "pop " + reg + " ; ret";
            g.instructions = {{"pop", reg}, {"ret", ""}};
            return g;
        };

        auto makeInsn = [](uint64_t addr, const std::string& mnem, const std::string& op = "") {
            Gadget g;
            g.address = addr;
            g.preferred_va = addr;
            g.assembly = op.empty() ? mnem : (mnem + " " + op);
            g.instructions = {{mnem, op}};
            return g;
        };

        auto makeShadow = [](uint64_t addr) {
            Gadget g;
            g.address = addr;
            g.preferred_va = addr;
            g.assembly = "add rsp, 0x20 ; ret";
            g.instructions = {{"add", "rsp, 0x20"}, {"ret", ""}};
            return g;
        };

        // 1. Linux x86_64
        {
            std::vector<Gadget> gadgets = {
                makePop(0x401000, "rdi"),
                makePop(0x402000, "rsi"),
                makePop(0x403000, "rdx"),
                makePop(0x404000, "rax"),
                makeInsn(0x405000, "syscall")
            };
            ChainBuilder builder(gadgets, "x86_64", "ELF");
            ROPChain chain = builder.buildExecveChain(0x601000ULL);
            const auto& steps = chain.get_steps();

            assertCond("x86_64 ChainBuilder produces 5 steps", steps.size() == 5);
            if (steps.size() == 5) {
                assertCond("x86_64 step 0 (rdi) is RegisterAssignment",
                           steps[0].type == ROPStepType::RegisterAssignment && steps[0].value == 0x601000ULL);
                assertCond("x86_64 step 1 (rsi) is RegisterAssignment",
                           steps[1].type == ROPStepType::RegisterAssignment && steps[1].value == 0);
                assertCond("x86_64 step 2 (rdx) is RegisterAssignment",
                           steps[2].type == ROPStepType::RegisterAssignment && steps[2].value == 0);
                assertCond("x86_64 step 3 (rax) is SystemCallSetup",
                           steps[3].type == ROPStepType::SystemCallSetup && steps[3].value == 59);
                assertCond("x86_64 step 4 (syscall) is SystemCallExecution",
                           steps[4].type == ROPStepType::SystemCallExecution && !steps[4].has_value);

                nlohmann::json json = chain.toJson();
                assertCond("x86_64 JSON step 0 type is RegisterAssignment",
                           json[0]["type"].get<std::string>() == "RegisterAssignment");
                assertCond("x86_64 JSON step 3 type is SystemCallSetup",
                           json[3]["type"].get<std::string>() == "SystemCallSetup");
                assertCond("x86_64 JSON step 4 type is SystemCallExecution",
                           json[4]["type"].get<std::string>() == "SystemCallExecution");
            }
        }

        // 2. Windows x64 Fastcall (PE)
        {
            std::vector<Gadget> gadgets = {
                makePop(0x140001000, "rcx"),
                makePop(0x140002000, "rdx"),
                makePop(0x140003000, "r8"),
                makePop(0x140004000, "r9"),
                makeShadow(0x140005000)
            };
            ChainBuilder builder(gadgets, "x86_64", "PE");
            ROPChain chain = builder.buildExecveChain(0);
            const auto& steps = chain.get_steps();

            assertCond("Win64 ChainBuilder produces 5 steps", steps.size() == 5);
            if (steps.size() == 5) {
                assertCond("Win64 step 0 (rcx) is RegisterAssignment",
                           steps[0].type == ROPStepType::RegisterAssignment && steps[0].value == 0x10000000);
                assertCond("Win64 step 1 (rdx) is RegisterAssignment",
                           steps[1].type == ROPStepType::RegisterAssignment && steps[1].value == 0x1000);
                assertCond("Win64 step 2 (r8) is RegisterAssignment",
                           steps[2].type == ROPStepType::RegisterAssignment && steps[2].value == 0x40);
                assertCond("Win64 step 3 (r9) is RegisterAssignment",
                           steps[3].type == ROPStepType::RegisterAssignment && steps[3].value == 0x10001000);
                assertCond("Win64 step 4 (shadow adjust) is StackAdjustment",
                           steps[4].type == ROPStepType::StackAdjustment && !steps[4].has_value);

                nlohmann::json json = chain.toJson();
                assertCond("Win64 JSON step 4 type is StackAdjustment",
                           json[4]["type"].get<std::string>() == "StackAdjustment");
            }
        }

        // 3. Linux x86 (32-bit)
        {
            std::vector<Gadget> gadgets = {
                makePop(0x08048100, "eax"),
                makePop(0x08048200, "ebx"),
                makePop(0x08048300, "ecx"),
                makePop(0x08048400, "edx"),
                makeInsn(0x08048500, "int 0x80")
            };
            ChainBuilder builder(gadgets, "x86", "ELF");
            ROPChain chain = builder.buildExecveChain(0x08049000ULL);
            const auto& steps = chain.get_steps();

            assertCond("x86 ChainBuilder produces 5 steps", steps.size() == 5);
            if (steps.size() == 5) {
                assertCond("x86 step 0 (eax) is SystemCallSetup",
                           steps[0].type == ROPStepType::SystemCallSetup && steps[0].value == 11);
                assertCond("x86 step 1 (ebx) is RegisterAssignment",
                           steps[1].type == ROPStepType::RegisterAssignment && steps[1].value == 0x08049000ULL);
                assertCond("x86 step 2 (ecx) is RegisterAssignment",
                           steps[2].type == ROPStepType::RegisterAssignment && steps[2].value == 0);
                assertCond("x86 step 3 (edx) is RegisterAssignment",
                           steps[3].type == ROPStepType::RegisterAssignment && steps[3].value == 0);
                assertCond("x86 step 4 (int 0x80) is SystemCallExecution",
                           steps[4].type == ROPStepType::SystemCallExecution && !steps[4].has_value);
            }
        }

        // 4. Linux AArch64 (64-bit)
        {
            std::vector<Gadget> gadgets = {
                makePop(0x400100, "x0"),
                makePop(0x400200, "x1"),
                makePop(0x400300, "x2"),
                makePop(0x400400, "x8"),
                makeInsn(0x400500, "svc #0")
            };
            ChainBuilder builder(gadgets, "aarch64", "ELF");
            ROPChain chain = builder.buildExecveChain(0x500000ULL);
            const auto& steps = chain.get_steps();

            assertCond("AArch64 ChainBuilder produces 5 steps", steps.size() == 5);
            if (steps.size() == 5) {
                assertCond("AArch64 step 0 (x0) is RegisterAssignment",
                           steps[0].type == ROPStepType::RegisterAssignment && steps[0].value == 0x500000ULL);
                assertCond("AArch64 step 1 (x1) is RegisterAssignment",
                           steps[1].type == ROPStepType::RegisterAssignment && steps[1].value == 0);
                assertCond("AArch64 step 2 (x2) is RegisterAssignment",
                           steps[2].type == ROPStepType::RegisterAssignment && steps[2].value == 0);
                assertCond("AArch64 step 3 (x8) is SystemCallSetup",
                           steps[3].type == ROPStepType::SystemCallSetup && steps[3].value == 221);
                assertCond("AArch64 step 4 (svc #0) is SystemCallExecution",
                           steps[4].type == ROPStepType::SystemCallExecution && !steps[4].has_value);
            }
        }

        // 5. Linux ARMv7 (32-bit)
        {
            std::vector<Gadget> gadgets = {
                makePop(0x10100, "r0"),
                makePop(0x10200, "r1"),
                makePop(0x10300, "r2"),
                makePop(0x10400, "r7"),
                makeInsn(0x10500, "svc #0")
            };
            ChainBuilder builder(gadgets, "armv7", "ELF");
            ROPChain chain = builder.buildExecveChain(0x20000ULL);
            const auto& steps = chain.get_steps();

            assertCond("ARMv7 ChainBuilder produces 5 steps", steps.size() == 5);
            if (steps.size() == 5) {
                assertCond("ARMv7 step 0 (r0) is RegisterAssignment",
                           steps[0].type == ROPStepType::RegisterAssignment && steps[0].value == 0x20000ULL);
                assertCond("ARMv7 step 1 (r1) is RegisterAssignment",
                           steps[1].type == ROPStepType::RegisterAssignment && steps[1].value == 0);
                assertCond("ARMv7 step 2 (r2) is RegisterAssignment",
                           steps[2].type == ROPStepType::RegisterAssignment && steps[2].value == 0);
                assertCond("ARMv7 step 3 (r7) is SystemCallSetup",
                           steps[3].type == ROPStepType::SystemCallSetup && steps[3].value == 11);
                assertCond("ARMv7 step 4 (svc #0) is SystemCallExecution",
                           steps[4].type == ROPStepType::SystemCallExecution && !steps[4].has_value);
            }
        }

        // 6. Linux RISC-V (64-bit / 32-bit)
        {
            std::vector<Gadget> gadgets = {
                makePop(0x20100, "a0"),
                makePop(0x20200, "a1"),
                makePop(0x20300, "a2"),
                makePop(0x20400, "a7"),
                makeInsn(0x20500, "ecall")
            };
            ChainBuilder builder(gadgets, "riscv", "ELF");
            ROPChain chain = builder.buildExecveChain(0x30000ULL);
            const auto& steps = chain.get_steps();

            assertCond("RISC-V ChainBuilder produces 5 steps", steps.size() == 5);
            if (steps.size() == 5) {
                assertCond("RISC-V step 0 (a0) is RegisterAssignment",
                           steps[0].type == ROPStepType::RegisterAssignment && steps[0].value == 0x30000ULL);
                assertCond("RISC-V step 1 (a1) is RegisterAssignment",
                           steps[1].type == ROPStepType::RegisterAssignment && steps[1].value == 0);
                assertCond("RISC-V step 2 (a2) is RegisterAssignment",
                           steps[2].type == ROPStepType::RegisterAssignment && steps[2].value == 0);
                assertCond("RISC-V step 3 (a7) is SystemCallSetup with corrected NR 221",
                           steps[3].type == ROPStepType::SystemCallSetup && steps[3].value == 221);
                assertCond("RISC-V step 4 (ecall) is SystemCallExecution",
                           steps[4].type == ROPStepType::SystemCallExecution && !steps[4].has_value);
            }
        }
    }

    // -------------------------------------------------------------
    // Test 19: Linux Syscall ABI Metadata Audit & Exact Number Assertions
    // -------------------------------------------------------------
    {
        // Independent canonical Linux UAPI constants
        // x86_64: arch/x86/entry/syscalls/syscall_64.tbl -> 59
        constexpr uint64_t ABI_LINUX_X86_64_NR_EXECVE = 59;
        // x86: arch/x86/entry/syscalls/syscall_32.tbl -> 11
        constexpr uint64_t ABI_LINUX_X86_32_NR_EXECVE = 11;
        // AArch64: include/uapi/asm-generic/unistd.h -> 221
        constexpr uint64_t ABI_LINUX_AARCH64_NR_EXECVE = 221;
        // ARM EABI: arch/arm/tools/syscall.tbl -> 11
        constexpr uint64_t ABI_LINUX_ARM_EABI_NR_EXECVE = 11;
        // RISC-V: include/uapi/asm-generic/unistd.h -> 221
        constexpr uint64_t ABI_LINUX_RISCV_NR_EXECVE = 221;

        auto makePop = [](uint64_t addr, const std::string& reg) {
            Gadget g;
            g.address = addr;
            g.preferred_va = addr;
            g.target_register = reg;
            g.assembly = "pop " + reg + " ; ret";
            g.instructions = {{"pop", reg}, {"ret", ""}};
            return g;
        };

        auto makeInsn = [](uint64_t addr, const std::string& mnem, const std::string& op = "") {
            Gadget g;
            g.address = addr;
            g.preferred_va = addr;
            g.assembly = op.empty() ? mnem : (mnem + " " + op);
            g.instructions = {{mnem, op}};
            return g;
        };

        // 1. Verify RISC-V 32-bit and 64-bit variants both produce A7 = 221
        for (const std::string riscvArch : {"riscv", "riscv32", "riscv64"}) {
            std::vector<Gadget> gadgets = {
                makePop(0x20100, "a0"),
                makePop(0x20200, "a1"),
                makePop(0x20300, "a2"),
                makePop(0x20400, "a7"),
                makeInsn(0x20500, "ecall")
            };
            ChainBuilder builder(gadgets, riscvArch, "ELF");
            ROPChain chain = builder.buildExecveChain(0x30000ULL);
            const auto& steps = chain.get_steps();

            assertCond(riscvArch + " ChainBuilder produces 5 steps", steps.size() == 5);
            if (steps.size() == 5) {
                // Assert exact ABI constant
                assertCond(riscvArch + " step 3 uses canonical Linux __NR_execve = 221",
                           steps[3].value == ABI_LINUX_RISCV_NR_EXECVE,
                           "Got: " + std::to_string(steps[3].value));
                assertCond(riscvArch + " step 3 semantic type is SystemCallSetup",
                           steps[3].type == ROPStepType::SystemCallSetup);
                assertCond(riscvArch + " step 3 comment mentions 221",
                           steps[3].comment.find("221") != std::string::npos,
                           "Got: " + steps[3].comment);
                assertCond(riscvArch + " step 3 comment does NOT mention 103",
                           steps[3].comment.find("103") == std::string::npos);

                // Check JSON output
                nlohmann::json json = chain.toJson();
                assertCond(riscvArch + " JSON step 3 type is SystemCallSetup",
                           json[3]["type"].get<std::string>() == "SystemCallSetup");
                assertCond(riscvArch + " JSON step 3 value_loaded is 0x00000000000000dd (221)",
                           json[3]["value_loaded"].get<std::string>() == "0x00000000000000dd");

                // Check ordering: a0, a1, a2 (args) -> a7 (syscall nr) -> ecall
                assertCond(riscvArch + " step ordering preserves execution flow",
                           steps[0].type == ROPStepType::RegisterAssignment &&
                           steps[1].type == ROPStepType::RegisterAssignment &&
                           steps[2].type == ROPStepType::RegisterAssignment &&
                           steps[3].type == ROPStepType::SystemCallSetup &&
                           steps[4].type == ROPStepType::SystemCallExecution);
            }
        }

        // 2. Verify Linux x86_64 matches canonical ABI constant (RAX = 59)
        {
            std::vector<Gadget> gadgets = {
                makePop(0x401000, "rdi"),
                makePop(0x402000, "rsi"),
                makePop(0x403000, "rdx"),
                makePop(0x404000, "rax"),
                makeInsn(0x405000, "syscall")
            };
            ChainBuilder builder(gadgets, "x86_64", "ELF");
            ROPChain chain = builder.buildExecveChain(0x601000ULL);
            const auto& steps = chain.get_steps();
            assertCond("x86_64 matches canonical Linux __NR_execve = 59",
                       steps[3].value == ABI_LINUX_X86_64_NR_EXECVE && steps[3].type == ROPStepType::SystemCallSetup);
        }

        // 3. Verify Linux x86 32-bit matches canonical ABI constant (EAX = 11)
        {
            std::vector<Gadget> gadgets = {
                makePop(0x08048100, "eax"),
                makePop(0x08048200, "ebx"),
                makePop(0x08048300, "ecx"),
                makePop(0x08048400, "edx"),
                makeInsn(0x08048500, "int 0x80")
            };
            ChainBuilder builder(gadgets, "x86", "ELF");
            ROPChain chain = builder.buildExecveChain(0x08049000ULL);
            const auto& steps = chain.get_steps();
            assertCond("x86 matches canonical Linux __NR_execve = 11",
                       steps[0].value == ABI_LINUX_X86_32_NR_EXECVE && steps[0].type == ROPStepType::SystemCallSetup);
        }

        // 4. Verify Linux AArch64 matches canonical ABI constant (X8 = 221)
        {
            std::vector<Gadget> gadgets = {
                makePop(0x400100, "x0"),
                makePop(0x400200, "x1"),
                makePop(0x400300, "x2"),
                makePop(0x400400, "x8"),
                makeInsn(0x400500, "svc #0")
            };
            ChainBuilder builder(gadgets, "aarch64", "ELF");
            ROPChain chain = builder.buildExecveChain(0x500000ULL);
            const auto& steps = chain.get_steps();
            assertCond("AArch64 matches canonical Linux __NR_execve = 221",
                       steps[3].value == ABI_LINUX_AARCH64_NR_EXECVE && steps[3].type == ROPStepType::SystemCallSetup);
        }

        // 5. Verify Linux ARMv7 (EABI) matches canonical ABI constant (R7 = 11)
        {
            std::vector<Gadget> gadgets = {
                makePop(0x10100, "r0"),
                makePop(0x10200, "r1"),
                makePop(0x10300, "r2"),
                makePop(0x10400, "r7"),
                makeInsn(0x10500, "svc #0")
            };
            ChainBuilder builder(gadgets, "armv7", "ELF");
            ROPChain chain = builder.buildExecveChain(0x20000ULL);
            const auto& steps = chain.get_steps();
            assertCond("ARMv7 matches canonical Linux ARM EABI __NR_execve = 11",
                       steps[3].value == ABI_LINUX_ARM_EABI_NR_EXECVE && steps[3].type == ROPStepType::SystemCallSetup);
        }
    }

    // -------------------------------------------------------------
    // Test 20: Architecture ABI Validation, Discrimination, and Rejection
    // -------------------------------------------------------------
    {
        class TestAbiParser : public FileParser {
            bool m_is64;
            std::string m_arch;
            uint8_t m_osabi;
            uint32_t m_elf_flags;
        public:
            TestAbiParser(bool is64, const std::string& arch, uint8_t osabi, uint32_t flags)
                : FileParser("abi_test"), m_is64(is64), m_arch(arch), m_osabi(osabi), m_elf_flags(flags) {}
            bool parse(const std::string&) override { return true; }
            const std::vector<uint8_t>& getTextSection() const override { static std::vector<uint8_t> d; return d; }
            uint64_t getTextSectionBaseAddress() const override { return 0; }
            std::string getArchitecture() const override { return m_arch; }
            bool is64Bit() const override { return m_is64; }
            std::string getBinaryType() const override { return "ELF"; }
            std::string getFilePath() const override { return "abi_test"; }
            uint8_t getOsAbi() const override { return m_osabi; }
            uint32_t getElfFlags() const override { return m_elf_flags; }
            bool isArmEabi() const override {
                if (m_arch != "armv7") return false;
                uint32_t ver = m_elf_flags & ropweaver::EF_ARM_EABIMASK;
                return (ver == ropweaver::EF_ARM_EABI_VER1 || ver == ropweaver::EF_ARM_EABI_VER2 ||
                        ver == ropweaver::EF_ARM_EABI_VER3 || ver == ropweaver::EF_ARM_EABI_VER4 ||
                        ver == ropweaver::EF_ARM_EABI_VER5);
            }
        };

        auto makePop = [](uint64_t addr, const std::string& reg) {
            Gadget g;
            g.address = addr;
            g.preferred_va = addr;
            g.target_register = reg;
            g.assembly = "pop " + reg + " ; ret";
            g.instructions = {{"pop", reg}, {"ret", ""}};
            return g;
        };

        auto makeInsn = [](uint64_t addr, const std::string& mnem, const std::string& op = "") {
            Gadget g;
            g.address = addr;
            g.preferred_va = addr;
            g.assembly = op.empty() ? mnem : (mnem + " " + op);
            g.instructions = {{mnem, op}};
            return g;
        };

        std::vector<Gadget> armGadgets = {
            makePop(0x10100, "r0"),
            makePop(0x10200, "r1"),
            makePop(0x10300, "r2"),
            makePop(0x10400, "r7"),
            makeInsn(0x10500, "svc #0")
        };

        std::vector<Gadget> riscvGadgets = {
            makePop(0x20100, "a0"),
            makePop(0x20200, "a1"),
            makePop(0x20300, "a2"),
            makePop(0x20400, "a7"),
            makeInsn(0x20500, "ecall")
        };

        // 1. ARMv7 with EABI version 5 (standard modern ARM Linux): accepted
        {
            TestAbiParser parser(false, "armv7", ropweaver::ELFOSABI_NONE, ropweaver::EF_ARM_EABI_VER5);
            ChainBuilder builder(armGadgets, "armv7", "ELF", &parser);
            ROPChain chain = builder.buildExecveChain(0x10000ULL);
            assertCond("ARMv7 with EF_ARM_EABI_VER5 is accepted", chain.get_steps().size() == 5);
            assertCond("ARMv7 parser isArmEabi() returns true for EF_ARM_EABI_VER5", parser.isArmEabi());
        }

        // 1b. ARMv7 EABI versions 1-4 are also accepted
        {
            for (uint32_t ver : {ropweaver::EF_ARM_EABI_VER1, ropweaver::EF_ARM_EABI_VER2,
                                 ropweaver::EF_ARM_EABI_VER3, ropweaver::EF_ARM_EABI_VER4}) {
                TestAbiParser parser(false, "armv7", ropweaver::ELFOSABI_NONE, ver);
                ChainBuilder builder(armGadgets, "armv7", "ELF", &parser);
                ROPChain chain = builder.buildExecveChain(0x10000ULL);
                assertCond("ARMv7 with EABI version 1-4 is accepted", chain.get_steps().size() == 5 && parser.isArmEabi());
            }
        }

        // 2. ARMv7 with unknown/unsupported ARM ABI (EABI version 0): rejected with descriptive error
        {
            TestAbiParser parser(false, "armv7", ropweaver::ELFOSABI_NONE, ropweaver::EF_ARM_EABI_UNKNOWN);
            assertCond("ARMv7 parser isArmEabi() returns false for unknown/unsupported ABI", !parser.isArmEabi());
            ChainBuilder builder(armGadgets, "armv7", "ELF", &parser);
            bool caught = false;
            std::string errMsg;
            try {
                builder.buildExecveChain(0x10000ULL);
            } catch (const std::runtime_error& e) {
                caught = true;
                errMsg = e.what();
            }
            assertCond("ARMv7 unknown or unsupported ARM ABI is rejected", caught);
            assertCond("ARMv7 ABI diagnostic identifies unknown or unsupported condition",
                       errMsg.find("unknown or unsupported ARM EABI version") != std::string::npos && errMsg.find("ARM EABI") != std::string::npos,
                       "Got: " + errMsg);
        }

        // 2b. ARMv7 with unrecognized EABI version (e.g. version 6): rejected
        {
            TestAbiParser parser(false, "armv7", ropweaver::ELFOSABI_NONE, 0x06000000);
            assertCond("ARMv7 parser isArmEabi() returns false for unrecognized version", !parser.isArmEabi());
            ChainBuilder builder(armGadgets, "armv7", "ELF", &parser);
            bool caught = false;
            try {
                builder.buildExecveChain(0x10000ULL);
            } catch (const std::runtime_error&) {
                caught = true;
            }
            assertCond("ARMv7 unrecognized ARM EABI version is rejected", caught);
        }

        // 3. ARMv7 with non-Linux OSABI (e.g. FreeBSD): rejected with descriptive error
        {
            TestAbiParser parser(false, "armv7", ropweaver::ELFOSABI_FREEBSD, ropweaver::EF_ARM_EABI_VER5);
            ChainBuilder builder(armGadgets, "armv7", "ELF", &parser);
            bool caught = false;
            std::string errMsg;
            try {
                builder.buildExecveChain(0x10000ULL);
            } catch (const std::runtime_error& e) {
                caught = true;
                errMsg = e.what();
            }
            assertCond("ARMv7 non-Linux OSABI is rejected", caught);
            assertCond("ARMv7 non-Linux OSABI diagnostic identifies condition",
                       errMsg.find("Non-Linux ARM OSABI") != std::string::npos,
                       "Got: " + errMsg);
        }

        // 4. RISC-V with standard Linux ABI (ELFOSABI_NONE): accepted
        {
            TestAbiParser parser(true, "riscv64", ropweaver::ELFOSABI_NONE, 0);
            ChainBuilder builder(riscvGadgets, "riscv64", "ELF", &parser);
            ROPChain chain = builder.buildExecveChain(0x20000ULL);
            assertCond("RISC-V with ELFOSABI_NONE is accepted",
                       chain.get_steps().size() == 5 && chain.get_steps()[3].value == 221);
        }

        // 5. RISC-V with Linux GNU ABI (ELFOSABI_GNU): accepted
        {
            TestAbiParser parser(true, "riscv64", ropweaver::ELFOSABI_GNU, 0);
            ChainBuilder builder(riscvGadgets, "riscv64", "ELF", &parser);
            ROPChain chain = builder.buildExecveChain(0x20000ULL);
            assertCond("RISC-V with ELFOSABI_GNU is accepted",
                       chain.get_steps().size() == 5 && chain.get_steps()[3].value == 221);
        }

        // 6. RISC-V with RVE embedded ISA (16 registers, A7/X17 does not exist): rejected
        {
            TestAbiParser parser(false, "riscv32", ropweaver::ELFOSABI_NONE, ropweaver::EF_RISCV_RVE);
            ChainBuilder builder(riscvGadgets, "riscv32", "ELF", &parser);
            bool caught = false;
            std::string errMsg;
            try {
                builder.buildExecveChain(0x20000ULL);
            } catch (const std::runtime_error& e) {
                caught = true;
                errMsg = e.what();
            }
            assertCond("RISC-V RVE embedded variant is rejected", caught);
            assertCond("RISC-V RVE diagnostic identifies 16 registers and A7 absence",
                       errMsg.find("RVE embedded ABI") != std::string::npos && errMsg.find("16 registers") != std::string::npos,
                       "Got: " + errMsg);
        }

        // 7. RISC-V with Standalone / bare-metal embedded (ELFOSABI_STANDALONE): rejected
        {
            TestAbiParser parser(true, "riscv64", ropweaver::ELFOSABI_STANDALONE, 0);
            ChainBuilder builder(riscvGadgets, "riscv64", "ELF", &parser);
            bool caught = false;
            std::string errMsg;
            try {
                builder.buildExecveChain(0x20000ULL);
            } catch (const std::runtime_error& e) {
                caught = true;
                errMsg = e.what();
            }
            assertCond("RISC-V bare-metal ELFOSABI_STANDALONE is rejected", caught);
            assertCond("RISC-V bare-metal diagnostic identifies bare-metal condition",
                       errMsg.find("ELFOSABI_STANDALONE") != std::string::npos && errMsg.find("bare-metal") != std::string::npos,
                       "Got: " + errMsg);
        }

        // 8. RISC-V with non-Linux OSABI (e.g. OpenBSD): rejected
        {
            TestAbiParser parser(true, "riscv64", ropweaver::ELFOSABI_OPENBSD, 0);
            ChainBuilder builder(riscvGadgets, "riscv64", "ELF", &parser);
            bool caught = false;
            std::string errMsg;
            try {
                builder.buildExecveChain(0x20000ULL);
            } catch (const std::runtime_error& e) {
                caught = true;
                errMsg = e.what();
            }
            assertCond("RISC-V non-Linux OSABI is rejected", caught);
            assertCond("RISC-V non-Linux OSABI non-Linux diagnostic",
                       errMsg.find("non-Linux RISC-V OSABI") != std::string::npos,
                       "Got: " + errMsg);
        }
    }

    // -------------------------------------------------------------
    // Test 21: Deterministic Semantic ROP Chain Validation
    // -------------------------------------------------------------
    {
        class ValidationMockParser : public FileParser {
            bool m_is64;
            std::string m_arch;
            uint8_t m_osabi;
            uint32_t m_elf_flags;
        public:
            ValidationMockParser(bool is64, const std::string& arch, uint8_t osabi = 0, uint32_t flags = 0)
                : FileParser("validation_test"), m_is64(is64), m_arch(arch), m_osabi(osabi), m_elf_flags(flags) {}
            bool parse(const std::string&) override { return true; }
            const std::vector<uint8_t>& getTextSection() const override { static std::vector<uint8_t> d; return d; }
            uint64_t getTextSectionBaseAddress() const override { return 0; }
            std::string getArchitecture() const override { return m_arch; }
            bool is64Bit() const override { return m_is64; }
            std::string getBinaryType() const override { return "ELF"; }
            std::string getFilePath() const override { return "validation_test"; }
            uint8_t getOsAbi() const override { return m_osabi; }
            uint32_t getElfFlags() const override { return m_elf_flags; }
            Endianness getMetadataEndianness() const override { return Endianness::Little; }
            bool isArmEabi() const override {
                if (m_arch != "armv7") return false;
                uint32_t ver = m_elf_flags & ropweaver::EF_ARM_EABIMASK;
                return (ver == ropweaver::EF_ARM_EABI_VER1 || ver == ropweaver::EF_ARM_EABI_VER2 ||
                        ver == ropweaver::EF_ARM_EABI_VER3 || ver == ropweaver::EF_ARM_EABI_VER4 ||
                        ver == ropweaver::EF_ARM_EABI_VER5);
            }
        };

        auto makePop = [](uint64_t addr, const std::string& reg) {
            Gadget g;
            g.address = addr;
            g.preferred_va = addr;
            g.target_register = reg;
            g.assembly = "pop " + reg + " ; ret";
            g.instructions = {{"pop", reg}, {"ret", ""}};
            g.registers_modified = {reg};
            return g;
        };

        auto makeAarch64Pop = [](uint64_t addr, const std::string& reg) {
            Gadget g;
            g.address = addr;
            g.preferred_va = addr;
            g.target_register = reg;
            g.assembly = "ldr " + reg + ", [sp], #8 ; ldr x30, [sp], #8 ; ret";
            g.instructions = {{"ldr", reg + ", [sp], #8"}, {"ldr", "x30, [sp], #8"}, {"ret", ""}};
            g.registers_modified = {reg, "x30"};
            return g;
        };

        auto makeRiscvPop = [](uint64_t addr, const std::string& reg) {
            Gadget g;
            g.address = addr;
            g.preferred_va = addr;
            g.target_register = reg;
            g.assembly = "ld " + reg + ", 0(sp) ; ld ra, 8(sp) ; addi sp, sp, 16 ; ret";
            g.instructions = {{"ld", reg + ", 0(sp)"}, {"ld", "ra, 8(sp)"}, {"addi", "sp, sp, 16"}, {"ret", ""}};
            g.registers_modified = {reg, "ra"};
            return g;
        };

        auto makeRiscv32Pop = [](uint64_t addr, const std::string& reg) {
            Gadget g;
            g.address = addr;
            g.preferred_va = addr;
            g.target_register = reg;
            g.assembly = "lw " + reg + ", 0(sp) ; lw ra, 4(sp) ; addi sp, sp, 8 ; ret";
            g.instructions = {{"lw", reg + ", 0(sp)"}, {"lw", "ra, 4(sp)"}, {"addi", "sp, sp, 8"}, {"ret", ""}};
            g.registers_modified = {reg, "ra"};
            return g;
        };

        auto makeInsn = [](uint64_t addr, const std::string& mnem, const std::string& op = "") {
            Gadget g;
            g.address = addr;
            g.preferred_va = addr;
            g.assembly = op.empty() ? mnem : (mnem + " " + op);
            g.instructions = {{mnem, op}};
            return g;
        };

        // 21.1 Valid reference chains for all 5 architectures
        {
            // x86_64
            {
                std::vector<Gadget> g = {
                    makePop(0x401000, "rdi"), makePop(0x402000, "rsi"),
                    makePop(0x403000, "rdx"), makePop(0x404000, "rax"),
                    makeInsn(0x405000, "syscall")
                };
                ChainBuilder b(g, "x86_64", "ELF");
                ROPChain c = b.buildExecveChain(0x601000ULL);
                auto res = c.validate("x86_64");
                assertCond("21.1a Canonical x86_64 chain passes semantic validation", res.valid);
                assertCond("21.1a x86_64 validation result has all required flags set",
                           res.has_arg1 && res.has_arg2 && res.has_arg3 && res.has_syscall_setup && res.has_syscall_exec);
            }
            // x86
            {
                std::vector<Gadget> g = {
                    makePop(0x101000, "eax"), makePop(0x102000, "ebx"),
                    makePop(0x103000, "ecx"), makePop(0x104000, "edx"),
                    makeInsn(0x105000, "int", "0x80")
                };
                ChainBuilder b(g, "x86", "ELF");
                ROPChain c = b.buildExecveChain(0x108000ULL);
                auto res = c.validate("x86");
                assertCond("21.1b Canonical x86 chain passes semantic validation", res.valid);
            }
            // aarch64
            {
                std::vector<Gadget> g = {
                    makeAarch64Pop(0x401000, "x0"), makeAarch64Pop(0x402000, "x1"),
                    makeAarch64Pop(0x403000, "x2"), makeAarch64Pop(0x404000, "x8"),
                    makeInsn(0x405000, "svc", "#0")
                };
                ChainBuilder b(g, "aarch64", "ELF");
                ROPChain c = b.buildExecveChain(0x501000ULL);
                auto res = c.validate("aarch64");
                assertCond("21.1c Canonical AArch64 chain passes semantic validation", res.valid);
            }
            // armv7
            {
                std::vector<Gadget> g = {
                    makePop(0x10100, "r0"), makePop(0x10200, "r1"),
                    makePop(0x10300, "r2"), makePop(0x10400, "r7"),
                    makeInsn(0x10500, "svc", "#0")
                };
                ValidationMockParser armParser(false, "armv7", ropweaver::ELFOSABI_NONE, ropweaver::EF_ARM_EABI_VER5);
                ChainBuilder b(g, "armv7", "ELF", &armParser);
                ROPChain c = b.buildExecveChain(0x20000ULL);
                auto res = c.validate("armv7", &armParser);
                assertCond("21.1d Canonical ARMv7 chain passes semantic validation", res.valid);
            }
            // riscv64
            {
                std::vector<Gadget> g = {
                    makeRiscvPop(0x201000, "a0"), makeRiscvPop(0x202000, "a1"),
                    makeRiscvPop(0x203000, "a2"), makeRiscvPop(0x204000, "a7"),
                    makeInsn(0x205000, "ecall")
                };
                ValidationMockParser rvParser(true, "riscv64", ropweaver::ELFOSABI_NONE, 0);
                ChainBuilder b(g, "riscv64", "ELF", &rvParser);
                ROPChain c = b.buildExecveChain(0x301000ULL);
                auto res = c.validate("riscv64", &rvParser);
                assertCond("21.1e Canonical RISC-V 64 chain passes semantic validation", res.valid);
            }
            // riscv32
            {
                std::vector<Gadget> g = {
                    makeRiscv32Pop(0x101000, "a0"), makeRiscv32Pop(0x102000, "a1"),
                    makeRiscv32Pop(0x103000, "a2"), makeRiscv32Pop(0x104000, "a7"),
                    makeInsn(0x105000, "ecall")
                };
                ValidationMockParser rv32Parser(false, "riscv32", ropweaver::ELFOSABI_NONE, 0);
                ChainBuilder b(g, "riscv32", "ELF", &rv32Parser);
                ROPChain c = b.buildExecveChain(0x108000ULL);
                auto res = c.validate("riscv32", &rv32Parser);
                assertCond("21.1f Canonical RISC-V 32 chain passes semantic validation", res.valid);
                assertCond("21.1f RISC-V 32 validation result has all required flags set",
                           res.has_arg1 && res.has_arg2 && res.has_arg3 && res.has_syscall_setup && res.has_syscall_exec);
                assertCond("21.1f RISC-V 32 bounds verified", res.bounds_verified);
            }
        }

        // 21.2 Missing staged value (has_value == false) rejected
        {
            ROPChain c;
            c.add_step(makePop(0x401000, "rdi"), "load rdi without value", ROPStepType::RegisterAssignment, "rdi");
            auto res = c.validate("x86_64");
            assertCond("21.2 Missing staged value rejected", !res.valid && res.error_message.find("missing an explicitly staged value") != std::string::npos);
        }

        // 21.3 Incorrect argument values (non-zero Arg2 / Arg3) rejected
        {
            ROPChain c;
            c.add_step(makePop(0x401000, "rdi"), 0x601000ULL, "rdi", ROPStepType::RegisterAssignment, "rdi");
            c.add_step(makePop(0x402000, "rsi"), 0x1234ULL, "rsi non-zero", ROPStepType::RegisterAssignment, "rsi");
            c.add_step(makePop(0x403000, "rdx"), 0, "rdx", ROPStepType::RegisterAssignment, "rdx");
            c.add_step(makePop(0x404000, "rax"), 59, "rax", ROPStepType::SystemCallSetup, "rax");
            c.add_step(makeInsn(0x405000, "syscall"), "syscall", ROPStepType::SystemCallExecution);
            auto res = c.validate("x86_64");
            assertCond("21.3a Non-zero Arg2 rejected", !res.valid && res.error_message.find("Arg 2") != std::string::npos && res.error_message.find("NULL") != std::string::npos);

            ROPChain c3;
            c3.add_step(makePop(0x401000, "rdi"), 0x601000ULL, "rdi", ROPStepType::RegisterAssignment, "rdi");
            c3.add_step(makePop(0x402000, "rsi"), 0, "rsi", ROPStepType::RegisterAssignment, "rsi");
            c3.add_step(makePop(0x403000, "rdx"), 0x5678ULL, "rdx non-zero", ROPStepType::RegisterAssignment, "rdx");
            c3.add_step(makePop(0x404000, "rax"), 59, "rax", ROPStepType::SystemCallSetup, "rax");
            c3.add_step(makeInsn(0x405000, "syscall"), "syscall", ROPStepType::SystemCallExecution);
            auto res3 = c3.validate("x86_64");
            assertCond("21.3b Non-zero Arg3 rejected", !res3.valid && res3.error_message.find("Arg 3") != std::string::npos && res3.error_message.find("NULL") != std::string::npos);
        }

        // 21.4 Null Arg 1 rejected
        {
            ROPChain c;
            c.add_step(makePop(0x401000, "rdi"), 0, "rdi null", ROPStepType::RegisterAssignment, "rdi");
            c.add_step(makePop(0x402000, "rsi"), 0, "rsi", ROPStepType::RegisterAssignment, "rsi");
            c.add_step(makePop(0x403000, "rdx"), 0, "rdx", ROPStepType::RegisterAssignment, "rdx");
            c.add_step(makePop(0x404000, "rax"), 59, "rax", ROPStepType::SystemCallSetup, "rax");
            c.add_step(makeInsn(0x405000, "syscall"), "syscall", ROPStepType::SystemCallExecution);
            auto res = c.validate("x86_64");
            assertCond("21.4 Null Arg 1 rejected", !res.valid && res.error_message.find("non-zero pointer") != std::string::npos);
        }

        // 21.5 Incorrect syscall number rejected
        {
            ROPChain c;
            c.add_step(makePop(0x401000, "rdi"), 0x601000ULL, "rdi", ROPStepType::RegisterAssignment, "rdi");
            c.add_step(makePop(0x402000, "rsi"), 0, "rsi", ROPStepType::RegisterAssignment, "rsi");
            c.add_step(makePop(0x403000, "rdx"), 0, "rdx", ROPStepType::RegisterAssignment, "rdx");
            c.add_step(makePop(0x404000, "rax"), 60, "rax incorrect nr", ROPStepType::SystemCallSetup, "rax");
            c.add_step(makeInsn(0x405000, "syscall"), "syscall", ROPStepType::SystemCallExecution);
            auto res = c.validate("x86_64");
            assertCond("21.5 Incorrect syscall number rejected", !res.valid && res.error_message.find("Syscall number mismatch") != std::string::npos);
        }

        // 21.6 Target-register mismatch rejected
        {
            ROPChain c;
            // Declared target register is "rdi" but gadget instruction is "pop rsi"
            Gadget gMismatch = makePop(0x401000, "rsi");
            c.add_step(gMismatch, 0x601000ULL, "mismatch rdi vs rsi", ROPStepType::RegisterAssignment, "rdi");
            c.add_step(makePop(0x402000, "rsi"), 0, "rsi", ROPStepType::RegisterAssignment, "rsi");
            c.add_step(makePop(0x403000, "rdx"), 0, "rdx", ROPStepType::RegisterAssignment, "rdx");
            c.add_step(makePop(0x404000, "rax"), 59, "rax", ROPStepType::SystemCallSetup, "rax");
            c.add_step(makeInsn(0x405000, "syscall"), "syscall", ROPStepType::SystemCallExecution);
            auto res = c.validate("x86_64");
            assertCond("21.6 Target register mismatch rejected", !res.valid && res.error_message.find("target register") != std::string::npos);
        }

        // 21.7 Unknown register effects rejected
        {
            ROPChain c;
            Gadget gUnk;
            gUnk.address = 0x401000;
            gUnk.assembly = "unknown_insn rdi ; ret";
            gUnk.instructions = {{"unknown_insn", "rdi"}, {"ret", ""}};
            c.add_step(gUnk, 0x601000ULL, "unknown instr effect", ROPStepType::RegisterAssignment, "rdi");
            auto res = c.validate("x86_64");
            assertCond("21.7 Unknown register effects rejected", !res.valid && res.error_message.find("cannot be established reliably") != std::string::npos);
        }

        // 21.8 Register clobbers across relevant step types rejected
        {
            ROPChain c;
            c.add_step(makePop(0x401000, "rdi"), 0x601000ULL, "rdi", ROPStepType::RegisterAssignment, "rdi");
            c.add_step(makePop(0x402000, "rsi"), 0, "rsi", ROPStepType::RegisterAssignment, "rsi");
            // Interleaved GadgetExecution clobbering rdi
            Gadget gClobber = makePop(0x406000, "rdi");
            c.add_step(gClobber, "generic gadget clobbering rdi", ROPStepType::GadgetExecution);
            c.add_step(makePop(0x403000, "rdx"), 0, "rdx", ROPStepType::RegisterAssignment, "rdx");
            c.add_step(makePop(0x404000, "rax"), 59, "rax", ROPStepType::SystemCallSetup, "rax");
            c.add_step(makeInsn(0x405000, "syscall"), "syscall", ROPStepType::SystemCallExecution);
            auto res = c.validate("x86_64");
            assertCond("21.8 Interleaved gadget clobbering staged register rejected", !res.valid && res.error_message.find("clobbers previously staged register") != std::string::npos);
        }

        // 21.9 Pre-trap register clobber in syscall gadget rejected
        {
            ROPChain c;
            c.add_step(makePop(0x401000, "rdi"), 0x601000ULL, "rdi", ROPStepType::RegisterAssignment, "rdi");
            c.add_step(makePop(0x402000, "rsi"), 0, "rsi", ROPStepType::RegisterAssignment, "rsi");
            c.add_step(makePop(0x403000, "rdx"), 0, "rdx", ROPStepType::RegisterAssignment, "rdx");
            c.add_step(makePop(0x404000, "rax"), 59, "rax", ROPStepType::SystemCallSetup, "rax");
            // Syscall gadget with instructions before syscall that clobber rdi
            Gadget gPreTrap;
            gPreTrap.address = 0x405000;
            gPreTrap.assembly = "xor rdi, rdi ; syscall";
            gPreTrap.instructions = {{"xor", "rdi, rdi"}, {"syscall", ""}};
            c.add_step(gPreTrap, "pretrap clobber", ROPStepType::SystemCallExecution);
            auto res = c.validate("x86_64");
            assertCond("21.9 Pre-trap register clobber rejected", !res.valid && res.error_message.find("clobbers") != std::string::npos);
        }

        // 21.10 Multi-pop stack desynchronization rejected
        {
            ROPChain c;
            Gadget gMultiPop;
            gMultiPop.address = 0x401000;
            gMultiPop.assembly = "pop rdi ; pop rbp ; ret";
            gMultiPop.instructions = {{"pop", "rdi"}, {"pop", "rbp"}, {"ret", ""}};
            gMultiPop.target_register = "rdi";
            c.add_step(gMultiPop, 0x601000ULL, "multi-pop", ROPStepType::RegisterAssignment, "rdi");
            c.add_step(makePop(0x402000, "rsi"), 0, "rsi", ROPStepType::RegisterAssignment, "rsi");
            c.add_step(makePop(0x403000, "rdx"), 0, "rdx", ROPStepType::RegisterAssignment, "rdx");
            c.add_step(makePop(0x404000, "rax"), 59, "rax", ROPStepType::SystemCallSetup, "rax");
            c.add_step(makeInsn(0x405000, "syscall"), "syscall", ROPStepType::SystemCallExecution);
            auto res = c.validate("x86_64");
            assertCond("21.10a Multi-pop gadget rejected", !res.valid && res.error_message.find("Multi-pop") != std::string::npos);
        }

        // 21.10b ARMv7 multi-register pop rejected
        {
            ROPChain c;
            Gadget gArmMulti;
            gArmMulti.address = 0x10100;
            gArmMulti.assembly = "pop {r0, r1, pc}";
            gArmMulti.instructions = {{"pop", "{r0, r1, pc}"}};
            gArmMulti.target_register = "r0";
            c.add_step(gArmMulti, 0x20000ULL, "multi-pop arm", ROPStepType::RegisterAssignment, "r0");
            c.add_step(makePop(0x10200, "r1"), 0, "r1", ROPStepType::RegisterAssignment, "r1");
            c.add_step(makePop(0x10300, "r2"), 0, "r2", ROPStepType::RegisterAssignment, "r2");
            c.add_step(makePop(0x10400, "r7"), 11, "r7", ROPStepType::SystemCallSetup, "r7");
            c.add_step(makeInsn(0x10500, "svc", "#0"), "svc #0", ROPStepType::SystemCallExecution);
            ValidationMockParser armParser(false, "armv7", ropweaver::ELFOSABI_NONE, ropweaver::EF_ARM_EABI_VER5);
            auto res = c.validate("armv7", &armParser);
            assertCond("21.10b ARMv7 multi-register pop rejected", !res.valid && res.error_message.find("Multi-pop") != std::string::npos);
        }

        // 21.10c AArch64 ldp multi-register load rejected
        {
            ROPChain c;
            Gadget gAarch64Ldp;
            gAarch64Ldp.address = 0x401000;
            gAarch64Ldp.assembly = "ldp x0, x1, [sp], #16 ; ret";
            gAarch64Ldp.instructions = {{"ldp", "x0, x1, [sp], #16"}, {"ret", ""}};
            gAarch64Ldp.target_register = "x0";
            c.add_step(gAarch64Ldp, 0x501000ULL, "ldp x0 x1", ROPStepType::RegisterAssignment, "x0");
            c.add_step(makePop(0x402000, "x1"), 0, "x1", ROPStepType::RegisterAssignment, "x1");
            c.add_step(makePop(0x403000, "x2"), 0, "x2", ROPStepType::RegisterAssignment, "x2");
            c.add_step(makePop(0x404000, "x8"), 221, "x8", ROPStepType::SystemCallSetup, "x8");
            c.add_step(makeInsn(0x405000, "svc", "#0"), "svc #0", ROPStepType::SystemCallExecution);
            auto res = c.validate("aarch64");
            assertCond("21.10c AArch64 ldp multi-register load rejected", !res.valid && res.error_message.find("Multi-register load") != std::string::npos);
        }

        // 21.10d RISC-V multiple stack loads rejected
        {
            ROPChain c;
            Gadget gRvMulti;
            gRvMulti.address = 0x201000;
            gRvMulti.assembly = "ld a0, 0(sp) ; ld a1, 8(sp) ; addi sp, sp, 16 ; ret";
            gRvMulti.instructions = {{"ld", "a0, 0(sp)"}, {"ld", "a1, 8(sp)"}, {"addi", "sp, sp, 16"}, {"ret", ""}};
            gRvMulti.target_register = "a0";
            c.add_step(gRvMulti, 0x301000ULL, "multi ld riscv", ROPStepType::RegisterAssignment, "a0");
            c.add_step(makePop(0x202000, "a1"), 0, "a1", ROPStepType::RegisterAssignment, "a1");
            c.add_step(makePop(0x203000, "a2"), 0, "a2", ROPStepType::RegisterAssignment, "a2");
            c.add_step(makePop(0x204000, "a7"), 221, "a7", ROPStepType::SystemCallSetup, "a7");
            c.add_step(makeInsn(0x205000, "ecall"), "ecall", ROPStepType::SystemCallExecution);
            ValidationMockParser rvParser(true, "riscv64", ropweaver::ELFOSABI_NONE, 0);
            auto res = c.validate("riscv64", &rvParser);
            assertCond("21.10d RISC-V multiple stack loads rejected", !res.valid && (res.error_message.find("Multi-register load") != std::string::npos || res.error_message.find("multi-pop") != std::string::npos));
        }

        // 21.10e Empty ARM POP register list rejected
        {
            ROPChain c;
            Gadget gEmpty;
            gEmpty.address = 0x10100;
            gEmpty.assembly = "pop {}";
            gEmpty.instructions = {{"pop", "{}"}};
            gEmpty.target_register = "r0";
            c.add_step(gEmpty, 0x20000ULL, "empty pop arm", ROPStepType::RegisterAssignment, "r0");
            c.add_step(makePop(0x10200, "r1"), 0, "r1", ROPStepType::RegisterAssignment, "r1");
            c.add_step(makePop(0x10300, "r2"), 0, "r2", ROPStepType::RegisterAssignment, "r2");
            c.add_step(makePop(0x10400, "r7"), 11, "r7", ROPStepType::SystemCallSetup, "r7");
            c.add_step(makeInsn(0x10500, "svc", "#0"), "svc #0", ROPStepType::SystemCallExecution);
            ValidationMockParser armParser(false, "armv7", ropweaver::ELFOSABI_NONE, ropweaver::EF_ARM_EABI_VER5);
            auto res = c.validate("armv7", &armParser);
            assertCond("21.10e Empty ARM POP register list rejected", !res.valid && res.error_message.find("Empty register list") != std::string::npos);
        }

        // 21.10f Malformed ARM POP register list rejected
        {
            ROPChain c;
            Gadget gMalformed;
            gMalformed.address = 0x10100;
            gMalformed.assembly = "pop {r0,}";
            gMalformed.instructions = {{"pop", "{r0,}"}};
            gMalformed.target_register = "r0";
            c.add_step(gMalformed, 0x20000ULL, "malformed pop arm", ROPStepType::RegisterAssignment, "r0");
            c.add_step(makePop(0x10200, "r1"), 0, "r1", ROPStepType::RegisterAssignment, "r1");
            c.add_step(makePop(0x10300, "r2"), 0, "r2", ROPStepType::RegisterAssignment, "r2");
            c.add_step(makePop(0x10400, "r7"), 11, "r7", ROPStepType::SystemCallSetup, "r7");
            c.add_step(makeInsn(0x10500, "svc", "#0"), "svc #0", ROPStepType::SystemCallExecution);
            ValidationMockParser armParser(false, "armv7", ropweaver::ELFOSABI_NONE, ropweaver::EF_ARM_EABI_VER5);
            auto res = c.validate("armv7", &armParser);
            assertCond("21.10f Malformed ARM POP register list rejected", !res.valid && res.error_message.find("Malformed ARM pop syntax") != std::string::npos);
        }

        // 21.10g Unsupported register-range syntax rejected
        {
            ROPChain c;
            Gadget gRange;
            gRange.address = 0x10100;
            gRange.assembly = "pop {r0-r3}";
            gRange.instructions = {{"pop", "{r0-r3}"}};
            gRange.target_register = "r0";
            c.add_step(gRange, 0x20000ULL, "range pop arm", ROPStepType::RegisterAssignment, "r0");
            c.add_step(makePop(0x10200, "r1"), 0, "r1", ROPStepType::RegisterAssignment, "r1");
            c.add_step(makePop(0x10300, "r2"), 0, "r2", ROPStepType::RegisterAssignment, "r2");
            c.add_step(makePop(0x10400, "r7"), 11, "r7", ROPStepType::SystemCallSetup, "r7");
            c.add_step(makeInsn(0x10500, "svc", "#0"), "svc #0", ROPStepType::SystemCallExecution);
            ValidationMockParser armParser(false, "armv7", ropweaver::ELFOSABI_NONE, ropweaver::EF_ARM_EABI_VER5);
            auto res = c.validate("armv7", &armParser);
            assertCond("21.10g Unsupported register-range syntax rejected", !res.valid && res.error_message.find("Unsupported register-range") != std::string::npos);
        }

        // 21.10h Valid single-register POP with pc accepted
        {
            ROPChain c;
            Gadget gPopR0Pc;
            gPopR0Pc.address = 0x10100;
            gPopR0Pc.assembly = "pop {r0, pc}";
            gPopR0Pc.instructions = {{"pop", "{r0, pc}"}};
            gPopR0Pc.target_register = "r0";
            gPopR0Pc.registers_modified = {"r0", "pc", "sp"};

            Gadget gPopR1Pc;
            gPopR1Pc.address = 0x10200;
            gPopR1Pc.assembly = "pop {r1, pc}";
            gPopR1Pc.instructions = {{"pop", "{r1, pc}"}};
            gPopR1Pc.target_register = "r1";
            gPopR1Pc.registers_modified = {"r1", "pc", "sp"};

            Gadget gPopR2Pc;
            gPopR2Pc.address = 0x10300;
            gPopR2Pc.assembly = "pop {r2, pc}";
            gPopR2Pc.instructions = {{"pop", "{r2, pc}"}};
            gPopR2Pc.target_register = "r2";
            gPopR2Pc.registers_modified = {"r2", "pc", "sp"};

            Gadget gPopR7Pc;
            gPopR7Pc.address = 0x10400;
            gPopR7Pc.assembly = "pop {r7, pc}";
            gPopR7Pc.instructions = {{"pop", "{r7, pc}"}};
            gPopR7Pc.target_register = "r7";
            gPopR7Pc.registers_modified = {"r7", "pc", "sp"};

            c.add_step(gPopR0Pc, 0x20000ULL, "r0", ROPStepType::RegisterAssignment, "r0");
            c.add_step(gPopR1Pc, 0, "r1", ROPStepType::RegisterAssignment, "r1");
            c.add_step(gPopR2Pc, 0, "r2", ROPStepType::RegisterAssignment, "r2");
            c.add_step(gPopR7Pc, 11, "r7", ROPStepType::SystemCallSetup, "r7");
            c.add_step(makeInsn(0x10500, "svc", "#0"), "svc #0", ROPStepType::SystemCallExecution);
            ValidationMockParser armParser(false, "armv7", ropweaver::ELFOSABI_NONE, ropweaver::EF_ARM_EABI_VER5);
            auto res = c.validate("armv7", &armParser);
            assertCond("21.10h Valid single-register POP with pc accepted", res.valid);
        }

        // 21.10i AArch64 pre-indexed and post-indexed SP writeback
        {
            // Valid post-indexed SP staging with exact word-size displacement (8 bytes)
            ROPChain cValid;
            Gadget gPostSp;
            gPostSp.address = 0x401000;
            gPostSp.assembly = "ldr x0, [sp], #8 ; ldr x30, [sp], #8 ; ret";
            gPostSp.instructions = {{"ldr", "x0, [sp], #8"}, {"ldr", "x30, [sp], #8"}, {"ret", ""}};
            gPostSp.target_register = "x0";
            cValid.add_step(gPostSp, 0x501000ULL, "x0 post-indexed 8", ROPStepType::RegisterAssignment, "x0");
            cValid.add_step(makeAarch64Pop(0x402000, "x1"), 0, "x1", ROPStepType::RegisterAssignment, "x1");
            cValid.add_step(makeAarch64Pop(0x403000, "x2"), 0, "x2", ROPStepType::RegisterAssignment, "x2");
            cValid.add_step(makeAarch64Pop(0x404000, "x8"), 221, "x8", ROPStepType::SystemCallSetup, "x8");
            cValid.add_step(makeInsn(0x405000, "svc", "#0"), "svc #0", ROPStepType::SystemCallExecution);
            auto resValid = cValid.validate("aarch64");
            assertCond("21.10i Valid AArch64 post-indexed SP load with word_size displacement accepted", resValid.valid);

            // Post-indexed SP load with displacement not matching word size (16 != 8) rejected
            ROPChain cPost16;
            Gadget gPost16;
            gPost16.address = 0x401000;
            gPost16.assembly = "ldr x0, [sp], #16 ; ret";
            gPost16.instructions = {{"ldr", "x0, [sp], #16"}, {"ret", ""}};
            gPost16.target_register = "x0";
            cPost16.add_step(gPost16, 0x501000ULL, "x0 post-indexed 16", ROPStepType::RegisterAssignment, "x0");
            cPost16.add_step(makeAarch64Pop(0x402000, "x1"), 0, "x1", ROPStepType::RegisterAssignment, "x1");
            cPost16.add_step(makeAarch64Pop(0x403000, "x2"), 0, "x2", ROPStepType::RegisterAssignment, "x2");
            cPost16.add_step(makeAarch64Pop(0x404000, "x8"), 221, "x8", ROPStepType::SystemCallSetup, "x8");
            cPost16.add_step(makeInsn(0x405000, "svc", "#0"), "svc #0", ROPStepType::SystemCallExecution);
            auto resPost16 = cPost16.validate("aarch64");
            assertCond("21.10i AArch64 ldr x0, [sp], #16 rejected", !resPost16.valid && resPost16.error_message.find("does not match serialized stack word size") != std::string::npos);

            // Pre-indexed SP writeback staging rejected as unsupported stack effect
            ROPChain cPreSp;
            Gadget gPreSp;
            gPreSp.address = 0x401000;
            gPreSp.assembly = "ldr x0, [sp, #16]! ; ret";
            gPreSp.instructions = {{"ldr", "x0, [sp, #16]!"}, {"ret", ""}};
            gPreSp.target_register = "x0";
            cPreSp.add_step(gPreSp, 0x501000ULL, "x0 pre-indexed sp", ROPStepType::RegisterAssignment, "x0");
            cPreSp.add_step(makeAarch64Pop(0x402000, "x1"), 0, "x1", ROPStepType::RegisterAssignment, "x1");
            cPreSp.add_step(makeAarch64Pop(0x403000, "x2"), 0, "x2", ROPStepType::RegisterAssignment, "x2");
            cPreSp.add_step(makeAarch64Pop(0x404000, "x8"), 221, "x8", ROPStepType::SystemCallSetup, "x8");
            cPreSp.add_step(makeInsn(0x405000, "svc", "#0"), "svc #0", ROPStepType::SystemCallExecution);
            auto resPreSp = cPreSp.validate("aarch64");
            assertCond("21.10i Pre-indexed SP writeback staging rejected as unsupported", !resPreSp.valid && resPreSp.error_message.find("pre-indexed SP writeback") != std::string::npos);

            // Clobber rejection: pre-indexed writeback clobbers staged register x0
            ROPChain cClobber;
            cClobber.add_step(makeAarch64Pop(0x401000, "x0"), 0x501000ULL, "x0", ROPStepType::RegisterAssignment, "x0");
            Gadget gPreWriteback;
            gPreWriteback.address = 0x402000;
            gPreWriteback.assembly = "ldr x1, [x0, #16]! ; ldr x30, [sp], #8 ; ret";
            gPreWriteback.instructions = {{"ldr", "x1, [x0, #16]!"}, {"ldr", "x30, [sp], #8"}, {"ret", ""}};
            gPreWriteback.target_register = "x1";
            cClobber.add_step(gPreWriteback, 0, "x1 clobbers x0 via pre-index writeback", ROPStepType::RegisterAssignment, "x1");
            cClobber.add_step(makeAarch64Pop(0x403000, "x2"), 0, "x2", ROPStepType::RegisterAssignment, "x2");
            cClobber.add_step(makeAarch64Pop(0x404000, "x8"), 221, "x8", ROPStepType::SystemCallSetup, "x8");
            cClobber.add_step(makeInsn(0x405000, "svc", "#0"), "svc #0", ROPStepType::SystemCallExecution);
            auto resClobber = cClobber.validate("aarch64");
            assertCond("21.10i Pre-indexed writeback clobbering staged register rejected", !resClobber.valid && resClobber.error_message.find("clobbers previously staged register 'x0'") != std::string::npos);
        }

        // 21.10j RISC-V SP arithmetic and indirect SP modification
        {
            ValidationMockParser rvParser(true, "riscv64", ropweaver::ELFOSABI_NONE, 0);

            // Unmodeled RISC-V SP arithmetic (addi sp, sp, 16 != word_size 8) rejected
            ROPChain cSpAdj16;
            Gadget gSpAdj16;
            gSpAdj16.address = 0x201000;
            gSpAdj16.assembly = "ld a0, 0(sp) ; ld ra, 8(sp) ; addi sp, sp, 24 ; ret";
            gSpAdj16.instructions = {{"ld", "a0, 0(sp)"}, {"ld", "ra, 8(sp)"}, {"addi", "sp, sp, 24"}, {"ret", ""}};
            gSpAdj16.target_register = "a0";
            cSpAdj16.add_step(gSpAdj16, 0x301000ULL, "a0 with unmodeled sp arithmetic", ROPStepType::RegisterAssignment, "a0");
            cSpAdj16.add_step(makeRiscvPop(0x202000, "a1"), 0, "a1", ROPStepType::RegisterAssignment, "a1");
            cSpAdj16.add_step(makeRiscvPop(0x203000, "a2"), 0, "a2", ROPStepType::RegisterAssignment, "a2");
            cSpAdj16.add_step(makeRiscvPop(0x204000, "a7"), 221, "a7", ROPStepType::SystemCallSetup, "a7");
            cSpAdj16.add_step(makeInsn(0x205000, "ecall"), "ecall", ROPStepType::SystemCallExecution);
            auto resSpAdj16 = cSpAdj16.validate("riscv64", &rvParser);
            assertCond("21.10j Unmodelled addi sp, sp, 16 rejected", !resSpAdj16.valid && resSpAdj16.error_message.find("does not match serialized stack word size") != std::string::npos);

            // Register-indirect SP assignment mv sp, s0 rejected
            ROPChain cMvSp;
            cMvSp.add_step(makeRiscvPop(0x201000, "a0"), 0x301000ULL, "a0", ROPStepType::RegisterAssignment, "a0");
            cMvSp.add_step(makeRiscvPop(0x202000, "a1"), 0, "a1", ROPStepType::RegisterAssignment, "a1");
            cMvSp.add_step(makeRiscvPop(0x203000, "a2"), 0, "a2", ROPStepType::RegisterAssignment, "a2");
            Gadget gMvSp;
            gMvSp.address = 0x202500;
            gMvSp.assembly = "mv sp, s0 ; ret";
            gMvSp.instructions = {{"mv", "sp, s0"}, {"ret", ""}};
            cMvSp.add_step(gMvSp, "stack adjustment via mv sp, s0", ROPStepType::StackAdjustment);
            cMvSp.add_step(makeRiscvPop(0x204000, "a7"), 221, "a7", ROPStepType::SystemCallSetup, "a7");
            cMvSp.add_step(makeInsn(0x205000, "ecall"), "ecall", ROPStepType::SystemCallExecution);
            auto resMvSp = cMvSp.validate("riscv64", &rvParser);
            assertCond("21.10j RISC-V mv sp, s0 rejected", !resMvSp.valid && (resMvSp.error_message.find("cannot be established reliably") != std::string::npos || resMvSp.error_message.find("Unmodeled stack adjustment") != std::string::npos));

            // Dynamic register-based SP arithmetic add sp, sp, s0 rejected
            ROPChain cAddSp;
            cAddSp.add_step(makeRiscvPop(0x201000, "a0"), 0x301000ULL, "a0", ROPStepType::RegisterAssignment, "a0");
            cAddSp.add_step(makeRiscvPop(0x202000, "a1"), 0, "a1", ROPStepType::RegisterAssignment, "a1");
            cAddSp.add_step(makeRiscvPop(0x203000, "a2"), 0, "a2", ROPStepType::RegisterAssignment, "a2");
            Gadget gAddSp;
            gAddSp.address = 0x202600;
            gAddSp.assembly = "add sp, sp, s0 ; ret";
            gAddSp.instructions = {{"add", "sp, sp, s0"}, {"ret", ""}};
            cAddSp.add_step(gAddSp, "stack adjustment via add sp, sp, s0", ROPStepType::StackAdjustment);
            cAddSp.add_step(makeRiscvPop(0x204000, "a7"), 221, "a7", ROPStepType::SystemCallSetup, "a7");
            cAddSp.add_step(makeInsn(0x205000, "ecall"), "ecall", ROPStepType::SystemCallExecution);
            auto resAddSp = cAddSp.validate("riscv64", &rvParser);
            assertCond("21.10j RISC-V add sp, sp, s0 rejected", !resAddSp.valid && (resAddSp.error_message.find("unestablished displacement") != std::string::npos || resAddSp.error_message.find("cannot be established reliably") != std::string::npos || resAddSp.error_message.find("Unmodeled stack adjustment") != std::string::npos));

            // Interleaved instruction clobbering staged register a0 rejected
            ROPChain cClobber;
            cClobber.add_step(makeRiscvPop(0x201000, "a0"), 0x301000ULL, "a0", ROPStepType::RegisterAssignment, "a0");
            Gadget gClobber;
            gClobber.address = 0x202000;
            gClobber.assembly = "add a0, a0, s0 ; ld ra, 8(sp) ; ret";
            gClobber.instructions = {{"add", "a0, a0, s0"}, {"ld", "ra, 8(sp)"}, {"ret", ""}};
            cClobber.add_step(gClobber, "clobbers a0", ROPStepType::GadgetExecution);
            cClobber.add_step(makeRiscvPop(0x203000, "a1"), 0, "a1", ROPStepType::RegisterAssignment, "a1");
            cClobber.add_step(makeRiscvPop(0x204000, "a2"), 0, "a2", ROPStepType::RegisterAssignment, "a2");
            cClobber.add_step(makeRiscvPop(0x205000, "a7"), 221, "a7", ROPStepType::SystemCallSetup, "a7");
            cClobber.add_step(makeInsn(0x206000, "ecall"), "ecall", ROPStepType::SystemCallExecution);
            auto resClobber = cClobber.validate("riscv64", &rvParser);
            assertCond("21.10j Interleaved instruction clobbering staged register rejected", !resClobber.valid && resClobber.error_message.find("clobbers previously staged register 'a0'") != std::string::npos);
        }

        // 21.10k Architecture stack-pointer safety and link-register control-flow tests
        {
            ValidationMockParser rvParser(true, "riscv64", ropweaver::ELFOSABI_NONE, 0);

            // 1. x86 add esp, 8 rejected
            ROPChain cAddEsp;
            cAddEsp.add_step(makePop(0x101000, "eax"), 11, "eax", ROPStepType::SystemCallSetup, "eax");
            Gadget gAddEsp;
            gAddEsp.address = 0x101500;
            gAddEsp.assembly = "add esp, 8 ; ret";
            gAddEsp.instructions = {{"add", "esp, 8"}, {"ret", ""}};
            cAddEsp.add_step(gAddEsp, "add esp, 8", ROPStepType::GadgetExecution);
            cAddEsp.add_step(makePop(0x102000, "ebx"), 0x108000ULL, "ebx", ROPStepType::RegisterAssignment, "ebx");
            cAddEsp.add_step(makePop(0x103000, "ecx"), 0, "ecx", ROPStepType::RegisterAssignment, "ecx");
            cAddEsp.add_step(makePop(0x104000, "edx"), 0, "edx", ROPStepType::RegisterAssignment, "edx");
            cAddEsp.add_step(makeInsn(0x105000, "int", "0x80"), "int 0x80", ROPStepType::SystemCallExecution);
            auto resAddEsp = cAddEsp.validate("x86");
            assertCond("21.10k x86 add esp, 8 rejected", !resAddEsp.valid && resAddEsp.error_message.find("modifies stack pointer") != std::string::npos);

            // 2. x86 mov esp, ebp rejected
            ROPChain cMovEsp;
            cMovEsp.add_step(makePop(0x101000, "eax"), 11, "eax", ROPStepType::SystemCallSetup, "eax");
            Gadget gMovEsp;
            gMovEsp.address = 0x101500;
            gMovEsp.assembly = "mov esp, ebp ; ret";
            gMovEsp.instructions = {{"mov", "esp, ebp"}, {"ret", ""}};
            cMovEsp.add_step(gMovEsp, "mov esp, ebp", ROPStepType::GadgetExecution);
            cMovEsp.add_step(makePop(0x102000, "ebx"), 0x108000ULL, "ebx", ROPStepType::RegisterAssignment, "ebx");
            cMovEsp.add_step(makePop(0x103000, "ecx"), 0, "ecx", ROPStepType::RegisterAssignment, "ecx");
            cMovEsp.add_step(makePop(0x104000, "edx"), 0, "edx", ROPStepType::RegisterAssignment, "edx");
            cMovEsp.add_step(makeInsn(0x105000, "int", "0x80"), "int 0x80", ROPStepType::SystemCallExecution);
            auto resMovEsp = cMovEsp.validate("x86");
            assertCond("21.10k x86 mov esp, ebp rejected", !resMovEsp.valid && (resMovEsp.error_message.find("cannot be established reliably") != std::string::npos || resMovEsp.error_message.find("modifies stack pointer") != std::string::npos));

            // 3. x86 dynamic SP arithmetic add esp, ebx rejected
            ROPChain cDynEsp;
            cDynEsp.add_step(makePop(0x101000, "eax"), 11, "eax", ROPStepType::SystemCallSetup, "eax");
            Gadget gDynEsp;
            gDynEsp.address = 0x101500;
            gDynEsp.assembly = "add esp, ebx ; ret";
            gDynEsp.instructions = {{"add", "esp, ebx"}, {"ret", ""}};
            cDynEsp.add_step(gDynEsp, "add esp, ebx", ROPStepType::GadgetExecution);
            cDynEsp.add_step(makePop(0x102000, "ebx"), 0x108000ULL, "ebx", ROPStepType::RegisterAssignment, "ebx");
            cDynEsp.add_step(makePop(0x103000, "ecx"), 0, "ecx", ROPStepType::RegisterAssignment, "ecx");
            cDynEsp.add_step(makePop(0x104000, "edx"), 0, "edx", ROPStepType::RegisterAssignment, "edx");
            cDynEsp.add_step(makeInsn(0x105000, "int", "0x80"), "int 0x80", ROPStepType::SystemCallExecution);
            auto resDynEsp = cDynEsp.validate("x86");
            assertCond("21.10k x86 dynamic SP arithmetic add esp, ebx rejected", !resDynEsp.valid && (resDynEsp.error_message.find("cannot be established reliably") != std::string::npos || resDynEsp.error_message.find("modifies stack pointer") != std::string::npos));

            // 4. x86_64 add rsp, 8 rejected
            ROPChain cAddRsp;
            cAddRsp.add_step(makePop(0x401000, "rdi"), 0x601000ULL, "rdi", ROPStepType::RegisterAssignment, "rdi");
            Gadget gAddRsp;
            gAddRsp.address = 0x401500;
            gAddRsp.assembly = "add rsp, 8 ; ret";
            gAddRsp.instructions = {{"add", "rsp, 8"}, {"ret", ""}};
            cAddRsp.add_step(gAddRsp, "add rsp, 8", ROPStepType::GadgetExecution);
            cAddRsp.add_step(makePop(0x402000, "rsi"), 0, "rsi", ROPStepType::RegisterAssignment, "rsi");
            cAddRsp.add_step(makePop(0x403000, "rdx"), 0, "rdx", ROPStepType::RegisterAssignment, "rdx");
            cAddRsp.add_step(makePop(0x404000, "rax"), 59, "rax", ROPStepType::SystemCallSetup, "rax");
            cAddRsp.add_step(makeInsn(0x405000, "syscall"), "syscall", ROPStepType::SystemCallExecution);
            auto resAddRsp = cAddRsp.validate("x86_64");
            assertCond("21.10k x86_64 add rsp, 8 rejected", !resAddRsp.valid && resAddRsp.error_message.find("modifies stack pointer") != std::string::npos);

            // 5. x86_64 sub rsp, 8 rejected
            ROPChain cSubRsp;
            cSubRsp.add_step(makePop(0x401000, "rdi"), 0x601000ULL, "rdi", ROPStepType::RegisterAssignment, "rdi");
            Gadget gSubRsp;
            gSubRsp.address = 0x401500;
            gSubRsp.assembly = "sub rsp, 8 ; ret";
            gSubRsp.instructions = {{"sub", "rsp, 8"}, {"ret", ""}};
            cSubRsp.add_step(gSubRsp, "sub rsp, 8", ROPStepType::GadgetExecution);
            cSubRsp.add_step(makePop(0x402000, "rsi"), 0, "rsi", ROPStepType::RegisterAssignment, "rsi");
            cSubRsp.add_step(makePop(0x403000, "rdx"), 0, "rdx", ROPStepType::RegisterAssignment, "rdx");
            cSubRsp.add_step(makePop(0x404000, "rax"), 59, "rax", ROPStepType::SystemCallSetup, "rax");
            cSubRsp.add_step(makeInsn(0x405000, "syscall"), "syscall", ROPStepType::SystemCallExecution);
            auto resSubRsp = cSubRsp.validate("x86_64");
            assertCond("21.10k x86_64 sub rsp, 8 rejected", !resSubRsp.valid && resSubRsp.error_message.find("modifies stack pointer") != std::string::npos);

            // 6. x86_64 mov rsp, rbp rejected
            ROPChain cMovRsp;
            cMovRsp.add_step(makePop(0x401000, "rdi"), 0x601000ULL, "rdi", ROPStepType::RegisterAssignment, "rdi");
            Gadget gMovRsp;
            gMovRsp.address = 0x401500;
            gMovRsp.assembly = "mov rsp, rbp ; ret";
            gMovRsp.instructions = {{"mov", "rsp, rbp"}, {"ret", ""}};
            cMovRsp.add_step(gMovRsp, "mov rsp, rbp", ROPStepType::GadgetExecution);
            cMovRsp.add_step(makePop(0x402000, "rsi"), 0, "rsi", ROPStepType::RegisterAssignment, "rsi");
            cMovRsp.add_step(makePop(0x403000, "rdx"), 0, "rdx", ROPStepType::RegisterAssignment, "rdx");
            cMovRsp.add_step(makePop(0x404000, "rax"), 59, "rax", ROPStepType::SystemCallSetup, "rax");
            cMovRsp.add_step(makeInsn(0x405000, "syscall"), "syscall", ROPStepType::SystemCallExecution);
            auto resMovRsp = cMovRsp.validate("x86_64");
            assertCond("21.10k x86_64 mov rsp, rbp rejected", !resMovRsp.valid && (resMovRsp.error_message.find("cannot be established reliably") != std::string::npos || resMovRsp.error_message.find("modifies stack pointer") != std::string::npos));

            // 7. x86_64 dynamic SP arithmetic add rsp, rbx rejected
            ROPChain cDynRsp;
            cDynRsp.add_step(makePop(0x401000, "rdi"), 0x601000ULL, "rdi", ROPStepType::RegisterAssignment, "rdi");
            Gadget gDynRsp;
            gDynRsp.address = 0x401500;
            gDynRsp.assembly = "add rsp, rbx ; ret";
            gDynRsp.instructions = {{"add", "rsp, rbx"}, {"ret", ""}};
            cDynRsp.add_step(gDynRsp, "add rsp, rbx", ROPStepType::GadgetExecution);
            cDynRsp.add_step(makePop(0x402000, "rsi"), 0, "rsi", ROPStepType::RegisterAssignment, "rsi");
            cDynRsp.add_step(makePop(0x403000, "rdx"), 0, "rdx", ROPStepType::RegisterAssignment, "rdx");
            cDynRsp.add_step(makePop(0x404000, "rax"), 59, "rax", ROPStepType::SystemCallSetup, "rax");
            cDynRsp.add_step(makeInsn(0x405000, "syscall"), "syscall", ROPStepType::SystemCallExecution);
            auto resDynRsp = cDynRsp.validate("x86_64");
            assertCond("21.10k x86_64 dynamic SP arithmetic add rsp, rbx rejected", !resDynRsp.valid && (resDynRsp.error_message.find("cannot be established reliably") != std::string::npos || resDynRsp.error_message.find("modifies stack pointer") != std::string::npos));

            // 8. RISC-V StackAdjustment with positive immediate rejected
            ROPChain cRvAdjPos;
            cRvAdjPos.add_step(makeRiscvPop(0x201000, "a0"), 0x301000ULL, "a0", ROPStepType::RegisterAssignment, "a0");
            cRvAdjPos.add_step(makeRiscvPop(0x202000, "a1"), 0, "a1", ROPStepType::RegisterAssignment, "a1");
            cRvAdjPos.add_step(makeRiscvPop(0x203000, "a2"), 0, "a2", ROPStepType::RegisterAssignment, "a2");
            Gadget gAdjPos;
            gAdjPos.address = 0x203500;
            gAdjPos.assembly = "addi sp, sp, 16 ; ret";
            gAdjPos.instructions = {{"addi", "sp, sp, 16"}, {"ret", ""}};
            cRvAdjPos.add_step(gAdjPos, 16, "StackAdjustment positive", ROPStepType::StackAdjustment);
            cRvAdjPos.add_step(makeRiscvPop(0x204000, "a7"), 221, "a7", ROPStepType::SystemCallSetup, "a7");
            cRvAdjPos.add_step(makeInsn(0x205000, "ecall"), "ecall", ROPStepType::SystemCallExecution);
            auto resRvAdjPos = cRvAdjPos.validate("riscv64", &rvParser);
            assertCond("21.10k RISC-V StackAdjustment with positive immediate rejected", !resRvAdjPos.valid && resRvAdjPos.error_message.find("Unmodeled stack adjustment") != std::string::npos);

            // 9. RISC-V StackAdjustment with negative immediate rejected
            ROPChain cRvAdjNeg;
            cRvAdjNeg.add_step(makeRiscvPop(0x201000, "a0"), 0x301000ULL, "a0", ROPStepType::RegisterAssignment, "a0");
            cRvAdjNeg.add_step(makeRiscvPop(0x202000, "a1"), 0, "a1", ROPStepType::RegisterAssignment, "a1");
            cRvAdjNeg.add_step(makeRiscvPop(0x203000, "a2"), 0, "a2", ROPStepType::RegisterAssignment, "a2");
            Gadget gAdjNeg;
            gAdjNeg.address = 0x203500;
            gAdjNeg.assembly = "addi sp, sp, -16 ; ret";
            gAdjNeg.instructions = {{"addi", "sp, sp, -16"}, {"ret", ""}};
            cRvAdjNeg.add_step(gAdjNeg, "StackAdjustment negative", ROPStepType::StackAdjustment);
            cRvAdjNeg.add_step(makeRiscvPop(0x204000, "a7"), 221, "a7", ROPStepType::SystemCallSetup, "a7");
            cRvAdjNeg.add_step(makeInsn(0x205000, "ecall"), "ecall", ROPStepType::SystemCallExecution);
            auto resRvAdjNeg = cRvAdjNeg.validate("riscv64", &rvParser);
            assertCond("21.10k RISC-V StackAdjustment with negative immediate rejected", !resRvAdjNeg.valid && resRvAdjNeg.error_message.find("Unmodeled stack adjustment") != std::string::npos);

            // 10. AArch64 ret without a proven link-register load rejected
            ROPChain cA64NoLr;
            Gadget gA64NoLr;
            gA64NoLr.address = 0x401000;
            gA64NoLr.assembly = "ldr x0, [sp], #8 ; ret";
            gA64NoLr.instructions = {{"ldr", "x0, [sp], #8"}, {"ret", ""}};
            gA64NoLr.target_register = "x0";
            cA64NoLr.add_step(gA64NoLr, 0x501000ULL, "x0 no lr", ROPStepType::RegisterAssignment, "x0");
            cA64NoLr.add_step(makeAarch64Pop(0x402000, "x1"), 0, "x1", ROPStepType::RegisterAssignment, "x1");
            cA64NoLr.add_step(makeAarch64Pop(0x403000, "x2"), 0, "x2", ROPStepType::RegisterAssignment, "x2");
            cA64NoLr.add_step(makeAarch64Pop(0x404000, "x8"), 221, "x8", ROPStepType::SystemCallSetup, "x8");
            cA64NoLr.add_step(makeInsn(0x405000, "svc", "#0"), "svc #0", ROPStepType::SystemCallExecution);
            auto resA64NoLr = cA64NoLr.validate("aarch64");
            assertCond("21.10k AArch64 ret without a proven link-register load rejected", !resA64NoLr.valid && resA64NoLr.error_message.find("without loading link register x30") != std::string::npos);

            // 11. RISC-V ret without a proven link-register load rejected
            ROPChain cRvNoRa;
            Gadget gRvNoRa;
            gRvNoRa.address = 0x201000;
            gRvNoRa.assembly = "ld a0, 0(sp) ; ret";
            gRvNoRa.instructions = {{"ld", "a0, 0(sp)"}, {"ret", ""}};
            gRvNoRa.target_register = "a0";
            cRvNoRa.add_step(gRvNoRa, 0x301000ULL, "a0 no ra", ROPStepType::RegisterAssignment, "a0");
            cRvNoRa.add_step(makeRiscvPop(0x202000, "a1"), 0, "a1", ROPStepType::RegisterAssignment, "a1");
            cRvNoRa.add_step(makeRiscvPop(0x203000, "a2"), 0, "a2", ROPStepType::RegisterAssignment, "a2");
            cRvNoRa.add_step(makeRiscvPop(0x204000, "a7"), 221, "a7", ROPStepType::SystemCallSetup, "a7");
            cRvNoRa.add_step(makeInsn(0x205000, "ecall"), "ecall", ROPStepType::SystemCallExecution);
            auto resRvNoRa = cRvNoRa.validate("riscv64", &rvParser);
            assertCond("21.10k RISC-V ret without a proven link-register load rejected", !resRvNoRa.valid && resRvNoRa.error_message.find("without loading link register ra") != std::string::npos);
        }

        // 21.10l Critical validation hardening: Load ordering, offset parsing, logical SP operations, and native loads
        {
            ValidationMockParser rvParser(true, "riscv64", ropweaver::ELFOSABI_NONE, 0);

            // 1. AArch64 reversed load order (x30 loaded before target x0) rejected
            {
                ROPChain cRev;
                Gadget gRev;
                gRev.address = 0x401000;
                gRev.assembly = "ldr x30, [sp], #8 ; ldr x0, [sp], #8 ; ret";
                gRev.instructions = {{"ldr", "x30, [sp], #8"}, {"ldr", "x0, [sp], #8"}, {"ret", ""}};
                gRev.target_register = "x0";
                cRev.add_step(gRev, 0x501000ULL, "x0 reversed load order", ROPStepType::RegisterAssignment, "x0");
                cRev.add_step(makeAarch64Pop(0x402000, "x1"), 0, "x1", ROPStepType::RegisterAssignment, "x1");
                cRev.add_step(makeAarch64Pop(0x403000, "x2"), 0, "x2", ROPStepType::RegisterAssignment, "x2");
                cRev.add_step(makeAarch64Pop(0x404000, "x8"), 221, "x8", ROPStepType::SystemCallSetup, "x8");
                cRev.add_step(makeInsn(0x405000, "svc", "#0"), "svc #0", ROPStepType::SystemCallExecution);
                auto resRev = cRev.validate("aarch64");
                assertCond("21.10l AArch64 reversed load order rejected", !resRev.valid && resRev.error_message.find("loads link register x30 before loading target register") != std::string::npos);
            }

            // 2. RISC-V reversed load order (ra loaded before target a0) rejected
            {
                ROPChain cRev;
                Gadget gRev;
                gRev.address = 0x201000;
                gRev.assembly = "ld ra, 8(sp) ; ld a0, 0(sp) ; addi sp, sp, 16 ; ret";
                gRev.instructions = {{"ld", "ra, 8(sp)"}, {"ld", "a0, 0(sp)"}, {"addi", "sp, sp, 16"}, {"ret", ""}};
                gRev.target_register = "a0";
                cRev.add_step(gRev, 0x301000ULL, "a0 reversed load order", ROPStepType::RegisterAssignment, "a0");
                cRev.add_step(makeRiscvPop(0x202000, "a1"), 0, "a1", ROPStepType::RegisterAssignment, "a1");
                cRev.add_step(makeRiscvPop(0x203000, "a2"), 0, "a2", ROPStepType::RegisterAssignment, "a2");
                cRev.add_step(makeRiscvPop(0x204000, "a7"), 221, "a7", ROPStepType::SystemCallSetup, "a7");
                cRev.add_step(makeInsn(0x205000, "ecall"), "ecall", ROPStepType::SystemCallExecution);
                auto resRev = cRev.validate("riscv64", &rvParser);
                assertCond("21.10l RISC-V reversed load order rejected", !resRev.valid && resRev.error_message.find("loads link register ra before loading target register") != std::string::npos);
            }

            // 3. RISC-V data register load with non-zero displacement rejected
            {
                ROPChain cOff;
                Gadget gOff;
                gOff.address = 0x201000;
                gOff.assembly = "ld a0, 8(sp) ; ld ra, 8(sp) ; addi sp, sp, 16 ; ret";
                gOff.instructions = {{"ld", "a0, 8(sp)"}, {"ld", "ra, 8(sp)"}, {"addi", "sp, sp, 16"}, {"ret", ""}};
                gOff.target_register = "a0";
                cOff.add_step(gOff, 0x301000ULL, "a0 wrong offset", ROPStepType::RegisterAssignment, "a0");
                cOff.add_step(makeRiscvPop(0x202000, "a1"), 0, "a1", ROPStepType::RegisterAssignment, "a1");
                cOff.add_step(makeRiscvPop(0x203000, "a2"), 0, "a2", ROPStepType::RegisterAssignment, "a2");
                cOff.add_step(makeRiscvPop(0x204000, "a7"), 221, "a7", ROPStepType::SystemCallSetup, "a7");
                cOff.add_step(makeInsn(0x205000, "ecall"), "ecall", ROPStepType::SystemCallExecution);
                auto resOff = cOff.validate("riscv64", &rvParser);
                assertCond("21.10l RISC-V data load with non-zero displacement rejected", !resOff.valid && resOff.error_message.find("expected 0") != std::string::npos);
            }

            // 4. RISC-V link register load with wrong displacement rejected
            {
                ROPChain cOff;
                Gadget gOff;
                gOff.address = 0x201000;
                gOff.assembly = "ld a0, 0(sp) ; ld ra, 0(sp) ; addi sp, sp, 16 ; ret";
                gOff.instructions = {{"ld", "a0, 0(sp)"}, {"ld", "ra, 0(sp)"}, {"addi", "sp, sp, 16"}, {"ret", ""}};
                gOff.target_register = "a0";
                cOff.add_step(gOff, 0x301000ULL, "ra wrong offset", ROPStepType::RegisterAssignment, "a0");
                cOff.add_step(makeRiscvPop(0x202000, "a1"), 0, "a1", ROPStepType::RegisterAssignment, "a1");
                cOff.add_step(makeRiscvPop(0x203000, "a2"), 0, "a2", ROPStepType::RegisterAssignment, "a2");
                cOff.add_step(makeRiscvPop(0x204000, "a7"), 221, "a7", ROPStepType::SystemCallSetup, "a7");
                cOff.add_step(makeInsn(0x205000, "ecall"), "ecall", ROPStepType::SystemCallExecution);
                auto resOff = cOff.validate("riscv64", &rvParser);
                assertCond("21.10l RISC-V link load with wrong displacement rejected", !resOff.valid && resOff.error_message.find("expected 8") != std::string::npos);
            }

            // 5. RISC-V malformed load operand rejected
            {
                ROPChain cMal;
                Gadget gMal;
                gMal.address = 0x201000;
                gMal.assembly = "ld a0, 0 sp ; ld ra, 8(sp) ; addi sp, sp, 16 ; ret";
                gMal.instructions = {{"ld", "a0, 0 sp"}, {"ld", "ra, 8(sp)"}, {"addi", "sp, sp, 16"}, {"ret", ""}};
                gMal.target_register = "a0";
                cMal.add_step(gMal, 0x301000ULL, "malformed load", ROPStepType::RegisterAssignment, "a0");
                cMal.add_step(makeRiscvPop(0x202000, "a1"), 0, "a1", ROPStepType::RegisterAssignment, "a1");
                cMal.add_step(makeRiscvPop(0x203000, "a2"), 0, "a2", ROPStepType::RegisterAssignment, "a2");
                cMal.add_step(makeRiscvPop(0x204000, "a7"), 221, "a7", ROPStepType::SystemCallSetup, "a7");
                cMal.add_step(makeInsn(0x205000, "ecall"), "ecall", ROPStepType::SystemCallExecution);
                auto resMal = cMal.validate("riscv64", &rvParser);
                assertCond("21.10l RISC-V malformed load operand rejected", !resMal.valid && resMal.error_message.find("Malformed or unsupported RISC-V load") != std::string::npos);
            }

            // 6. x86_64 and rsp, -16 rejected
            {
                ROPChain c;
                c.add_step(makePop(0x401000, "rdi"), 0x601000ULL, "rdi", ROPStepType::RegisterAssignment, "rdi");
                Gadget gAndRsp;
                gAndRsp.address = 0x401500;
                gAndRsp.assembly = "and rsp, -16 ; ret";
                gAndRsp.instructions = {{"and", "rsp, -16"}, {"ret", ""}};
                c.add_step(gAndRsp, "and rsp, -16", ROPStepType::GadgetExecution);
                c.add_step(makePop(0x402000, "rsi"), 0, "rsi", ROPStepType::RegisterAssignment, "rsi");
                c.add_step(makePop(0x403000, "rdx"), 0, "rdx", ROPStepType::RegisterAssignment, "rdx");
                c.add_step(makePop(0x404000, "rax"), 59, "rax", ROPStepType::SystemCallSetup, "rax");
                c.add_step(makeInsn(0x405000, "syscall"), "syscall", ROPStepType::SystemCallExecution);
                auto res = c.validate("x86_64");
                assertCond("21.10l x86_64 and rsp, -16 rejected", !res.valid && (res.error_message.find("cannot be established reliably") != std::string::npos || res.error_message.find("modifies stack pointer") != std::string::npos));
            }

            // 7. x86 and esp, -16 rejected
            {
                ROPChain c;
                c.add_step(makePop(0x101000, "ebx"), 0x201000ULL, "ebx", ROPStepType::RegisterAssignment, "ebx");
                Gadget gAndEsp;
                gAndEsp.address = 0x101500;
                gAndEsp.assembly = "and esp, -16 ; ret";
                gAndEsp.instructions = {{"and", "esp, -16"}, {"ret", ""}};
                c.add_step(gAndEsp, "and esp, -16", ROPStepType::GadgetExecution);
                c.add_step(makePop(0x102000, "ecx"), 0, "ecx", ROPStepType::RegisterAssignment, "ecx");
                c.add_step(makePop(0x103000, "edx"), 0, "edx", ROPStepType::RegisterAssignment, "edx");
                c.add_step(makePop(0x104000, "eax"), 11, "eax", ROPStepType::SystemCallSetup, "eax");
                c.add_step(makeInsn(0x105000, "int", "0x80"), "int 0x80", ROPStepType::SystemCallExecution);
                auto res = c.validate("x86");
                assertCond("21.10l x86 and esp, -16 rejected", !res.valid && (res.error_message.find("cannot be established reliably") != std::string::npos || res.error_message.find("modifies stack pointer") != std::string::npos));
            }

            // 8. x86_64 or rsp, rbx rejected
            {
                ROPChain c;
                c.add_step(makePop(0x401000, "rdi"), 0x601000ULL, "rdi", ROPStepType::RegisterAssignment, "rdi");
                Gadget gOrRsp;
                gOrRsp.address = 0x401500;
                gOrRsp.assembly = "or rsp, rbx ; ret";
                gOrRsp.instructions = {{"or", "rsp, rbx"}, {"ret", ""}};
                c.add_step(gOrRsp, "or rsp, rbx", ROPStepType::GadgetExecution);
                c.add_step(makePop(0x402000, "rsi"), 0, "rsi", ROPStepType::RegisterAssignment, "rsi");
                c.add_step(makePop(0x403000, "rdx"), 0, "rdx", ROPStepType::RegisterAssignment, "rdx");
                c.add_step(makePop(0x404000, "rax"), 59, "rax", ROPStepType::SystemCallSetup, "rax");
                c.add_step(makeInsn(0x405000, "syscall"), "syscall", ROPStepType::SystemCallExecution);
                auto res = c.validate("x86_64");
                assertCond("21.10l x86_64 or rsp, rbx rejected", !res.valid && (res.error_message.find("cannot be established reliably") != std::string::npos || res.error_message.find("modifies stack pointer") != std::string::npos));
            }

            // 9. x86_64 xor rsp, rbx rejected
            {
                ROPChain c;
                c.add_step(makePop(0x401000, "rdi"), 0x601000ULL, "rdi", ROPStepType::RegisterAssignment, "rdi");
                Gadget gXorRsp;
                gXorRsp.address = 0x401500;
                gXorRsp.assembly = "xor rsp, rbx ; ret";
                gXorRsp.instructions = {{"xor", "rsp, rbx"}, {"ret", ""}};
                c.add_step(gXorRsp, "xor rsp, rbx", ROPStepType::GadgetExecution);
                c.add_step(makePop(0x402000, "rsi"), 0, "rsi", ROPStepType::RegisterAssignment, "rsi");
                c.add_step(makePop(0x403000, "rdx"), 0, "rdx", ROPStepType::RegisterAssignment, "rdx");
                c.add_step(makePop(0x404000, "rax"), 59, "rax", ROPStepType::SystemCallSetup, "rax");
                c.add_step(makeInsn(0x405000, "syscall"), "syscall", ROPStepType::SystemCallExecution);
                auto res = c.validate("x86_64");
                assertCond("21.10l x86_64 xor rsp, rbx rejected", !res.valid && (res.error_message.find("cannot be established reliably") != std::string::npos || res.error_message.find("modifies stack pointer") != std::string::npos));
            }

            // 10. AArch64 and sp, sp, -16 rejected
            {
                ROPChain c;
                c.add_step(makeAarch64Pop(0x401000, "x0"), 0x501000ULL, "x0", ROPStepType::RegisterAssignment, "x0");
                Gadget gAndSp;
                gAndSp.address = 0x401500;
                gAndSp.assembly = "and sp, sp, -16 ; ret";
                gAndSp.instructions = {{"and", "sp, sp, -16"}, {"ret", ""}};
                c.add_step(gAndSp, "and sp, sp, -16", ROPStepType::GadgetExecution);
                c.add_step(makeAarch64Pop(0x402000, "x1"), 0, "x1", ROPStepType::RegisterAssignment, "x1");
                c.add_step(makeAarch64Pop(0x403000, "x2"), 0, "x2", ROPStepType::RegisterAssignment, "x2");
                c.add_step(makeAarch64Pop(0x404000, "x8"), 221, "x8", ROPStepType::SystemCallSetup, "x8");
                c.add_step(makeInsn(0x405000, "svc", "#0"), "svc #0", ROPStepType::SystemCallExecution);
                auto res = c.validate("aarch64");
                assertCond("21.10l AArch64 and sp, sp, -16 rejected", !res.valid && (res.error_message.find("cannot be established reliably") != std::string::npos || res.error_message.find("modifies stack pointer") != std::string::npos));
            }

            // 11. RISC-V andi sp, sp, -16 rejected
            {
                ROPChain c;
                c.add_step(makeRiscvPop(0x201000, "a0"), 0x301000ULL, "a0", ROPStepType::RegisterAssignment, "a0");
                Gadget gAndiSp;
                gAndiSp.address = 0x201500;
                gAndiSp.assembly = "andi sp, sp, -16 ; ret";
                gAndiSp.instructions = {{"andi", "sp, sp, -16"}, {"ret", ""}};
                c.add_step(gAndiSp, "andi sp, sp, -16", ROPStepType::GadgetExecution);
                c.add_step(makeRiscvPop(0x202000, "a1"), 0, "a1", ROPStepType::RegisterAssignment, "a1");
                c.add_step(makeRiscvPop(0x203000, "a2"), 0, "a2", ROPStepType::RegisterAssignment, "a2");
                c.add_step(makeRiscvPop(0x204000, "a7"), 221, "a7", ROPStepType::SystemCallSetup, "a7");
                c.add_step(makeInsn(0x205000, "ecall"), "ecall", ROPStepType::SystemCallExecution);
                auto res = c.validate("riscv64", &rvParser);
                assertCond("21.10l RISC-V andi sp, sp, -16 rejected", !res.valid && (res.error_message.find("cannot be established reliably") != std::string::npos || res.error_message.find("modifies stack pointer") != std::string::npos));
            }

            // 12. AArch64 synthetic pop rejected
            {
                ROPChain c;
                Gadget gPopA64;
                gPopA64.address = 0x401000;
                gPopA64.assembly = "pop x0 ; ret";
                gPopA64.instructions = {{"pop", "x0"}, {"ret", ""}};
                gPopA64.target_register = "x0";
                c.add_step(gPopA64, 0x501000ULL, "synthetic pop x0", ROPStepType::RegisterAssignment, "x0");
                c.add_step(makeAarch64Pop(0x402000, "x1"), 0, "x1", ROPStepType::RegisterAssignment, "x1");
                c.add_step(makeAarch64Pop(0x403000, "x2"), 0, "x2", ROPStepType::RegisterAssignment, "x2");
                c.add_step(makeAarch64Pop(0x404000, "x8"), 221, "x8", ROPStepType::SystemCallSetup, "x8");
                c.add_step(makeInsn(0x405000, "svc", "#0"), "svc #0", ROPStepType::SystemCallExecution);
                auto res = c.validate("aarch64");
                assertCond("21.10l AArch64 synthetic pop rejected", !res.valid && (res.error_message.find("no native 'pop'") != std::string::npos || res.error_message.find("cannot be established reliably") != std::string::npos));
            }

            // 13. RISC-V synthetic pop rejected
            {
                ROPChain c;
                Gadget gPopRv;
                gPopRv.address = 0x201000;
                gPopRv.assembly = "pop a0 ; ret";
                gPopRv.instructions = {{"pop", "a0"}, {"ret", ""}};
                gPopRv.target_register = "a0";
                c.add_step(gPopRv, 0x301000ULL, "synthetic pop a0", ROPStepType::RegisterAssignment, "a0");
                c.add_step(makeRiscvPop(0x202000, "a1"), 0, "a1", ROPStepType::RegisterAssignment, "a1");
                c.add_step(makeRiscvPop(0x203000, "a2"), 0, "a2", ROPStepType::RegisterAssignment, "a2");
                c.add_step(makeRiscvPop(0x204000, "a7"), 221, "a7", ROPStepType::SystemCallSetup, "a7");
                c.add_step(makeInsn(0x205000, "ecall"), "ecall", ROPStepType::SystemCallExecution);
                auto res = c.validate("riscv64", &rvParser);
                assertCond("21.10l RISC-V synthetic pop rejected", !res.valid && (res.error_message.find("no native 'pop'") != std::string::npos || res.error_message.find("cannot be established reliably") != std::string::npos));
            }
        }

        // 21.11 Incorrect syscall instruction rejected
        {
            ROPChain c;
            c.add_step(makePop(0x401000, "rdi"), 0x601000ULL, "rdi", ROPStepType::RegisterAssignment, "rdi");
            c.add_step(makePop(0x402000, "rsi"), 0, "rsi", ROPStepType::RegisterAssignment, "rsi");
            c.add_step(makePop(0x403000, "rdx"), 0, "rdx", ROPStepType::RegisterAssignment, "rdx");
            c.add_step(makePop(0x404000, "rax"), 59, "rax", ROPStepType::SystemCallSetup, "rax");
            // Wrong trap: int 0x80 on x86_64
            c.add_step(makeInsn(0x405000, "int", "0x80"), "wrong trap", ROPStepType::SystemCallExecution);
            auto res = c.validate("x86_64");
            assertCond("21.11 Incorrect syscall instruction for architecture rejected", !res.valid && res.error_message.find("does not contain the expected") != std::string::npos);
        }

        // 21.12a Non-terminal syscall instruction (followed by other instruction) rejected
        {
            ROPChain c;
            c.add_step(makePop(0x401000, "rdi"), 0x601000ULL, "rdi", ROPStepType::RegisterAssignment, "rdi");
            c.add_step(makePop(0x402000, "rsi"), 0, "rsi", ROPStepType::RegisterAssignment, "rsi");
            c.add_step(makePop(0x403000, "rdx"), 0, "rdx", ROPStepType::RegisterAssignment, "rdx");
            c.add_step(makePop(0x404000, "rax"), 59, "rax", ROPStepType::SystemCallSetup, "rax");
            // Syscall followed by nop
            Gadget gNonTerm;
            gNonTerm.address = 0x405000;
            gNonTerm.assembly = "syscall ; nop";
            gNonTerm.instructions = {{"syscall", ""}, {"nop", ""}};
            c.add_step(gNonTerm, "non-terminal syscall", ROPStepType::SystemCallExecution);
            auto res = c.validate("x86_64");
            assertCond("21.12a Non-terminal syscall instruction rejected", !res.valid && res.error_message.find("not at terminal position") != std::string::npos);
        }

        // 21.12b Trap followed by ret rejected
        {
            ROPChain c;
            c.add_step(makePop(0x401000, "rdi"), 0x601000ULL, "rdi", ROPStepType::RegisterAssignment, "rdi");
            c.add_step(makePop(0x402000, "rsi"), 0, "rsi", ROPStepType::RegisterAssignment, "rsi");
            c.add_step(makePop(0x403000, "rdx"), 0, "rdx", ROPStepType::RegisterAssignment, "rdx");
            c.add_step(makePop(0x404000, "rax"), 59, "rax", ROPStepType::SystemCallSetup, "rax");
            // Syscall followed by ret
            Gadget gTrapRet;
            gTrapRet.address = 0x405000;
            gTrapRet.assembly = "syscall ; ret";
            gTrapRet.instructions = {{"syscall", ""}, {"ret", ""}};
            c.add_step(gTrapRet, "syscall followed by ret", ROPStepType::SystemCallExecution);
            auto res = c.validate("x86_64");
            assertCond("21.12b Trap followed by ret rejected", !res.valid && res.error_message.find("not at terminal position") != std::string::npos);
        }

        // 21.13 Steps following syscall execution (dead code) rejected
        {
            ROPChain c;
            c.add_step(makePop(0x401000, "rdi"), 0x601000ULL, "rdi", ROPStepType::RegisterAssignment, "rdi");
            c.add_step(makePop(0x402000, "rsi"), 0, "rsi", ROPStepType::RegisterAssignment, "rsi");
            c.add_step(makePop(0x403000, "rdx"), 0, "rdx", ROPStepType::RegisterAssignment, "rdx");
            c.add_step(makePop(0x404000, "rax"), 59, "rax", ROPStepType::SystemCallSetup, "rax");
            c.add_step(makeInsn(0x405000, "syscall"), "syscall", ROPStepType::SystemCallExecution);
            c.add_step(makePop(0x406000, "rdi"), 0x1111ULL, "dead code after syscall", ROPStepType::RegisterAssignment, "rdi");
            auto res = c.validate("x86_64");
            assertCond("21.13 Dead code following syscall execution rejected", !res.valid && res.error_message.find("Dead code") != std::string::npos);
        }

        // 21.14 Parser architecture and bitness mismatches rejected
        {
            ROPChain c;
            c.add_step(makePop(0x401000, "rdi"), 0x601000ULL, "rdi", ROPStepType::RegisterAssignment, "rdi");
            c.add_step(makePop(0x402000, "rsi"), 0, "rsi", ROPStepType::RegisterAssignment, "rsi");
            c.add_step(makePop(0x403000, "rdx"), 0, "rdx", ROPStepType::RegisterAssignment, "rdx");
            c.add_step(makePop(0x404000, "rax"), 59, "rax", ROPStepType::SystemCallSetup, "rax");
            c.add_step(makeInsn(0x405000, "syscall"), "syscall", ROPStepType::SystemCallExecution);

            ValidationMockParser mismatchParser(false, "x86", ropweaver::ELFOSABI_NONE, 0); // 32-bit parser
            auto res = c.validate("x86_64", &mismatchParser);
            assertCond("21.14 Parser bitness mismatch rejected", !res.valid && res.error_message.find("bitness mismatch") != std::string::npos);
        }

        // 21.15 32-bit overflow rejected
        {
            ROPChain c;
            c.add_step(makePop(0x101000, "eax"), 11, "eax", ROPStepType::SystemCallSetup, "eax");
            c.add_step(makePop(0x102000, "ebx"), 0x100000000ULL, "ebx overflows 32-bit", ROPStepType::RegisterAssignment, "ebx");
            c.add_step(makePop(0x103000, "ecx"), 0, "ecx", ROPStepType::RegisterAssignment, "ecx");
            c.add_step(makePop(0x104000, "edx"), 0, "edx", ROPStepType::RegisterAssignment, "edx");
            c.add_step(makeInsn(0x105000, "int", "0x80"), "int 0x80", ROPStepType::SystemCallExecution);
            auto res = c.validate("x86");
            assertCond("21.15 32-bit value overflow rejected", !res.valid && res.error_message.find("exceeds 32-bit bounds") != std::string::npos);
        }

        // 21.16 PayloadGenerator payload suppression on validation failure
        {
            std::string tempReport = "build-win/test_invalid_chain_report.json";
            std::string tempPayload = "build-win/test_invalid_chain_payload.bin";
            std::string tempReportsPayload = "build-win/reports_test_invalid_chain_payload.bin";

            std::error_code ec;
            std::filesystem::remove(tempPayload, ec);
            std::filesystem::remove(tempReportsPayload, ec);

            ROPChain invalidChain;
            // Missing Arg1 (/bin/sh) entirely
            invalidChain.add_step(makePop(0x402000, "rsi"), 0, "rsi", ROPStepType::RegisterAssignment, "rsi");
            invalidChain.add_step(makePop(0x403000, "rdx"), 0, "rdx", ROPStepType::RegisterAssignment, "rdx");
            invalidChain.add_step(makePop(0x404000, "rax"), 59, "rax", ROPStepType::SystemCallSetup, "rax");
            invalidChain.add_step(makeInsn(0x405000, "syscall"), "syscall", ROPStepType::SystemCallExecution);

            ValidationMockParser validParser(true, "x86_64", ropweaver::ELFOSABI_NONE, 0);
            PayloadGenerator gen;
            gen.generate(invalidChain, 104, "test_target", {}, "x86_64", "ELF", {}, "", "", &validParser,
                         tempReport, tempPayload, tempReportsPayload);

            assertCond("21.16a Invalid chain does NOT export payload.bin", !std::filesystem::exists(tempPayload));
            assertCond("21.16b Invalid chain does NOT export reports/payload.bin", !std::filesystem::exists(tempReportsPayload));

            // Verify report status in JSON
            std::ifstream rf(tempReport);
            nlohmann::json rJson;
            if (rf.is_open()) {
                rf >> rJson;
                rf.close();
            }
            assertCond("21.16c Report rop_chain_generation status indicates validation failure",
                       rJson.contains("rop_chain_generation") &&
                       rJson["rop_chain_generation"]["status"].get<std::string>() == "Failure (Validation Error)");
            assertCond("21.16d Report raw_payload status indicates validation failure",
                       rJson.contains("raw_payload") &&
                       rJson["raw_payload"]["status"].get<std::string>().find("Validation Failed") != std::string::npos);
            assertCond("21.16e Report rop_chain_generation contains structured validation result",
                       rJson["rop_chain_generation"].contains("validation") &&
                       rJson["rop_chain_generation"]["validation"]["valid"].get<bool>() == false);

            std::filesystem::remove(tempReport, ec);
        }
    }

    // =============================================================
    // Group 22: Dynamic Exploit Offset Configuration (Step 3.2)
    // =============================================================
    {
        std::cout << "\n--- Group 22: Dynamic Exploit Offset Configuration (Step 3.2) ---\n";

        class OffsetTestMockParser : public FileParser {
            bool m_is64;
            std::string m_arch;
        public:
            OffsetTestMockParser(bool is64, const std::string& arch)
                : FileParser("offset_test"), m_is64(is64), m_arch(arch) {}
            bool parse(const std::string&) override { return true; }
            const std::vector<uint8_t>& getTextSection() const override { static std::vector<uint8_t> d; return d; }
            uint64_t getTextSectionBaseAddress() const override { return 0; }
            std::string getArchitecture() const override { return m_arch; }
            bool is64Bit() const override { return m_is64; }
            std::string getBinaryType() const override { return "ELF"; }
            std::string getFilePath() const override { return "offset_test"; }
            uint8_t getOsAbi() const override { return 0; }
            uint32_t getElfFlags() const override { return 0; }
            Endianness getMetadataEndianness() const override { return Endianness::Little; }
            bool isArmEabi() const override { return false; }
            bool isRvcEnabled() const override { return false; }
        };

        auto makePop = [](uint64_t addr, const std::string& reg) {
            Gadget g;
            g.address = addr;
            g.preferred_va = addr;
            g.target_register = reg;
            g.assembly = "pop " + reg + " ; ret";
            g.instructions = {{"pop", reg}, {"ret", ""}};
            g.registers_modified = {reg};
            return g;
        };

        auto makeInsn = [](uint64_t addr, const std::string& asmStr) {
            Gadget g;
            g.address = addr;
            g.preferred_va = addr;
            g.assembly = asmStr;
            g.instructions = {{asmStr, ""}};
            return g;
        };

        OffsetTestMockParser validParser(true, "x86_64");

        ROPChain validChain;
        validChain.add_step(makePop(0x401000, "rdi"), 0x601000ULL, "rdi", ROPStepType::RegisterAssignment, "rdi");
        validChain.add_step(makePop(0x402000, "rsi"), 0, "rsi", ROPStepType::RegisterAssignment, "rsi");
        validChain.add_step(makePop(0x403000, "rdx"), 0, "rdx", ROPStepType::RegisterAssignment, "rdx");
        validChain.add_step(makePop(0x404000, "rax"), 59, "rax", ROPStepType::SystemCallSetup, "rax");
        validChain.add_step(makeInsn(0x405000, "syscall"), "syscall", ROPStepType::SystemCallExecution);

        std::vector<char> expectedChainBytes = validChain.getPayloadBytes(8, Endianness::Little);
        assertCond("22.0 Precondition: chain bytes generated", !expectedChainBytes.empty());

        auto test_offset = [&](size_t offset, const std::string& label) {
            std::filesystem::path tempDir = std::filesystem::temp_directory_path();
            std::string tempReport = (tempDir / ("ropw_test_offset_report_" + std::to_string(offset) + ".json")).string();
            std::string tempPayload = (tempDir / ("ropw_test_offset_payload_" + std::to_string(offset) + ".bin")).string();
            std::string tempReportsPayload = (tempDir / ("ropw_test_offset_reports_payload_" + std::to_string(offset) + ".bin")).string();

            std::error_code ec;
            std::filesystem::remove(tempReport, ec);
            std::filesystem::remove(tempPayload, ec);
            std::filesystem::remove(tempReportsPayload, ec);

            PayloadGenerator gen;
            gen.generate(validChain, offset, "test_target", {}, "x86_64", "ELF", {}, "", "", &validParser,
                         tempReport, tempPayload, tempReportsPayload);

            assertCond("22." + label + "a Payload file created", std::filesystem::exists(tempPayload));
            assertCond("22." + label + "b Reports payload file created", std::filesystem::exists(tempReportsPayload));

            if (std::filesystem::exists(tempPayload)) {
                size_t actualSize = std::filesystem::file_size(tempPayload);
                assertCond("22." + label + "c Total payload size matches offset + chain bytes",
                           actualSize == offset + expectedChainBytes.size());

                std::ifstream binF(tempPayload, std::ios::binary);
                std::vector<char> actualBytes(actualSize);
                binF.read(actualBytes.data(), actualSize);
                binF.close();

                // Check prefix padding bytes
                bool prefixOk = true;
                for (size_t i = 0; i < offset; ++i) {
                    if (actualBytes[i] != 'A') {
                        prefixOk = false;
                        break;
                    }
                }
                assertCond("22." + label + "d Prefix contains exactly " + std::to_string(offset) + " 'A' bytes", prefixOk);

                // Check serialized chain bytes
                bool chainOk = (actualBytes.size() == offset + expectedChainBytes.size()) &&
                               (std::memcmp(actualBytes.data() + offset, expectedChainBytes.data(), expectedChainBytes.size()) == 0);
                assertCond("22." + label + "e Serialized chain bytes correctly positioned after offset", chainOk);
            }

            // Check JSON report
            std::ifstream rf(tempReport);
            if (rf.is_open()) {
                nlohmann::json rJson;
                rf >> rJson;
                rf.close();

                assertCond("22." + label + "f raw_payload.status is Success",
                           rJson["raw_payload"]["status"].get<std::string>() == "Success");
                assertCond("22." + label + "g verified_padding_offset matches configured offset",
                           rJson["raw_payload"]["verified_padding_offset"].get<size_t>() == offset);
                assertCond("22." + label + "h raw_payload.data matches total payload byte count",
                           rJson["raw_payload"]["data"].get<std::string>().size() == (offset + expectedChainBytes.size()) * 4);
            } else {
                assertCond("22." + label + "f JSON report opened", false);
            }

            std::filesystem::remove(tempReport, ec);
            std::filesystem::remove(tempPayload, ec);
            std::filesystem::remove(tempReportsPayload, ec);
        };

        // 22.1 Default offset (104 bytes)
        test_offset(104, "1_default_104_");
        // 22.2 Custom decimal offset (208 bytes)
        test_offset(208, "2_custom_208_");
        // 22.3 Hexadecimal offset (0x80 = 128 bytes)
        test_offset(128, "3_hex_128_");
        // 22.4 Zero offset boundary (0 bytes)
        test_offset(0, "4_zero_0_");
        // 22.5 Large valid offset (4096 bytes)
        test_offset(4096, "5_large_4096_");
    }

    // =========================================================================
    // Group 23: Darwin Mach-O x86_64 Chain Synthesis & Semantic Validation
    // =========================================================================
    std::cout << "\n--- Group 23: Darwin Mach-O x86_64 Chain Synthesis & Validation ---\n";
    {
        namespace fs = std::filesystem;
        std::error_code ec;
        fs::path tempDir = fs::temp_directory_path();
        fs::path validFixturePath = tempDir / "test_darwin_fixture_valid.bin";
        fs::path pieFixturePath = tempDir / "test_darwin_fixture_pie.bin";
        fs::path invalidArgvPath = tempDir / "test_darwin_fixture_bad_argv.bin";
        fs::path invalidEnvpPath = tempDir / "test_darwin_fixture_bad_envp.bin";
        fs::path zerofillPath = tempDir / "test_darwin_fixture_zerofill.bin";
        fs::path fatFixturePath = tempDir / "test_darwin_fixture_fat.bin";

        auto make_synthetic_macho64 = [](
            uint64_t text_vmaddr, uint64_t text_vmsize,
            uint64_t text_sec_addr, uint64_t text_sec_size, uint64_t text_sec_off,
            uint64_t cstr_sec_addr, uint64_t cstr_sec_size, uint64_t cstr_sec_off,
            uint64_t data_vmaddr, uint64_t data_vmsize, uint64_t data_fileoff,
            uint64_t data_sec_addr, uint64_t data_sec_size, uint64_t data_sec_off,
            uint32_t flags = 0, bool is_zerofill_data = false,
            const std::string& path_str = "/bin/sh",
            uint64_t argv0_override = 0, uint64_t argv1_override = 0, uint64_t envp0_override = 0,
            bool omit_null_term_path = false,
            uint32_t text_initprot = 5, uint32_t data_initprot = 3)
        {
            size_t total_size = 0x3000;
            std::vector<uint8_t> buf(total_size, 0);

            auto write_u32 = [&](size_t offset, uint32_t val) {
                buf[offset + 0] = static_cast<uint8_t>((val >> 0) & 0xFF);
                buf[offset + 1] = static_cast<uint8_t>((val >> 8) & 0xFF);
                buf[offset + 2] = static_cast<uint8_t>((val >> 16) & 0xFF);
                buf[offset + 3] = static_cast<uint8_t>((val >> 24) & 0xFF);
            };

            auto write_u64 = [&](size_t offset, uint64_t val) {
                for (int i = 0; i < 8; ++i) {
                    buf[offset + i] = static_cast<uint8_t>((val >> (8 * i)) & 0xFF);
                }
            };

            // Mach-O Header (32 bytes)
            write_u32(0,  0xFEEDFACF); // MH_MAGIC_64
            write_u32(4,  0x01000007); // CPU_TYPE_X86_64
            write_u32(8,  0x00000003); // CPU_SUBTYPE_X86_64_ALL
            write_u32(12, 0x00000002); // MH_EXECUTE
            write_u32(16, 2);          // ncmds (2 segment commands)
            write_u32(20, 232 + 152);  // sizeofcmds (384 bytes)
            write_u32(24, flags);      // flags
            write_u32(28, 0);          // reserved

            // Command 1: LC_SEGMENT_64 __TEXT (232 bytes)
            size_t cmd1_off = 32;
            write_u32(cmd1_off + 0, 0x19); // LC_SEGMENT_64
            write_u32(cmd1_off + 4, 232);  // cmdsize = 72 + 2*80
            std::memcpy(&buf[cmd1_off + 8], "__TEXT\0\0\0\0\0\0\0\0\0\0", 16);
            write_u64(cmd1_off + 24, text_vmaddr);
            write_u64(cmd1_off + 32, text_vmsize);
            write_u64(cmd1_off + 40, 0); // fileoff = 0
            write_u64(cmd1_off + 48, 0x2000); // filesize = 0x2000
            write_u32(cmd1_off + 56, 7); // maxprot = 7 (RWX)
            write_u32(cmd1_off + 60, text_initprot); // initprot
            write_u32(cmd1_off + 64, 2); // nsects = 2
            write_u32(cmd1_off + 68, 0); // flags

            // Section 1.1: __TEXT,__text (80 bytes)
            size_t s1_off = cmd1_off + 72;
            std::memcpy(&buf[s1_off + 0], "__text\0\0\0\0\0\0\0\0\0\0", 16);
            std::memcpy(&buf[s1_off + 16], "__TEXT\0\0\0\0\0\0\0\0\0\0", 16);
            write_u64(s1_off + 32, text_sec_addr);
            write_u64(s1_off + 40, text_sec_size);
            write_u32(s1_off + 48, static_cast<uint32_t>(text_sec_off));
            write_u32(s1_off + 52, 4); // align
            write_u32(s1_off + 56, 0); // reloff
            write_u32(s1_off + 60, 0); // nreloc
            write_u32(s1_off + 64, 0x80000400); // S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS
            write_u32(s1_off + 68, 0);
            write_u32(s1_off + 72, 0);
            write_u32(s1_off + 76, 0);

            // Section 1.2: __TEXT,__cstring (80 bytes)
            size_t s2_off = s1_off + 80;
            std::memcpy(&buf[s2_off + 0], "__cstring\0\0\0\0\0\0\0", 16);
            std::memcpy(&buf[s2_off + 16], "__TEXT\0\0\0\0\0\0\0\0\0\0", 16);
            write_u64(s2_off + 32, cstr_sec_addr);
            write_u64(s2_off + 40, cstr_sec_size);
            write_u32(s2_off + 48, static_cast<uint32_t>(cstr_sec_off));
            write_u32(s2_off + 52, 0); // align
            write_u32(s2_off + 56, 0);
            write_u32(s2_off + 60, 0);
            write_u32(s2_off + 64, 0x00000002); // S_CSTRING_LITERALS
            write_u32(s2_off + 68, 0);
            write_u32(s2_off + 72, 0);
            write_u32(s2_off + 76, 0);

            // Command 2: LC_SEGMENT_64 __DATA (152 bytes)
            size_t cmd2_off = cmd1_off + 232;
            write_u32(cmd2_off + 0, 0x19); // LC_SEGMENT_64
            write_u32(cmd2_off + 4, 152);  // cmdsize = 72 + 1*80
            std::memcpy(&buf[cmd2_off + 8], "__DATA\0\0\0\0\0\0\0\0\0\0", 16);
            write_u64(cmd2_off + 24, data_vmaddr);
            write_u64(cmd2_off + 32, data_vmsize);
            write_u64(cmd2_off + 40, data_fileoff);
            write_u64(cmd2_off + 48, is_zerofill_data ? 0 : 0x1000);
            write_u32(cmd2_off + 56, 7); // maxprot = 7 (RWX)
            write_u32(cmd2_off + 60, data_initprot); // initprot
            write_u32(cmd2_off + 64, 1); // nsects = 1
            write_u32(cmd2_off + 68, 0); // flags

            // Section 2.1: __DATA,__data (80 bytes)
            size_t s3_off = cmd2_off + 72;
            std::memcpy(&buf[s3_off + 0], "__data\0\0\0\0\0\0\0\0\0\0", 16);
            std::memcpy(&buf[s3_off + 16], "__DATA\0\0\0\0\0\0\0\0\0\0", 16);
            write_u64(s3_off + 32, data_sec_addr);
            write_u64(s3_off + 40, data_sec_size);
            write_u32(s3_off + 48, is_zerofill_data ? 0 : static_cast<uint32_t>(data_sec_off));
            write_u32(s3_off + 52, 3); // align
            write_u32(s3_off + 56, 0);
            write_u32(s3_off + 60, 0);
            write_u32(s3_off + 64, is_zerofill_data ? 0x00000001 /* S_ZEROFILL */ : 0x00000000 /* S_REGULAR */);
            write_u32(s3_off + 68, 0);
            write_u32(s3_off + 72, 0);
            write_u32(s3_off + 76, 0);

            // Section payload bytes:
            // 1. Gadgets in __text (at text_sec_off)
            if (text_sec_off + 0x50 <= total_size) {
                buf[text_sec_off + 0x00] = 0x5F; buf[text_sec_off + 0x01] = 0xC3; // pop rdi ; ret
                buf[text_sec_off + 0x10] = 0x5E; buf[text_sec_off + 0x11] = 0xC3; // pop rsi ; ret
                buf[text_sec_off + 0x20] = 0x5A; buf[text_sec_off + 0x21] = 0xC3; // pop rdx ; ret
                buf[text_sec_off + 0x30] = 0x58; buf[text_sec_off + 0x31] = 0xC3; // pop rax ; ret
                buf[text_sec_off + 0x40] = 0x0F; buf[text_sec_off + 0x41] = 0x05; // syscall
            }

            // 2. Path string in __cstring (at cstr_sec_off)
            if (cstr_sec_off + path_str.size() < total_size) {
                std::memcpy(&buf[cstr_sec_off], path_str.data(), path_str.size());
                if (!omit_null_term_path && cstr_sec_off + path_str.size() < total_size) {
                    buf[cstr_sec_off + path_str.size()] = '\0';
                }
            }

            // 3. Pointer arrays in __data (at data_sec_off)
            if (!is_zerofill_data && data_sec_off + 0x20 <= total_size) {
                uint64_t a0 = (argv0_override != 0) ? argv0_override : cstr_sec_addr;
                uint64_t a1 = argv1_override; // default 0
                uint64_t e0 = envp0_override; // default 0
                write_u64(data_sec_off + 0x00, a0);
                write_u64(data_sec_off + 0x08, a1);
                write_u64(data_sec_off + 0x10, e0);
            }

            return buf;
        };

        auto write_bin = [](const fs::path& p, const std::vector<uint8_t>& d) {
            std::ofstream f(p, std::ios::binary);
            f.write(reinterpret_cast<const char*>(d.data()), d.size());
            f.close();
        };

        // 1. Construct and validate the canonical corrected synthetic fixture
        auto valid_buf = make_synthetic_macho64(
            0x100000000ULL, 0x2000ULL,
            0x100001000ULL, 0x100ULL, 0x1000ULL,
            0x100001800ULL, 0x20ULL,  0x1800ULL,
            0x100002000ULL, 0x1000ULL, 0x2000ULL,
            0x100002000ULL, 0x100ULL, 0x2000ULL
        );
        write_bin(validFixturePath, valid_buf);

        ropweaver::MachOParser parser(validFixturePath.string());
        bool parsed_ok = parser.parse(validFixturePath.string());
        assertCond("23.1a Fixture parser accepts corrected synthetic Mach-O", parsed_ok);
        assertCond("23.1b Fixture detected binary type is Mach-O", parser.getBinaryType() == "Mach-O");
        assertCond("23.1c Fixture detected architecture is x86_64", parser.getArchitecture() == "x86_64");
        assertCond("23.1d Fixture imageBase matches __TEXT vmaddr (0x100000000)", parser.getImageBase() == 0x100000000ULL);
        assertCond("23.1e Fixture has 3 sections", parser.getSections().size() == 3);

        // 2. Discover gadgets and verify byte verification
        GadgetFinder gf(parser.getTextSection(), parser.getTextSectionBaseAddress(), "x86_64",
                         validFixturePath.string(), parser.getExecBufferMappings(), 10, Endianness::Little);
        gf.findGadgets();
        const auto& gadgets = gf.getGadgets();
        assertCond("23.2a Discovered at least 5 gadgets", gadgets.size() >= 5);

        bool found_rdi = false, found_rsi = false, found_rdx = false, found_rax = false, found_syscall = false;
        bool all_byte_verified = true;
        for (const auto& g : gadgets) {
            if (!g.byte_verified) all_byte_verified = false;
            if (g.assembly == "pop rdi ; ret") found_rdi = true;
            if (g.assembly == "pop rsi ; ret") found_rsi = true;
            if (g.assembly == "pop rdx ; ret") found_rdx = true;
            if (g.assembly == "pop rax ; ret") found_rax = true;
            if (g.assembly == "syscall") found_syscall = true;
        }
        assertCond("23.2b All discovered gadgets are byte-verified", all_byte_verified);
        assertCond("23.2c Discovered pop rdi ; ret", found_rdi);
        assertCond("23.2d Discovered pop rsi ; ret", found_rsi);
        assertCond("23.2e Discovered pop rdx ; ret", found_rdx);
        assertCond("23.2f Discovered pop rax ; ret", found_rax);
        assertCond("23.2g Discovered syscall", found_syscall);

        // 3. Chain synthesis
        ChainBuilder builder(gadgets, "x86_64", "Mach-O", &parser);
        ROPChain chain;
        bool chain_built = false;
        try {
            chain = builder.buildExecveChain(0);
            chain_built = true;
        } catch (const std::exception& e) {
            chain_built = false;
        }
        assertCond("23.3a Darwin Mach-O chain synthesized successfully", chain_built);
        assertCond("23.3b Chain contains exactly 5 steps", chain.get_steps().size() == 5);

        // 4. Register values and syscall number
        if (chain.get_steps().size() == 5) {
            const auto& steps = chain.get_steps();
            assertCond("23.4a Step 1 sets RDI to /bin/sh address (0x100001800)",
                       steps[0].target_register == "rdi" && steps[0].value == 0x100001800ULL);
            assertCond("23.4b Step 2 sets RSI to argv address (0x100002000)",
                       steps[1].target_register == "rsi" && steps[1].value == 0x100002000ULL);
            assertCond("23.4c Step 3 sets RDX to dedicated envp address (0x100002010)",
                       steps[2].target_register == "rdx" && steps[2].value == 0x100002010ULL);
            assertCond("23.4d Step 4 sets RAX to Darwin BSD syscall number 0x200003B (33554491)",
                       steps[3].target_register == "rax" && steps[3].value == 0x200003BULL);
            assertCond("23.4e Step 5 invokes syscall",
                       steps[4].type == ROPStepType::SystemCallExecution);
        }

        // 5. Semantic Validation on valid fixture
        auto val_res = chain.validate("x86_64", &parser);
        assertCond("23.5a Semantic validation passes for valid Darwin chain", val_res.valid);
        assertCond("23.5b ABI conformance verified is true", val_res.abi_conformance_verified);
        assertCond("23.5c Bounds verified is true", val_res.bounds_verified);
        assertCond("23.5d Staged registers contain rdi, rsi, rdx, rax",
                   val_res.staged_registers.count("rdi") && val_res.staged_registers.count("rsi") &&
                   val_res.staged_registers.count("rdx") && val_res.staged_registers.count("rax"));

        // 6. Exact little-endian serialization
        auto payload_bytes = chain.getPayloadBytes();
        assertCond("23.6a Serialized payload size is 72 bytes (4 staging steps * 16 + 1 syscall * 8)", payload_bytes.size() == 72);
        bool le_syscall_match = (
            payload_bytes.size() >= 64 &&
            static_cast<uint8_t>(payload_bytes[56]) == 0x3B &&
            static_cast<uint8_t>(payload_bytes[57]) == 0x00 &&
            static_cast<uint8_t>(payload_bytes[58]) == 0x00 &&
            static_cast<uint8_t>(payload_bytes[59]) == 0x02 &&
            static_cast<uint8_t>(payload_bytes[60]) == 0x00 &&
            static_cast<uint8_t>(payload_bytes[61]) == 0x00 &&
            static_cast<uint8_t>(payload_bytes[62]) == 0x00 &&
            static_cast<uint8_t>(payload_bytes[63]) == 0x00
        );
        assertCond("23.6b RAX syscall number 0x200003B serialized as little-endian words", le_syscall_match);

        // 7. Null parser rejection (fail-closed)
        auto null_parser_res = chain.validate("x86_64", nullptr);
        assertCond("23.7 Null parser rejected for Darwin chain", !null_parser_res.valid &&
                   null_parser_res.error_message.find("active FileParser") != std::string::npos);

        // 8. Invalid syscall number rejection (e.g. 59 Linux syscall on Darwin)
        {
            ROPChain mod_chain;
            const auto& st = chain.get_steps();
            mod_chain.add_step(st[0].gadget, st[0].value, st[0].comment, st[0].type, st[0].target_register);
            mod_chain.add_step(st[1].gadget, st[1].value, st[1].comment, st[1].type, st[1].target_register);
            mod_chain.add_step(st[2].gadget, st[2].value, st[2].comment, st[2].type, st[2].target_register);
            mod_chain.add_step(st[3].gadget, 59ULL, "Linux syscall", st[3].type, st[3].target_register);
            mod_chain.add_step(st[4].gadget, st[4].comment, st[4].type);
            auto bad_sys_res = mod_chain.validate("x86_64", &parser);
            assertCond("23.8 Invalid syscall number (59) rejected on Darwin", !bad_sys_res.valid &&
                       bad_sys_res.error_message.find("Syscall number mismatch") != std::string::npos);
        }

        // 9. Zero or unmapped pointers rejection
        {
            const auto& st = chain.get_steps();
            // RDI = 0
            ROPChain c_rdi0;
            c_rdi0.add_step(st[0].gadget, 0ULL, "rdi 0", st[0].type, "rdi");
            c_rdi0.add_step(st[1].gadget, st[1].value, st[1].comment, st[1].type, "rsi");
            c_rdi0.add_step(st[2].gadget, st[2].value, st[2].comment, st[2].type, "rdx");
            c_rdi0.add_step(st[3].gadget, st[3].value, st[3].comment, st[3].type, "rax");
            c_rdi0.add_step(st[4].gadget, st[4].comment, st[4].type);
            auto rdi0_res = c_rdi0.validate("x86_64", &parser);
            assertCond("23.9a RDI = 0 rejected", !rdi0_res.valid && rdi0_res.error_message.find("Arg 1") != std::string::npos);

            // RSI = 0
            ROPChain c_rsi0;
            c_rsi0.add_step(st[0].gadget, st[0].value, st[0].comment, st[0].type, "rdi");
            c_rsi0.add_step(st[1].gadget, 0ULL, "rsi 0", st[1].type, "rsi");
            c_rsi0.add_step(st[2].gadget, st[2].value, st[2].comment, st[2].type, "rdx");
            c_rsi0.add_step(st[3].gadget, st[3].value, st[3].comment, st[3].type, "rax");
            c_rsi0.add_step(st[4].gadget, st[4].comment, st[4].type);
            auto rsi0_res = c_rsi0.validate("x86_64", &parser);
            assertCond("23.9b RSI = 0 rejected on Darwin", !rsi0_res.valid && rsi0_res.error_message.find("Arg 2") != std::string::npos);

            // RDX = 0
            ROPChain c_rdx0;
            c_rdx0.add_step(st[0].gadget, st[0].value, st[0].comment, st[0].type, "rdi");
            c_rdx0.add_step(st[1].gadget, st[1].value, st[1].comment, st[1].type, "rsi");
            c_rdx0.add_step(st[2].gadget, 0ULL, "rdx 0", st[2].type, "rdx");
            c_rdx0.add_step(st[3].gadget, st[3].value, st[3].comment, st[3].type, "rax");
            c_rdx0.add_step(st[4].gadget, st[4].comment, st[4].type);
            auto rdx0_res = c_rdx0.validate("x86_64", &parser);
            assertCond("23.9c RDX = 0 rejected on Darwin", !rdx0_res.valid && rdx0_res.error_message.find("Arg 3") != std::string::npos);

            // Unmapped pointer
            ROPChain c_unmap;
            c_unmap.add_step(st[0].gadget, 0x99999000ULL, "rdi unmapped", st[0].type, "rdi");
            c_unmap.add_step(st[1].gadget, st[1].value, st[1].comment, st[1].type, "rsi");
            c_unmap.add_step(st[2].gadget, st[2].value, st[2].comment, st[2].type, "rdx");
            c_unmap.add_step(st[3].gadget, st[3].value, st[3].comment, st[3].type, "rax");
            c_unmap.add_step(st[4].gadget, st[4].comment, st[4].type);
            auto unmap_res = c_unmap.validate("x86_64", &parser);
            assertCond("23.9d Unmapped RDI pointer rejected", !unmap_res.valid && unmap_res.error_message.find("does not resolve to any mapped section") != std::string::npos);
        }

        // 10. Invalid argv and envp contents
        {
            auto bad_argv_buf = make_synthetic_macho64(
                0x100000000ULL, 0x2000ULL,
                0x100001000ULL, 0x100ULL, 0x1000ULL,
                0x100001800ULL, 0x20ULL,  0x1800ULL,
                0x100002000ULL, 0x1000ULL, 0x2000ULL,
                0x100002000ULL, 0x100ULL, 0x2000ULL,
                0, false, "/bin/sh", 0xDEADBEEFULL /* bad argv[0] */, 0, 0
            );
            write_bin(invalidArgvPath, bad_argv_buf);
            ropweaver::MachOParser bad_argv_parser(invalidArgvPath.string());
            bad_argv_parser.parse(invalidArgvPath.string());
            auto bad_argv_res = chain.validate("x86_64", &bad_argv_parser);
            assertCond("23.10a argv[0] not matching path pointer rejected", !bad_argv_res.valid &&
                       bad_argv_res.error_message.find("does not equal Arg 1 path address") != std::string::npos);

            auto bad_envp_buf = make_synthetic_macho64(
                0x100000000ULL, 0x2000ULL,
                0x100001000ULL, 0x100ULL, 0x1000ULL,
                0x100001800ULL, 0x20ULL,  0x1800ULL,
                0x100002000ULL, 0x1000ULL, 0x2000ULL,
                0x100002000ULL, 0x100ULL, 0x2000ULL,
                0, false, "/bin/sh", 0, 0, 0x1234ULL /* bad envp[0] */
            );
            write_bin(invalidEnvpPath, bad_envp_buf);
            ropweaver::MachOParser bad_envp_parser(invalidEnvpPath.string());
            bad_envp_parser.parse(invalidEnvpPath.string());
            ROPChain c_bad_envp;
            const auto& st = chain.get_steps();
            c_bad_envp.add_step(st[0].gadget, st[0].value, st[0].comment, st[0].type, "rdi");
            c_bad_envp.add_step(st[1].gadget, st[1].value, st[1].comment, st[1].type, "rsi");
            c_bad_envp.add_step(st[2].gadget, 0x100002010ULL, st[2].comment, st[2].type, "rdx");
            c_bad_envp.add_step(st[3].gadget, st[3].value, st[3].comment, st[3].type, "rax");
            c_bad_envp.add_step(st[4].gadget, st[4].comment, st[4].type);
            auto bad_envp_res = c_bad_envp.validate("x86_64", &bad_envp_parser);
            assertCond("23.10b Non-null envp[0] rejected", !bad_envp_res.valid &&
                       bad_envp_res.error_message.find("envp[0] is not NULL") != std::string::npos);
        }

        // 11. Non-readable and zero-fill sections
        {
            auto zf_buf = make_synthetic_macho64(
                0x100000000ULL, 0x2000ULL,
                0x100001000ULL, 0x100ULL, 0x1000ULL,
                0x100001800ULL, 0x20ULL,  0x1800ULL,
                0x100002000ULL, 0x1000ULL, 0x2000ULL,
                0x100002000ULL, 0x100ULL, 0x2000ULL,
                0, true /* zerofill data */
            );
            write_bin(zerofillPath, zf_buf);
            ropweaver::MachOParser zf_parser(zerofillPath.string());
            zf_parser.parse(zerofillPath.string());
            auto zf_res = chain.validate("x86_64", &zf_parser);
            assertCond("23.11 Zerofill / non-file-backed data section rejected", !zf_res.valid &&
                       zf_res.error_message.find("zero-fill section") != std::string::npos);
        }

        // 12. Out-of-bounds and overflow bounds safety
        {
            const auto& st = chain.get_steps();
            ROPChain c_oob;
            c_oob.add_step(st[0].gadget, st[0].value, st[0].comment, st[0].type, "rdi");
            c_oob.add_step(st[1].gadget, 0x1000020F8ULL /* near end of 0x100 section */, "rsi oob", st[1].type, "rsi");
            c_oob.add_step(st[2].gadget, st[2].value, st[2].comment, st[2].type, "rdx");
            c_oob.add_step(st[3].gadget, st[3].value, st[3].comment, st[3].type, "rax");
            c_oob.add_step(st[4].gadget, st[4].comment, st[4].type);
            auto oob_res = c_oob.validate("x86_64", &parser);
            assertCond("23.12 Insufficient section bounds for argv array rejected", !oob_res.valid &&
                       oob_res.error_message.find("requires at least 16 file-backed bytes") != std::string::npos);
        }

        // 13. Fat Mach-O slice-offset handling
        {
            std::vector<uint8_t> fat_buf(0x1000 + valid_buf.size(), 0);
            fat_buf[0] = 0xCA; fat_buf[1] = 0xFE; fat_buf[2] = 0xBA; fat_buf[3] = 0xBE;
            fat_buf[4] = 0x00; fat_buf[5] = 0x00; fat_buf[6] = 0x00; fat_buf[7] = 0x01;
            fat_buf[8]  = 0x01; fat_buf[9]  = 0x00; fat_buf[10] = 0x00; fat_buf[11] = 0x07;
            fat_buf[12] = 0x00; fat_buf[13] = 0x00; fat_buf[14] = 0x00; fat_buf[15] = 0x03;
            fat_buf[16] = 0x00; fat_buf[17] = 0x00; fat_buf[18] = 0x10; fat_buf[19] = 0x00;
            fat_buf[20] = 0x00; fat_buf[21] = 0x00; fat_buf[22] = 0x30; fat_buf[23] = 0x00;
            fat_buf[24] = 0x00; fat_buf[25] = 0x00; fat_buf[26] = 0x00; fat_buf[27] = 0x0C;

            std::memcpy(&fat_buf[0x1000], valid_buf.data(), valid_buf.size());
            write_bin(fatFixturePath, fat_buf);

            ropweaver::MachOParser fat_parser(fatFixturePath.string(), "x86_64");
            bool fat_ok = fat_parser.parse(fatFixturePath.string(), "x86_64");
            assertCond("23.13a Fat Mach-O binary parsed successfully", fat_ok);

            GadgetFinder fat_gf(fat_parser.getTextSection(), fat_parser.getTextSectionBaseAddress(), "x86_64",
                                fatFixturePath.string(), fat_parser.getExecBufferMappings(), 10, Endianness::Little);
            fat_gf.findGadgets();
            ChainBuilder fat_builder(fat_gf.getGadgets(), "x86_64", "Mach-O", &fat_parser);
            ROPChain fat_chain = fat_builder.buildExecveChain(0);
            auto fat_val_res = fat_chain.validate("x86_64", &fat_parser);
            assertCond("23.13b Fat Mach-O chain synthesized and validated across slice offset", fat_val_res.valid);
        }

        // 14. PIE relocation transparency in JSON report
        {
            auto pie_buf = make_synthetic_macho64(
                0x100000000ULL, 0x2000ULL,
                0x100001000ULL, 0x100ULL, 0x1000ULL,
                0x100001800ULL, 0x20ULL,  0x1800ULL,
                0x100002000ULL, 0x1000ULL, 0x2000ULL,
                0x100002000ULL, 0x100ULL, 0x2000ULL,
                0x200000 /* MH_PIE */
            );
            write_bin(pieFixturePath, pie_buf);
            ropweaver::MachOParser pie_parser(pieFixturePath.string());
            pie_parser.parse(pieFixturePath.string());
            assertCond("23.14a PIE enabled detected on Mach-O fixture", pie_parser.isPieEnabled());

            PayloadGenerator pg;
            std::string tempReport = (tempDir / "test_pie_report.json").string();
            std::string tempPayload = (tempDir / "test_pie_payload.bin").string();
            std::string tempReportsPayload = (tempDir / "test_pie_reports_payload.bin").string();
            nlohmann::json base_report = {
                {"PIE", true}
            };
            pg.generate(chain, 104, pieFixturePath.string(), gadgets,
                        "x86_64", "Mach-O", base_report,
                        "", "", &pie_parser,
                        tempReport, tempPayload, tempReportsPayload);

            std::ifstream rfile(tempReport);
            nlohmann::json rjson;
            rfile >> rjson;
            rfile.close();

            assertCond("23.14b PIE report status is Success (Relocation Required)",
                       rjson["rop_chain_generation"]["status"].get<std::string>() == "Success (Relocation Required)");
            assertCond("23.14c PIE report aslr_slide_applied is false",
                       rjson["rop_chain_generation"]["aslr_slide_applied"].get<bool>() == false);
            assertCond("23.14d PIE report records relocation_status with MH_PIE note",
                       rjson["rop_chain_generation"]["relocation_status"].get<std::string>().find("MH_PIE") != std::string::npos);

            fs::remove(tempReport, ec);
            fs::remove(tempPayload, ec);
            fs::remove(tempReportsPayload, ec);
        }

        // 15. File-backed section in a segment without VM_PROT_READ
        {
            fs::path noReadPath = tempDir / "test_darwin_fixture_no_read.bin";
            auto no_read_buf = make_synthetic_macho64(
                0x100000000ULL, 0x2000ULL,
                0x100001000ULL, 0x100ULL, 0x1000ULL,
                0x100001800ULL, 0x20ULL,  0x1800ULL,
                0x100002000ULL, 0x1000ULL, 0x2000ULL,
                0x100002000ULL, 0x100ULL, 0x2000ULL,
                0, false, "/bin/sh", 0, 0, 0, false,
                5 /* __TEXT R-X */, 2 /* __DATA -W- (lacks VM_PROT_READ) */
            );
            write_bin(noReadPath, no_read_buf);
            ropweaver::MachOParser nr_parser(noReadPath.string());
            nr_parser.parse(noReadPath.string());
            auto nr_res = chain.validate("x86_64", &nr_parser);
            assertCond("23.15 File-backed section in segment lacking VM_PROT_READ rejected",
                       !nr_res.valid && nr_res.error_message.find("without VM_PROT_READ permission") != std::string::npos);
            fs::remove(noReadPath, ec);
        }

        // 16. Pointer array crossing a readable segment boundary
        {
            fs::path segCrossPath = tempDir / "test_darwin_fixture_seg_cross.bin";
            auto seg_cross_buf = make_synthetic_macho64(
                0x100000000ULL, 0x2000ULL,
                0x100001000ULL, 0x100ULL, 0x1000ULL,
                0x100001800ULL, 0x20ULL,  0x1800ULL,
                0x100002000ULL, 0x108ULL, 0x2000ULL, // __DATA vmsize = 0x108 (ends at 0x100002108)
                0x100002000ULL, 0x108ULL, 0x2000ULL  // data_sec_size = 0x108 (ends at 0x100002108)
            );
            uint64_t a0 = 0x100001800ULL;
            for (int i = 0; i < 8; ++i) {
                seg_cross_buf[0x2100 + i] = static_cast<uint8_t>((a0 >> (8 * i)) & 0xFF);
            }
            write_bin(segCrossPath, seg_cross_buf);
            ropweaver::MachOParser cross_parser(segCrossPath.string());
            cross_parser.parse(segCrossPath.string());

            const auto& st = chain.get_steps();
            ROPChain c_cross_seg;
            c_cross_seg.add_step(st[0].gadget, st[0].value, st[0].comment, st[0].type, "rdi");
            // Set RSI to 0x100002100 (crosses 0x100002108 segment boundary)
            c_cross_seg.add_step(st[1].gadget, 0x100002100ULL, "cross segment boundary", st[1].type, "rsi");
            c_cross_seg.add_step(st[2].gadget, 0x100002010ULL, st[2].comment, st[2].type, "rdx");
            c_cross_seg.add_step(st[3].gadget, st[3].value, st[3].comment, st[3].type, "rax");
            c_cross_seg.add_step(st[4].gadget, st[4].comment, st[4].type);
            auto cross_res = c_cross_seg.validate("x86_64", &cross_parser);
            assertCond("23.16 Pointer array crossing readable segment boundary rejected",
                       !cross_res.valid && cross_res.error_message.find("crosses readable segment boundary") != std::string::npos);
            fs::remove(segCrossPath, ec);
        }

        // 17. Path string crossing a readable segment boundary
        {
            fs::path pathCrossPath = tempDir / "test_darwin_fixture_path_cross.bin";
            // __TEXT vmsize = 0x1804 (ends at 0x100001804). cstr section ends at 0x100001804.
            auto path_cross_buf = make_synthetic_macho64(
                0x100000000ULL, 0x1804ULL,
                0x100001000ULL, 0x100ULL, 0x1000ULL,
                0x100001800ULL, 0x4ULL,   0x1800ULL, // cstr size = 4 bytes
                0x100002000ULL, 0x1000ULL, 0x2000ULL,
                0x100002000ULL, 0x100ULL, 0x2000ULL,
                0, false, "/bin", 0, 0, 0, true // 4 bytes, no null terminator
            );
            write_bin(pathCrossPath, path_cross_buf);
            ropweaver::MachOParser path_cross_parser(pathCrossPath.string());
            path_cross_parser.parse(pathCrossPath.string());

            const auto& st = chain.get_steps();
            ROPChain c_path_cross;
            c_path_cross.add_step(st[0].gadget, 0x100001800ULL, "cross segment boundary", st[0].type, "rdi");
            c_path_cross.add_step(st[1].gadget, st[1].value, st[1].comment, st[1].type, "rsi");
            c_path_cross.add_step(st[2].gadget, st[2].value, st[2].comment, st[2].type, "rdx");
            c_path_cross.add_step(st[3].gadget, st[3].value, st[3].comment, st[3].type, "rax");
            c_path_cross.add_step(st[4].gadget, st[4].comment, st[4].type);
            auto path_cross_res = c_path_cross.validate("x86_64", &path_cross_parser);
            assertCond("23.17 Path string crossing readable segment boundary rejected",
                       !path_cross_res.valid && (path_cross_res.error_message.find("crosses readable segment boundary") != std::string::npos ||
                                                path_cross_res.error_message.find("not null-terminated within section bounds") != std::string::npos ||
                                                path_cross_res.error_message.find("crosses section boundary") != std::string::npos));
            fs::remove(pathCrossPath, ec);
        }

        // 18. Missing or inconsistent segment metadata
        {
            struct EmptySegParser : public ropweaver::MachOParser {
                EmptySegParser(const std::string& p) : ropweaver::MachOParser(p) {}
                const std::vector<MachOSegmentInfo>& getMachOSegments() const override {
                    static const std::vector<MachOSegmentInfo> empty;
                    return empty;
                }
            };
            EmptySegParser empty_seg_parser(validFixturePath.string());
            empty_seg_parser.parse(validFixturePath.string());
            auto empty_seg_res = chain.validate("x86_64", &empty_seg_parser);
            assertCond("23.18a Missing segment metadata rejected",
                       !empty_seg_res.valid && empty_seg_res.error_message.find("Segment metadata is unavailable") != std::string::npos);

            struct CorruptedSegParser : public ropweaver::MachOParser {
                CorruptedSegParser(const std::string& p) : ropweaver::MachOParser(p) {}
                const std::vector<MachOSegmentInfo>& getMachOSegments() const override {
                    static std::vector<MachOSegmentInfo> corrupted = {
                        {"__CORRUPTED", 0x300000000ULL, 0x1000ULL, 0, 0, 7, 7, 0, 0}
                    };
                    return corrupted;
                }
            };
            CorruptedSegParser corrupted_seg_parser(validFixturePath.string());
            corrupted_seg_parser.parse(validFixturePath.string());
            auto corrupted_seg_res = chain.validate("x86_64", &corrupted_seg_parser);
            assertCond("23.18b Inconsistent segment metadata rejected",
                       !corrupted_seg_res.valid && corrupted_seg_res.error_message.find("Missing or inconsistent segment metadata") != std::string::npos);
        }

        // 19. Rejection when only string padding or argv's NULL terminator is available
        {
            fs::path noDedicatedEnvpPath = tempDir / "test_darwin_fixture_no_envp.bin";
            // __data section is only 16 bytes: argv[0] and argv[1] (NULL). No dedicated envp array.
            auto no_envp_buf = make_synthetic_macho64(
                0x100000000ULL, 0x2000ULL,
                0x100001000ULL, 0x100ULL, 0x1000ULL,
                0x100001800ULL, 0x20ULL,  0x1800ULL,
                0x100002000ULL, 0x1000ULL, 0x2000ULL,
                0x100002000ULL, 0x10ULL,  0x2000ULL
            );
            write_bin(noDedicatedEnvpPath, no_envp_buf);
            ropweaver::MachOParser no_envp_parser(noDedicatedEnvpPath.string());
            no_envp_parser.parse(noDedicatedEnvpPath.string());

            GadgetFinder no_envp_gf(no_envp_parser.getTextSection(), no_envp_parser.getTextSectionBaseAddress(), "x86_64",
                                    noDedicatedEnvpPath.string(), no_envp_parser.getExecBufferMappings(), 10, Endianness::Little);
            no_envp_gf.findGadgets();
            ChainBuilder no_envp_builder(no_envp_gf.getGadgets(), "x86_64", "Mach-O", &no_envp_parser);

            uint64_t discovered_envp = no_envp_builder.findDarwinEnvpAddress();
            assertCond("23.19a findDarwinEnvpAddress returns 0 when only string padding or argv[1] is present",
                       discovered_envp == 0);

            bool build_threw = false;
            try {
                no_envp_builder.buildExecveChain(0);
            } catch (const std::runtime_error& ex) {
                build_threw = true;
                std::string msg = ex.what();
                assertCond("23.19b Synthesis fails closed without valid dedicated envp array",
                           msg.find("Could not find valid envp array") != std::string::npos);
            }
            assertCond("23.19c ChainBuilder threw on missing dedicated envp", build_threw);

            fs::remove(noDedicatedEnvpPath, ec);
        }

        // Cleanup temporary fixture files
        fs::remove(validFixturePath, ec);
        fs::remove(pieFixturePath, ec);
        fs::remove(invalidArgvPath, ec);
        fs::remove(invalidEnvpPath, ec);
        fs::remove(zerofillPath, ec);
        fs::remove(fatFixturePath, ec);
    }

    std::cout << "\n============================================================\n";
    std::cout << "Test Results: " << passed << " Passed, " << failures << " Failed\n";
    std::cout << "============================================================\n";

    return (failures == 0) ? 0 : 1;
}
