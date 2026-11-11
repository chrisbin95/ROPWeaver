#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include <cassert>
#include "core/gadget_finder.h"
#include "core/parsers/file_parser.h"

int main() {
    int failures = 0;

    auto assertCond = [&](const std::string& testName, bool condition, const std::string& details = "") {
        if (condition) {
            std::cout << "  [PASS] " << testName << "\n";
        } else {
            std::cerr << "  [FAIL] " << testName << ": " << details << "\n";
            failures++;
        }
    };

    std::cout << "=== Running GadgetFinder Endianness Unit Tests ===\n";

    // Dummy x86_64 code: ret (0xc3)
    std::vector<unsigned char> code_x64 = { 0xc3 };
    uint64_t base = 0x400000;
    std::string dummyPath = "dummy.bin";

    // 1. Unknown instruction endianness rejected before Capstone initialization
    {
        bool caught = false;
        std::string errMsg;
        try {
            GadgetFinder finder(code_x64, base, "x86_64", dummyPath, 10, Endianness::Unknown);
        } catch (const std::runtime_error& e) {
            caught = true;
            errMsg = e.what();
        } catch (...) {
            caught = false;
        }
        assertCond("GadgetFinder rejects Endianness::Unknown in constructor", caught, "Expected std::runtime_error");
        assertCond("GadgetFinder Unknown error message identifies condition and arch",
                   errMsg.find("Unknown instruction endianness") != std::string::npos &&
                   errMsg.find("x86_64") != std::string::npos,
                   "Error message: " + errMsg);
    }

    // 2. Unsupported instruction endianness rejected before Capstone initialization
    {
        bool caught = false;
        std::string errMsg;
        try {
            GadgetFinder finder(code_x64, base, "x86_64", dummyPath, 10, Endianness::Unsupported);
        } catch (const std::runtime_error& e) {
            caught = true;
            errMsg = e.what();
        } catch (...) {
            caught = false;
        }
        assertCond("GadgetFinder rejects Endianness::Unsupported in constructor", caught, "Expected std::runtime_error");
        assertCond("GadgetFinder Unsupported error message identifies condition and arch",
                   errMsg.find("Unsupported instruction endianness") != std::string::npos &&
                   errMsg.find("x86_64") != std::string::npos,
                   "Error message: " + errMsg);
    }

    // 3. Backward compatibility: default constructor argument defaults to Little Endian
    {
        bool constructOk = false;
        bool getOk = false;
        bool disasmOk = false;
        try {
            GadgetFinder finder(code_x64, base, "x86_64", dummyPath, 10);
            constructOk = true;
            getOk = (finder.getInstructionEndianness() == Endianness::Little);
            finder.findGadgets();
            disasmOk = true;
        } catch (const std::exception& e) {
            std::cerr << "Unexpected exception: " << e.what() << "\n";
        }
        assertCond("GadgetFinder default parameter constructs successfully", constructOk);
        assertCond("GadgetFinder default parameter is Endianness::Little", getOk);
        assertCond("GadgetFinder default parameter findGadgets() succeeds", disasmOk);
    }

    // 4. Explicit Little Endian x86_64
    {
        bool constructOk = false;
        bool getOk = false;
        bool disasmOk = false;
        try {
            GadgetFinder finder(code_x64, base, "x86_64", dummyPath, 10, Endianness::Little);
            constructOk = true;
            getOk = (finder.getInstructionEndianness() == Endianness::Little);
            finder.findGadgets();
            disasmOk = true;
        } catch (const std::exception& e) {
            std::cerr << "Unexpected exception: " << e.what() << "\n";
        }
        assertCond("GadgetFinder explicit Endianness::Little constructs successfully", constructOk);
        assertCond("GadgetFinder getInstructionEndianness() returns Little", getOk);
        assertCond("GadgetFinder explicit Little findGadgets() succeeds", disasmOk);
    }

    // 5. Rejection of Endianness::Big for architectures without big-endian instruction support
    {
        auto testBeReject = [&](const std::string& arch) {
            bool caught = false;
            std::string errMsg;
            try {
                GadgetFinder finder(code_x64, base, arch, dummyPath, 10, Endianness::Big);
            } catch (const std::runtime_error& e) {
                caught = true;
                errMsg = e.what();
            }
            assertCond("Big Endian rejected for " + arch, caught && errMsg.find("Big-endian instruction decoding is not supported") != std::string::npos,
                       "Error message: " + errMsg);
        };

        testBeReject("x86");
        testBeReject("x86_64");
        testBeReject("aarch64");
        testBeReject("arm64");
        testBeReject("riscv32");
        testBeReject("riscv64");
    }

    // 6. ARM Big Endian disassembly: E1 2F FF 1E decodes as 'bx lr'
    {
        std::vector<unsigned char> arm_be_bxlr = { 0xe1, 0x2f, 0xff, 0x1e };
        try {
            GadgetFinder finder(arm_be_bxlr, 0x10000, "armv7", dummyPath, 10, Endianness::Big);
            assertCond("ARM Big Endian (armv7) constructor succeeds", true);
            assertCond("ARM Big Endian getInstructionEndianness() == Big", finder.getInstructionEndianness() == Endianness::Big);
            finder.findGadgets();
            const auto& gadgets = finder.getGadgets();
            assertCond("ARM Big Endian finds gadget for E1 2F FF 1E", gadgets.size() == 1,
                       "Found " + std::to_string(gadgets.size()) + " gadgets");
            if (!gadgets.empty()) {
                assertCond("ARM Big Endian decoded as 'bx lr'", gadgets[0].assembly == "bx lr",
                           "Assembly: " + gadgets[0].assembly);
                assertCond("ARM Big Endian gadget byte_verified == true", gadgets[0].byte_verified);
            }
        } catch (const std::exception& e) {
            assertCond("ARM Big Endian (armv7) disassembly", false, e.what());
        }

        // Also test arch 'arm' alias
        try {
            GadgetFinder finder(arm_be_bxlr, 0x10000, "arm", dummyPath, 10, Endianness::Big);
            finder.findGadgets();
            const auto& gadgets = finder.getGadgets();
            assertCond("ARM Big Endian ('arm' alias) finds gadget", gadgets.size() == 1);
            if (!gadgets.empty()) {
                assertCond("ARM Big Endian ('arm' alias) decoded as 'bx lr'", gadgets[0].assembly == "bx lr");
            }
        } catch (const std::exception& e) {
            assertCond("ARM Big Endian ('arm' alias) disassembly", false, e.what());
        }
    }

    // 7. ARM Little Endian disassembly: 1E FF 2F E1 decodes as 'bx lr'
    {
        std::vector<unsigned char> arm_le_bxlr = { 0x1e, 0xff, 0x2f, 0xe1 };
        try {
            GadgetFinder finder(arm_le_bxlr, 0x10000, "armv7", dummyPath, 10, Endianness::Little);
            assertCond("ARM Little Endian (armv7) constructor succeeds", true);
            finder.findGadgets();
            const auto& gadgets = finder.getGadgets();
            assertCond("ARM Little Endian finds gadget for 1E FF 2F E1", gadgets.size() == 1,
                       "Found " + std::to_string(gadgets.size()) + " gadgets");
            if (!gadgets.empty()) {
                assertCond("ARM Little Endian decoded as 'bx lr'", gadgets[0].assembly == "bx lr",
                           "Assembly: " + gadgets[0].assembly);
                assertCond("ARM Little Endian gadget byte_verified == true", gadgets[0].byte_verified);
            }
        } catch (const std::exception& e) {
            assertCond("ARM Little Endian (armv7) disassembly", false, e.what());
        }
    }

    // 8. Cross-Endian negative checks:
    // Big-endian ARM mode must not incorrectly decode the little-endian sequence as 'bx lr'
    {
        std::vector<unsigned char> arm_le_bxlr = { 0x1e, 0xff, 0x2f, 0xe1 };
        try {
            GadgetFinder finder(arm_le_bxlr, 0x10000, "armv7", dummyPath, 10, Endianness::Big);
            finder.findGadgets();
            const auto& gadgets = finder.getGadgets();
            bool has_bxlr = false;
            for (const auto& g : gadgets) {
                if (g.assembly == "bx lr") has_bxlr = true;
            }
            assertCond("Big-endian ARM mode does NOT decode little-endian bytes as 'bx lr'", !has_bxlr);
        } catch (const std::exception& e) {
            assertCond("Cross-endian negative check (BE on LE bytes)", false, e.what());
        }
    }

    // Little-endian ARM mode must not incorrectly decode the big-endian sequence as 'bx lr'
    {
        std::vector<unsigned char> arm_be_bxlr = { 0xe1, 0x2f, 0xff, 0x1e };
        try {
            GadgetFinder finder(arm_be_bxlr, 0x10000, "armv7", dummyPath, 10, Endianness::Little);
            finder.findGadgets();
            const auto& gadgets = finder.getGadgets();
            bool has_bxlr = false;
            for (const auto& g : gadgets) {
                if (g.assembly == "bx lr") has_bxlr = true;
            }
            assertCond("Little-endian ARM mode does NOT decode big-endian bytes as 'bx lr'", !has_bxlr);
        } catch (const std::exception& e) {
            assertCond("Cross-endian negative check (LE on BE bytes)", false, e.what());
        }
    }

    std::cout << "GadgetFinder Endianness tests completed with " << failures << " failures.\n";
    return (failures == 0) ? 0 : 1;
}
