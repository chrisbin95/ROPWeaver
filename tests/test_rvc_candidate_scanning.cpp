#include "core/gadget_finder.h"
#include "core/capstone_compat.h"
#include <iostream>
#include <vector>
#include <cassert>
#include <cstring>

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

// 1. Candidate 2-byte aligned starts for RVC
static void test_rvc_candidate_2byte_starts() {
    // 0x00: c.li a0, 5     (16-bit: 0x4515 -> 0x15, 0x45)
    // 0x02: c.jr ra        (16-bit: 0x8082 -> 0x82, 0x80)
    std::vector<unsigned char> code = {
        0x15, 0x45, // c.li a0, 5
        0x82, 0x80  // c.jr ra
    };

    GadgetFinder finder(code, 0x1000, "riscv32", "", 10, Endianness::Little, true);
    ASSERT_TRUE(finder.isRvcEnabled(), "Finder must report RVC enabled");
    finder.findGadgets();

    const auto& gadgets = finder.getGadgets();
    ASSERT_EQ(gadgets.size(), 2, "Expected exactly 2 gadgets (at 0x1000 and 0x1002)");

    bool found_1000 = false;
    bool found_1002 = false;

    for (const auto& g : gadgets) {
        if (g.address == 0x1000) {
            found_1000 = true;
            ASSERT_EQ(g.instructions.size(), 2, "Gadget at 0x1000 must have 2 instructions");
            ASSERT_EQ(g.terminator_type, "RET", "Gadget at 0x1000 must have RET terminator");
            ASSERT_TRUE(g.byte_verified, "Gadget at 0x1000 must be byte verified");
        } else if (g.address == 0x1002) {
            found_1002 = true;
            ASSERT_EQ(g.instructions.size(), 1, "Gadget at 0x1002 must have 1 instruction (c.jr ra)");
            ASSERT_EQ(g.terminator_type, "RET", "Gadget at 0x1002 must have RET terminator");
            ASSERT_TRUE(g.byte_verified, "Gadget at 0x1002 must be byte verified");
        }
    }
    ASSERT_TRUE(found_1000, "Must find gadget at 0x1000");
    ASSERT_TRUE(found_1002, "Must find gadget at 2-byte aligned address 0x1002 (unaligned to 4)");
}

// 2. Variable-length mixed 16-bit and 32-bit sequence
static void test_rvc_variable_length_mixed_sequence() {
    // 0x00: c.addi a0, 1           (16-bit: 0x0505 -> 0x05, 0x05)
    // 0x02: addi a1, a1, 2         (32-bit: 0x00258593 -> 0x93, 0x85, 0x25, 0x00)
    // 0x06: c.jr ra                (16-bit: 0x8082 -> 0x82, 0x80)
    std::vector<unsigned char> code = {
        0x05, 0x05,             // c.addi a0, 1 (2 bytes)
        0x93, 0x85, 0x25, 0x00, // addi a1, a1, 2 (4 bytes)
        0x82, 0x80              // c.jr ra (2 bytes)
    };

    GadgetFinder finder(code, 0x2000, "riscv64", "", 10, Endianness::Little, true);
    ASSERT_TRUE(finder.isRvcEnabled(), "Finder must report RVC enabled for RV64");
    finder.findGadgets();

    const auto& gadgets = finder.getGadgets();
    // Gadgets expected:
    // 0x2000: c.addi a0, 1 ; addi a1, a1, 2 ; c.jr ra (3 instructions)
    // 0x2002: addi a1, a1, 2 ; c.jr ra (2 instructions, starts at 2-byte boundary)
    // 0x2006: c.jr ra (1 instruction, starts at 2-byte boundary 0x2006)
    ASSERT_EQ(gadgets.size(), 3, "Expected 3 gadgets across variable-length sequence");

    bool found_2000 = false;
    bool found_2002 = false;
    bool found_2006 = false;

    for (const auto& g : gadgets) {
        if (g.address == 0x2000) {
            found_2000 = true;
            ASSERT_EQ(g.instructions.size(), 3, "Gadget at 0x2000 must have 3 instructions");
            ASSERT_TRUE(g.byte_verified, "Gadget at 0x2000 must be byte verified");
        } else if (g.address == 0x2002) {
            found_2002 = true;
            ASSERT_EQ(g.instructions.size(), 2, "Gadget at 0x2002 must have 2 instructions");
            ASSERT_TRUE(g.byte_verified, "Gadget at 0x2002 must be byte verified");
        } else if (g.address == 0x2006) {
            found_2006 = true;
            ASSERT_EQ(g.instructions.size(), 1, "Gadget at 0x2006 must have 1 instruction");
            ASSERT_TRUE(g.byte_verified, "Gadget at 0x2006 must be byte verified");
        }
    }
    ASSERT_TRUE(found_2000, "Must find gadget at 0x2000");
    ASSERT_TRUE(found_2002, "Must find gadget at 0x2002 (mixed 32-bit + 16-bit)");
    ASSERT_TRUE(found_2006, "Must find gadget at 0x2006 (16-bit ret)");
}

// 3. RVC with 32-bit return terminator (ret / jalr x0, 0(ra))
static void test_rvc_with_32bit_ret() {
    // 0x00: c.li a0, 1             (16-bit: 0x4505 -> 0x05, 0x45)
    // 0x02: c.li a1, 2             (16-bit: 0x4589 -> 0x89, 0x45)
    // 0x04: ret                    (32-bit: 0x00008067 -> 0x67, 0x80, 0x00, 0x00)
    std::vector<unsigned char> code = {
        0x05, 0x45,             // c.li a0, 1
        0x89, 0x45,             // c.li a1, 2
        0x67, 0x80, 0x00, 0x00  // ret
    };

    GadgetFinder finder(code, 0x3000, "riscv32", "", 10, Endianness::Little, true);
    finder.findGadgets();

    const auto& gadgets = finder.getGadgets();
    // Gadgets:
    // 0x3000: c.li a0, 1 ; c.li a1, 2 ; ret
    // 0x3002: c.li a1, 2 ; ret (starts at 0x3002)
    // 0x3004: ret
    ASSERT_EQ(gadgets.size(), 3, "Expected 3 gadgets ending in 32-bit ret");

    bool found_3002 = false;
    for (const auto& g : gadgets) {
        if (g.address == 0x3002) {
            found_3002 = true;
            ASSERT_EQ(g.instructions.size(), 2, "Gadget at 0x3002 must have 2 instructions");
            ASSERT_EQ(g.terminator_type, "RET", "Gadget at 0x3002 must have RET terminator");
            ASSERT_TRUE(g.byte_verified, "Gadget at 0x3002 must be byte verified");
        }
    }
    ASSERT_TRUE(found_3002, "Must find gadget starting at 2-byte boundary 0x3002");
}

// 4. Distinction between c.jr ra (ret) and c.jalr (call)
static void test_rvc_c_jalr_is_not_ret() {
    // 0x00: c.li a0, 1   (16-bit: 0x05, 0x45)
    // 0x02: c.jalr ra    (16-bit: 0x9082 -> 0x82, 0x90)
    std::vector<unsigned char> code = {
        0x05, 0x45,
        0x82, 0x90
    };

    GadgetFinder finder(code, 0x4000, "riscv32", "", 10, Endianness::Little, true);
    finder.findGadgets();

    const auto& gadgets = finder.getGadgets();
    ASSERT_EQ(gadgets.size(), 0, "c.jalr must NEVER be accepted as a return terminator");
}

// 5. Rejection of traps: c.ebreak and ebreak
static void test_rvc_traps_rejected() {
    // 0x00: c.li a0, 1   (16-bit: 0x05, 0x45)
    // 0x02: c.ebreak     (16-bit: 0x9002 -> 0x02, 0x90)
    std::vector<unsigned char> code_c_ebreak = {
        0x05, 0x45,
        0x02, 0x90
    };

    GadgetFinder finder1(code_c_ebreak, 0x5000, "riscv32", "", 10, Endianness::Little, true);
    finder1.findGadgets();
    ASSERT_EQ(finder1.getGadgets().size(), 0, "c.ebreak must NEVER be accepted as a terminator");

    // Intermediate c.ebreak:
    // 0x00: c.li a0, 1
    // 0x02: c.ebreak
    // 0x04: c.jr ra
    std::vector<unsigned char> code_inter_trap = {
        0x05, 0x45,
        0x02, 0x90,
        0x82, 0x80
    };

    GadgetFinder finder2(code_inter_trap, 0x5000, "riscv32", "", 10, Endianness::Little, true);
    finder2.findGadgets();
    const auto& gadgets2 = finder2.getGadgets();
    // Only 0x5004 (c.jr ra) is valid; sequence through 0x5002 c.ebreak must be rejected!
    ASSERT_EQ(gadgets2.size(), 1, "Intermediate c.ebreak must invalidate multi-instruction gadget");
    if (!gadgets2.empty()) {
        ASSERT_EQ(gadgets2[0].address, 0x5004, "Only gadget at 0x5004 can survive");
    }
}

// 6. Intermediate compressed branch rejection
static void test_rvc_intermediate_branch_rejected() {
    // 0x00: c.li a0, 1   (16-bit: 0x05, 0x45)
    // 0x02: c.j 0        (16-bit: 0xa001 -> 0x01, 0xa0)
    // 0x04: c.jr ra      (16-bit: 0x82, 0x80)
    std::vector<unsigned char> code = {
        0x05, 0x45,
        0x01, 0xa0, // c.j offset 0
        0x82, 0x80  // c.jr ra
    };

    GadgetFinder finder(code, 0x6000, "riscv32", "", 10, Endianness::Little, true);
    finder.findGadgets();

    const auto& gadgets = finder.getGadgets();
    // Gadget starting at 0x6000 should be rejected because c.j is an intermediate jump!
    // Only gadget at 0x6004 should be discovered.
    ASSERT_EQ(gadgets.size(), 1, "Intermediate compressed jump must be rejected");
    if (!gadgets.empty()) {
        ASSERT_EQ(gadgets[0].address, 0x6004, "Only c.jr ra at 0x6004 must be discovered");
    }
}

// 7. Non-RVC backward compatibility preservation
static void test_non_rvc_preservation() {
    // In a non-RVC binary (rvc_enabled = false), 16-bit compressed bytes are NOT valid RVC instructions.
    // Capstone in pure RISC-V mode will decode 32-bit instructions only.
    std::vector<unsigned char> code = {
        0x15, 0x45, 0x82, 0x80 // Not a valid 32-bit instruction or not a 32-bit ret
    };

    GadgetFinder finder(code, 0x7000, "riscv32", "", 10, Endianness::Little, false);
    ASSERT_TRUE(!finder.isRvcEnabled(), "Finder must report RVC disabled");
    finder.findGadgets();
    ASSERT_EQ(finder.getGadgets().size(), 0, "Non-RVC finder must not decode 16-bit RVC gadgets");
}

// 8. Deduplication check across overlapping ranges
static void test_rvc_deduplication() {
    // 0x00: c.li a0, 1
    // 0x02: c.jr ra
    std::vector<unsigned char> code = {
        0x05, 0x45,
        0x82, 0x80
    };

    GadgetFinder finder(code, 0x8000, "riscv32", "", 10, Endianness::Little, true);
    finder.findGadgets();

    const auto& gadgets = finder.getGadgets();
    for (size_t i = 0; i < gadgets.size(); ++i) {
        for (size_t j = i + 1; j < gadgets.size(); ++j) {
            bool duplicate = (gadgets[i].address == gadgets[j].address && gadgets[i].assembly == gadgets[j].assembly);
            ASSERT_TRUE(!duplicate, "Deduplication must prevent identical gadgets");
        }
    }
}

// 9. Truncated sequence rejected
static void test_rvc_truncated_sequence() {
    // 0x00: Half of a 32-bit instruction (first 2 bytes of addi: 0x93, 0x85)
    // Followed by EOF
    std::vector<unsigned char> code = {
        0x93, 0x85
    };

    GadgetFinder finder(code, 0x9000, "riscv32", "", 10, Endianness::Little, true);
    finder.findGadgets();

    const auto& gadgets = finder.getGadgets();
    ASSERT_EQ(gadgets.size(), 0, "Truncated instruction sequence must be rejected");
}

int main() {
    std::cout << "=== ROPWeaver Phase 2 Step 4.2: RVC Candidate Scanning Tests ===" << std::endl;

    test_rvc_candidate_2byte_starts();
    test_rvc_variable_length_mixed_sequence();
    test_rvc_with_32bit_ret();
    test_rvc_c_jalr_is_not_ret();
    test_rvc_traps_rejected();
    test_rvc_intermediate_branch_rejected();
    test_non_rvc_preservation();
    test_rvc_deduplication();
    test_rvc_truncated_sequence();

    std::cout << "Results: " << g_tests_passed << " passed, " << g_tests_failed << " failed." << std::endl;
    return (g_tests_failed == 0) ? 0 : 1;
}

