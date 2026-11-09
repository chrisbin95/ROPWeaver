#include "gadget_finder.h"
#include <algorithm>
#include <capstone/capstone.h>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <vector>

// Helper: Detect ELF class for RISC-V
static cs_mode get_riscv_mode_from_binary(const std::string &binary_path) {
  std::ifstream file(binary_path, std::ios::binary);
  if (!file) {
    throw std::runtime_error("Could not open binary file.");
  }
  unsigned char e_ident[16];
  if (!file.read(reinterpret_cast<char *>(e_ident), sizeof(e_ident))) {
    throw std::runtime_error("Failed to read ELF header.");
  }
  if (e_ident[4] == 1) { // 32-bit ELF
    return CS_MODE_RISCV32;
  } else if (e_ident[4] == 2) { // 64-bit ELF
    return CS_MODE_RISCV64;
  }
  throw std::runtime_error("Unsupported ELF class.");
}

GadgetFinder::GadgetFinder(const std::vector<unsigned char> &code,
                           uint64_t base, const std::string &arch,
                           const std::string &binary_path, size_t maxSize)
    : m_code(code), m_baseAddress(base), m_arch(arch),
      m_binaryPath(binary_path), m_maxSize(maxSize) {
  // Choose Capstone arch/mode
  if (arch == "x86") {
    arch_id = CS_ARCH_X86;
    mode = CS_MODE_32;
  } else if (arch == "x86_64") {
    arch_id = CS_ARCH_X86;
    mode = CS_MODE_64;
  } else if (arch == "aarch64" || arch == "arm64") {
    arch_id = CS_ARCH_ARM64;
    mode = CS_MODE_LITTLE_ENDIAN;
  } else if (arch == "armv7" || arch == "arm") {
    arch_id = CS_ARCH_ARM;
    // We'll let capstone autodetect thumb/arm based on binary usage; default to
    // ARM mode.
    mode = CS_MODE_ARM;
  } else if (arch == "riscv32") {
    arch_id = CS_ARCH_RISCV;
    mode = get_riscv_mode_from_binary(binary_path);
    if (mode != CS_MODE_RISCV32)
      mode = CS_MODE_RISCV32;
  } else if (arch == "riscv64") {
    arch_id = CS_ARCH_RISCV;
    mode = get_riscv_mode_from_binary(binary_path);
    if (mode != CS_MODE_RISCV64)
      mode = CS_MODE_RISCV64;
  } else {
    throw std::runtime_error("Unsupported architecture: " + arch);
  }

  if (cs_open(arch_id, mode, &handle) != CS_ERR_OK) {
    throw std::runtime_error("Failed to initialize Capstone handle");
  }
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
}

#include <set>

GadgetFinder::~GadgetFinder() { cs_close(&handle); }

static bool is_terminator_instruction(const cs_insn &insn,
                                      const std::string &arch) {
  std::string mnem = insn.mnemonic ? insn.mnemonic : "";
  std::string ops = insn.op_str ? insn.op_str : "";
  std::transform(mnem.begin(), mnem.end(), mnem.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  std::transform(ops.begin(), ops.end(), ops.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  // Universal / x86 / x86_64 returns
  if (mnem == "ret" || mnem == "retf" || mnem == "retfq" || mnem == "iret" ||
      mnem == "iretd" || mnem == "iretq") {
    return true;
  }

  // x86 / x86_64 syscall / interrupt
  if (mnem == "syscall" || mnem == "sysenter") {
    return true;
  }
  if (mnem == "int" && ops.find("0x80") != std::string::npos) {
    return true;
  }

  // ARM / Thumb
  if (arch == "armv7" || arch == "arm" || arch == "thumb") {
    if (mnem == "bx" && (ops.find("lr") != std::string::npos ||
                         ops.find("r14") != std::string::npos)) {
      return true;
    }
    if (mnem == "pop" && ops.find("pc") != std::string::npos) {
      return true;
    }
    if (mnem == "svc" || mnem == "swi") {
      return true;
    }
  }

  // AArch64
  if (arch == "aarch64" || arch == "arm64") {
    if (mnem == "ret" || mnem == "eret" || mnem == "svc") {
      return true;
    }
  }

  // RISC-V
  if (arch == "riscv32" || arch == "riscv64") {
    if (mnem == "ret" ||
        (mnem == "jalr" && (ops.find("ra") != std::string::npos ||
                            ops.find("zero") != std::string::npos))) {
      return true;
    }
    if (mnem == "ecall") {
      return true;
    }
  }

  return false;
}

static bool is_invalid_or_branch_instruction(const cs_insn &insn,
                                             const std::string &arch) {
  std::string mnem = insn.mnemonic ? insn.mnemonic : "";
  std::transform(mnem.begin(), mnem.end(), mnem.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  // Halting / trapping / illegal
  if (mnem == "hlt" || mnem == "ud2" || mnem == "int3" || mnem == "ill") {
    return true;
  }

  // Intermediate returns and system calls
  if (mnem == "ret" || mnem == "retf" || mnem == "retfq" || mnem == "syscall" ||
      mnem == "sysenter" || mnem == "ecall") {
    return true;
  }
  if (mnem == "int") {
    return true;
  }

  // Intermediate calls
  if (mnem == "call" || mnem == "callq" || mnem == "bl" || mnem == "blx" ||
      mnem == "jal") {
    return true;
  }

  // Intermediate jumps & loops
  if (arch == "x86" || arch == "x86_64") {
    if (mnem.rfind("j", 0) == 0 || mnem.rfind("loop", 0) == 0) {
      return true;
    }
  } else if (arch == "armv7" || arch == "arm" || arch == "thumb" ||
             arch == "aarch64" || arch == "arm64") {
    if (mnem.rfind("b", 0) == 0 || mnem == "cbz" || mnem == "cbnz") {
      return true;
    }
  } else if (arch == "riscv32" || arch == "riscv64") {
    if (mnem.rfind("b", 0) == 0 || mnem.rfind("j", 0) == 0) {
      return true;
    }
  }

  return false;
}

static bool is_padding_or_prefix(const cs_insn &insn) {
  std::string mnem = insn.mnemonic ? insn.mnemonic : "";
  std::transform(mnem.begin(), mnem.end(), mnem.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  return (mnem == "nop" || mnem == "endbr64" || mnem == "endbr32");
}

void GadgetFinder::findGadgets() {
  m_gadgets.clear();

  cs_insn *all_insns = nullptr;
  size_t count = cs_disasm(handle, m_code.data(), m_code.size(), m_baseAddress,
                           0, &all_insns);
  if (count == 0) {
    std::cerr << "[!] Failed to disassemble code!" << std::endl;
    return;
  }

  // Maximum gadget instruction depth (typically 5 instructions max)
  size_t max_depth = std::min<size_t>(m_maxSize, 5);
  if (max_depth < 1)
    max_depth = 1;

  std::set<std::pair<uint64_t, std::string>> seen_gadgets;

  for (size_t i = 0; i < count; ++i) {
    if (!is_terminator_instruction(all_insns[i], m_arch)) {
      continue;
    }

    // Test sequences ending at all_insns[i] with length 1 to max_depth
    for (size_t len = 1; len <= max_depth && (i + 1) >= len; ++len) {
      size_t start_idx = i - (len - 1);

      // Skip multi-instruction candidates that begin with padding or endbr
      if (len > 1 && is_padding_or_prefix(all_insns[start_idx])) {
        continue;
      }

      // Check contiguity and ensure no branches/calls/traps/intermediate
      // terminators
      bool valid = true;
      for (size_t k = start_idx; k < i; ++k) {
        // Must be physically contiguous in memory
        if (all_insns[k].address + all_insns[k].size !=
            all_insns[k + 1].address) {
          valid = false;
          break;
        }
        // No control flow or invalid instruction before the terminator
        if (is_invalid_or_branch_instruction(all_insns[k], m_arch)) {
          valid = false;
          break;
        }
      }
      if (!valid)
        continue;

      // Also check the terminator itself isn't a trap
      std::string term_mnem =
          all_insns[i].mnemonic ? all_insns[i].mnemonic : "";
      std::transform(term_mnem.begin(), term_mnem.end(), term_mnem.begin(),
                     [](unsigned char c) { return std::tolower(c); });
      if (term_mnem == "hlt" || term_mnem == "ud2" || term_mnem == "int3") {
        continue;
      }

      Gadget g;
      g.architecture = m_arch;
      g.address = all_insns[start_idx].address;

      std::string asm_str;
      for (size_t k = start_idx; k <= i; ++k) {
        std::string mnem = all_insns[k].mnemonic ? all_insns[k].mnemonic : "";
        std::string ops = all_insns[k].op_str ? all_insns[k].op_str : "";
        g.instructions.push_back({mnem, ops});

        if (!asm_str.empty())
          asm_str += " ; ";
        asm_str += mnem;
        if (!ops.empty())
          asm_str += " " + ops;
      }
      g.assembly = asm_str;

      // Target register for pop gadgets
      if (g.instructions.size() == 2 && g.instructions[0].mnemonic == "pop") {
        g.target_register = g.instructions[0].op_str;
      }

      // Validate gadget bytes directly against original binary m_code
      if (g.address >= m_baseAddress) {
        size_t code_offset = static_cast<size_t>(g.address - m_baseAddress);
        size_t total_gadget_bytes = static_cast<size_t>((all_insns[i].address + all_insns[i].size) - all_insns[start_idx].address);
        if (code_offset + total_gadget_bytes <= m_code.size()) {
          bool bytes_match = true;
          size_t cur_offset = code_offset;
          for (size_t k = start_idx; k <= i; ++k) {
            if (std::memcmp(m_code.data() + cur_offset, all_insns[k].bytes, all_insns[k].size) != 0) {
              bytes_match = false;
              break;
            }
            cur_offset += all_insns[k].size;
          }
          g.byte_verified = bytes_match;
        } else {
          g.byte_verified = false;
        }
      }

      if (seen_gadgets.insert({g.address, g.assembly}).second) {
        m_gadgets.push_back(g);
      }
    }
  }

  cs_free(all_insns, count);

  // Sort gadgets by address ascending
  std::sort(m_gadgets.begin(), m_gadgets.end(),
            [](const Gadget &a, const Gadget &b) {
              if (a.address != b.address)
                return a.address < b.address;
              return a.instructions.size() < b.instructions.size();
            });

  // Populate Gadget::category during discovery
  categorizeGadgets();
}

// ---------------------------------------------------------------------------
// Utility helpers for parsing operand strings (simple, conservative)
// ---------------------------------------------------------------------------
static bool contains_register(const std::string &opstr,
                              const std::string &reg) {
  if (opstr.empty())
    return false;
  return opstr.find(reg) != std::string::npos;
}

static bool op_contains_any_reg(const std::string &opstr,
                                const std::vector<std::string> &regs) {
  for (const auto &r : regs)
    if (contains_register(opstr, r))
      return true;
  return false;
}

// ---------------------------------------------------------------------------
// classify_gadget_multidim: populates g.categories, g.registers_read,
// g.registers_modified, g.stack_delta, g.has_memory_read/write,
// g.terminator_type, g.instruction_count, g.classification_confidence.
// Also sets g.category (backward-compat primary string).
// ---------------------------------------------------------------------------
static void classify_gadget_multidim(Gadget &g, const std::string &arch) {
  g.categories.clear();
  g.registers_read.clear();
  g.registers_modified.clear();
  g.stack_delta = 0;
  g.has_memory_read = false;
  g.has_memory_write = false;
  g.terminator_type.clear();
  g.instruction_count = static_cast<uint8_t>(g.instructions.size());
  g.classification_confidence = 50; // default baseline

  if (g.instructions.empty()) {
    g.categories.push_back("misc");
    g.category = "misc";
    return;
  }

  // Helper lambdas
  auto lc = [](std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
  };

  bool is_x86 = (arch == "x86" || arch == "x86_64");
  bool is_arm = (arch == "armv7" || arch == "arm");
  bool is_a64 = (arch == "aarch64" || arch == "arm64");
  bool is_rv = (arch == "riscv32" || arch == "riscv64");

  // --- Terminator type (from last instruction) ---
  {
    const auto &last = g.instructions.back();
    std::string lm = lc(last.mnemonic);
    if (lm == "ret" || lm == "retf" || lm == "retfq") {
      g.terminator_type = "RET";
    } else if (lm == "syscall" || lm == "sysenter" || lm == "ecall" ||
               lm == "svc" || lm == "swi" ||
               (lm == "int" && last.op_str.find("0x80") != std::string::npos)) {
      g.terminator_type = "SYSCALL";
    } else if (lm == "jmp" || lm == "b") {
      g.terminator_type = "JMP";
    } else if (lm == "call" || lm == "bl" || lm == "blx" || lm == "blr") {
      g.terminator_type = "CALL";
    } else if (lm == "bx" && (last.op_str.find("lr") != std::string::npos)) {
      g.terminator_type = "RET"; // ARM BX LR = return
    } else if (lm == "pop" && last.op_str.find("pc") != std::string::npos) {
      g.terminator_type = "RET"; // ARM POP {pc} = return
    } else if (lm == "jalr") {
      g.terminator_type = "RET"; // RISC-V jalr ra
    } else {
      g.terminator_type = lm;
    }
  }

  // Track category flags
  bool has_register_load = false;
  bool has_stack_adjust = false;
  bool has_arithmetic = false;
  bool has_logical = false;
  bool has_mem_read = false;
  bool has_mem_write = false;
  bool has_control_xfer = false;
  bool has_stack_pivot = false;
  bool has_syscall = false;

  // Sets to avoid duplicates in registers lists
  std::set<std::string> regs_read_set, regs_mod_set;

  // x86/x64 register lists
  static const std::vector<std::string> x86_gp_regs = {
      "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8",
      "r9",  "r10", "r11", "r12", "r13", "r14", "r15", "eax",
      "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "ax",
      "bx",  "cx",  "dx",  "si",  "di",  "bp",  "sp"};
  static const std::vector<std::string> arm_gp_regs = {
      "r0",  "r1",  "r2",  "r3",  "r4",  "r5",  "r6",  "r7",  "r8",
      "r9",  "r10", "r11", "r12", "sp",  "lr",  "pc",  "x0",  "x1",
      "x2",  "x3",  "x4",  "x5",  "x6",  "x7",  "x8",  "x9",  "x10",
      "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19",
      "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28",
      "x29", "x30", "w0",  "w1",  "w2",  "w3",  "w4",  "w5",  "w6",
      "w7",  "w8",  "w9",  "w10", "w11", "w12", "w13", "w14", "w15"};

  const std::vector<std::string> &gp_regs = is_x86 ? x86_gp_regs : arm_gp_regs;

  // --- Analyse each instruction ---
  for (size_t idx = 0; idx < g.instructions.size(); ++idx) {
    const auto &ins = g.instructions[idx];
    bool is_term_ins = (idx == g.instructions.size() - 1);
    std::string mnem = lc(ins.mnemonic);
    std::string ops = lc(ins.op_str);

    // --- Stack delta tracking ---
    if (is_x86) {
      int ptr_sz = (arch == "x86_64") ? 8 : 4;
      if (mnem == "push") {
        g.stack_delta -= ptr_sz;
        has_mem_write = true;
      } else if (mnem == "pop") {
        g.stack_delta += ptr_sz;
        has_mem_read = true;
      } else if (mnem == "ret" || mnem == "retf") {
        g.stack_delta += ptr_sz;
      } else if (mnem == "add" && ops.rfind("rsp,", 0) == 0) {
        // "add rsp, N" -> try to parse N
        size_t comma = ops.find(',');
        if (comma != std::string::npos) {
          try {
            std::string val = ops.substr(comma + 1);
            val.erase(std::remove_if(val.begin(), val.end(), ::isspace),
                      val.end());
            g.stack_delta += (int64_t)std::stoll(val, nullptr, 0);
          } catch (...) {
          }
        }
      } else if (mnem == "sub" && ops.rfind("rsp,", 0) == 0) {
        size_t comma = ops.find(',');
        if (comma != std::string::npos) {
          try {
            std::string val = ops.substr(comma + 1);
            val.erase(std::remove_if(val.begin(), val.end(), ::isspace),
                      val.end());
            g.stack_delta -= (int64_t)std::stoll(val, nullptr, 0);
          } catch (...) {
          }
        }
      } else if (mnem == "leave") {
        // leave = mov rsp, rbp ; pop rbp
        g.stack_delta += ptr_sz;
        has_stack_pivot = true;
      }
    } else if (is_arm) {
      if (mnem == "push") {
        g.stack_delta -= 4;
        has_mem_write = true;
      } else if (mnem == "pop") {
        g.stack_delta += 4;
        has_mem_read = true;
      }
    }

    // --- Memory access detection ---
    if (ops.find('[') != std::string::npos ||
        ops.find("ptr") != std::string::npos) {
      // A bracket means memory operand; decide read vs write from mnemonic
      if (mnem == "mov" || mnem == "movzx" || mnem == "movsx" ||
          mnem == "lea" || mnem == "ldr" || mnem == "ldm" || mnem == "ldp" ||
          mnem == "ld" || mnem == "ldrb" || mnem == "ldrd" || mnem == "ldrh") {
        // If destination is register (first operand has no '['), it's a load
        size_t comma = ops.find(',');
        std::string dst =
            (comma != std::string::npos) ? ops.substr(0, comma) : ops;
        if (dst.find('[') == std::string::npos) {
          has_mem_read = true;
        } else {
          has_mem_write = true;
        }
      } else if (mnem == "str" || mnem == "strb" || mnem == "strh" ||
                 mnem == "stm" || mnem == "stp") {
        has_mem_write = true;
      } else if (!is_term_ins) {
        // Generic: bracket in a non-terminator = memory access
        has_mem_read = true;
      }
    }

    // --- Classify mnemonic ---
    if (mnem == "pop" && (is_x86 || is_arm)) {
      // pop into a GP register = register load
      for (const auto &r : gp_regs) {
        if (ops.find(r) != std::string::npos && r != "rsp" && r != "esp" &&
            r != "sp") {
          has_register_load = true;
          regs_mod_set.insert(r);
        }
      }
      regs_read_set.insert("rsp"); // RSP is consumed
    } else if (mnem == "push" && is_x86) {
      has_mem_write = true;
      // Source register
      for (const auto &r : gp_regs) {
        if (ops.find(r) != std::string::npos) {
          regs_read_set.insert(r);
          break;
        }
      }
      regs_mod_set.insert("rsp");
    } else if ((mnem == "add" || mnem == "sub") &&
               (ops.find("rsp") != std::string::npos ||
                ops.find("esp") != std::string::npos ||
                ops.find("sp") != std::string::npos)) {
      has_stack_adjust = true;
      regs_mod_set.insert("rsp");
    } else if (mnem == "xchg" && (ops.find("rsp") != std::string::npos ||
                                  ops.find("esp") != std::string::npos ||
                                  ops.find("sp") != std::string::npos)) {
      has_stack_pivot = true;
    } else if (mnem == "mov" || mnem == "movzx" || mnem == "movsx" ||
               mnem == "movsxd") {
      // Check destination
      size_t comma = ops.find(',');
      if (comma != std::string::npos) {
        std::string dst = ops.substr(0, comma);
        dst.erase(std::remove_if(dst.begin(), dst.end(), ::isspace), dst.end());
        if (dst == "rsp" || dst == "esp" || dst == "sp") {
          has_stack_pivot = true;
        } else if (dst.find('[') == std::string::npos) {
          has_register_load = true;
          regs_mod_set.insert(dst);
        } else {
          has_mem_write = true;
        }
      }
    } else if (mnem == "lea") {
      size_t comma = ops.find(',');
      if (comma != std::string::npos) {
        std::string dst = ops.substr(0, comma);
        dst.erase(std::remove_if(dst.begin(), dst.end(), ::isspace), dst.end());
        has_register_load = true;
        regs_mod_set.insert(dst);
        has_mem_read = false; // LEA doesn't actually access memory
      }
    } else if (mnem == "add" || mnem == "sub" || mnem == "mul" ||
               mnem == "imul" || mnem == "div" || mnem == "idiv" ||
               mnem == "inc" || mnem == "dec" || mnem == "neg" ||
               mnem == "adc" || mnem == "sbb") {
      has_arithmetic = true;
    } else if (mnem == "xor" || mnem == "and" || mnem == "or" ||
               mnem == "not" || mnem == "shl" || mnem == "shr" ||
               mnem == "sar" || mnem == "rol" || mnem == "ror" ||
               mnem == "test" || mnem == "cmp") {
      has_logical = true;
    } else if (mnem == "syscall" || mnem == "sysenter" || mnem == "ecall" ||
               mnem == "svc" || mnem == "swi" ||
               (mnem == "int" && ops.find("0x80") != std::string::npos)) {
      has_syscall = true;
    } else if (mnem == "ret" || mnem == "retf" || mnem == "retfq" ||
               (mnem == "bx" && ops.find("lr") != std::string::npos) ||
               (mnem == "pop" && ops.find("pc") != std::string::npos) ||
               (mnem == "jalr" && ops.find("ra") != std::string::npos)) {
      has_control_xfer = true;
    } else if (mnem == "jmp" || mnem == "call" || mnem == "b" || mnem == "bl" ||
               mnem == "blx" || mnem == "blr") {
      has_control_xfer = true;
    } else if (mnem == "leave") {
      has_stack_pivot = true;
    }
  }

  g.has_memory_read = has_mem_read;
  g.has_memory_write = has_mem_write;

  // --- Build categories vector (multi-dimensional, ordered by specificity) ---
  if (has_syscall)
    g.categories.push_back("syscall");
  if (has_stack_pivot)
    g.categories.push_back("stack_pivot");
  if (has_stack_adjust)
    g.categories.push_back("stack_adjustment");
  if (has_register_load)
    g.categories.push_back("register_load");
  if (has_mem_write)
    g.categories.push_back("memory_write");
  if (has_mem_read)
    g.categories.push_back("memory_read");
  if (has_arithmetic)
    g.categories.push_back("arithmetic");
  if (has_logical)
    g.categories.push_back("logical");
  // "control_transfer" is implied by all gadgets (they end with ret/jmp etc.)
  // Add it only for non-ret terminators to avoid noise
  if (g.terminator_type == "JMP" || g.terminator_type == "CALL") {
    g.categories.push_back("control_transfer");
  }
  if (g.categories.empty()) {
    g.categories.push_back("misc");
  }

  // Populate sorted register lists
  for (const auto &r : regs_read_set)
    g.registers_read.push_back(r);
  for (const auto &r : regs_mod_set)
    g.registers_modified.push_back(r);
  std::sort(g.registers_read.begin(), g.registers_read.end());
  std::sort(g.registers_modified.begin(), g.registers_modified.end());

  // Confidence: more instructions = less confident in auto-classification
  if (g.instructions.size() == 1)
    g.classification_confidence = 95;
  else if (g.instructions.size() == 2)
    g.classification_confidence = 85;
  else if (g.instructions.size() == 3)
    g.classification_confidence = 75;
  else
    g.classification_confidence = 60;

  // Set backward-compat g.category from primary category
  g.category = g.categories[0];
}

// ---------------------------------------------------------------------------
// determineCategory — backward-compat single-string category for callers
// that still use g.category directly (e.g., --suggest-gadgets display).
// ---------------------------------------------------------------------------
std::string GadgetFinder::determineCategory(const Gadget &g) const {
  // Indirect jump/call detection
  if (g.isIndirectJumpOrCall()) {
    return "indirect jump/call";
  }

  // Stack pivot detection
  if (g.isStackPivot()) {
    return "stack pivot";
  }

  // Syscall detection: cover ARM SVC/SWI and x86 int 0x80
  if (g.hasMnemonic("syscall") || g.hasMnemonic("sysenter") ||
      g.hasMnemonic("int80") ||
      (g.hasMnemonic("int") && !g.instructions.empty() &&
       g.instructions.back().op_str.find("0x80") != std::string::npos)) {
    return "syscall";
  }

  // ARM specific: SVC (Supervisor Call) / SWI
  if ((m_arch == "armv7" || m_arch == "arm") &&
      (g.hasMnemonic("svc") || g.hasMnemonic("swi"))) {
    return "syscall";
  }

  // POP-style gadgets
  if (g.hasMnemonic("pop")) {
    for (const auto &ins : g.instructions) {
      if (ins.mnemonic == "pop") {
        std::string ops = ins.op_str;
        std::transform(ops.begin(), ops.end(), ops.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        std::vector<std::string> target_regs;
        if (m_arch == "x86" || m_arch == "x86_64") {
          target_regs = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                         "rbp", "rsp", "r8",  "r9",  "r10", "r11",
                         "r12", "r13", "r14", "r15", "eax", "ebx",
                         "ecx", "edx", "esi", "edi", "ebp", "esp"};
        } else {
          target_regs = {"r0", "r1", "r2",  "r3",  "r4",  "r5", "r6", "r7",
                         "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"};
        }
        for (const auto &reg : target_regs) {
          if (ops.find(reg) != std::string::npos) {
            return "pop " + reg;
          }
        }
        if (ops.find('{') != std::string::npos &&
            ops.find('}') != std::string::npos) {
          auto start = ops.find('{');
          auto end = ops.find('}');
          if (end > start + 1) {
            std::string inside = ops.substr(start + 1, end - start - 1);
            inside.erase(
                std::remove_if(inside.begin(), inside.end(), ::isspace),
                inside.end());
            return "pop {" + inside + "}";
          }
        }
        if (ops.find("pc") != std::string::npos)
          return "pop pc";
      }
    }
  }

  // ARM-specific stack pivot patterns
  if (m_arch == "armv7" || m_arch == "arm") {
    for (const auto &ins : g.instructions) {
      std::string mnem = ins.mnemonic;
      std::string ops = ins.op_str;
      std::transform(mnem.begin(), mnem.end(), mnem.begin(),
                     [](unsigned char c) { return std::tolower(c); });
      std::transform(ops.begin(), ops.end(), ops.begin(),
                     [](unsigned char c) { return std::tolower(c); });

      if (mnem == "mov" && ops.find("sp,") != std::string::npos)
        return "stack pivot/mov sp";
      if ((mnem == "add" || mnem == "sub") &&
          ops.find("sp, sp") != std::string::npos)
        return "stack pivot/addsub sp";
      if (mnem == "ldr" && ops.find("sp,") != std::string::npos)
        return "stack pivot/ldr sp";
      if (mnem == "ldm" && ops.find("sp") != std::string::npos)
        return "stack pivot/ldm sp";
    }
  }

  if (g.hasMnemonic("pop") && (m_arch == "x86" || m_arch == "x86_64")) {
    if (g.popInstructionCount() > 0)
      return "pop";
  }

  if (m_arch == "aarch64" && g.hasMnemonic("svc"))
    return "syscall";

  if (g.hasArithmeticOrLogic())
    return "arithmetic/logic";

  return "others";
}

std::map<std::string, std::vector<Gadget>> GadgetFinder::categorizeGadgets() {
  std::map<std::string, std::vector<Gadget>> categories;
  for (auto &g : m_gadgets) {
    // Run multi-dimensional classification first
    classify_gadget_multidim(g, m_arch);
    // Also set the backward-compat single string (already set by
    // classify_gadget_multidim)
    if (g.category.empty())
      g.category = determineCategory(g);
    categories[g.category].push_back(g);
  }
  return categories;
}

std::map<std::string, std::vector<Gadget>>
GadgetFinder::categorizeGadgets() const {
  std::map<std::string, std::vector<Gadget>> categories;
  for (const auto &g : m_gadgets) {
    std::string cat = g.category.empty() ? determineCategory(g) : g.category;
    categories[cat].push_back(g);
  }
  return categories;
}