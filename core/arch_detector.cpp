// arch_detector.cpp
#include "arch_detector.h"
#include "core/elf_parser.h"
#include <elf.h>   // For EM_* constants

std::string ArchDetector::detectArchitecture(const ELFParser& parser) {
    auto header = parser.getHeader(); // returns a struct with e_machine

    switch (header.e_machine) {
        case EM_386:
            return "i386";
        case EM_X86_64:
            return "x86_64";
        case EM_ARM:
            return "arm";
        case EM_AARCH64:
            return "arm64";
        case EM_RISCV:
            return "riscv";
        case EM_MIPS:
            return "mips";
        default:
            return "unknown";
    }
}