#include "elf_parser.h"
#include "elf_defs.h"
#include <fstream>
#include <iostream>
#include <cstring>
#include <algorithm>
#include <vector>

using namespace ropweaver;

// Helper to determine architecture from e_machine field
static std::string getElfMachineArchitecture(uint16_t e_machine) {
    switch (e_machine) {
        case EM_386:    return "x86";
        case EM_X86_64: return "x86_64";
        case EM_ARM:    return "armv7";
        case EM_AARCH64:return "aarch64";
        case EM_RISCV:  return "riscv";
        default:        return "unknown";
    }
}

// ---------------------------------------------------------------------------
// extract_exec_sections: finds ALL sections with SHF_EXECINSTR set.
// Sections are concatenated in VA order; gaps between non-contiguous sections
// are filled with 0xCC (INT3) so that GadgetFinder stops cleanly at section
// boundaries without generating cross-section gadgets.
//
// Falls back to .text-by-name if no SHF_EXECINSTR sections are found.
// ---------------------------------------------------------------------------
template <typename Elf_Ehdr, typename Elf_Shdr>
bool extract_exec_sections(const uint8_t* data, size_t size, const Elf_Ehdr& ehdr,
                           std::vector<uint8_t>& out_text,
                           uint64_t& out_base_addr,
                           uint64_t& out_entry_point,
                           std::vector<SectionInfo>& out_sections)
{
    size_t sh_off     = ehdr.e_shoff;
    uint16_t sh_num   = ehdr.e_shnum;
    uint16_t sh_esz   = ehdr.e_shentsize;

    out_sections.clear();
    // Entry point (may be 0 for PIE / relocatable)
    out_entry_point = static_cast<uint64_t>(ehdr.e_entry);

    if (sh_off == 0 || sh_num == 0 || sh_esz != sizeof(Elf_Shdr)) {
        std::cerr << "[!] ELFParser: Invalid or missing section header table.\n";
        return false;
    }

    if (sh_off + static_cast<size_t>(sh_num) * sh_esz > size) {
        std::cerr << "[!] ELFParser: Section Header Table out of file bounds.\n";
        return false;
    }

    const Elf_Shdr* shdr_table = reinterpret_cast<const Elf_Shdr*>(data + sh_off);

    // String table
    if (ehdr.e_shstrndx == SHN_UNDEF || ehdr.e_shstrndx >= sh_num) {
        std::cerr << "[!] ELFParser: Invalid section header string table index.\n";
        return false;
    }
    const Elf_Shdr& shstr_hdr = shdr_table[ehdr.e_shstrndx];
    if (shstr_hdr.sh_offset + shstr_hdr.sh_size > size) {
        std::cerr << "[!] ELFParser: Section name string table out of bounds.\n";
        return false;
    }
    const char* shstr_table = reinterpret_cast<const char*>(data + shstr_hdr.sh_offset);

    // Record all sections and collect executable ones
    struct SecInfo {
        uint64_t va;
        size_t   offset;
        size_t   raw_size;
    };
    std::vector<SecInfo> exec_secs;

    for (uint16_t i = 0; i < sh_num; ++i) {
        const Elf_Shdr& shdr = shdr_table[i];
        const char* sec_name = shstr_table + shdr.sh_name;

        SectionInfo sec;
        sec.name = sec_name;
        sec.virtual_address = shdr.sh_addr;
        sec.virtual_size = shdr.sh_size;
        sec.raw_offset = shdr.sh_offset;
        sec.raw_size = shdr.sh_size;
        sec.characteristics = static_cast<uint32_t>(shdr.sh_flags);
        sec.is_executable = (shdr.sh_flags & SHF_EXECINSTR) != 0;
        out_sections.push_back(sec);

        // SHF_EXECINSTR = 0x4
        if (!(shdr.sh_flags & SHF_EXECINSTR)) continue;
        if (shdr.sh_type == SHT_NOBITS) continue;  // .bss-like
        if (shdr.sh_size == 0) continue;

        size_t raw_offset = static_cast<size_t>(shdr.sh_offset);
        size_t raw_size   = static_cast<size_t>(shdr.sh_size);

        if (raw_offset >= size) continue;
        if (raw_offset + raw_size > size) raw_size = size - raw_offset;

        exec_secs.push_back({ static_cast<uint64_t>(shdr.sh_addr), raw_offset, raw_size });
    }

    // Fallback: search for .text by name if no SHF_EXECINSTR sections found
    if (exec_secs.empty()) {
        for (uint16_t i = 0; i < sh_num; ++i) {
            const Elf_Shdr& shdr = shdr_table[i];
            const char* sh_name  = shstr_table + shdr.sh_name;
            if (std::strcmp(sh_name, ".text") == 0) {
                size_t raw_offset = static_cast<size_t>(shdr.sh_offset);
                size_t raw_size   = static_cast<size_t>(shdr.sh_size);
                if (raw_offset < size) {
                    if (raw_offset + raw_size > size) raw_size = size - raw_offset;
                    exec_secs.push_back({ static_cast<uint64_t>(shdr.sh_addr), raw_offset, raw_size });
                }
                break;
            }
        }
    }

    if (exec_secs.empty()) {
        std::cerr << "[!] ELFParser: No executable sections found.\n";
        return false;
    }

    // Sort by VA
    std::sort(exec_secs.begin(), exec_secs.end(),
              [](const SecInfo& a, const SecInfo& b){ return a.va < b.va; });

    out_base_addr = exec_secs[0].va;

    // Concatenate with INT3 gap-fills
    out_text.clear();
    uint64_t prevEnd = out_base_addr;
    for (const auto& sec : exec_secs) {
        if (sec.va > prevEnd) {
            size_t gap = static_cast<size_t>(sec.va - prevEnd);
            if (gap <= 0x10000) {
                out_text.insert(out_text.end(), gap, 0xCC);
            } else {
                // Large gap — use 4-byte INT3 fence to prevent cross-section gadgets
                out_text.push_back(0xCC);
                out_text.push_back(0xCC);
                out_text.push_back(0xCC);
                out_text.push_back(0xCC);
            }
        }
        const uint8_t* ptr = data + sec.offset;
        out_text.insert(out_text.end(), ptr, ptr + sec.raw_size);
        prevEnd = sec.va + sec.raw_size;
    }

    return !out_text.empty();
}

// ---------------------------------------------------------------------------
// detect_elf_mitigations: inspects dynamic section and program headers
// for NX, PIE, stack canary, and RELRO.
// ---------------------------------------------------------------------------
template <typename Elf_Ehdr, typename Elf_Phdr, typename Elf_Dyn>
static void detect_mitigations(const uint8_t* data, size_t size, const Elf_Ehdr& ehdr,
                                bool& nx_out, bool& pie_out,
                                bool& canary_out, std::string& relro_out)
{
    // PIE: ET_DYN with no fixed load address
    pie_out = (ehdr.e_type == ET_DYN);

    // NX: check if any PT_GNU_STACK segment has execute permission
    nx_out = true; // assume NX unless PF_X found on GNU_STACK
    bool has_gnu_stack = false;

    if (ehdr.e_phoff != 0 && ehdr.e_phnum > 0 && ehdr.e_phentsize == sizeof(Elf_Phdr)) {
        const Elf_Phdr* phdr_table = reinterpret_cast<const Elf_Phdr*>(data + ehdr.e_phoff);
        bool partial_relro = false, full_relro = false;

        for (uint16_t i = 0; i < ehdr.e_phnum; ++i) {
            const Elf_Phdr& phdr = phdr_table[i];
            if (phdr.p_type == PT_GNU_STACK) {
                has_gnu_stack = true;
                // If execute bit is set, NX is disabled
                if (phdr.p_flags & PF_X) nx_out = false;
            }
            if (phdr.p_type == PT_GNU_RELRO) {
                partial_relro = true;
            }
        }

        // Full RELRO requires PT_GNU_RELRO + BIND_NOW in dynamic section
        // Check dynamic section for DT_FLAGS / DT_FLAGS_1 / DT_BIND_NOW
        for (uint16_t i = 0; i < ehdr.e_phnum; ++i) {
            const Elf_Phdr& phdr = phdr_table[i];
            if (phdr.p_type != PT_DYNAMIC) continue;
            if (phdr.p_offset + phdr.p_filesz > size) break;

            const Elf_Dyn* dyn = reinterpret_cast<const Elf_Dyn*>(data + phdr.p_offset);
            size_t dyn_count = phdr.p_filesz / sizeof(Elf_Dyn);
            for (size_t d = 0; d < dyn_count; ++d) {
                if (dyn[d].d_tag == DT_NULL) break;
                if (dyn[d].d_tag == DT_BIND_NOW) { full_relro = true; }
                // DF_BIND_NOW = 0x08 in DT_FLAGS
                if (dyn[d].d_tag == DT_FLAGS && (dyn[d].d_un.d_val & 0x08)) { full_relro = true; }
            }
            break;
        }

        if (full_relro && partial_relro) relro_out = "Full";
        else if (partial_relro)          relro_out = "Partial";
        else                             relro_out = "None";
    }

    if (!has_gnu_stack) {
        // No PT_GNU_STACK: NX behaviour is undefined (treat as disabled for older binaries)
        nx_out = false;
    }

    // Stack canary: search for symbol name in binary bytes
    const std::vector<std::string> canary_syms = {
        "__stack_chk_fail", "__stack_chk_guard",
        "__security_cookie", "__security_check_cookie"
    };
    for (const auto& sym : canary_syms) {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(
            std::search(reinterpret_cast<const char*>(data),
                        reinterpret_cast<const char*>(data + size),
                        sym.c_str(), sym.c_str() + sym.size()));
        if (p != data + size) { canary_out = true; break; }
    }
}

// ---------------------------------------------------------------------------
// ELFParser::parse
// ---------------------------------------------------------------------------
bool ELFParser::parse(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "[!] ELFParser: Could not open file: " << filepath << std::endl;
        return false;
    }

    std::streamsize sz = file.tellg();
    file.seekg(0, std::ios::beg);
    m_file_data.resize(static_cast<size_t>(sz));
    if (!file.read(reinterpret_cast<char*>(m_file_data.data()), sz)) {
        std::cerr << "[!] ELFParser: Read error in file: " << filepath << std::endl;
        return false;
    }

    const auto* data = m_file_data.data();
    size_t size = m_file_data.size();

    if (size < EI_NIDENT) return false;

    // ELF Magic Check
    if (data[EI_MAG0] != ELFMAG0 || data[EI_MAG1] != ELFMAG1 ||
        data[EI_MAG2] != ELFMAG2 || data[EI_MAG3] != ELFMAG3) {
        std::cerr << "[!] ELFParser: Not a valid ELF file: " << filepath << std::endl;
        return false;
    }

    if (data[EI_CLASS] == ELFCLASS32) {
        if (size < sizeof(Elf32_Ehdr)) return false;
        hdr32 = *reinterpret_cast<const Elf32_Ehdr*>(data);
        m_arch = getElfMachineArchitecture(hdr32.e_machine);

        if (!extract_exec_sections<Elf32_Ehdr, Elf32_Shdr>(
                data, size, hdr32,
                m_text_section, m_text_section_base_address, m_entry_point, m_sections)) {
            return false;
        }

        detect_mitigations<Elf32_Ehdr, Elf32_Phdr, Elf32_Dyn>(
            data, size, hdr32,
            m_nx_enabled, m_pie_enabled, m_canary_enabled, m_relro);

    } else if (data[EI_CLASS] == ELFCLASS64) {
        if (size < sizeof(Elf64_Ehdr)) return false;
        hdr64 = *reinterpret_cast<const Elf64_Ehdr*>(data);
        m_arch = getElfMachineArchitecture(hdr64.e_machine);

        if (!extract_exec_sections<Elf64_Ehdr, Elf64_Shdr>(
                data, size, hdr64,
                m_text_section, m_text_section_base_address, m_entry_point, m_sections)) {
            return false;
        }

        detect_mitigations<Elf64_Ehdr, Elf64_Phdr, Elf64_Dyn>(
            data, size, hdr64,
            m_nx_enabled, m_pie_enabled, m_canary_enabled, m_relro);

    } else {
        std::cerr << "[!] ELFParser: Unknown ELF class: " << int(data[EI_CLASS]) << std::endl;
        return false;
    }

    // RISC-V: differentiate 32 vs 64 from ELF class
    if (m_arch == "riscv") {
        m_arch = (data[EI_CLASS] == ELFCLASS32) ? "riscv32" : "riscv64";
    }

    return true;
}

// --- Getters ---

const std::vector<uint8_t>& ELFParser::getTextSection() const {
    return m_text_section;
}

uint64_t ELFParser::getTextSectionBaseAddress() const {
    return m_text_section_base_address;
}

std::string ELFParser::getArchitecture() const {
    return m_arch;
}

bool ELFParser::is64Bit() const {
    if (hdr64.e_ident[EI_CLASS] == ELFCLASS64) return true;
    if (hdr32.e_ident[EI_CLASS] == ELFCLASS32) return false;
    if (!m_file_data.empty() && m_file_data[EI_CLASS] == ELFCLASS64) return true;
    return false;
}
