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

// Internal normalized structures for safe, bounds-checked, endian-aware parsing
namespace {

struct DecodedShdr {
    uint32_t sh_name = 0;
    uint32_t sh_type = 0;
    uint64_t sh_flags = 0;
    uint64_t sh_addr = 0;
    uint64_t sh_offset = 0;
    uint64_t sh_size = 0;
    uint32_t sh_link = 0;
    uint32_t sh_info = 0;
    uint64_t sh_addralign = 0;
    uint64_t sh_entsize = 0;
};

bool decode_shdr(const uint8_t* p, size_t remaining, bool is_64, bool is_be, DecodedShdr& out) {
    if (is_64) {
        if (remaining < sizeof(Elf64_Shdr)) return false;
        out.sh_name      = read_u32(p + 0, is_be);
        out.sh_type      = read_u32(p + 4, is_be);
        out.sh_flags     = read_u64(p + 8, is_be);
        out.sh_addr      = read_u64(p + 16, is_be);
        out.sh_offset    = read_u64(p + 24, is_be);
        out.sh_size      = read_u64(p + 32, is_be);
        out.sh_link      = read_u32(p + 40, is_be);
        out.sh_info      = read_u32(p + 44, is_be);
        out.sh_addralign = read_u64(p + 48, is_be);
        out.sh_entsize   = read_u64(p + 56, is_be);
        return true;
    } else {
        if (remaining < sizeof(Elf32_Shdr)) return false;
        out.sh_name      = read_u32(p + 0, is_be);
        out.sh_type      = read_u32(p + 4, is_be);
        out.sh_flags     = read_u32(p + 8, is_be);
        out.sh_addr      = read_u32(p + 12, is_be);
        out.sh_offset    = read_u32(p + 16, is_be);
        out.sh_size      = read_u32(p + 20, is_be);
        out.sh_link      = read_u32(p + 24, is_be);
        out.sh_info      = read_u32(p + 28, is_be);
        out.sh_addralign = read_u32(p + 32, is_be);
        out.sh_entsize   = read_u32(p + 36, is_be);
        return true;
    }
}

struct DecodedPhdr {
    uint32_t p_type = 0;
    uint32_t p_flags = 0;
    uint64_t p_offset = 0;
    uint64_t p_vaddr = 0;
    uint64_t p_paddr = 0;
    uint64_t p_filesz = 0;
    uint64_t p_memsz = 0;
    uint64_t p_align = 0;
};

bool decode_phdr(const uint8_t* p, size_t remaining, bool is_64, bool is_be, DecodedPhdr& out) {
    if (is_64) {
        if (remaining < sizeof(Elf64_Phdr)) return false;
        out.p_type   = read_u32(p + 0, is_be);
        out.p_flags  = read_u32(p + 4, is_be);
        out.p_offset = read_u64(p + 8, is_be);
        out.p_vaddr  = read_u64(p + 16, is_be);
        out.p_paddr  = read_u64(p + 24, is_be);
        out.p_filesz = read_u64(p + 32, is_be);
        out.p_memsz  = read_u64(p + 40, is_be);
        out.p_align  = read_u64(p + 48, is_be);
        return true;
    } else {
        if (remaining < sizeof(Elf32_Phdr)) return false;
        out.p_type   = read_u32(p + 0, is_be);
        out.p_offset = read_u32(p + 4, is_be);
        out.p_vaddr  = read_u32(p + 8, is_be);
        out.p_paddr  = read_u32(p + 12, is_be);
        out.p_filesz = read_u32(p + 16, is_be);
        out.p_memsz  = read_u32(p + 20, is_be);
        out.p_flags  = read_u32(p + 24, is_be);
        out.p_align  = read_u32(p + 28, is_be);
        return true;
    }
}

struct DecodedDyn {
    int64_t d_tag = 0;
    uint64_t d_val = 0;
};

bool decode_dyn(const uint8_t* p, size_t remaining, bool is_64, bool is_be, DecodedDyn& out) {
    if (is_64) {
        if (remaining < sizeof(Elf64_Dyn)) return false;
        out.d_tag = read_i64(p + 0, is_be);
        out.d_val = read_u64(p + 8, is_be);
        return true;
    } else {
        if (remaining < sizeof(Elf32_Dyn)) return false;
        out.d_tag = read_i32(p + 0, is_be);
        out.d_val = read_u32(p + 4, is_be);
        return true;
    }
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// extract_exec_sections: finds ALL sections with SHF_EXECINSTR set.
// Sections are packed into out_text separated by 4-byte INT3 (0xCC) fences,
// while out_mappings records each section's exact virtual address, buffer offset,
// size, and file offset.
//
// Falls back to .text-by-name if no SHF_EXECINSTR sections are found.
// ---------------------------------------------------------------------------
template <typename Elf_Ehdr>
static bool extract_exec_sections(const uint8_t* data, size_t size, const Elf_Ehdr& ehdr,
                                  bool is_64, bool is_be,
                                  std::vector<uint8_t>& out_text,
                                  uint64_t& out_base_addr,
                                  uint64_t& out_entry_point,
                                  std::vector<SectionInfo>& out_sections,
                                  std::vector<ExecBufferMapping>& out_mappings)
{
    uint64_t sh_off   = ehdr.e_shoff;
    uint16_t sh_num   = ehdr.e_shnum;
    uint16_t sh_esz   = ehdr.e_shentsize;
    size_t expected_esz = is_64 ? sizeof(Elf64_Shdr) : sizeof(Elf32_Shdr);

    out_sections.clear();
    out_mappings.clear();
    out_entry_point = static_cast<uint64_t>(ehdr.e_entry);

    if (sh_off == 0 || sh_num == 0 || sh_esz < expected_esz) {
        std::cerr << "[!] ELFParser: Invalid or missing section header table.\n";
        return false;
    }

    if (sh_off >= size || static_cast<size_t>(sh_num) > (size - sh_off) / sh_esz) {
        std::cerr << "[!] ELFParser: Section Header Table out of file bounds.\n";
        return false;
    }

    // Decode all section headers safely
    std::vector<DecodedShdr> shdrs(sh_num);
    for (uint16_t i = 0; i < sh_num; ++i) {
        size_t offset = static_cast<size_t>(sh_off) + static_cast<size_t>(i) * sh_esz;
        if (!decode_shdr(data + offset, size - offset, is_64, is_be, shdrs[i])) {
            std::cerr << "[!] ELFParser: Failed to decode section header " << i << ".\n";
            return false;
        }
    }

    // Section header string table
    if (ehdr.e_shstrndx == SHN_UNDEF || ehdr.e_shstrndx >= sh_num) {
        std::cerr << "[!] ELFParser: Invalid section header string table index.\n";
        return false;
    }

    const auto& shstr_hdr = shdrs[ehdr.e_shstrndx];
    if (shstr_hdr.sh_offset >= size || shstr_hdr.sh_size > size - shstr_hdr.sh_offset) {
        std::cerr << "[!] ELFParser: Section name string table out of bounds.\n";
        return false;
    }

    const char* shstr_table = reinterpret_cast<const char*>(data + shstr_hdr.sh_offset);
    size_t shstr_size = static_cast<size_t>(shstr_hdr.sh_size);

    // Record all sections and collect executable ones
    struct SecInfo {
        uint64_t va;
        size_t   offset;
        size_t   raw_size;
        std::string name;
    };
    std::vector<SecInfo> exec_secs;

    for (uint16_t i = 0; i < sh_num; ++i) {
        const auto& shdr = shdrs[i];
        std::string sec_name;
        if (shdr.sh_name < shstr_size) {
            size_t max_len = shstr_size - shdr.sh_name;
            size_t len = strnlen(shstr_table + shdr.sh_name, max_len);
            sec_name.assign(shstr_table + shdr.sh_name, len);
        }

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

        if (shdr.sh_offset >= size) continue;
        size_t raw_offset = static_cast<size_t>(shdr.sh_offset);
        size_t raw_size   = static_cast<size_t>(shdr.sh_size);

        if (raw_size > size - raw_offset) {
            raw_size = size - raw_offset;
        }

        exec_secs.push_back({ shdr.sh_addr, raw_offset, raw_size, sec_name });
    }

    // Fallback: search for .text by name if no SHF_EXECINSTR sections found
    if (exec_secs.empty()) {
        for (uint16_t i = 0; i < sh_num; ++i) {
            const auto& shdr = shdrs[i];
            if (shdr.sh_name >= shstr_size) continue;
            const char* sname = shstr_table + shdr.sh_name;
            if (std::strcmp(sname, ".text") == 0) {
                if (shdr.sh_offset < size) {
                    size_t raw_offset = static_cast<size_t>(shdr.sh_offset);
                    size_t raw_size   = static_cast<size_t>(shdr.sh_size);
                    if (raw_size > size - raw_offset) raw_size = size - raw_offset;
                    exec_secs.push_back({ shdr.sh_addr, raw_offset, raw_size, ".text" });
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

    // Pack sections into out_text separated by 4-byte INT3 boundaries, recording exact mappings
    out_text.clear();
    for (size_t i = 0; i < exec_secs.size(); ++i) {
        const auto& sec = exec_secs[i];
        if (i > 0) {
            // 4-byte INT3 boundary fence between sections
            out_text.push_back(0xCC);
            out_text.push_back(0xCC);
            out_text.push_back(0xCC);
            out_text.push_back(0xCC);
        }

        ExecBufferMapping mapping;
        mapping.virtual_address = sec.va;
        mapping.buffer_offset   = out_text.size();
        mapping.size            = sec.raw_size;
        mapping.raw_offset      = sec.offset;
        mapping.section_name    = sec.name;
        out_mappings.push_back(mapping);

        const uint8_t* ptr = data + sec.offset;
        out_text.insert(out_text.end(), ptr, ptr + sec.raw_size);
    }

    return !out_text.empty();
}

// ---------------------------------------------------------------------------
// compute_elf_image_base: determines the ELF image base from PT_LOAD segments
// ---------------------------------------------------------------------------
template <typename Elf_Ehdr>
static uint64_t compute_elf_image_base(const uint8_t* data, size_t size, const Elf_Ehdr& ehdr,
                                       bool is_64, bool is_be,
                                       const std::vector<SectionInfo>& sections)
{
    size_t expected_pesz = is_64 ? sizeof(Elf64_Phdr) : sizeof(Elf32_Phdr);
    if (ehdr.e_phoff != 0 && ehdr.e_phnum > 0 && ehdr.e_phentsize >= expected_pesz) {
        if (ehdr.e_phoff < size && static_cast<size_t>(ehdr.e_phnum) <= (size - ehdr.e_phoff) / ehdr.e_phentsize) {
            uint64_t min_vaddr = UINT64_MAX;
            bool found_pt_load = false;
            for (uint16_t i = 0; i < ehdr.e_phnum; ++i) {
                size_t offset = static_cast<size_t>(ehdr.e_phoff) + static_cast<size_t>(i) * ehdr.e_phentsize;
                DecodedPhdr phdr;
                if (decode_phdr(data + offset, size - offset, is_64, is_be, phdr)) {
                    if (phdr.p_type == PT_LOAD) {
                        if (phdr.p_vaddr < min_vaddr) {
                            min_vaddr = phdr.p_vaddr;
                            found_pt_load = true;
                        }
                    }
                }
            }
            if (found_pt_load && min_vaddr != UINT64_MAX) {
                return min_vaddr;
            }
        }
    }
    // Fallback if no PT_LOAD: lowest non-zero section virtual address
    uint64_t lowest_sec_va = UINT64_MAX;
    for (const auto& sec : sections) {
        if (sec.virtual_address != 0 && sec.virtual_address < lowest_sec_va) {
            lowest_sec_va = sec.virtual_address;
        }
    }
    return (lowest_sec_va != UINT64_MAX) ? lowest_sec_va : 0;
}

// ---------------------------------------------------------------------------
// detect_elf_mitigations: inspects dynamic section and program headers
// for NX, PIE, stack canary, and RELRO.
// ---------------------------------------------------------------------------
template <typename Elf_Ehdr>
static void detect_mitigations(const uint8_t* data, size_t size, const Elf_Ehdr& ehdr,
                               bool is_64, bool is_be,
                               bool& nx_out, bool& pie_out,
                               bool& canary_out, std::string& relro_out)
{
    // PIE: ET_DYN with no fixed load address
    pie_out = (ehdr.e_type == ET_DYN);

    // NX: check if any PT_GNU_STACK segment has execute permission
    nx_out = true; // assume NX unless PF_X found on GNU_STACK
    bool has_gnu_stack = false;

    size_t expected_pesz = is_64 ? sizeof(Elf64_Phdr) : sizeof(Elf32_Phdr);
    if (ehdr.e_phoff != 0 && ehdr.e_phnum > 0 && ehdr.e_phentsize >= expected_pesz) {
        if (ehdr.e_phoff < size && static_cast<size_t>(ehdr.e_phnum) <= (size - ehdr.e_phoff) / ehdr.e_phentsize) {
            bool partial_relro = false, full_relro = false;
            std::vector<DecodedPhdr> phdrs;
            phdrs.reserve(ehdr.e_phnum);

            for (uint16_t i = 0; i < ehdr.e_phnum; ++i) {
                size_t offset = static_cast<size_t>(ehdr.e_phoff) + static_cast<size_t>(i) * ehdr.e_phentsize;
                DecodedPhdr phdr;
                if (decode_phdr(data + offset, size - offset, is_64, is_be, phdr)) {
                    phdrs.push_back(phdr);
                    if (phdr.p_type == PT_GNU_STACK) {
                        has_gnu_stack = true;
                        // If execute bit is set, NX is disabled
                        if (phdr.p_flags & PF_X) nx_out = false;
                    }
                    if (phdr.p_type == PT_GNU_RELRO) {
                        partial_relro = true;
                    }
                }
            }

            // Full RELRO requires PT_GNU_RELRO + BIND_NOW in dynamic section
            // Check dynamic section for DT_FLAGS / DT_FLAGS_1 / DT_BIND_NOW
            size_t dyn_esz = is_64 ? sizeof(Elf64_Dyn) : sizeof(Elf32_Dyn);
            for (const auto& phdr : phdrs) {
                if (phdr.p_type != PT_DYNAMIC) continue;
                if (phdr.p_offset >= size || phdr.p_filesz > size - phdr.p_offset) break;

                size_t dyn_count = phdr.p_filesz / dyn_esz;
                for (size_t d = 0; d < dyn_count; ++d) {
                    size_t d_offset = static_cast<size_t>(phdr.p_offset) + d * dyn_esz;
                    DecodedDyn dyn;
                    if (!decode_dyn(data + d_offset, size - d_offset, is_64, is_be, dyn)) break;
                    if (dyn.d_tag == DT_NULL) break;
                    if (dyn.d_tag == DT_BIND_NOW) { full_relro = true; }
                    // DF_BIND_NOW = 0x08 in DT_FLAGS
                    if (dyn.d_tag == DT_FLAGS && (dyn.d_val & 0x08)) { full_relro = true; }
                }
                break;
            }

            if (full_relro && partial_relro) relro_out = "Full";
            else if (partial_relro)          relro_out = "Partial";
            else                             relro_out = "None";
        }
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

    // Data encoding validation
    uint8_t data_encoding = data[EI_DATA];
    if (data_encoding == ELFDATA2LSB) {
        m_metadata_endianness = Endianness::Little;
        m_is_big_endian = false;
    } else if (data_encoding == ELFDATA2MSB) {
        m_metadata_endianness = Endianness::Big;
        m_is_big_endian = true;
    } else {
        std::cerr << "[!] ELFParser: Invalid or unsupported data encoding: " << static_cast<int>(data_encoding) << std::endl;
        m_metadata_endianness = Endianness::Unsupported;
        m_instruction_endianness = Endianness::Unsupported;
        return false;
    }
    m_arm_be8 = false;

    if (data[EI_CLASS] == ELFCLASS32) {
        if (size < sizeof(Elf32_Ehdr)) return false;
        std::memcpy(hdr32.e_ident, data, 16);
        hdr32.e_type      = read_u16(data + 16, m_is_big_endian);
        hdr32.e_machine   = read_u16(data + 18, m_is_big_endian);
        hdr32.e_version   = read_u32(data + 20, m_is_big_endian);
        hdr32.e_entry     = read_u32(data + 24, m_is_big_endian);
        hdr32.e_phoff     = read_u32(data + 28, m_is_big_endian);
        hdr32.e_shoff     = read_u32(data + 32, m_is_big_endian);
        hdr32.e_flags     = read_u32(data + 36, m_is_big_endian);
        hdr32.e_ehsize    = read_u16(data + 40, m_is_big_endian);
        hdr32.e_phentsize = read_u16(data + 42, m_is_big_endian);
        hdr32.e_phnum     = read_u16(data + 44, m_is_big_endian);
        hdr32.e_shentsize = read_u16(data + 46, m_is_big_endian);
        hdr32.e_shnum     = read_u16(data + 48, m_is_big_endian);
        hdr32.e_shstrndx  = read_u16(data + 50, m_is_big_endian);

        m_elf_flags = hdr32.e_flags;
        m_arch = getElfMachineArchitecture(hdr32.e_machine);

        if (hdr32.e_machine == EM_ARM && (hdr32.e_flags & EF_ARM_BE8)) {
            m_arm_be8 = true;
        }

        if (!extract_exec_sections(data, size, hdr32, false, m_is_big_endian,
                m_text_section, m_text_section_base_address, m_entry_point, m_sections, m_exec_mappings)) {
            return false;
        }

        m_image_base = compute_elf_image_base(data, size, hdr32, false, m_is_big_endian, m_sections);

        detect_mitigations(data, size, hdr32, false, m_is_big_endian,
            m_nx_enabled, m_pie_enabled, m_canary_enabled, m_relro);

    } else if (data[EI_CLASS] == ELFCLASS64) {
        if (size < sizeof(Elf64_Ehdr)) return false;
        std::memcpy(hdr64.e_ident, data, 16);
        hdr64.e_type      = read_u16(data + 16, m_is_big_endian);
        hdr64.e_machine   = read_u16(data + 18, m_is_big_endian);
        hdr64.e_version   = read_u32(data + 20, m_is_big_endian);
        hdr64.e_entry     = read_u64(data + 24, m_is_big_endian);
        hdr64.e_phoff     = read_u64(data + 32, m_is_big_endian);
        hdr64.e_shoff     = read_u64(data + 40, m_is_big_endian);
        hdr64.e_flags     = read_u32(data + 48, m_is_big_endian);
        hdr64.e_ehsize    = read_u16(data + 52, m_is_big_endian);
        hdr64.e_phentsize = read_u16(data + 54, m_is_big_endian);
        hdr64.e_phnum     = read_u16(data + 56, m_is_big_endian);
        hdr64.e_shentsize = read_u16(data + 58, m_is_big_endian);
        hdr64.e_shnum     = read_u16(data + 60, m_is_big_endian);
        hdr64.e_shstrndx  = read_u16(data + 62, m_is_big_endian);

        m_elf_flags = hdr64.e_flags;
        m_arch = getElfMachineArchitecture(hdr64.e_machine);

        if (!extract_exec_sections(data, size, hdr64, true, m_is_big_endian,
                m_text_section, m_text_section_base_address, m_entry_point, m_sections, m_exec_mappings)) {
            return false;
        }

        m_image_base = compute_elf_image_base(data, size, hdr64, true, m_is_big_endian, m_sections);

        detect_mitigations(data, size, hdr64, true, m_is_big_endian,
            m_nx_enabled, m_pie_enabled, m_canary_enabled, m_relro);

    } else {
        std::cerr << "[!] ELFParser: Unknown ELF class: " << int(data[EI_CLASS]) << std::endl;
        return false;
    }

    // RISC-V: differentiate 32 vs 64 from ELF class
    if (m_arch == "riscv") {
        m_arch = (data[EI_CLASS] == ELFCLASS32) ? "riscv32" : "riscv64";
    }

    // Determine instruction endianness
    if (m_arch == "x86" || m_arch == "x86_64") {
        m_instruction_endianness = Endianness::Little;
    } else if (m_arch == "aarch64") {
        // AAELF64 §5.1 mandates little-endian instruction encoding even when data is big-endian
        m_instruction_endianness = Endianness::Little;
    } else if (m_arch == "armv7") {
        if (!m_is_big_endian) {
            m_instruction_endianness = Endianness::Little;
        } else if (m_arm_be8) {
            // ARMv7 BE-8: big-endian metadata/data, but little-endian instructions
            m_instruction_endianness = Endianness::Little;
        } else {
            // Ambiguous/unverified big-endian ARM (legacy BE-32 or unspecified).
            // Do not infer BE-32 merely because EF_ARM_BE8 is absent.
            m_instruction_endianness = Endianness::Unsupported;
        }
    } else if (m_arch == "riscv32" || m_arch == "riscv64") {
        if (!m_is_big_endian) {
            m_instruction_endianness = Endianness::Little;
        } else {
            // Big-endian RISC-V is not supported by Capstone 5.0
            m_instruction_endianness = Endianness::Unsupported;
        }
    } else {
        m_instruction_endianness = Endianness::Unknown;
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
    if (!m_file_data.empty() && m_file_data.size() > EI_CLASS) {
        return m_file_data[EI_CLASS] == ELFCLASS64;
    }
    if (hdr64.e_ident[EI_CLASS] == ELFCLASS64) return true;
    if (hdr32.e_ident[EI_CLASS] == ELFCLASS32) return false;
    return false;
}
