#include "payload_gen.h"
#include "version.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include "nlohmann/json.hpp"
#include <ctime>
#include <filesystem>
#include <algorithm>
#include "parsers/file_parser.h"
#include "parsers/pe_parser.h"
#include "parsers/macho_parser.h"

using json = nlohmann::json;

// ANSI escape codes for coloring
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_ORANGE  "\033[33m"
#define ANSI_COLOR_RESET   "\x1b[0m"

// Utility function to pack 64-bit integer into little-endian bytes
std::vector<char> pack64(uint64_t n) {
    std::vector<char> result(8);
    for (int i = 0; i < 8; ++i) {
        result[i] = static_cast<char>((n >> (8 * i)) & 0xFF);
    }
    return result;
}

// Helper to convert the raw payload bytes to a Python hex string format
std::string to_python_hex(const std::vector<char>& payload) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (char byte : payload) {
        ss << "\\x" << std::setw(2) << static_cast<int>(static_cast<unsigned char>(byte));
    }
    return ss.str();
}

void PayloadGenerator::generate(const ROPChain& chain, size_t paddingSize, const std::string& filename,
                                const std::vector<Gadget>& gadgets,
                                const std::string& architecture,
                                const std::string& fileType,
                                const json& protections,
                                const std::string& customReportId,
                                const std::string& fileHash,
                                const FileParser* parser,
                                const std::string& reportPath,
                                const std::string& payloadBinPath,
                                const std::string& payloadBinReportsPath) {
    // --- 1. Construct the Raw Payload ---
    std::vector<char> chain_bytes;
    std::string serialization_error;
    bool serialization_ok = true;
    bool has_chain = !chain.get_steps().empty();

    if (has_chain) {
        if (!parser) {
            serialization_error = "Target parser metadata is required for architecture-aware payload serialization";
            serialization_ok = false;
        } else {
            size_t wordSize = parser->is64Bit() ? 8 : 4;
            // Requirement 6: Use FileParser::getMetadataEndianness() for payload data serialization.
            // Do not use instruction endianness because ARM BE-8 can have different instruction and data byte orders.
            Endianness dataEndian = parser->getMetadataEndianness();
            try {
                chain_bytes = chain.getPayloadBytes(wordSize, dataEndian);
            } catch (const std::exception& e) {
                serialization_error = e.what();
                serialization_ok = false;
            }
        }
    }

    ChainValidationResult vres;
    if (has_chain && serialization_ok && fileType != "PE") {
        vres = chain.validate(architecture, parser);
    }

    std::vector<char> payload;
    // Only construct payload if we have a valid chain, serialization succeeded, validation passed, and it's not an unsupported platform
    if (has_chain && serialization_ok && vres.valid && fileType != "PE") {
        payload.assign(paddingSize, 'A');
        payload.insert(payload.end(), chain_bytes.begin(), chain_bytes.end());
    }

    // --- 2. Construct the Comprehensive JSON Report ---
    json report = json::object();
    std::time_t now = std::time(nullptr);

    try {
        // Basic Metadata
        if (!customReportId.empty()) {
            report["report_id"] = customReportId;
        } else {
            report["report_id"] = "ROPW-" + std::to_string(now);
        }
        
        std::stringstream ss;
        ss << std::put_time(std::gmtime(&now), "%Y-%m-%dT%H:%M:%SZ");
        report["report_date"] = ss.str();
        
        report["tool_version"] = ROPWEAVER_VERSION_FULL;
        report["build_id"] = ROPWEAVER_BUILD_ID;
        report["commit_hash"] = ROPWEAVER_COMMIT_HASH;
        report["build_date"] = ROPWEAVER_BUILD_DATE;
        report["architecture"] = architecture;
        report["file_type"] = fileType;

        // Discovered Gadget Counts
        report["total_gadgets"] = gadgets.size();
        report["discovered_gadgets_count"] = gadgets.size();

        // Target binary details
        report["target_binary"] = {
            {"filename", filename},
            {"hash", fileHash.empty() ? filename : fileHash},
            {"sha256", fileHash}
        };

        // Section & layout information
        if (parser) {
            std::stringstream ibSs, epSs;
            ibSs << "0x" << std::hex << std::setw(16) << std::setfill('0') << parser->getImageBase();
            epSs << "0x" << std::hex << std::setw(16) << std::setfill('0') << parser->getEntryPoint();
            report["image_base"] = ibSs.str();
            report["entry_point"] = epSs.str();

            json sectionsArr = json::array();
            for (const auto& sec : parser->getSections()) {
                std::stringstream vaSs, rawSs;
                vaSs << "0x" << std::hex << std::setw(16) << std::setfill('0') << sec.virtual_address;
                rawSs << "0x" << std::hex << std::setw(8) << std::setfill('0') << sec.raw_offset;
                sectionsArr.push_back({
                    {"name", sec.name},
                    {"virtual_address", vaSs.str()},
                    {"virtual_size", sec.virtual_size},
                    {"raw_offset", rawSs.str()},
                    {"raw_size", sec.raw_size},
                    {"is_executable", sec.is_executable}
                });
            }
            report["sections"] = sectionsArr;
        }

        // --- Mitigation Reporting (Requirement 3: Strict platform terminology) ---
        if (fileType == "PE") {
            const ropweaver::PEParser* pe_parser = parser ? dynamic_cast<const ropweaver::PEParser*>(parser) : nullptr;
            ropweaver::PEMitigations peMit;
            if (pe_parser) {
                peMit = pe_parser->getPEMitigations();
            } else {
                // Infer from protections json if parser is not provided
                if (protections.contains("DEP_NX")) peMit.nx_compat = protections["DEP_NX"].get<bool>();
                if (protections.contains("ASLR_PIE")) peMit.dynamic_base = protections["ASLR_PIE"].get<bool>();
                if (protections.contains("HighEntropyVA")) peMit.high_entropy_va = protections["HighEntropyVA"].get<bool>();
                if (protections.contains("CFG")) peMit.guard_cf = protections["CFG"].get<bool>();
                if (protections.contains("SafeSEH_NoSEH")) peMit.no_seh = protections["SafeSEH_NoSEH"].get<bool>();
                if (protections.contains("GS_Canary") && protections["GS_Canary"].get<bool>()) peMit.gs_status = "HEURISTIC_PRESENT";
            }

            json pe_prots;
            pe_prots["NX_COMPAT"] = {
                {"enabled", peMit.nx_compat},
                {"static_indicator", peMit.nx_compat ? "COMPATIBLE" : "NOT_COMPATIBLE"},
                {"description", "Binary explicitly opts into DEP via PE header; runtime enforcement is governed by host OS policy and hardware NX support"},
                {"flag", "IMAGE_DLLCHARACTERISTICS_NX_COMPAT (0x0100)"}
            };
            pe_prots["DYNAMIC_BASE"] = {
                {"enabled", peMit.dynamic_base},
                {"static_indicator", peMit.dynamic_base ? "COMPATIBLE" : "NOT_COMPATIBLE"},
                {"description", "Binary explicitly opts into ASLR via PE header; runtime address randomization is governed by host OS ASLR policy"},
                {"flag", "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040)"}
            };
            pe_prots["HIGH_ENTROPY_VA"] = {
                {"enabled", peMit.high_entropy_va},
                {"static_indicator", peMit.high_entropy_va ? "COMPATIBLE" : "NOT_COMPATIBLE"},
                {"description", "Binary declares compatibility with 64-bit high-entropy ASLR (>4GB virtual address space) when loaded by OS"},
                {"flag", "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA (0x0020)"}
            };
            pe_prots["GUARD_CF"] = {
                {"enabled", peMit.guard_cf},
                {"static_indicator", peMit.guard_cf ? "COMPATIBLE" : "NOT_COMPATIBLE"},
                {"description", "Control Flow Guard compiler instrumentation; inactive if CFG function table or static flag is absent"},
                {"cf_instrumented", peMit.cf_instrumented},
                {"cf_table_present", peMit.cf_table_present},
                {"flag", "IMAGE_DLLCHARACTERISTICS_GUARD_CF (0x4000)"}
            };
            pe_prots["CET_COMPAT"] = {
                {"enabled", peMit.cet_unknown ? nullptr : json(peMit.cet_compat)},
                {"static_indicator", peMit.cet_unknown ? "UNKNOWN" : (peMit.cet_compat ? "COMPATIBLE" : "NOT_COMPATIBLE")},
                {"description", "Control-flow Enforcement Technology (Shadow Stack / IBT); reported as UNKNOWN when Load Config Directory is absent"},
                {"evidence", peMit.cet_unknown ? "Insufficient evidence: Load Config Directory absent or empty" : "Load Config flags verified"}
            };
            pe_prots["GS_COOKIE"] = {
                {"enabled", peMit.gs_status != "NOT_DETECTED"},
                {"static_indicator", peMit.gs_status},
                {"description", "Compiler stack buffer overrun guard (__security_cookie); static scan of sections and imports"},
                {"security_cookie_va", peMit.security_cookie_va != 0 ? ("0x" + ([&](){
                    std::stringstream ss; ss << std::hex << peMit.security_cookie_va; return ss.str();
                })()) : "N/A"}
            };
            pe_prots["SafeSEH"] = {
                {"enabled", peMit.safeseh_status == "ENABLED"},
                {"static_indicator", peMit.safeseh_status},
                {"description", "Structured Exception Handler table verification (x86 only; x86_64 PE targets use table-based unwind in .pdata/.xdata)"}
            };

            // Backward-compatibility boolean aliases (NEVER include RELRO)
            pe_prots["DEP_NX"]        = peMit.nx_compat;
            pe_prots["ASLR_PIE"]      = peMit.dynamic_base;
            pe_prots["GS_Canary"]     = peMit.gs_status != "NOT_DETECTED";
            pe_prots["HighEntropyVA"] = peMit.high_entropy_va;
            pe_prots["CFG"]           = peMit.guard_cf;
            pe_prots["SafeSEH_NoSEH"] = peMit.no_seh;

            report["protections"] = pe_prots;
        } else if (fileType == "Mach-O") {
            const ropweaver::MachOParser* macho_parser = dynamic_cast<const ropweaver::MachOParser*>(parser);
            ropweaver::MachOMitigations machoMit;
            if (macho_parser) {
                machoMit = macho_parser->getMachOMitigations();
            }

            json macho_prots;
            macho_prots["Stack_NX"] = machoMit.stack_nx;
            macho_prots["Heap_NX"]  = (machoMit.heap_nx == ropweaver::HeapNxStatus::ExplicitEnabled) ? "EXPLICIT_ENABLED" : "UNKNOWN";

            std::string wx_status_str = "INCOMPLETE_OR_UNAVAILABLE";
            if (machoMit.segment_wx_status == ropweaver::SegmentWxStatus::Compliant) {
                wx_status_str = "COMPLIANT";
            } else if (machoMit.segment_wx_status == ropweaver::SegmentWxStatus::InitViolation) {
                wx_status_str = "INIT_VIOLATION";
            } else if (machoMit.segment_wx_status == ropweaver::SegmentWxStatus::MaxprotPermissive) {
                wx_status_str = "MAXPROT_PERMISSIVE";
            }

            macho_prots["Segment_WX"] = {
                {"status", wx_status_str},
                {"initprot_compliant", !machoMit.has_wx_initprot},
                {"maxprot_compliant", !machoMit.has_wx_maxprot}
            };
            macho_prots["PIE"] = machoMit.pie;

            std::string canary_status_str = "UNKNOWN";
            if (machoMit.canary_status == ropweaver::CanaryStatus::SymbolDetected) {
                canary_status_str = "SYMBOL_DETECTED";
            } else if (machoMit.canary_status == ropweaver::CanaryStatus::NotDetected) {
                canary_status_str = "NOT_DETECTED";
            }

            macho_prots["Canary"] = {
                {"status", canary_status_str},
                {"symbol", machoMit.canary_symbol_name.empty() ? nullptr : json(machoMit.canary_symbol_name)},
                {"notes", (machoMit.canary_status == ropweaver::CanaryStatus::SymbolDetected)
                          ? "Exact symbol found in LC_SYMTAB. Indicates stack protection runtime dependency; does not prove universal function instrumentation."
                          : "No canary symbol detected or symbol table unavailable."}
            };

            macho_prots["Code_Signature"] = {
                {"load_command_present", machoMit.has_code_signature_cmd},
                {"data_range_valid", machoMit.data_range_valid},
                {"superblob_header_valid", machoMit.superblob_header_valid},
                {"cryptographically_verified", false},
                {"notes", machoMit.code_signature_notes.empty() ? "No code signature command present." : machoMit.code_signature_notes}
            };

            macho_prots["RELRO"] = "NOT_APPLICABLE";

            // Backward-compatibility aliases
            macho_prots["NX"] = parser ? parser->isNxEnabled() : false;

            report["protections"] = macho_prots;
        } else {
            // ELF Protections
            if (protections.empty()) {
                report["protections"] = {
                    {"NX",     parser ? parser->isNxEnabled() : false},
                    {"PIE",    parser ? parser->isPieEnabled() : false},
                    {"Canary", parser ? parser->isCanaryEnabled() : false},
                    {"RELRO",  parser ? parser->getRelro() : "None"}
                };
            } else {
                report["protections"] = protections;
            }
        }

        // --- ROP Chain & Raw Payload Details (Requirement 1 & 6) ---
        if (fileType == "PE") {
            // Windows PE automated chain is unsupported
            report["rop_chain_generation"] = {
                {"status", "Unsupported for Windows PE targets"},
                {"target_syscall", "N/A"},
                {"chain_notes", "Automated ROP chain synthesis currently targets POSIX execve on Linux ELF. Windows x64 requires Win64 Fastcall staging (RCX, RDX, R8, R9, 32-byte shadow space) and dynamic API resolution (e.g. VirtualProtect / WinExec)."},
                {"platform", "Windows PE"}
            };
            report["rop_chain_details"] = nullptr;
            report["raw_payload"] = {
                {"status", "Unsupported: Automated ROP chain synthesis not implemented for Windows PE"},
                {"format", "None"},
                {"data", nullptr},
                {"verified_padding_offset", nullptr}
            };
        } else if (fileType == "Mach-O") {
            bool isPie = false;
            if (report.contains("protections") && report["protections"].contains("PIE")) {
                isPie = report["protections"]["PIE"].get<bool>();
            }

            if (!has_chain) {
                report["rop_chain_generation"] = {
                    {"status", "Failed: Required gadgets missing for Darwin execve chain synthesis"},
                    {"target_syscall", "execve (0x200003B)"},
                    {"chain_notes", "Attempted Darwin ROP chain generation. Binary is missing required staging gadgets, /bin/sh string, or pointer arrays."},
                    {"platform", "macOS Mach-O"},
                    {"aslr_slide_applied", false},
                    {"relocation_status", isPie ? "Unresolved: Target binary has MH_PIE enabled. Generated chain uses link-time Preferred Virtual Addresses. Dynamic execution requires runtime ASLR slide adjustment." : "PVA Link-Time Base"}
                };
                report["rop_chain_details"] = nullptr;
                report["raw_payload"] = {
                    {"status", "Failed: ROP chain generation unsuccessful"},
                    {"format", "None"},
                    {"data", nullptr},
                    {"verified_padding_offset", nullptr}
                };
            } else if (!vres.valid) {
                report["rop_chain_generation"] = {
                    {"status", "Failure (Validation Error)"},
                    {"error", vres.error_message},
                    {"target_syscall", "execve (0x200003B)"},
                    {"chain_notes", "Darwin ROP chain failed static semantic validation: " + vres.error_message},
                    {"platform", "macOS Mach-O"},
                    {"aslr_slide_applied", false},
                    {"relocation_status", isPie ? "Unresolved: Target binary has MH_PIE enabled. Generated chain uses link-time Preferred Virtual Addresses. Dynamic execution requires runtime ASLR slide adjustment." : "PVA Link-Time Base"},
                    {"validation", vres.toJson()}
                };
                report["rop_chain_details"] = chain.toJson();
                report["raw_payload"] = {
                    {"status", "Validation Failed: " + vres.error_message},
                    {"format", "None"},
                    {"data", nullptr},
                    {"verified_padding_offset", nullptr}
                };
            } else {
                std::string chain_notes = "Synthesized Darwin x86_64 ROP chain targeting BSD syscall SYS_execve (0x200003B).";
                std::string rel_status = "PVA Link-Time Base";
                if (isPie) {
                    rel_status = "Unresolved: Target binary has MH_PIE enabled. Generated chain uses link-time Preferred Virtual Addresses. Dynamic execution requires runtime ASLR slide adjustment.";
                    chain_notes += " Warning: Target binary has MH_PIE enabled; chain uses link-time Preferred Virtual Addresses. Dynamic execution requires ASLR slide resolution.";
                }

                report["rop_chain_generation"] = {
                    {"status", isPie ? "Success (Relocation Required)" : "Success"},
                    {"target_syscall", "execve (0x200003B)"},
                    {"chain_notes", chain_notes},
                    {"platform", "macOS Mach-O"},
                    {"aslr_slide_applied", false},
                    {"relocation_status", rel_status},
                    {"validation", vres.toJson()}
                };
                report["rop_chain_details"] = chain.toJson();
                report["raw_payload"] = {
                    {"status", "Success"},
                    {"format", "python_hex_string"},
                    {"data", to_python_hex(payload)},
                    {"verified_padding_offset", paddingSize}
                };
            }
        } else {
            // Linux ELF
            if (!has_chain) {
                report["rop_chain_generation"] = {
                    {"status", "Failed: Required gadgets missing for execve chain synthesis"},
                    {"target_syscall", "execve (59)"},
                    {"chain_notes", "Attempted ROP chain generation. Binary is missing required staging gadgets or /bin/sh string."},
                    {"platform", "Linux ELF"}
                };
                report["rop_chain_details"] = nullptr;
                report["raw_payload"] = {
                    {"status", "Payload Generation Incomplete - No ROP Chain Synthesized"},
                    {"format", "None"},
                    {"data", nullptr},
                    {"verified_padding_offset", nullptr}
                };
            } else if (!serialization_ok) {
                report["rop_chain_generation"] = {
                    {"status", "Failed: Payload serialization error - " + serialization_error},
                    {"target_syscall", "execve (59)"},
                    {"chain_notes", "ROP chain synthesized but target payload serialization failed: " + serialization_error},
                    {"platform", "Linux ELF"}
                };
                report["rop_chain_details"] = chain.toJson();
                report["raw_payload"] = {
                    {"status", "Serialization Failed: " + serialization_error},
                    {"format", "None"},
                    {"data", nullptr},
                    {"verified_padding_offset", nullptr}
                };
            } else if (!vres.valid) {
                report["rop_chain_generation"] = {
                    {"status", "Failure (Validation Error)"},
                    {"error", vres.error_message},
                    {"target_syscall", "execve"},
                    {"chain_notes", "ROP chain failed static semantic validation: " + vres.error_message},
                    {"platform", "Linux ELF"},
                    {"validation", vres.toJson()}
                };
                report["rop_chain_details"] = chain.toJson();
                report["raw_payload"] = {
                    {"status", "Validation Failed: " + vres.error_message},
                    {"format", "None"},
                    {"data", nullptr},
                    {"verified_padding_offset", nullptr}
                };
            } else {
                report["rop_chain_generation"] = {
                    {"status", "Success (Execve-Shell)"},
                    {"target_syscall", "execve (59)"},
                    {"chain_notes", "Automated ROP chain synthesized and validated successfully."},
                    {"platform", "Linux ELF"},
                    {"validation", vres.toJson()}
                };
                report["rop_chain_details"] = chain.toJson();
                report["raw_payload"] = {
                    {"status", "Success"},
                    {"format", "python_hex_string"},
                    {"data", to_python_hex(payload)},
                    {"verified_padding_offset", paddingSize}
                };
            }
        }

        // --- Discovered Gadgets with Multi-dimensional Classification (Requirement 2 & 4 & 5) ---
        json gadgetsArr = json::array();
        for (const auto& g : gadgets) {
            std::stringstream prefVaSs, rvaSs, foSs, entryVaSs;
            prefVaSs << "0x" << std::hex << std::setw(16) << std::setfill('0') << g.preferred_va;
            entryVaSs << "0x" << std::hex << std::setw(16) << std::setfill('0') << g.entry_address;
            rvaSs    << "0x" << std::hex << std::setw(8)  << std::setfill('0') << g.rva;
            foSs     << "0x" << std::hex << std::setw(8)  << std::setfill('0') << g.file_offset;

            std::string instrStr;
            for (size_t i = 0; i < g.instructions.size(); ++i) {
                instrStr += g.instructions[i].mnemonic;
                if (!g.instructions[i].op_str.empty()) instrStr += " " + g.instructions[i].op_str;
                if (i + 1 < g.instructions.size()) instrStr += " ; ";
            }

            // Determine runtime VA representation: null when ASLR is active
            json runtimeVaVal = nullptr;
            std::string runtimeVaNote = "ASLR / DYNAMIC_BASE active; runtime address randomized by OS at process execution";
            if (g.runtime_va != "ASLR Dependent" && g.runtime_va != "null" && !g.runtime_va.empty()) {
                runtimeVaVal = g.runtime_va;
                runtimeVaNote = "Fixed load address (ASLR disabled); runtime address matches preferred VA";
            }

            json gadgetEntry = {
                {"address",                   prefVaSs.str()},
                {"preferred_va",              prefVaSs.str()},
                {"entry_address",             entryVaSs.str()},
                {"is_thumb",                  g.is_thumb},
                {"rva",                       rvaSs.str()},
                {"file_offset",               foSs.str()},
                {"runtime_va",                runtimeVaVal},
                {"runtime_va_note",           runtimeVaNote},
                {"gadget",                    instrStr},
                {"instructions",              instrStr},
                {"category",                  g.category.empty() ? "others" : g.category},
                {"categories",                !g.categories.empty() ? json(g.categories) : json::array({g.category.empty() ? "others" : g.category})},
                {"registers_read",            g.registers_read},
                {"registers_modified",        g.registers_modified},
                {"stack_delta",               g.stack_delta},
                {"stack_consumption",         g.stack_consumption},
                {"has_memory_read",           g.has_memory_read},
                {"has_memory_write",          g.has_memory_write},
                {"terminator_type",           g.terminator_type.empty() ? "UNKNOWN" : g.terminator_type},
                {"instruction_count",         g.instruction_count},
                {"classification_confidence", g.classification_confidence},
                {"byte_verified",             g.byte_verified},
                {"side_effects",              g.side_effects}
            };

            gadgetsArr.push_back(gadgetEntry);
        }
        report["gadgets"] = gadgetsArr;

    } catch (const std::exception& e) {
        std::cerr << "[x] JSON Report Generation Error: " << e.what() << std::endl;
        return; 
    }

    // --- 3. Write the JSON Report File ---
    const std::string& REPORT_PATH = reportPath;
    std::error_code ec;
    std::filesystem::path reportFilePath(REPORT_PATH);
    if (reportFilePath.has_parent_path() && !reportFilePath.parent_path().empty()) {
        std::filesystem::create_directories(reportFilePath.parent_path(), ec);
    }
    std::ofstream outfile(REPORT_PATH);

    if (outfile.is_open()) {
        outfile << report.dump(4);
        outfile.close();
        std::cout << ANSI_COLOR_GREEN << "[+] Comprehensive report written to: " 
                  << REPORT_PATH << ANSI_COLOR_RESET << std::endl;
    } else {
        std::cerr << ANSI_COLOR_RESET << "[x] FATAL ERROR: Could not open file for writing: " 
                  << REPORT_PATH << ".\n(Check 'reports/' folder permissions.)" << std::endl;
        return;
    }

    // --- 4. Write Raw Exploit Payload Files (payload.bin and reports/payload.bin) ---
    if (has_chain && serialization_ok && vres.valid && !payload.empty() && fileType != "PE") {
        if (!payloadBinReportsPath.empty()) {
            std::filesystem::path p(payloadBinReportsPath);
            if (p.has_parent_path() && !p.parent_path().empty()) {
                std::filesystem::create_directories(p.parent_path(), ec);
            }
            std::ofstream binFile(payloadBinReportsPath, std::ios::binary);
            if (binFile.is_open()) {
                binFile.write(payload.data(), payload.size());
                binFile.close();
                std::cout << ANSI_COLOR_GREEN << "[+] Raw exploit payload written to: "
                          << payloadBinReportsPath << ANSI_COLOR_RESET << std::endl;
            }
        }

        if (!payloadBinPath.empty()) {
            std::filesystem::path p(payloadBinPath);
            if (p.has_parent_path() && !p.parent_path().empty()) {
                std::filesystem::create_directories(p.parent_path(), ec);
            }
            std::ofstream binFileCwd(payloadBinPath, std::ios::binary);
            if (binFileCwd.is_open()) {
                binFileCwd.write(payload.data(), payload.size());
                binFileCwd.close();
                std::cout << ANSI_COLOR_GREEN << "[+] Exploit payload also saved to: "
                          << payloadBinPath << ANSI_COLOR_RESET << std::endl;
            }
        }
    } else {
        if (fileType == "PE") {
            std::cout << ANSI_COLOR_ORANGE << "[!] Skipping payload.bin export: Automated payload generation unsupported for Windows PE."
                      << ANSI_COLOR_RESET << std::endl;
        } else if (fileType == "Mach-O") {
            std::cout << ANSI_COLOR_ORANGE << "[!] Skipping payload.bin export: Automated payload generation unsupported for macOS Mach-O."
                      << ANSI_COLOR_RESET << std::endl;
        } else if (!has_chain) {
            std::cout << ANSI_COLOR_ORANGE << "[!] Skipping payload.bin export: No ROP chain synthesized."
                      << ANSI_COLOR_RESET << std::endl;
        } else if (!serialization_ok) {
            std::cout << ANSI_COLOR_ORANGE << "[!] Skipping payload.bin export: Payload serialization failed ("
                      << serialization_error << ")." << ANSI_COLOR_RESET << std::endl;
        } else if (!vres.valid) {
            std::cout << ANSI_COLOR_ORANGE << "[!] Skipping payload.bin export: Semantic ROP chain validation failed ("
                      << vres.error_message << ")." << ANSI_COLOR_RESET << std::endl;
        }
    }
}
