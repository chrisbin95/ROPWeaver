// main.cpp
#include <iostream>
#include <vector>
#include <iomanip>
#include <string>
#include <map>
#include <memory>
#include <fstream>
#include <cstdint>
#include <stdexcept>
#include <filesystem>
#include <chrono>
#include <sstream>

// Core modules
#include "core/arch_detector.h"
#include "core/gadget_finder.h"
#include "core/chain_builder.h"
#include "core/utils.h"
#include "core/gadget.h"
#include "core/rop_chain.h"
#include "core/parsers/file_parser.h"
#include "core/parsers/pe_parser.h"
#include "core/parsers/elf_parser.h"
#include "core/payload_gen.h"

// UI and Firebase
#include "ui/cli.h"
#include "firebase/firebase_uploader.h"

// ANSI escape codes for coloring
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_ORANGE  "\033[33m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

namespace fs = std::filesystem;

size_t filesize(const std::string &filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) throw std::runtime_error("Cannot open file: " + filename);
    return static_cast<size_t>(file.tellg());
}

static std::string basename_noext(const std::string& path) {
    fs::path p(path);
    return p.stem().string();
}

static std::string timestamp_now_string() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", &tm);
    return std::string(buf);
}

#if defined(_WIN32)
#include <windows.h>
#endif

int main(int argc, char* argv[]) {
#if defined(_WIN32)
    SetConsoleOutputCP(CP_UTF8);
#endif
    std::cout << "\n==«✪»==" << ANSI_COLOR_ORANGE << "ROPWeaver: ROP Exploit Generator v1.2.4 (Build: ae613b6)" << ANSI_COLOR_RESET << "==«✪»== \n" << std::endl;

    CLI cli;
    CLIOptions options = cli.parseArguments(argc, argv);
    if (options.helpRequested) return 0;
    if (!options.valid) return 1;

    // If generating payload, uploading a report, or force uploading, auto-chain is required
    if (options.forceUpload) {
        options.uploadReport = true;
    }
    if (options.generatePayload || options.uploadReport) {
        options.autoChain = true;
    }

    std::cout << "[" << ANSI_COLOR_ORANGE << "*" << ANSI_COLOR_RESET << "] Analyzing binary: " << options.filename << std::endl;

    // Arch detector is in ropweaver namespace
    ropweaver::ArchDetector arch_detector;
    std::unique_ptr<FileParser> parser = arch_detector.createFileParser(options.filename);
    if (!parser || !parser->parse(options.filename)) {
        std::cerr << "[!] Error: Failed to parse binary: " << options.filename << std::endl;
        return 1;
    }

    std::string arch_to_use = options.architecture.empty() ? parser->getArchitecture() : options.architecture;
    if (arch_to_use == "unknown" || !arch_detector.isSupported(arch_to_use)) {
        std::cerr << "[!] Error: Unsupported or unknown architecture: " << arch_to_use << std::endl;
        return 1;
    }
    std::cout << "[" << ANSI_COLOR_ORANGE << "*" << ANSI_COLOR_RESET << "] Detected architecture: " << arch_to_use << std::endl;

    // Build protections JSON — differentiate PE vs ELF terminology
    std::string binaryType = parser ? parser->getBinaryType() : "ELF";
    nlohmann::json protections = nlohmann::json::object();

    // Cast to concrete parser types to access extended fields
    ropweaver::PEParser*  pe_parser  = dynamic_cast<ropweaver::PEParser*>(parser.get());
    ropweaver::ELFParser* elf_parser = dynamic_cast<ropweaver::ELFParser*>(parser.get());

    if (binaryType == "PE") {
        ropweaver::PEMitigations peMit;
        if (pe_parser) peMit = pe_parser->getPEMitigations();

        // PE-specific mitigation fields — never use RELRO for PE files
        protections["DEP_NX"]          = parser->isNxEnabled();
        protections["ASLR_PIE"]        = parser->isPieEnabled();
        protections["GS_Canary"]       = parser->isCanaryEnabled();
        protections["HighEntropyVA"]   = pe_parser ? pe_parser->isHighEntropyVAEnabled() : false;
        protections["CFG"]             = pe_parser ? pe_parser->isCFGEnabled() : false;
        protections["SafeSEH_NoSEH"]   = pe_parser ? pe_parser->isSafeSEHDisabled() : false;
        // NX/PIE/Canary aliases for backward compat in payload_gen
        protections["NX"]              = parser->isNxEnabled();
        protections["PIE"]             = parser->isPieEnabled();
        protections["Canary"]          = parser->isCanaryEnabled();

        std::cout << "[" << ANSI_COLOR_ORANGE << "*" << ANSI_COLOR_RESET << "] Mitigations (PE):"
                  << " NX_COMPAT(DEP)=" << (parser->isNxEnabled() ? ANSI_COLOR_GREEN "COMPATIBLE" : "\033[31mOFF") << ANSI_COLOR_RESET
                  << ", DYNAMIC_BASE(ASLR)=" << (parser->isPieEnabled() ? ANSI_COLOR_GREEN "COMPATIBLE" : "\033[31mOFF") << ANSI_COLOR_RESET
                  << ", HIGH_ENTROPY_VA=" << (pe_parser && pe_parser->isHighEntropyVAEnabled() ? ANSI_COLOR_GREEN "COMPATIBLE" : "\033[31mOFF") << ANSI_COLOR_RESET
                  << ", GUARD_CF=" << (pe_parser && pe_parser->isCFGEnabled() ? ANSI_COLOR_GREEN "COMPATIBLE" : "\033[31mOFF") << ANSI_COLOR_RESET
                  << ", CET=" << (peMit.cet_unknown ? "\033[33mUNKNOWN" : (peMit.cet_compat ? ANSI_COLOR_GREEN "COMPATIBLE" : "\033[31mOFF")) << ANSI_COLOR_RESET
                  << ", GS-Cookie=" << (peMit.gs_status != "NOT_DETECTED" ? ANSI_COLOR_GREEN + peMit.gs_status : "\033[31mNOT_DETECTED") << ANSI_COLOR_RESET
                  << ", SafeSEH=" << peMit.safeseh_status
                  << std::endl;
    } else {
        // ELF / Mach-O — keep existing terminology
        protections["NX"]     = parser->isNxEnabled();
        protections["PIE"]    = parser->isPieEnabled();
        protections["Canary"] = parser->isCanaryEnabled();
        protections["RELRO"]  = parser->getRelro();

        std::cout << "[" << ANSI_COLOR_ORANGE << "*" << ANSI_COLOR_RESET << "] Mitigations: NX="
                  << (parser->isNxEnabled() ? "ON" : "OFF")
                  << ", PIE/ASLR=" << (parser->isPieEnabled() ? "ON" : "OFF")
                  << ", Canary=" << (parser->isCanaryEnabled() ? "ON" : "OFF")
                  << ", RELRO=" << parser->getRelro() << std::endl;
    }

    const std::vector<uint8_t>& binaryCode = parser->getTextSection();
    uint64_t baseAddress = parser->getTextSectionBaseAddress();
    if (binaryCode.empty()) {
        std::cerr << "[!] Error: Could not find the .text section. Is this a valid executable?" << std::endl;
        return 1;
    }

    std::cout << "[" << ANSI_COLOR_ORANGE << "*" << ANSI_COLOR_RESET << "] Searching for ROP gadgets..." << std::endl;
    GadgetFinder gadget_finder(binaryCode, baseAddress, arch_to_use, options.filename, 10);
    gadget_finder.findGadgets();
    std::vector<Gadget>& gadgets = gadget_finder.getGadgets();
    std::cout << "[" << ANSI_COLOR_ORANGE << "*" << ANSI_COLOR_RESET << "] Found " << gadgets.size() << " gadgets." << std::endl;

    // Address resolution: compute file_offset, rva, preferred_va, and runtime_va
    bool isAslr = (binaryType == "PE") ? parser->isPieEnabled() : parser->isPieEnabled();
    for (auto& g : gadgets) {
        g.preferred_va = g.address;
        uint64_t fo = 0, rva = 0;
        if (parser->vaToOffsets(g.preferred_va, fo, rva)) {
            g.file_offset = fo;
            g.rva = rva;
        } else {
            g.file_offset = 0;
            g.rva = (g.preferred_va >= parser->getImageBase()) ? (g.preferred_va - parser->getImageBase()) : g.preferred_va;
        }
        if (isAslr) {
            g.runtime_va = "ASLR Dependent";
        } else {
            std::stringstream ss;
            ss << "0x" << std::hex << std::setw(16) << std::setfill('0') << g.preferred_va;
            g.runtime_va = ss.str();
        }
    }

    // --- Find /bin/sh address for auto-chain (ELF targets only) ---
    uint64_t binsh_addr = 0;
    ROPChain ropChain; // remains empty if building fails

    if (options.autoChain && binaryType == "ELF") {
        try {
            MemoryRegion memRegion;
            memRegion.start = 0;
            memRegion.end = filesize(options.filename);
            memRegion.path = options.filename;
            std::vector<MemoryRegion> memRegions = { memRegion };

            ChainBuilder tempBuilder({}, "", binaryType);
            binsh_addr = tempBuilder.findBinShAddress(memRegions);
            if (binsh_addr != 0) {
                std::cout << "[" << ANSI_COLOR_ORANGE << "*" << ANSI_COLOR_RESET << "] Found /bin/sh." << std::endl;
            } else {
                std::cout << "[" << ANSI_COLOR_ORANGE << "*" << ANSI_COLOR_RESET << "] /bin/sh Not Found." << std::endl;
            }
        } catch (const std::runtime_error&) {
            std::cout << "[" << ANSI_COLOR_ORANGE << "*" << ANSI_COLOR_RESET << "] /bin/sh Not Found." << std::endl;
        }
        if (binsh_addr == 0) {
            std::cerr << "[!] Options --auto-chain & --upload-report may fail." << std::endl;
        }
    }

    // --- Optional UI listing / suggestions ---
    if (options.listGadgets) {
        std::cout << ANSI_COLOR_CYAN << "\n--- Found Gadgets ---" << ANSI_COLOR_RESET << std::endl;
        std::cout << std::hex << std::setfill('0');
        for (const auto& g : gadgets) {
            std::cout << ANSI_COLOR_GREEN << "  " << g.toString() << ANSI_COLOR_RESET << std::endl;
        }
        std::cout << std::dec << std::setfill(' ');
    }

    if (options.suggestGadgets) {
        std::cout << ANSI_COLOR_CYAN << "\n--- Suggested Gadgets ---" << ANSI_COLOR_RESET << std::endl;
        auto categorized = gadget_finder.categorizeGadgets();
        for (const auto& pair : categorized) {
            const std::string& category = pair.first;
            const std::vector<Gadget>& gadgetsList = pair.second;

            std::cout << "\n> " << ANSI_COLOR_ORANGE << category << ANSI_COLOR_RESET << std::endl;
            std::cout << std::hex << std::setfill('0');
            for (const auto& gadget : gadgetsList) {
                std::cout << ANSI_COLOR_GREEN << "  " << gadget.toString() << ANSI_COLOR_RESET << std::endl;
            }
            std::cout << std::dec << std::setfill(' ');
        }
    }

    // --- Build the ROP chain (if requested) ---
    if (options.autoChain) {
        if (binaryType == "PE") {
            std::cout << ANSI_COLOR_CYAN << "\n--- Building ROP Chain ---" << ANSI_COLOR_RESET << std::endl;
            std::cout << "[" << ANSI_COLOR_ORANGE << "!" << ANSI_COLOR_RESET 
                      << "] Automated ROP chain synthesis is unsupported for Windows PE binaries." << std::endl;
            std::cout << "    POSIX execve syscall is not applicable to Windows." << std::endl;
            std::cout << "    Windows exploitation requires Win64 Fastcall staging (RCX, RDX, R8, R9, 32-byte shadow space)" << std::endl;
            std::cout << "    and dynamic resolution of Win32 APIs (e.g. VirtualProtect / WinExec)." << std::endl;
            std::cout << "    Discovered gadgets are exported in the report for manual chain development." << std::endl;
        } else {
            if (binaryType == "Mach-O") {
                std::cout << "[" << ANSI_COLOR_ORANGE << "*" << ANSI_COLOR_RESET 
                          << "] Target is a macOS Mach-O binary (skipping Linux /bin/sh scan)." << std::endl;
            } else if (binaryType == "ELF") {
                std::cout << ANSI_COLOR_CYAN << "\n--- /bin/sh memory address ---" << ANSI_COLOR_RESET << std::endl;
                if (binsh_addr != 0) {
                    std::cout << "  " << ANSI_COLOR_GREEN << "0x" << std::hex << std::setw(16) << std::setfill('0')
                              << binsh_addr << ANSI_COLOR_RESET << ": \"/bin/sh\"" << std::dec << std::endl;
                } else {
                    std::cerr << "[!] Warning: /bin/sh address not found, auto-chain may fail." << std::endl;
                }
            }

            std::cout << ANSI_COLOR_CYAN << "\n--- Building ROP Chain ---" << ANSI_COLOR_RESET << std::endl;
            ChainBuilder builder(gadgets, arch_to_use, binaryType);

            try {
                if (options.binshAddress != 0) {
                    std::cout << "[*] Using manually provided /bin/sh address: 0x" << std::hex << options.binshAddress << std::dec << std::endl;
                    ropChain = builder.buildExecveChain(options.binshAddress);
                } else if (binsh_addr != 0) {
                    ropChain = builder.buildExecveChain(binsh_addr);
                } else {
                    ropChain = builder.buildExecveChain(0);
                }

                std::cout << "[+] ROP chain created successfully:\n" << ropChain.to_string() << std::endl;
            } catch (const std::runtime_error &e) {
                std::cerr << "[x] " << e.what() << std::endl;
                std::string targetBinary = options.filename.empty() ? "filename" : options.filename;
                std::string targetBase = (options.filename.empty() || options.filename == "filename") ? "filename" : fs::path(options.filename).stem().string();
                std::string targetSource = targetBase + ".c";

                if (binaryType == "Mach-O") {
                    std::cerr << "\n[i] macOS Mach-O Staging Strategy Note:\n";
                    std::cerr << "    macOS x86_64 ROP chains require the BSD syscall class mask (RAX = 0x200003B),\n";
                    std::cerr << "    and macOS ARM64 (Apple Silicon) enforces Pointer Authentication (PAC) and X16 register dispatch.\n";
                } else {
                    if (binsh_addr == 0 && options.binshAddress == 0) {
                        std::cerr << "[!] Reason: Could not find '/bin/sh' in binary memory sections.\n";
                        std::cerr << "[i] How to fix: Provide the memory address manually:\n";
                        std::cerr << "    ropweaver " << targetBinary << " -a --binsh-addr 0x<address>\n";
                    } else {
                        std::cerr << "\n[!] Why auto-chain failed:\n";
                        std::cerr << "    Your CLI syntax is correct! However, automated ROP chain synthesis requires\n";
                        std::cerr << "    specific machine instructions ('gadgets') to exist inside the compiled binary.\n";
                        std::cerr << "    ROPWeaver cannot synthesize instructions that were not compiled into the binary.\n\n";
                        std::cerr << "[i] How to perform successful auto-chaining:\n";
                        std::cerr << "    1. Compile source code containing the required gadget sequence:\n";
                        std::cerr << "       gcc -fno-stack-protector -O0 " << targetSource << " -o " << targetBinary << "\n";
                        std::cerr << "    2. Run auto-chain (no --binsh-addr needed when /bin/sh is present):\n";
                        std::cerr << "       ropweaver " << targetBinary << " -a\n\n";
                        std::cerr << "    (Use '--list-gadgets' or '--suggest-gadgets' to inspect what gadgets exist in this binary)\n";
                    }
                }

                if (options.uploadReport) {
                    std::cerr << "[!] Continuing without ROP chain because --upload-report was requested. Report may be incomplete.\n";
                } else if (!options.generatePayload) {
                    return 1;
                }
            }
        }
    }

    // Ensure reports dir exists in current working directory
    fs::path reportsDir = fs::current_path() / "reports";
    std::error_code ec;
    if (!fs::exists(reportsDir)) {
        fs::create_directories(reportsDir, ec);
    }

    // Compute cryptographic hash of binary for deterministic identification & deduplication
    std::string base = basename_noext(options.filename);
    std::string fileHash = Utils::computeFileSHA256(options.filename);
    std::string hashShort = (fileHash.size() >= 12) ? fileHash.substr(0, 12) : base;
    std::string reportId = "ROPW-" + base + "_" + hashShort + "_v1.2.4";

    // Deterministic Firestore document ID (safe characters only)
    std::string reportDocId = base + "_" + ((fileHash.size() >= 16) ? fileHash.substr(0, 16) : base);
    std::replace(reportDocId.begin(), reportDocId.end(), '/', '_');
    std::replace(reportDocId.begin(), reportDocId.end(), '\\', '_');
    std::replace(reportDocId.begin(), reportDocId.end(), '.', '_');
    std::replace(reportDocId.begin(), reportDocId.end(), ' ', '_');

    // --- Payload Generation (writes reports/output.json and payload.bin) ---
    if (options.generatePayload || options.uploadReport) {
        PayloadGenerator payloadGen;
        const size_t paddingSize = 104;
        std::cout << ANSI_COLOR_CYAN << "\n--- Generating Exploit Payload / Report ---" << ANSI_COLOR_RESET << std::endl;

        payloadGen.generate(ropChain, paddingSize, options.filename, gadgets, arch_to_use, binaryType, protections, reportId, fileHash, parser.get());

        if (options.generatePayload && ropChain.isSuccessful() && binaryType != "PE") {
            std::cout << ANSI_COLOR_GREEN << "\n[+] Exploit payload generated successfully!" << ANSI_COLOR_RESET << std::endl;
            std::cout << "[i] Delivery one-liner (PowerShell):\n";
            std::cout << "    cmd /c \"" << options.filename << " < payload.bin\"\n";
            std::cout << "[i] Delivery one-liner (Python):\n";
            std::cout << "    python -c \"import sys; sys.stdout.buffer.write(open('payload.bin','rb').read())\" | .\\" << options.filename << "\n" << std::endl;
        }
    }

    // --- Firebase Report Upload ---
    if (options.uploadReport) {
        if (!fs::exists(reportsDir)) {
            if (!fs::create_directories(reportsDir, ec)) {
                std::cerr << "[!] Could not create reports directory: " << reportsDir.string()
                          << " (" << ec.message() << ") — skipping upload.\n";
                // skip upload
                goto end_main;
            }
        }

        ropweaver::FirebaseUploader uploader;
        if (!uploader.isConfigured()) {
            std::cerr << "[!] Firebase config could not be loaded — skipping upload.\n";
            goto end_main;
        }

        // Deduplication Check: Check if report already exists in Firestore!
        if (uploader.reportExists(reportDocId) && !options.forceUpload) {
            std::cout << "\n[" << ANSI_COLOR_CYAN << "i" << ANSI_COLOR_RESET << "] Binary '" << base 
                      << "' (SHA-256: " << hashShort << "...) already exists in Firebase Firestore." << std::endl;
            std::cout << "[" << ANSI_COLOR_CYAN << "i" << ANSI_COLOR_RESET << "] Existing Document ID: " 
                      << ANSI_COLOR_GREEN << reportDocId << ANSI_COLOR_RESET << std::endl;
            std::cout << "[" << ANSI_COLOR_GREEN << "✓" << ANSI_COLOR_RESET << "] Skipping upload to prevent database clutter." << std::endl;
            std::cout << "[i] Tip: Use " << ANSI_COLOR_ORANGE << "--force" << ANSI_COLOR_RESET 
                      << " or " << ANSI_COLOR_ORANGE << "-f" << ANSI_COLOR_RESET 
                      << " to overwrite the existing Firestore report.\n" << std::endl;
            goto end_main;
        }

        // Default report path (where PayloadGenerator wrote)
        fs::path reportPath = fs::current_path() / "reports" / "output.json";
        if (!fs::exists(reportPath)) {
            std::cerr << "[!] Report file not found: " << reportPath.string() << " — nothing to upload.\n";
            goto end_main;
        }

        // Save a clean deduplicated copy named <binary>_<hashShort>.json in reports/
        fs::path copyPath = reportsDir / (base + "_" + hashShort + ".json");
        std::error_code copy_ec;
        fs::copy_file(reportPath, copyPath, fs::copy_options::overwrite_existing, copy_ec);
        if (copy_ec) {
            copyPath = reportPath;
        }

        std::cout << "[" << ANSI_COLOR_ORANGE << "*" << ANSI_COLOR_RESET << "] Uploading report to Firebase (Doc ID: "
                  << reportDocId << ")..." << std::endl;

        if (uploader.uploadReport(copyPath.string(), reportDocId)) {
            std::cout << "[+] Report uploaded to Firebase." << std::endl;
        } else {
            std::cerr << "[x] Firebase upload failed." << std::endl;
        }

        // Upload discovered gadgets to Firestore 'gadgets' collection
        uploader.uploadGadgets(base, arch_to_use, fileHash, reportId, gadgets);
    }

end_main:
    return 0;
}