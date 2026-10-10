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

int main(int argc, char* argv[]) {
    std::cout << "\n==«✪»==" << ANSI_COLOR_ORANGE << "ROPWeaver: ROP Exploit Generator" << ANSI_COLOR_RESET << "==«✪»== \n" << std::endl;

    CLI cli;
    CLIOptions options = cli.parseArguments(argc, argv);
    if (options.helpRequested) return 0;
    if (!options.valid) return 1;

    // If generating payload or uploading a report, we need auto-chain (report depends on chain)
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

    const std::vector<uint8_t>& binaryCode = parser->getTextSection();
    uint64_t baseAddress = parser->getTextSectionBaseAddress();
    if (binaryCode.empty()) {
        std::cerr << "[!] Error: Could not find the .text section. Is this a valid executable?" << std::endl;
        return 1;
    }

    std::cout << "[" << ANSI_COLOR_ORANGE << "*" << ANSI_COLOR_RESET << "] Searching for ROP gadgets..." << std::endl;
    GadgetFinder gadget_finder(binaryCode, baseAddress, arch_to_use, options.filename, 10);
    gadget_finder.findGadgets();
    std::vector<Gadget> gadgets = gadget_finder.getGadgets();
    std::cout << "[" << ANSI_COLOR_ORANGE << "*" << ANSI_COLOR_RESET << "] Found " << gadgets.size() << " gadgets." << std::endl;

    // --- Find /bin/sh address for auto-chain ---
    uint64_t binsh_addr = 0;
    ROPChain ropChain; // remains empty if building fails

    if (options.autoChain) {
        try {
            MemoryRegion memRegion;
            memRegion.start = 0;
            memRegion.end = filesize(options.filename);
            memRegion.path = options.filename;
            std::vector<MemoryRegion> memRegions = { memRegion };

            ChainBuilder tempBuilder({}, "");
            binsh_addr = tempBuilder.findBinShAddress(memRegions);
            std::cout << "[" << ANSI_COLOR_ORANGE << "*" << ANSI_COLOR_RESET << "] Found /bin/sh." << std::endl;
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
        std::cout << ANSI_COLOR_CYAN << "\n--- /bin/sh memory address ---" << ANSI_COLOR_RESET << std::endl;
        if (binsh_addr != 0) {
            std::cout << "  " << ANSI_COLOR_GREEN << "0x" << std::hex << std::setw(16) << std::setfill('0')
                      << binsh_addr << ANSI_COLOR_RESET << ": \"/bin/sh\"" << std::dec << std::endl;
        } else {
            std::cerr << "[!] Warning: /bin/sh address not found, auto-chain may fail." << std::endl;
        }

        std::cout << ANSI_COLOR_CYAN << "\n--- Building ROP Chain ---" << ANSI_COLOR_RESET << std::endl;
        ChainBuilder builder(gadgets, arch_to_use);

        try {
            if (options.binshAddress != 0) {
                std::cout << "[*] Using manually provided /bin/sh address: 0x" << std::hex << options.binshAddress << std::dec << std::endl;
                ropChain = builder.buildExecveChain(options.binshAddress);
            } else if (binsh_addr != 0) {
                ropChain = builder.buildExecveChain(binsh_addr);
            } else {
                throw std::runtime_error("No /bin/sh address available for auto-chain");
            }

            std::cout << "[+] ROP chain created successfully:\n" << ropChain.to_string() << std::endl;
        } catch (const std::runtime_error &e) {
            std::cerr << "[x] error: " << e.what() << std::endl;
            std::cerr << "[!] Hint: Make sure your binary contains '/bin/sh' string or provide its address manually." << std::endl;
            std::cerr << "[i] Usage: ./ropweaver file_name --auto-chain --binsh-addr 0x0000000000000000" << std::endl;

            // If the user explicitly asked to generate a payload we must fail.
            if (options.generatePayload) {
                return 1;
            }

            // Otherwise (e.g. upload-only), continue and let payload/report generator produce a partial report.
            std::cerr << "[!] Continuing without ROP chain because --upload-report was requested. Report may be incomplete.\n";
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
    std::string reportId = "ROPW-" + base + "_" + hashShort;

    // Deterministic Firestore document ID (safe characters only)
    std::string reportDocId = base + "_" + ((fileHash.size() >= 16) ? fileHash.substr(0, 16) : base);
    std::replace(reportDocId.begin(), reportDocId.end(), '/', '_');
    std::replace(reportDocId.begin(), reportDocId.end(), '\\', '_');
    std::replace(reportDocId.begin(), reportDocId.end(), '.', '_');
    std::replace(reportDocId.begin(), reportDocId.end(), ' ', '_');

    // --- Payload Generation (writes reports/output.json) ---
    if (options.generatePayload || options.uploadReport) {
        PayloadGenerator payloadGen;
        const size_t paddingSize = 104;
        std::cout << ANSI_COLOR_CYAN << "\n--- Generating Exploit Payload / Report ---" << ANSI_COLOR_RESET << std::endl;

        std::string binaryType = parser ? parser->getBinaryType() : "ELF";
        payloadGen.generate(ropChain, paddingSize, options.filename, gadgets, arch_to_use, binaryType, nlohmann::json::object(), reportId, fileHash);
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

        // Look for firebase config in two likely locations (project-root or build/ run-from-build)
        std::vector<fs::path> candidateConfigs = {
            fs::current_path() / "config" / "firebase_config.json",      // run from project root
            fs::current_path().parent_path() / "config" / "firebase_config.json", // run from build/
            fs::current_path() / ".." / "config" / "firebase_config.json" // explicit fallback
        };

        fs::path foundConfig;
        for (const auto &c : candidateConfigs) {
            if (fs::exists(c)) {
                foundConfig = c;
                break;
            }
        }

        if (foundConfig.empty()) {
            std::cerr << "[!] Firebase config not found in expected locations — skipping upload.\n";
            goto end_main;
        }

        ropweaver::FirebaseUploader uploader(foundConfig.string());

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