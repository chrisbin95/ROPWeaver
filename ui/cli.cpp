#include "cli.h"
#include "version.h"
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <limits>
#include <cerrno>
#include <cstdlib>
#include <cctype>
#include <cstddef>

// ANSI escape codes for coloring
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_ORANGE  "\033[33m"
#define ANSI_COLOR_RESET   "\x1b[0m"

CLIOptions CLI::parseArguments(int argc, char** argv) {
    CLIOptions opts;
    opts.valid = false;

    if (argc < 2) {
        printUsage();
        return opts;
    }

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            printUsage();
            opts.helpRequested = true;
            opts.valid = true;
            return opts;
        } 
        else if (arg == "--version" || arg == "-v") {
            std::cout << ANSI_COLOR_GREEN << "ROPWeaver " << ROPWEAVER_VERSION << ANSI_COLOR_RESET << " (Academic Research Edition | Build: " << ROPWEAVER_BUILD_ID << ")\n"
                      << "Disassembly Engine: Capstone v5.0+ | Transport: libcurl\n"
                      << "Supported Targets: x86_64, i386, ARM, AArch64, RISC-V | Formats: PE, ELF, Mach-O, RAW\n"
                      << "Oxford Brookes University Master of Science Research Tool\n";
            opts.helpRequested = true;
            opts.valid = true;
            return opts;
        } 
        else if (arg == "--arch") {
            if (i + 1 < argc && argv[i+1][0] != '-') {
                opts.architecture = argv[++i];
            }
        } 
        else if (arg == "--list-gadgets") {
            opts.listGadgets = true;
        } 
        else if (arg == "--suggest-gadgets") {
            opts.suggestGadgets = true;
        } 
        else if (arg == "--auto-chain" || arg == "-a" || arg == "autochain") {
            opts.autoChain = true;
        } 
        else if (arg == "--upload-report" || arg == "--upload" || arg == "upload") {
            opts.uploadReport = true;
            opts.autoChain = true;
        } 
        else if (arg == "--binsh-addr") {
            if (i + 1 < argc && argv[i+1][0] != '-') {
                std::string addrStr = argv[++i];
                std::stringstream ss;
                if (addrStr.rfind("0x", 0) == 0 || addrStr.rfind("0X", 0) == 0) {
                    ss << std::hex << addrStr;
                } else {
                    ss << addrStr; // decimal fallback
                }
                ss >> opts.binshAddress;
                opts.useManualBinsh = true;
            } else {
                std::cerr << "[!] Error: Missing value for --binsh-addr option.\n";
                printUsage();
                return opts;
            }
        }
        else if (arg == "--offset" || arg == "-O") {
            if (i + 1 >= argc) {
                std::cerr << "[!] Error: Missing value for --offset option.\n";
                printUsage();
                return opts;
            }
            std::string offsetStr = argv[++i];
            if (offsetStr.empty()) {
                std::cerr << "[!] Error: Missing value for --offset option.\n";
                printUsage();
                return opts;
            }

            // Check if it's another flag or negative number
            if (offsetStr[0] == '-') {
                if (offsetStr.size() > 1 && std::isdigit(static_cast<unsigned char>(offsetStr[1]))) {
                    std::cerr << "[!] Error: Invalid --offset value \"" << offsetStr << "\": negative offsets are not permitted.\n";
                } else {
                    std::cerr << "[!] Error: Missing value for --offset option (received flag \"" << offsetStr << "\").\n";
                }
                printUsage();
                return opts;
            }

            // Reject explicit plus signs
            if (offsetStr[0] == '+') {
                std::cerr << "[!] Error: Invalid --offset value \"" << offsetStr << "\": explicit plus signs are not permitted.\n";
                printUsage();
                return opts;
            }

            // Must start with an ASCII digit
            if (!std::isdigit(static_cast<unsigned char>(offsetStr[0]))) {
                std::cerr << "[!] Error: Invalid --offset value \"" << offsetStr << "\": malformed number.\n";
                printUsage();
                return opts;
            }

            // Determine base and enforce strict formatting:
            // - Values starting with 0x or 0X are parsed as hexadecimal (base 16)
            // - All other values are parsed as decimal (base 10); octal interpretation is strictly prohibited
            int base = 10;
            if (offsetStr.size() >= 2 && offsetStr[0] == '0' && (offsetStr[1] == 'x' || offsetStr[1] == 'X')) {
                base = 16;
                if (offsetStr.size() == 2) {
                    std::cerr << "[!] Error: Invalid --offset value \"" << offsetStr << "\": missing hexadecimal digits.\n";
                    printUsage();
                    return opts;
                }
                for (size_t idx = 2; idx < offsetStr.size(); ++idx) {
                    if (!std::isxdigit(static_cast<unsigned char>(offsetStr[idx]))) {
                        std::cerr << "[!] Error: Invalid --offset value \"" << offsetStr << "\": malformed hexadecimal character '" << offsetStr[idx] << "'.\n";
                        printUsage();
                        return opts;
                    }
                }
            } else {
                // Reject unsupported prefixes (e.g. binary 0b/0B or octal 0o/0O)
                if (offsetStr.size() >= 2 && offsetStr[0] == '0' && (offsetStr[1] == 'b' || offsetStr[1] == 'B' || offsetStr[1] == 'o' || offsetStr[1] == 'O')) {
                    std::cerr << "[!] Error: Invalid --offset value \"" << offsetStr << "\": unsupported prefix.\n";
                    printUsage();
                    return opts;
                }
                // Strictly validate all characters as decimal digits (0-9)
                for (size_t idx = 0; idx < offsetStr.size(); ++idx) {
                    if (!std::isdigit(static_cast<unsigned char>(offsetStr[idx]))) {
                        std::cerr << "[!] Error: Invalid --offset value \"" << offsetStr << "\": malformed decimal character '" << offsetStr[idx] << "'.\n";
                        printUsage();
                        return opts;
                    }
                }
            }

            char* endptr = nullptr;
            errno = 0;
            unsigned long long val = std::strtoull(offsetStr.c_str(), &endptr, base);

            // Check for malformed / trailing non-numeric characters
            if (endptr == offsetStr.c_str() || *endptr != '\0') {
                std::cerr << "[!] Error: Invalid --offset value \"" << offsetStr << "\": malformed number (trailing non-numeric characters).\n";
                printUsage();
                return opts;
            }

            // Check for numerical overflow (ERANGE)
            if (errno == ERANGE) {
                std::cerr << "[!] Error: Invalid --offset value \"" << offsetStr << "\": numerical overflow (exceeds range).\n";
                printUsage();
                return opts;
            }

            // Check against platform size_t capacity
            if (val > std::numeric_limits<size_t>::max()) {
                std::cerr << "[!] Error: Invalid --offset value \"" << offsetStr << "\": value exceeds platform size_t capacity.\n";
                printUsage();
                return opts;
            }

            // Check against maximum permitted 16 MiB limit (16 * 1024 * 1024 = 16777216 bytes)
            constexpr unsigned long long MAX_EXPLOIT_OFFSET = 16ULL * 1024ULL * 1024ULL; // 16 MiB
            if (val > MAX_EXPLOIT_OFFSET) {
                std::cerr << "[!] Error: Invalid --offset value " << val << ": exceeds maximum permitted limit (16 MiB).\n";
                printUsage();
                return opts;
            }

            opts.exploitOffset = static_cast<size_t>(val);
            opts.useCustomOffset = true;
        }
        else if (arg == "--payload-gen" || arg == "--payload" || arg == "-p" || arg == "payload") {
            opts.generatePayload = true;
            opts.autoChain = true;
        }
        else if (arg == "--force" || arg == "-f" || arg == "force") {
            opts.forceUpload = true;
            opts.uploadReport = true;
            opts.autoChain = true;
        }
        else if (arg[0] == '-') {
            std::cerr << "[!] Error: Unknown option: \"" << arg << "\"\n";
            printUsage();
            return opts;
        } 
        else {
            if (opts.filename.empty()) {
                opts.filename = arg;
            } else {
                std::cerr << "[!] Error: Multiple binary files specified: " << arg << "\n";
                printUsage();
                return opts;
            }
        }
    }

    if (opts.filename.empty() && !opts.helpRequested) {
        std::cerr << "[!] Error: Please provide a binary file to analyze.\n";
        printUsage();
        return opts;
    }

    opts.valid = true;
    return opts;
}

void CLI::printUsage() const {
    std::cout << ANSI_COLOR_GREEN << "> ROPWeaver Help:\n" << ANSI_COLOR_RESET
              << "[i] usage: ./ropweaver <binary> [options]\n\n"
              << ANSI_COLOR_ORANGE << "Options:\n" << ANSI_COLOR_RESET
              << "  --help, -h            Show help message\n"
              << "  --version, -v         Display tool version\n"
              << "  --arch [arch]         Specify architecture (optional, auto-detected by default)\n"
              << "  --list-gadgets        List all ROP gadgets found in the binary\n"
              << "  --suggest-gadgets     List suggested gadgets grouped by category\n"
              << "  --auto-chain, -a      Attempt automatic ROP chain generation\n"
              << "  --binsh-addr [addr]   Manually specify /bin/sh address (hex or decimal)\n"
              << "  --offset, -O [bytes]  Payload padding offset to return address (default: 104, max: 16MiB)\n"
              << "  --upload-report       Upload json to Firebase\n"
              << "  --force, -f           Force upload to Firebase (overwrite if report exists)\n"
              << "  --payload-gen, -p     Generate a raw exploit payload from a successful ROP chain\n"
              << "\n" << std::endl;
}