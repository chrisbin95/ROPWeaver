#include "cli.h"
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

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
        else if (arg == "--auto-chain" || arg == "-a") {
            opts.autoChain = true;
        } 
        else if (arg == "--upload-report") {
            opts.uploadReport = true;
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
        else if (arg == "--payload-gen" || arg == "-p") { // Correctly add the new option here
            opts.generatePayload = true;
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
              << "  --arch [arch]         Specify architecture (optional, auto-detected by default)\n"
              << "  --list-gadgets        List all ROP gadgets found in the binary\n"
              << "  --suggest-gadgets     List suggested gadgets grouped by category\n"
              << "  --auto-chain, -a      Attempt automatic ROP chain generation\n"
              << "  --binsh-addr [addr]   Manually specify /bin/sh address (hex or decimal)\n"
              << "  --upload-report       Upload json to Firebase\n"
              << "  --payload-gen, -p     Generate a raw exploit payload from a successful ROP chain\n"
              << "\n" << std::endl;
}