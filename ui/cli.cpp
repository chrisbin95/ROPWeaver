// cli.cpp
#include "cli.h"
#include <iostream>
#include <cstring>

CLIOptions CLI::parseArguments(int argc, char** argv) {
    CLIOptions opts;

    if (argc < 2) {
        printUsage();
        return opts;
    }

    // Help shortcut or no input
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        printUsage();
        return opts;
    }

    // First arg as binary file name
    opts.filename = argv[1];
    opts.valid = true;

    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printUsage();
            opts.valid = false;
        } else if (strcmp(argv[i], "--arch") == 0 && i + 1 < argc) {
            opts.architecture = argv[++i];
        } else if (strcmp(argv[i], "--list-gadgets") == 0) {
            opts.listGadgets = true;
        } else if (strcmp(argv[i], "--auto-chain") == 0) {
            opts.autoChain = true;
        } else if (strcmp(argv[i], "--upload-report") == 0) {
            opts.uploadReport = true;
        } else {
            std::cerr << "⚠️ Unknown option: " << argv[i] << "\n";
        }
    }

    return opts;
}

void CLI::printUsage() const {
    std::cout << "ROPWeaver Help:\n"
              << "Usage: ./ropweaver <binary> [options]\n\n"
              << "Options:\n"
              << "  --help, -h           Show this help message\n"
              << "  --arch [arch]        Specify architecture (e.g., x86, armv7, RISC-V etc.)\n"
              << "  --list-gadgets       List ROP gadgets in the binary\n"
              << "  --auto-chain         Attempt automatic ROP chain generation\n"
              << "  --upload-report      Upload findings to Firebase\n";
}