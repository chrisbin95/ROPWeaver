// cli.cpp
#include "cli.h"
#include <iostream>
#include <cstring>

CLIOptions CLI::parseArguments(int argc, char** argv) {
    CLIOptions opts;

    if (argc < 2) {
        showHelp();
        return opts;
    }

    opts.filename = argv[1];
    opts.valid = true;

    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0) {
            showHelp();
        } else if (strcmp(argv[i], "--arch") == 0 && i + 1 < argc) {
            opts.architecture = argv[++i];
        } else if (strcmp(argv[i], "--list-gadgets") == 0) {
            opts.listGadgets = true;
        } else if (strcmp(argv[i], "--auto-chain") == 0) {
            opts.autoChain = true;
        } else if (strcmp(argv[i], "--upload-report") == 0) {
            opts.uploadReport = true;
        }
    }

    return opts;
}

void CLI::printUsage() const {
    std::cout << "ROPWeaver Help:\n"
              << "Usage: ./ropweaver <binary> [options]\n"
              << "--help             Show this help message\n"
              << "--arch [arch]      Specify architecture (e.g., x86, armv7)\n"
              << "--list-gadgets     List ROP gadgets in the binary\n"
              << "--auto-chain       Attempt automatic ROP chain generation\n"
              << "--upload-report    Upload findings to Firebase\n";
}
