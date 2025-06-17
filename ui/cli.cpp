// cli.cpp
#include "cli.h"
#include <iostream>
#include <cstring>

void CLI::parseArguments(int argc, char** argv) {
    if (argc < 2) {
        showHelp();
        return;
    }
    // Basic demo: recognize a help flag
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0) {
            showHelp();
        }
        // Add argument parsing for: --arch, --list-gadgets, --auto-chain, etc.
    }
}

void CLI::showHelp() const {
    std::cout << "ROPWeaver Help:\n"
              << "--help             Show this help message\n"
              << "--arch [arch]      Specify architecture (e.g., x86, armv7)\n"
              << "--list-gadgets     List ROP gadgets in the binary\n"
              << "--auto-chain       Attempt automatic ROP chain generation\n"
              << "--upload-report    Upload findings to Firebase\n";
}
