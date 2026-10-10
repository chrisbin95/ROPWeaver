// cli.h
#pragma once
#include <string>
#include <cstdint>  // <-- Add this

struct CLIOptions {
    bool valid = false;             // Set to true only when args are good
    bool helpRequested = false;     // Indicates if --help was requested
    std::string filename;           // Binary input file
    std::string architecture = "";  // Initialize as an empty string
    bool listGadgets = false;       // --list-gadgets
    bool suggestGadgets = false;    // --suggest-gadgets
    bool autoChain = false;         // --auto-chain
    bool uploadReport = false;      // --upload-report
    uint64_t binshAddress = 0;      // /bin/sh address
    bool useManualBinsh = false;    // true if user provides --binsh-addr
    bool generatePayload = false;   // payload generation
    bool forceUpload = false;       // --force, -f (overwrite / skip deduplication)
};

class CLI {
public:
    // Parses command-line arguments and returns options
    CLIOptions parseArguments(int argc, char** argv);

    // Displays usage/help message
    void printUsage() const;
};
