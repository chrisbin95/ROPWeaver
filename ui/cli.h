// cli.h
#ifndef CLI_H
#define CLI_H

#include <string>

struct CLIOptions {
    std::string filename;                  // Binary input file
    std::string architecture = "x86";      // Default arch if not specified
    bool listGadgets = false;              // --list-gadgets
    bool autoChain = false;                // --auto-chain
    bool uploadReport = false;             // --upload-report
    bool valid = false;                    // Set to true only when args are good
};

class CLI {
public:
    // Parses command-line arguments and returns options
    CLIOptions parseArguments(int argc, char** argv);

    // Displays usage/help message
    void printUsage() const;
};

#endif // CLI_H