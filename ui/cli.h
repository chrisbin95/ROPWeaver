// cli.h
#ifndef CLI_H
#define CLI_H

#include <string>

struct CLIOptions {
    std::string filename;
    std::string architecture = "x86";
    bool listGadgets = false;
    bool autoChain = false;
    bool uploadReport = false;
    bool valid = false;
};

class CLI {
public:
    CLIOptions parseArguments(int argc, char** argv);
    void printUsage() const;
};

#endif // CLI_H