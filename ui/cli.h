// cli.h
#ifndef CLI_H
#define CLI_H

#include <string>

class CLI {
public:
    void parseArguments(int argc, char** argv);
    void showHelp() const;
};

#endif // CLI_H