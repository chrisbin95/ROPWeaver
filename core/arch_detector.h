// arch_detector.h
#pragma once
#include <string>

class ELFParser;

class ArchDetector {
public:
    std::string detectArchitecture(const ELFParser& parser);
};
