// arch_detector.h
#pragma once
#include <string>

class ArchDetector {
public:
    std::string detectArchitecture(const ELFParser& parser);
};