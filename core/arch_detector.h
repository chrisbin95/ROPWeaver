// arch_detector.h
#pragma once
#include <string>

class ArchDetector {
public:
    static std::string detectArch(const std::string& filepath);
};