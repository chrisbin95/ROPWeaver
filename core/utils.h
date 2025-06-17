// utils.h
#pragma once // include once during compilation
#include <string>
#include <vector>

namespace Utils {
    std::vector<uint8_t> readBinaryFile(const std::string& path);
    void writeToFile(const std::string& path, const std::string& content);
}