// utils.h
#pragma once
#include <string>
#include <vector>
#include <cstdint>

class Utils {
public:
    static std::vector<uint8_t> readBinaryFile(const std::string& path);
    static void writeToFile(const std::string& path, const std::string& content);
};
