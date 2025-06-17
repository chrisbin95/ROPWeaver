// utils.cpp
#include "utils.h"
#include <fstream>

std::vector<uint8_t> Utils::readBinaryFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

void Utils::writeToFile(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    file << content;
}
