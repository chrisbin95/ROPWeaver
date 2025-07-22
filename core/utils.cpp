// utils.cpp
#include "utils.h"
#include <fstream>
#include <iostream>
#include <iterator>
#include <cstdio>

std::vector<uint8_t> Utils::readBinaryFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::cerr << "[Error] Cannot open binary file: " << path << std::endl;
        return {};
    }

    return std::vector<uint8_t>(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    );
}

void Utils::writeToFile(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    if (!file) {
        std::cerr << "[Error] Cannot write to file: " << path << std::endl;
        return;
    }

    file << content;
    file.close();
}
