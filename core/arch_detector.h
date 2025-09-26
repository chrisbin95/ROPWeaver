#pragma once
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include "parsers/file_parser.h"

namespace ropweaver {

class ArchDetector {
public:
    bool isSupported(const std::string& arch) const;

    std::string detectArchitecture32(std::ifstream& file) const;
    std::string detectArchitecture64(std::ifstream& file) const;

    std::string detectPEArchitecture(const std::vector<uint8_t>& data) const;
    std::string detectMachOArchitecture(const std::vector<uint8_t>& data) const;

    std::unique_ptr<FileParser> createFileParser(const std::string& filepath) const;
};

} // namespace ropweaver