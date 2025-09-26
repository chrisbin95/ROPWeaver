#pragma once
#include <string>
#include <vector>
#include <cstdint>

class FileParser {
public:
    explicit FileParser(const std::string& path) : m_filepath(path) {}
    virtual ~FileParser() = default;

    virtual bool parse(const std::string& filepath) = 0;
    virtual const std::vector<uint8_t>& getTextSection() const = 0;
    virtual uint64_t getTextSectionBaseAddress() const = 0;
    virtual std::string getArchitecture() const = 0;

    // Implementation of pure virtuals
    virtual bool is64Bit() const = 0;
    virtual std::string getBinaryType() const = 0; // ELF, PE, Mach-O
    virtual std::string getFilePath() const = 0;
protected:
    std::string m_filepath;
};
