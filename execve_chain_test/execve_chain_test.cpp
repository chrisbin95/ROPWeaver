#include <iostream>
#include <vector>
#include <iomanip>
#include <string>
#include <memory>
#include <stdexcept>
#include <fstream>
#include <cstdint>

// Core modules
#include "../core/parsers/file_parser.h"
#include "../core/arch_detector.h"
#include "../core/gadget_finder.h"
#include "../core/chain_builder.h"
#include "../core/utils.h"
#include "../core/gadget.h"
#include "../core/rop_chain.h"

using namespace ropweaver;

// Helper to get file size
size_t filesize(const std::string &filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) throw std::runtime_error("Cannot open file: " + filename);
    return file.tellg();
}

int main(int argc, char* argv[]) {
    std::cout << "=== Execve Chain Tester ===\n" << std::endl;

    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <binary>" << std::endl;
        return 1;
    }

    std::string filename = argv[1];
    std::cout << "[*] Analyzing binary: " << filename << std::endl;

    // Detect architecture and create parser
    ArchDetector arch_detector;
    std::unique_ptr<FileParser> parser = arch_detector.createFileParser(filename);

    if (!parser) {
        std::cerr << "⚠️ [Error] Failed to create parser for binary: " << filename << std::endl;
        return 1;
    }

    if (!parser->parse(filename)) {
        std::cerr << "⚠️ [Error] Failed to parse binary: " << filename << std::endl;
        return 1;
    }

    std::string arch_to_use = parser->getArchitecture();
    std::cout << "[*] Detected architecture: " << arch_to_use << std::endl;

    if (!arch_detector.isSupported(arch_to_use)) {
        std::cerr << "⚠️ [Error] Unsupported architecture: " << arch_to_use << std::endl;
        return 1;
    }

    auto binaryCode = parser->getTextSection();
    uint64_t baseAddress = parser->getTextSectionBaseAddress();

    if (binaryCode.empty()) {
        std::cerr << "[!] .text section is empty. Cannot find gadgets." << std::endl;
        return 1;
    }

    std::cout << "[*] Searching for ROP gadgets..." << std::endl;
    GadgetFinder finder(binaryCode, baseAddress, arch_to_use, filename, 20);
    finder.findGadgets();
    auto gadgets = finder.getGadgets();

    std::cout << "[*] Found " << gadgets.size() << " gadgets." << std::endl;

    if (gadgets.empty()) {
        std::cerr << "[!] No gadgets found. Cannot build execve chain." << std::endl;
        return 1;
    }

    // Display found gadgets
    std::cout << "\n--- Found Gadgets ---" << std::endl;
    std::cout << std::hex << std::setfill('0');
    for (const auto& g : gadgets) {
        std::cout << "  0x" << std::setw(16) << g.address << ": " << g.toString() << std::endl;
    }

    std::vector<MemoryRegion> memRegions = {
        { 0, filesize(filename), filename }
    };
    // -----------------------------------------------------------

    std::cout << "\n[*] Building execve('/bin/sh') ROP chain..." << std::endl;
    ChainBuilder builder(gadgets, arch_to_use);
    ROPChain ropChain;

    try {
        // Now using fully qualified classes inside the function body
        ropChain = builder.buildExecveChain(memRegions); 
        std::cout << "[+] ROP chain created successfully:\n"
                  << ropChain.to_string() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "⚠️ [Error] Failed to build ROP chain: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
