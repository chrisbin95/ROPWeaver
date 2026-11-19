// firebase/firebase_uploader.cpp
#include "firebase_uploader.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstdint>
#include <curl/curl.h>
#include "nlohmann/json.hpp"

using json = nlohmann::json;

namespace ropweaver {

// Callback for capturing CURL response data
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    if (!userp) return 0;
    static_cast<std::string*>(userp)->append(static_cast<char*>(contents), size * nmemb);
    return size * nmemb;
}

// Converts standard JSON values into Google Firestore REST API format
json toFirestoreValue(const json& value) {
    if (value.is_string()) {
        return { {"stringValue", value.get<std::string>()} };
    }
    if (value.is_number_unsigned()) {
        return { {"integerValue", std::to_string(value.get<uint64_t>())} };
    }
    if (value.is_number_integer()) {
        return { {"integerValue", std::to_string(value.get<int64_t>())} };
    }
    if (value.is_number_float()) {
        return { {"doubleValue", value.get<double>()} };
    }
    if (value.is_boolean()) {
        return { {"booleanValue", value.get<bool>()} };
    }
    if (value.is_array()) {
        json arr = json::object();
        json values = json::array();
        for (const auto& elem : value) {
            json fVal = ropweaver::toFirestoreValue(elem);
            if (!fVal.empty()) {
                values.push_back(fVal);
            }
        }
        if (!values.empty()) {
            arr["values"] = values;
        }
        return { {"arrayValue", arr} };
    }
    if (value.is_object()) {
        json fields = json::object();
        for (const auto& [k, v] : value.items()) {
            json fVal = ropweaver::toFirestoreValue(v);
            if (!fVal.empty()) {
                fields[k] = fVal;
            }
        }
        return { {"mapValue", { {"fields", fields} }} };
    }
    if (value.is_null()) {
        return { {"nullValue", nullptr} };
    }

    std::cerr << "[!] Unsupported Firestore value type encountered.\n";
    return {};
}

#include <filesystem>
#if defined(_WIN32)
#include <windows.h>
#endif

namespace fs = std::filesystem;

static fs::path getExeDir() {
#if defined(_WIN32)
    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(NULL, path, MAX_PATH) > 0) {
        return fs::path(path).parent_path();
    }
#endif
    return fs::current_path();
}

static const char* EMBEDDED_FIREBASE_CONFIG = R"({
  "apiKey": "AIzaSyDZ3BEfUstg32hqnbctG7X3LQ5onNJ98qs",
  "firebase_url": "https://firestore.googleapis.com/v1/projects/ropweaver/databases/(default)/documents/reports",
  "authDomain": "ropweaver.firebaseapp.com",
  "projectId": "ropweaver",
  "storageBucket": "ropweaver.firebasestorage.app",
  "messagingSenderId": "356547989098",
  "appId": "1:356547989098:web:16a48b40d0bde270df8413",
  "measurementId": "G-CR1P508GPH"
})";

FirebaseUploader::FirebaseUploader(const std::string& configPath) {
    loadConfig(configPath);
}

void FirebaseUploader::loadConfig(const std::string& configPath) {
    json config;
    bool loaded = false;

    // 1. Try explicit path if provided
    if (!configPath.empty()) {
        std::ifstream file(configPath);
        if (file.is_open()) {
            try {
                config = json::parse(file, nullptr, true, true);
                loaded = true;
            } catch (...) {}
        }
    }

    // 2. Try candidate locations on disk
    if (!loaded) {
        fs::path exeDir = getExeDir();
        std::vector<fs::path> candidates = {
            fs::current_path() / "config" / "firebase_config.json",
            fs::current_path() / "firebase_config.json",
            exeDir / "config" / "firebase_config.json",
            exeDir / "firebase_config.json",
            fs::current_path().parent_path() / "config" / "firebase_config.json",
            fs::current_path() / ".." / "config" / "firebase_config.json"
        };
        for (const auto& p : candidates) {
            std::error_code ec;
            if (fs::exists(p, ec)) {
                std::ifstream file(p.string());
                if (file.is_open()) {
                    try {
                        config = json::parse(file, nullptr, true, true);
                        loaded = true;
                        break;
                    } catch (...) {}
                }
            }
        }
    }

    // 3. Fallback to embedded default configuration
    if (!loaded) {
        try {
            config = json::parse(EMBEDDED_FIREBASE_CONFIG);
            loaded = true;
        } catch (...) {}
    }

    if (!loaded) {
        std::cerr << "[x] Failed to load any Firebase configuration.\n";
        firebaseUrl.clear();
        apiKey.clear();
        return;
    }

    try {
        
        // Flexible key resolution for firebaseUrl (or auto-derive from projectId)
        if (config.contains("firebase_url") && config["firebase_url"].is_string()) {
            firebaseUrl = config["firebase_url"].get<std::string>();
        } else if (config.contains("projectId") && config["projectId"].is_string()) {
            std::string proj = config["projectId"].get<std::string>();
            firebaseUrl = "https://firestore.googleapis.com/v1/projects/" + proj + "/databases/(default)/documents/reports";
        } else {
            firebaseUrl.clear();
        }

        // Project ID resolution
        if (config.contains("projectId") && config["projectId"].is_string()) {
            projectId = config["projectId"].get<std::string>();
        } else if (config.contains("project_id") && config["project_id"].is_string()) {
            projectId = config["project_id"].get<std::string>();
        } else {
            size_t p1 = firebaseUrl.find("/projects/");
            if (p1 != std::string::npos) {
                size_t p2 = firebaseUrl.find("/databases/", p1 + 10);
                if (p2 != std::string::npos) {
                    projectId = firebaseUrl.substr(p1 + 10, p2 - (p1 + 10));
                }
            }
        }
        if (projectId.empty()) {
            projectId = "ropweaver";
        }

        // Flexible key resolution for apiKey / api_key
        if (config.contains("apiKey") && config["apiKey"].is_string()) {
            apiKey = config["apiKey"].get<std::string>();
        } else if (config.contains("api_key") && config["api_key"].is_string()) {
            apiKey = config["api_key"].get<std::string>();
        } else {
            apiKey.clear();
        }

        if (firebaseUrl.empty() || apiKey.empty()) {
            std::cerr << "[x] Firebase configuration is incomplete. Check for missing 'firebase_url' (or 'projectId') or 'apiKey'.\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "[x] Error parsing config JSON: " << e.what() << "\n";
        firebaseUrl.clear();
        apiKey.clear();
    }
}

bool FirebaseUploader::reportExists(const std::string& docId) {
    if (!isConfigured() || docId.empty()) return false;

    std::string proj = !projectId.empty() ? projectId : "ropweaver";
    std::string endpoint = "https://firestore.googleapis.com/v1/projects/" + proj +
                           "/databases/(default)/documents/reports/" + docId + "?key=" + apiKey;

    CURL* curl = curl_easy_init();
    if (!curl) return false;

    std::string responseString;
    curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
#if defined(_WIN32)
#ifndef CURLSSLOPT_NATIVE_CA
#define CURLSSLOPT_NATIVE_CA (1L << 4)
#endif
    curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
#endif

    std::string exeCa1 = (getExeDir() / "curl-ca-bundle.crt").string();
    if (std::ifstream("curl-ca-bundle.crt").good()) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, "curl-ca-bundle.crt");
    } else if (std::ifstream(exeCa1).good()) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, exeCa1.c_str());
    } else if (std::ifstream("C:/msys64/mingw64/etc/ssl/certs/ca-bundle.crt").good()) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, "C:/msys64/mingw64/etc/ssl/certs/ca-bundle.crt");
    }

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseString);

    CURLcode res = curl_easy_perform(curl);
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK && httpCode == 200);
}

json FirebaseUploader::buildReportDocumentFields(const json& inputJson) {
    // 1. Calculate total gadgets count from metadata or raw gadgets array
    size_t totalGadgets = 0;
    if (inputJson.contains("total_gadgets") && inputJson["total_gadgets"].is_number()) {
        totalGadgets = inputJson["total_gadgets"].get<size_t>();
    } else if (inputJson.contains("discovered_gadgets_count") && inputJson["discovered_gadgets_count"].is_number()) {
        totalGadgets = inputJson["discovered_gadgets_count"].get<size_t>();
    } else if (inputJson.contains("gadgets") && inputJson["gadgets"].is_array()) {
        totalGadgets = inputJson["gadgets"].size();
    }

    // 2. Compute category counts from complete gadget collection if available
    std::map<std::string, size_t> categoryCounts;
    if (inputJson.contains("category_counts") && inputJson["category_counts"].is_object()) {
        for (const auto& [cat, cnt] : inputJson["category_counts"].items()) {
            if (cnt.is_number()) {
                categoryCounts[cat] = cnt.get<size_t>();
            }
        }
    } else if (inputJson.contains("gadgets") && inputJson["gadgets"].is_array()) {
        for (const auto& gItem : inputJson["gadgets"]) {
            if (!gItem.is_object()) continue;
            if (gItem.contains("category") && gItem["category"].is_string()) {
                std::string c = gItem["category"].get<std::string>();
                categoryCounts[c.empty() ? "others" : c]++;
            } else if (gItem.contains("categories") && gItem["categories"].is_array() && !gItem["categories"].empty()) {
                std::string c = gItem["categories"][0].get<std::string>();
                categoryCounts[c.empty() ? "others" : c]++;
            } else {
                categoryCounts["others"]++;
            }
        }
    }

    // 3. Serialize all metadata fields into Firestore format, excluding the unbounded gadgets array
    json fields = json::object();
    for (const auto& [key, value] : inputJson.items()) {
        if (key == "gadgets") {
            continue; // Exclude complete raw gadgets array to strictly respect Firestore's 1 MiB document limit
        }
        json fVal = toFirestoreValue(value);
        if (!fVal.empty()) {
            fields[key] = fVal;
        }
    }

    // 4. Ensure total gadget counts are explicitly present in the report document
    fields["total_gadgets"] = toFirestoreValue(json(totalGadgets));
    fields["discovered_gadgets_count"] = toFirestoreValue(json(totalGadgets));

    // 5. Populate category counts if available
    if (!categoryCounts.empty()) {
        json catObj = json::object();
        for (const auto& [cat, count] : categoryCounts) {
            catObj[cat] = count;
        }
        fields["category_counts"] = toFirestoreValue(catObj);
    }

    // 6. Explicitly flag that individual gadgets are indexed separately in the 'gadgets' collection
    fields["gadgets_stored_separately"] = toFirestoreValue(json(true));

    // 7. Standardize filename field while preserving backward-compatible aliases
    std::string binName;
    if (inputJson.contains("target_binary") && inputJson["target_binary"].is_object() &&
        inputJson["target_binary"].contains("filename") && inputJson["target_binary"]["filename"].is_string()) {
        binName = inputJson["target_binary"]["filename"].get<std::string>();
    } else if (inputJson.contains("filename") && inputJson["filename"].is_string()) {
        binName = inputJson["filename"].get<std::string>();
    } else if (inputJson.contains("file name") && inputJson["file name"].is_string()) {
        binName = inputJson["file name"].get<std::string>();
    } else if (inputJson.contains("binary_name") && inputJson["binary_name"].is_string()) {
        binName = inputJson["binary_name"].get<std::string>();
    }

    if (!binName.empty()) {
        if (!fields.contains("filename")) {
            fields["filename"] = toFirestoreValue(json(binName));
        }
        if (!fields.contains("file name")) {
            fields["file name"] = toFirestoreValue(json(binName));
        }
        if (!fields.contains("binary_name")) {
            fields["binary_name"] = toFirestoreValue(json(binName));
        }
    }

    return fields;
}

std::string FirebaseUploader::makeGadgetDocumentId(const std::string& binaryName,
                                                    const std::string& binaryHash,
                                                    uint64_t address) {
    std::stringstream shortAddr;
    shortAddr << std::hex << address;

    std::string hashPart = (!binaryHash.empty() && binaryHash != binaryName)
                           ? ((binaryHash.size() >= 12) ? binaryHash.substr(0, 12) : binaryHash)
                           : "";
    std::string docId;
    if (!hashPart.empty()) {
        docId = binaryName + "_" + hashPart + "_0x" + shortAddr.str();
    } else {
        docId = binaryName + "_0x" + shortAddr.str();
    }
    std::replace(docId.begin(), docId.end(), '/', '_');
    std::replace(docId.begin(), docId.end(), '\\', '_');
    std::replace(docId.begin(), docId.end(), '.', '_');
    std::replace(docId.begin(), docId.end(), ' ', '_');
    return docId;
}

bool FirebaseUploader::uploadReport(const std::string& jsonPath, const std::string& docId) {
    if (!isConfigured()) {
        std::cerr << "[x] Firebase config not loaded properly.\n";
        return false;
    }

    std::ifstream file(jsonPath);
    if (!file.is_open()) {
        std::cerr << "[x] Failed to open report JSON file: " << jsonPath << "\n";
        return false;
    }

    json inputJson;
    try {
        // Parse with comments allowed to prevent syntax errors on comments
        inputJson = json::parse(file, nullptr, true, true);
    } catch (const std::exception& e) { 
        std::cerr << "[x] Error parsing input JSON: " << e.what() << "\n"; 
        return false; 
    }

    json firestoreFormat = { {"fields", buildReportDocumentFields(inputJson)} };

    std::string proj = !projectId.empty() ? projectId : "ropweaver";
    std::string endpoint;
    std::string method = "POST";

    if (!docId.empty()) {
        // Upsert to specific document ID: PATCH /reports/<docId>
        endpoint = "https://firestore.googleapis.com/v1/projects/" + proj +
                   "/databases/(default)/documents/reports/" + docId + "?key=" + apiKey;
        method = "PATCH";
    } else {
        std::string separator = (firebaseUrl.find('?') == std::string::npos) ? "?key=" : "&key=";
        endpoint = firebaseUrl + separator + apiKey;
    }

    return uploadToEndpointWithMethod(endpoint, firestoreFormat.dump(), method);
}

bool FirebaseUploader::uploadReportFromData(const std::string& binaryName,
                                             const std::string& architecture,
                                             const std::string& jsonData) {
    if (!isConfigured()) {
        std::cerr << "[x] Firebase config not loaded properly.\n";
        return false;
    }

    json reportJson;
    try {
        reportJson = json::parse(jsonData, nullptr, true, true);
    } catch (...) {
        reportJson = { {"raw", jsonData} };
    }

    reportJson["binary_name"] = binaryName;
    reportJson["architecture"] = architecture;
    
    json firestoreFormat = { {"fields", buildReportDocumentFields(reportJson)} };

    std::string separator = (firebaseUrl.find('?') == std::string::npos) ? "?key=" : "&key=";
    return uploadToEndpoint(firebaseUrl + separator + apiKey, firestoreFormat.dump());
}

bool FirebaseUploader::uploadGadgets(const std::string& binaryName,
                                     const std::string& architecture,
                                     const std::string& binaryHash,
                                     const std::string& reportId,
                                     const std::vector<Gadget>& gadgets) {
    if (!isConfigured() || gadgets.empty()) {
        std::cerr << "[!] Firebase not configured or no gadgets to upload.\n";
        return false;
    }

    std::string proj = !projectId.empty() ? projectId : "ropweaver";
    std::string commitEndpoint = "https://firestore.googleapis.com/v1/projects/" + proj +
                                 "/databases/(default)/documents:commit?key=" + apiKey;

    std::cout << "[*] Uploading " << gadgets.size() << " gadgets to Firestore 'gadgets' collection..." << std::endl;

    const size_t BATCH_SIZE = 400;
    size_t uploadedCount = 0;

    for (size_t i = 0; i < gadgets.size(); i += BATCH_SIZE) {
        size_t endIdx = std::min(i + BATCH_SIZE, gadgets.size());
        json writesArray = json::array();

        for (size_t j = i; j < endIdx; ++j) {
            const auto& g = gadgets[j];

            std::stringstream addrSs;
            addrSs << "0x" << std::hex << std::setw(16) << std::setfill('0') << g.address;
            std::string addrStr = addrSs.str();

            std::stringstream offSs;
            offSs << "0x" << std::hex << (g.address & 0xFFFF);
            std::string offStr = offSs.str();

            std::string instrStr;
            for (size_t k = 0; k < g.instructions.size(); ++k) {
                instrStr += g.instructions[k].mnemonic;
                if (!g.instructions[k].op_str.empty()) instrStr += " " + g.instructions[k].op_str;
                if (k + 1 < g.instructions.size()) instrStr += " ; ";
            }

            // Create a deterministic collision-resistant document ID: <binary>_<hashShort>_0x<address>
            std::string docId = makeGadgetDocumentId(binaryName, binaryHash, g.address);
            std::string docPath = "projects/" + proj + "/databases/(default)/documents/gadgets/" + docId;

            json fields = {
                {"filename", { {"stringValue", binaryName} }},
                {"file name", { {"stringValue", binaryName} }},
                {"architecture", { {"stringValue", architecture} }},
                {"category", { {"stringValue", g.category.empty() ? "others" : g.category} }},
                {"instructions", { {"stringValue", instrStr} }},
                {"address", { {"stringValue", addrStr} }},
                {"offset", { {"stringValue", offStr} }},
                {"hash", { {"stringValue", binaryHash.empty() ? binaryName : binaryHash} }},
                {"report_id", { {"stringValue", reportId} }}
            };

            writesArray.push_back({
                {"update", {
                    {"name", docPath},
                    {"fields", fields}
                }}
            });
        }

        json commitPayload = { {"writes", writesArray} };
        if (uploadToEndpoint(commitEndpoint, commitPayload.dump())) {
            uploadedCount += (endIdx - i);
        } else {
            std::cerr << "[x] Failed to upload batch of gadgets.\n";
            return false;
        }
    }

    std::cout << "[+] Successfully uploaded " << uploadedCount << " gadgets to Firebase 'gadgets' collection." << std::endl;
    return true;
}

bool FirebaseUploader::uploadToEndpoint(const std::string& endpoint,
                                         const std::string& jsonData) {
    return uploadToEndpointWithMethod(endpoint, jsonData, "POST");
}

bool FirebaseUploader::uploadToEndpointWithMethod(const std::string& endpoint,
                                                  const std::string& jsonData,
                                                  const std::string& method) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "[x] curl_easy_init() failed.\n";
        return false;
    }

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    std::string responseString;
    curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    if (method == "PATCH") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
    }

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData.c_str());
    char errbuf[CURL_ERROR_SIZE] = {0};
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
#if defined(_WIN32)
#ifndef CURLSSLOPT_NATIVE_CA
#define CURLSSLOPT_NATIVE_CA (1L << 4)
#endif
    curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
#endif

    // Look for local, exeDir, or standard CA bundle
    std::string exeCa2 = (getExeDir() / "curl-ca-bundle.crt").string();
    if (std::ifstream("curl-ca-bundle.crt").good()) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, "curl-ca-bundle.crt");
    } else if (std::ifstream(exeCa2).good()) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, exeCa2.c_str());
    } else if (std::ifstream("C:/msys64/mingw64/etc/ssl/certs/ca-bundle.crt").good()) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, "C:/msys64/mingw64/etc/ssl/certs/ca-bundle.crt");
    }

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseString);

    CURLcode res = curl_easy_perform(curl);
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    bool success = false;
    if (res != CURLE_OK) {
        std::cerr << "[x] CURL failed: " << curl_easy_strerror(res) << "\n";
        if (errbuf[0] != '\0') {
            std::cerr << "[x] CURL error detail: " << errbuf << "\n";
        }
    } else if (httpCode >= 200 && httpCode < 300) {
        std::cout << "[+] Report successfully uploaded to Firestore (HTTP " << httpCode << ").\n";
        success = true;
    } else {
        std::cerr << "[x] Firestore upload failed! HTTP Status: " << httpCode << "\n";
        if (!responseString.empty()) {
            std::cerr << "[x] Firestore response: " << responseString << "\n";
        }
        if (httpCode == 403) {
            std::cerr << "[!] Note: 403 Forbidden indicates cloud write access is restricted by Firestore security policy.\n"
                      << "    Local analysis reports and generated payloads remain intact.\n";
        }
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return success;
}

} // namespace ropweaver