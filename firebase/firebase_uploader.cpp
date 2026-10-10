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

FirebaseUploader::FirebaseUploader(const std::string& configPath) {
    loadConfig(configPath);
}

void FirebaseUploader::loadConfig(const std::string& configPath) {
    std::ifstream file(configPath);
    if (!file.is_open()) {
        std::cerr << "[x] Failed to open Firebase config file: " << configPath << "\n";
        firebaseUrl.clear();
        apiKey.clear();
        return;
    }

    try {
        // Parse with comments allowed to avoid syntax issues in config files
        json config = json::parse(file, nullptr, true, true);
        
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

    if (std::ifstream("curl-ca-bundle.crt").good()) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, "curl-ca-bundle.crt");
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

    json firestoreFormat = { {"fields", json::object()} };
    for (const auto& [key, value] : inputJson.items()) {
        json fVal = toFirestoreValue(value);
        if (!fVal.empty()) {
            firestoreFormat["fields"][key] = fVal;
        }
    }

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
    
    json firestoreFormat = { {"fields", json::object()} };
    for (const auto& [key, value] : reportJson.items()) {
        json fVal = toFirestoreValue(value);
        if (!fVal.empty()) {
            firestoreFormat["fields"][key] = fVal;
        }
    }

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

            // Create a deterministic safe document ID: <binary>_<address>
            std::stringstream shortAddr;
            shortAddr << std::hex << g.address;
            std::string docId = binaryName + "_0x" + shortAddr.str();
            std::replace(docId.begin(), docId.end(), '/', '_');
            std::replace(docId.begin(), docId.end(), '\\', '_');
            std::replace(docId.begin(), docId.end(), ' ', '_');

            std::string docPath = "projects/" + proj + "/databases/(default)/documents/gadgets/" + docId;

            json fields = {
                {"file name", { {"stringValue", binaryName} }},
                {"architecture", { {"stringValue", architecture} }},
                {"category", { {"stringValue", "ELF"} }},
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

    // Look for local or standard CA bundle
    if (std::ifstream("curl-ca-bundle.crt").good()) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, "curl-ca-bundle.crt");
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
            std::cerr << "[!] Hint: 403 Forbidden indicates insufficient Firestore security permissions.\n"
                      << "    Please verify that Firestore Rules allow writes to this collection (see config/firestore.rules).\n";
        }
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return success;
}

} // namespace ropweaver