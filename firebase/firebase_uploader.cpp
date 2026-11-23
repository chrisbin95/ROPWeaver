// firebase/firebase_uploader.cpp
#include "firebase_uploader.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstdint>
#include <chrono>
#include <thread>
#include <random>
#include <ctime>
#include <curl/curl.h>
#include "nlohmann/json.hpp"

#ifdef ERROR
#undef ERROR
#endif

using json = nlohmann::json;

namespace ropweaver {

// Callback for capturing CURL response data
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    if (!userp) return 0;
    static_cast<std::string*>(userp)->append(static_cast<char*>(contents), size * nmemb);
    return size * nmemb;
}

// Callback for capturing CURL response headers (case-insensitive Retry-After parsing)
static size_t HeaderCallback(char* buffer, size_t size, size_t nitems, void* userdata) {
    size_t total = size * nitems;
    std::string header(buffer, total);
    std::string* retryAfter = static_cast<std::string*>(userdata);
    if (!retryAfter) return total;

    std::string lower = header;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower.rfind("retry-after:", 0) == 0) {
        size_t pos = header.find(':');
        if (pos != std::string::npos) {
            std::string val = header.substr(pos + 1);
            size_t first = val.find_first_not_of(" \t\r\n");
            size_t last = val.find_last_not_of(" \t\r\n");
            if (first != std::string::npos && last != std::string::npos) {
                *retryAfter = val.substr(first, last - first + 1);
            }
        }
    }
    return total;
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
  "apiKey": "AIzaSyDSdptZ1bsqDwflZQ3QiT1fVZvfGFRF8mo",
  "firebase_url": "https://firestore.googleapis.com/v1/projects/rop-weaver/databases/(default)/documents/reports",
  "authDomain": "rop-weaver.firebaseapp.com",
  "projectId": "rop-weaver",
  "storageBucket": "rop-weaver.firebasestorage.app",
  "messagingSenderId": "466790753632",
  "appId": "1:466790753632:web:f8d0286a3a77f6a6bd6a05",
  "measurementId": "G-6GL8BCHHB3"
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
            projectId = "rop-weaver";
        }

        // Flexible key resolution for apiKey / api_key
        if (config.contains("apiKey") && config["apiKey"].is_string()) {
            apiKey = config["apiKey"].get<std::string>();
        } else if (config.contains("api_key") && config["api_key"].is_string()) {
            apiKey = config["api_key"].get<std::string>();
        } else {
            apiKey.clear();
        }

        auth.setApiKey(apiKey);

        if (firebaseUrl.empty() || apiKey.empty()) {
            std::cerr << "[x] Firebase configuration is incomplete. Check for missing 'firebase_url' (or 'projectId') or 'apiKey'.\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "[x] Error parsing config JSON: " << e.what() << "\n";
        firebaseUrl.clear();
        apiKey.clear();
    }
}

std::string FirebaseUploader::getFirestoreBaseUrl(bool& isEmulator, bool logError) {
    isEmulator = false;
    const char* envVal = std::getenv("FIRESTORE_EMULATOR_HOST");
    if (!envVal || envVal[0] == '\0') {
        return "https://firestore.googleapis.com";
    }

    std::string raw(envVal);
    size_t first = raw.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        if (logError) {
            std::cerr << "[x] Invalid FIRESTORE_EMULATOR_HOST: value cannot be whitespace only.\n";
        }
        return "";
    }
    size_t last = raw.find_last_not_of(" \t\r\n");
    std::string hostStr = raw.substr(first, (last - first + 1));

    if (hostStr.find("://") != std::string::npos ||
        hostStr.find('/') != std::string::npos ||
        hostStr.find('\\') != std::string::npos ||
        hostStr.find('?') != std::string::npos ||
        hostStr.find('#') != std::string::npos ||
        hostStr.find('@') != std::string::npos ||
        hostStr.find(' ') != std::string::npos ||
        hostStr.find('\t') != std::string::npos) {
        if (logError) {
            std::cerr << "[x] Invalid FIRESTORE_EMULATOR_HOST: must be a bare loopback host (localhost, 127.0.0.1, [::1]) optionally followed by :port without scheme or path: '" << hostStr << "'\n";
        }
        return "";
    }

    std::string hostPart;
    std::string portPart;
    bool hasColon = false;

    if (hostStr.front() == '[') {
        size_t closeBracket = hostStr.find(']');
        if (closeBracket == std::string::npos) {
            if (logError) {
                std::cerr << "[x] Invalid FIRESTORE_EMULATOR_HOST: unclosed IPv6 bracket in '" << hostStr << "'\n";
            }
            return "";
        }
        hostPart = hostStr.substr(0, closeBracket + 1);
        if (closeBracket + 1 < hostStr.size()) {
            if (hostStr[closeBracket + 1] != ':') {
                if (logError) {
                    std::cerr << "[x] Invalid FIRESTORE_EMULATOR_HOST: unexpected character after bracket in '" << hostStr << "'\n";
                }
                return "";
            }
            hasColon = true;
            portPart = hostStr.substr(closeBracket + 2);
        }
    } else {
        size_t colonPos = hostStr.find(':');
        if (colonPos != std::string::npos) {
            hasColon = true;
            hostPart = hostStr.substr(0, colonPos);
            portPart = hostStr.substr(colonPos + 1);
            if (portPart.find(':') != std::string::npos) {
                if (logError) {
                    std::cerr << "[x] Invalid FIRESTORE_EMULATOR_HOST: multiple colons in '" << hostStr << "' (IPv6 must be in brackets, e.g. [::1]:8080)\n";
                }
                return "";
            }
        } else {
            hostPart = hostStr;
        }
    }

    if (hasColon && portPart.empty()) {
        if (logError) {
            std::cerr << "[x] Invalid FIRESTORE_EMULATOR_HOST: trailing colon with missing port in '" << hostStr << "'\n";
        }
        return "";
    }

    std::string hostLower = hostPart;
    std::transform(hostLower.begin(), hostLower.end(), hostLower.begin(), ::tolower);
    if (hostLower != "localhost" && hostLower != "127.0.0.1" && hostLower != "[::1]") {
        if (logError) {
            std::cerr << "[x] Invalid FIRESTORE_EMULATOR_HOST: '" << hostPart << "' is not a permitted loopback address (allowed: localhost, 127.0.0.1, [::1]).\n";
        }
        return "";
    }

    if (!portPart.empty()) {
        if (portPart.size() > 5) {
            if (logError) {
                std::cerr << "[x] Invalid FIRESTORE_EMULATOR_HOST port length: '" << portPart << "'\n";
            }
            return "";
        }
        for (char c : portPart) {
            if (!std::isdigit(static_cast<unsigned char>(c))) {
                if (logError) {
                    std::cerr << "[x] Invalid FIRESTORE_EMULATOR_HOST port: '" << portPart << "' must contain only digits.\n";
                }
                return "";
            }
        }
        try {
            int portVal = std::stoi(portPart);
            if (portVal <= 0 || portVal > 65535) {
                if (logError) {
                    std::cerr << "[x] FIRESTORE_EMULATOR_HOST port out of range (1-65535): " << portVal << "\n";
                }
                return "";
            }
        } catch (...) {
            if (logError) {
                std::cerr << "[x] Invalid FIRESTORE_EMULATOR_HOST port: '" << portPart << "'\n";
            }
            return "";
        }
    }

    isEmulator = true;
    return "http://" + hostStr;
}

bool FirebaseUploader::reportExists(const std::string& docId) {
    std::string status;
    return getReportStatus(docId, status) == ReportStatusResult::FOUND;
}

ReportStatusResult FirebaseUploader::parseReportStatusResponse(
    int curlCode,
    long httpCode,
    const std::string& responseBody,
    std::string& statusOut) {
    statusOut.clear();

    if (curlCode != CURLE_OK) {
        return ReportStatusResult::ERROR;
    }

    if (httpCode == 404) {
        return ReportStatusResult::NOT_FOUND;
    }

    if (httpCode == 200) {
        try {
            json doc = json::parse(responseBody);
            if (doc.contains("fields") && doc["fields"].contains("upload_status") &&
                doc["fields"]["upload_status"].contains("stringValue")) {
                statusOut = doc["fields"]["upload_status"]["stringValue"].get<std::string>();
            } else {
                // Legacy report without upload_status: treat as completed
                statusOut = "completed";
            }
            return ReportStatusResult::FOUND;
        } catch (...) {
            return ReportStatusResult::ERROR;
        }
    }

    // 401, 403, 500, etc.
    return ReportStatusResult::ERROR;
}

ReportStatusResult FirebaseUploader::getReportStatus(const std::string& docId, std::string& statusOut) {
    statusOut.clear();
    if (!isConfigured() || docId.empty()) return ReportStatusResult::ERROR;

    bool isEmulator = false;
    std::string baseUrl = getFirestoreBaseUrl(isEmulator);
    if (baseUrl.empty()) {
        std::cerr << "[x] Aborting getReportStatus: invalid FIRESTORE_EMULATOR_HOST.\n";
        return ReportStatusResult::ERROR;
    }

    std::string proj = !projectId.empty() ? projectId : "rop-weaver";
    std::string endpoint = baseUrl + "/v1/projects/" + proj +
                           "/databases/(default)/documents/reports/" + docId + "?key=" + apiKey;

    CURL* curl = curl_easy_init();
    if (!curl) return ReportStatusResult::ERROR;

    std::string responseString;
    curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    if (isEmulator) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    } else {
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
    }

    // Attach Bearer token if authenticated
    struct curl_slist* headers = nullptr;
    std::string authToken = auth.getIdToken();
    if (!authToken.empty()) {
        std::string authHdr = "Authorization: Bearer " + authToken;
        headers = curl_slist_append(headers, authHdr.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseString);

    CURLcode res = curl_easy_perform(curl);
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    if (headers) curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return parseReportStatusResponse(res, httpCode, responseString, statusOut);
}

bool FirebaseUploader::updateReportStatus(const std::string& docId, const std::string& status) {
    if (!isConfigured() || docId.empty() || status.empty()) return false;

    bool isEmulator = false;
    std::string baseUrl = getFirestoreBaseUrl(isEmulator);
    if (baseUrl.empty()) {
        std::cerr << "[x] Aborting updateReportStatus: invalid FIRESTORE_EMULATOR_HOST.\n";
        return false;
    }

    std::string proj = !projectId.empty() ? projectId : "rop-weaver";
    std::string endpoint = baseUrl + "/v1/projects/" + proj +
                           "/databases/(default)/documents/reports/" + docId +
                           "?updateMask.fieldPaths=upload_status&key=" + apiKey;

    json patchFields = {
        {"fields", {
            {"upload_status", { {"stringValue", status} }}
        }}
    };

    std::string authToken = auth.getIdToken();
    if (authToken.empty()) {
        std::cerr << "[x] Firebase status update failed: authentication required.\n";
        return false;
    }

    UploadResult res = uploadToEndpointWithMethodEx(endpoint, patchFields.dump(), "PATCH", authToken, isEmulator, true);
    if (res.httpCode == 401) {
        std::cout << "[!] Received HTTP 401 Unauthorized during status update. Refreshing ID token and retrying...\n";
        authToken = auth.getIdToken(true);
        if (!authToken.empty()) {
            res = uploadToEndpointWithMethodEx(endpoint, patchFields.dump(), "PATCH", authToken, isEmulator, true);
        }
    }

    return res.success;
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

    // 6b. Set initial upload status to 'in_progress' if not explicitly specified
    if (!fields.contains("upload_status")) {
        fields["upload_status"] = toFirestoreValue(json("in_progress"));
    }

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

    bool isEmulator = false;
    std::string baseUrl = getFirestoreBaseUrl(isEmulator);
    if (baseUrl.empty()) {
        std::cerr << "[x] Aborting uploadReport: invalid FIRESTORE_EMULATOR_HOST.\n";
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

    std::string proj = !projectId.empty() ? projectId : "rop-weaver";
    std::string endpoint;
    std::string method = "POST";

    if (!docId.empty()) {
        // Upsert to specific document ID: PATCH /reports/<docId>
        endpoint = baseUrl + "/v1/projects/" + proj +
                   "/databases/(default)/documents/reports/" + docId + "?key=" + apiKey;
        method = "PATCH";
    } else {
        if (isEmulator) {
            endpoint = baseUrl + "/v1/projects/" + proj +
                       "/databases/(default)/documents/reports?key=" + apiKey;
        } else {
            std::string separator = (firebaseUrl.find('?') == std::string::npos) ? "?key=" : "&key=";
            endpoint = firebaseUrl + separator + apiKey;
        }
    }

    std::string authToken = auth.getIdToken();
    if (authToken.empty()) {
        std::cerr << "[x] Firebase report upload failed: authentication required.\n";
        return false;
    }

    bool isIdempotent = !docId.empty();
    UploadResult res = uploadToEndpointWithMethodEx(endpoint, firestoreFormat.dump(), method, authToken, isEmulator, isIdempotent);
    if (res.httpCode == 401) {
        std::cout << "[!] Received HTTP 401 Unauthorized from Firestore. Refreshing ID token and retrying report upload...\n";
        authToken = auth.getIdToken(true);
        if (!authToken.empty()) {
            res = uploadToEndpointWithMethodEx(endpoint, firestoreFormat.dump(), method, authToken, isEmulator, isIdempotent);
        }
    }

    return res.success;
}

bool FirebaseUploader::uploadReportFromData(const std::string& binaryName,
                                             const std::string& architecture,
                                             const std::string& jsonData) {
    if (!isConfigured()) {
        std::cerr << "[x] Firebase config not loaded properly.\n";
        return false;
    }

    bool isEmulator = false;
    std::string baseUrl = getFirestoreBaseUrl(isEmulator);
    if (baseUrl.empty()) {
        std::cerr << "[x] Aborting uploadReportFromData: invalid FIRESTORE_EMULATOR_HOST.\n";
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

    std::string proj = !projectId.empty() ? projectId : "rop-weaver";
    std::string endpoint;
    if (isEmulator) {
        endpoint = baseUrl + "/v1/projects/" + proj +
                   "/databases/(default)/documents/reports?key=" + apiKey;
    } else {
        std::string separator = (firebaseUrl.find('?') == std::string::npos) ? "?key=" : "&key=";
        endpoint = firebaseUrl + separator + apiKey;
    }

    std::string authToken = auth.getIdToken();
    if (authToken.empty()) {
        std::cerr << "[x] Firebase upload failed: authentication required.\n";
        return false;
    }

    UploadResult res = uploadToEndpointWithMethodEx(endpoint, firestoreFormat.dump(), "POST", authToken, isEmulator, false);
    if (res.httpCode == 401) {
        std::cout << "[!] Received HTTP 401 Unauthorized from Firestore. Refreshing ID token and retrying upload...\n";
        authToken = auth.getIdToken(true);
        if (!authToken.empty()) {
            res = uploadToEndpointWithMethodEx(endpoint, firestoreFormat.dump(), "POST", authToken, isEmulator, false);
        }
    }
    return res.success;
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

    bool isEmulator = false;
    std::string baseUrl = getFirestoreBaseUrl(isEmulator);
    if (baseUrl.empty()) {
        std::cerr << "[x] Aborting uploadGadgets: invalid FIRESTORE_EMULATOR_HOST.\n";
        return false;
    }

    std::string authToken = auth.getIdToken();
    if (authToken.empty()) {
        std::cerr << "[x] Firebase gadget upload failed: authentication required.\n";
        return false;
    }

    std::string proj = !projectId.empty() ? projectId : "rop-weaver";
    std::string commitEndpoint = baseUrl + "/v1/projects/" + proj +
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
        UploadResult res = uploadToEndpointWithMethodEx(commitEndpoint, commitPayload.dump(), "POST", authToken, isEmulator, true);

        // Controlled single refresh and retry on HTTP 401
        if (res.httpCode == 401) {
            std::cout << "[!] Received HTTP 401 Unauthorized during gadget batch commit (batch starting at index "
                      << i << "). Refreshing token and retrying batch...\n";
            authToken = auth.getIdToken(true);
            if (!authToken.empty()) {
                res = uploadToEndpointWithMethodEx(commitEndpoint, commitPayload.dump(), "POST", authToken, isEmulator, true);
            }
        }

        if (res.success) {
            uploadedCount += (endIdx - i);
        } else {
            std::cerr << "[x] Failed to upload gadget batch starting at index " << i
                      << " (" << (endIdx - i) << " gadgets). HTTP Status: " << res.httpCode << "\n";
            std::cerr << "[!] Partial upload progress preserved: " << uploadedCount << " of " << gadgets.size()
                      << " gadgets were committed to Firestore before failure.\n";
            return false;
        }
    }

    std::cout << "[+] Successfully uploaded " << uploadedCount << " gadgets to Firebase 'gadgets' collection." << std::endl;
    return true;
}

bool FirebaseUploader::uploadToEndpoint(const std::string& endpoint,
                                         const std::string& jsonData,
                                         bool isEmulator) {
    return uploadToEndpointWithMethod(endpoint, jsonData, "POST", isEmulator);
}

bool FirebaseUploader::isTransientCurlError(int curlCode) {
    return (curlCode == CURLE_OPERATION_TIMEDOUT ||
            curlCode == CURLE_COULDNT_CONNECT ||
            curlCode == CURLE_COULDNT_RESOLVE_HOST ||
            curlCode == CURLE_RECV_ERROR ||
            curlCode == CURLE_SEND_ERROR ||
            curlCode == CURLE_PARTIAL_FILE);
}

bool FirebaseUploader::isTransientHttpCode(long httpCode) {
    return (httpCode == 429 || httpCode == 500 || httpCode == 502 || httpCode == 503 || httpCode == 504);
}

static time_t portableTimegm(std::tm* tm) {
#if defined(_WIN32)
    return _mkgmtime(tm);
#else
    return timegm(tm);
#endif
}

long FirebaseUploader::parseRetryAfter(const std::string& headerValue,
                                      long maxCapSeconds,
                                      std::chrono::system_clock::time_point now) {
    if (headerValue.empty()) return 0;

    // Trim whitespace and quotes if present
    size_t first = headerValue.find_first_not_of(" \t\r\n\"");
    if (first == std::string::npos) return 0;
    size_t last = headerValue.find_last_not_of(" \t\r\n\"");
    std::string val = headerValue.substr(first, last - first + 1);
    if (val.empty()) return 0;

    // 1. Check if integer seconds
    bool isAllDigits = true;
    for (char c : val) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            isAllDigits = false;
            break;
        }
    }

    if (isAllDigits) {
        try {
            long seconds = std::stol(val);
            if (seconds < 0) return 0;
            if (seconds > maxCapSeconds) {
                std::cout << "[!] Retry-After delay (" << seconds << "s) exceeded maximum cap ("
                          << maxCapSeconds << "s). Capping at " << maxCapSeconds << "s.\n";
                return maxCapSeconds;
            }
            return seconds;
        } catch (...) {
            return 0;
        }
    }

    // 2. Try parsing as HTTP-date (RFC 1123, RFC 850, asctime)
    std::vector<std::string> dateFormats = {
        "%a, %d %b %Y %H:%M:%S GMT",
        "%a, %d-%b-%y %H:%M:%S GMT",
        "%a %b %d %H:%M:%S %Y"
    };

    for (const auto& fmt : dateFormats) {
        std::tm tm = {};
        std::istringstream ss(val);
        ss >> std::get_time(&tm, fmt.c_str());
        if (!ss.fail()) {
            time_t targetTime = portableTimegm(&tm);
            if (targetTime != (time_t)-1) {
                auto nowTimeT = std::chrono::system_clock::to_time_t(now);
                long diff = static_cast<long>(targetTime - nowTimeT);
                if (diff < 0) return 0;
                if (diff > maxCapSeconds) {
                    std::cout << "[!] Retry-After delay (" << diff << "s) exceeded maximum cap ("
                              << maxCapSeconds << "s). Capping at " << maxCapSeconds << "s.\n";
                    return maxCapSeconds;
                }
                return diff;
            }
        }
    }

    return 0;
}

std::chrono::milliseconds FirebaseUploader::calculateBackoffDelay(
    int retryAttempt,
    long retryAfterSeconds,
    double baseDelaySeconds,
    double maxBackoffSeconds,
    double jitterFactor) {

    if (retryAfterSeconds > 0) {
        long cappedSec = std::min(retryAfterSeconds, 30L);
        return std::chrono::milliseconds(cappedSec * 1000L);
    }

    double delaySec = baseDelaySeconds * std::pow(2.0, retryAttempt);
    if (delaySec > maxBackoffSeconds) {
        delaySec = maxBackoffSeconds;
    }

    // Bounded jitter in [1.0 - jitterFactor, 1.0 + jitterFactor]
    static thread_local std::mt19937 rng(static_cast<unsigned int>(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::uniform_real_distribution<double> dist(1.0 - jitterFactor, 1.0 + jitterFactor);
    double jitteredDelaySec = delaySec * dist(rng);
    if (jitteredDelaySec < 0.0) jitteredDelaySec = 0.0;

    return std::chrono::milliseconds(static_cast<long long>(jitteredDelaySec * 1000.0));
}

bool FirebaseUploader::uploadToEndpointWithMethod(const std::string& endpoint,
                                                  const std::string& jsonData,
                                                  const std::string& method,
                                                  bool isEmulator) {
    return uploadToEndpointWithMethodEx(endpoint, jsonData, method, "", isEmulator, false).success;
}

UploadResult FirebaseUploader::uploadToEndpointWithMethodEx(const std::string& endpoint,
                                                           const std::string& jsonData,
                                                           const std::string& method,
                                                           const std::string& authToken,
                                                           bool isEmulator,
                                                           bool isIdempotent,
                                                           std::chrono::milliseconds budgetDuration) {
    UploadResult result;
    const int maxRetries = isIdempotent ? 3 : 0;
    const auto startTime = std::chrono::steady_clock::now();

    for (int attempt = 0; attempt <= maxRetries; ++attempt) {
        // Calculate remaining budget before initiating HTTP attempt
        auto elapsedBeforeReq = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime);
        auto remainingBudget = budgetDuration - elapsedBeforeReq;

        if (remainingBudget <= std::chrono::milliseconds(0)) {
            std::cerr << "[!] Total retry budget (" << (budgetDuration.count() / 1000)
                      << "s) exhausted (" << elapsedBeforeReq.count()
                      << "ms elapsed) before attempt " << attempt << ". Aborting.\n";
            result.success = false;
            return result;
        }

        // Constrain request and connection timeouts so this request cannot exceed remaining budget
        long remainingSec = static_cast<long>(
            std::chrono::duration_cast<std::chrono::seconds>(remainingBudget).count());
        if (remainingSec < 1) remainingSec = 1;
        long connectTimeout = std::min(5L, remainingSec);
        long requestTimeout = std::min(15L, remainingSec);

        CURL* curl = curl_easy_init();
        if (!curl) {
            std::cerr << "[x] curl_easy_init() failed.\n";
            result.success = false;
            return result;
        }

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        if (!authToken.empty()) {
            std::string authHdr = "Authorization: Bearer " + authToken;
            headers = curl_slist_append(headers, authHdr.c_str());
        }

        std::string responseString;
        std::string capturedRetryAfter;

        curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        if (method == "PATCH") {
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
        } else if (method == "PUT") {
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
        } else if (method == "DELETE") {
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
        }

        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData.c_str());
        char errbuf[CURL_ERROR_SIZE] = {0};
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connectTimeout);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, requestTimeout);

        if (isEmulator) {
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        } else {
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
#if defined(_WIN32)
#ifndef CURLSSLOPT_NATIVE_CA
#define CURLSSLOPT_NATIVE_CA (1L << 4)
#endif
            curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
#endif
            std::string exeCa2 = (getExeDir() / "curl-ca-bundle.crt").string();
            if (std::ifstream("curl-ca-bundle.crt").good()) {
                curl_easy_setopt(curl, CURLOPT_CAINFO, "curl-ca-bundle.crt");
            } else if (std::ifstream(exeCa2).good()) {
                curl_easy_setopt(curl, CURLOPT_CAINFO, exeCa2.c_str());
            } else if (std::ifstream("C:/msys64/mingw64/etc/ssl/certs/ca-bundle.crt").good()) {
                curl_easy_setopt(curl, CURLOPT_CAINFO, "C:/msys64/mingw64/etc/ssl/certs/ca-bundle.crt");
            }
        }

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseString);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &capturedRetryAfter);

        CURLcode res = curl_easy_perform(curl);
        long httpCode = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

        result.httpCode = httpCode;
        result.response = responseString;

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);

        // Success check
        if (res == CURLE_OK && httpCode >= 200 && httpCode < 300) {
            std::cout << "[+] Firestore request succeeded (HTTP " << httpCode << ").\n";
            result.success = true;
            return result;
        }

        // Non-retryable status codes: fail immediately with 0 retries
        if (httpCode == 400 || httpCode == 403 || httpCode == 404) {
            std::cerr << "[x] Non-retryable HTTP Status: " << httpCode << "\n";
            if (!responseString.empty()) {
                std::cerr << "[x] Firestore response: " << responseString << "\n";
            }
            if (httpCode == 403) {
                std::cerr << "[!] Note: 403 Forbidden indicates cloud write access is restricted by Firestore security policy.\n"
                          << "    Local analysis reports and generated payloads remain intact.\n";
            }
            result.success = false;
            return result;
        }

        // HTTP 401 Unauthorized: caller handles token refresh and retry
        if (httpCode == 401) {
            result.success = false;
            return result;
        }

        // Check if error is transient
        bool isTransient = false;
        if (res != CURLE_OK && isTransientCurlError(res)) {
            isTransient = true;
        } else if (res == CURLE_OK && isTransientHttpCode(httpCode)) {
            isTransient = true;
        }

        if (!isTransient) {
            if (res != CURLE_OK) {
                std::cerr << "[x] Non-transient CURL error: " << curl_easy_strerror(res) << "\n";
                if (errbuf[0] != '\0') {
                    std::cerr << "[x] CURL error detail: " << errbuf << "\n";
                }
            } else {
                std::cerr << "[x] Non-transient HTTP Status: " << httpCode << "\n";
                if (!responseString.empty()) {
                    std::cerr << "[x] Firestore response: " << responseString << "\n";
                }
            }
            result.success = false;
            return result;
        }

        // If transient, check if retry budget or attempts exhausted
        if (attempt >= maxRetries) {
            std::cerr << "[!] Retry attempts exhausted (" << attempt << " retries). Operation failed.\n";
            result.success = false;
            return result;
        }

        long retryAfterSec = parseRetryAfter(capturedRetryAfter);
        result.retryAfterSeconds = retryAfterSec;
        auto delayMs = calculateBackoffDelay(attempt, retryAfterSec);

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startTime);
        if (elapsed + delayMs > budgetDuration) {
            std::cerr << "[!] Total retry budget (" << (budgetDuration.count() / 1000) << "s) exceeded ("
                      << elapsed.count() << "ms elapsed + "
                      << delayMs.count() << "ms delay > " << budgetDuration.count() << "ms). Aborting retries.\n";
            result.success = false;
            return result;
        }

        result.retryAttempts++;
        std::cout << "[!] Transient failure ("
                  << (res != CURLE_OK ? curl_easy_strerror(res) : ("HTTP " + std::to_string(httpCode)))
                  << "). Retrying in " << delayMs.count() << "ms (attempt " << (attempt + 1)
                  << " of " << maxRetries << ")...\n";

        std::this_thread::sleep_for(delayMs);
    }

    result.success = false;
    return result;
}

} // namespace ropweaver