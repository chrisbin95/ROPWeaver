// firebase/firebase_uploader.cpp
#include "firebase_uploader.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <curl/curl.h>
#include "nlohmann/json.hpp"

using json = nlohmann::json;

namespace ropweaver {

json toFirestoreValue(const json& value) {
    if (value.is_string()) return { {"stringValue", value.get<std::string>()} };
    // Safely cast to int64_t before conversion to string for 'integerValue'
    if (value.is_number_integer()) return { {"integerValue", std::to_string(value.get<int64_t>())} }; 
    if (value.is_number_float()) return { {"doubleValue", value.get<double>()} };
    if (value.is_boolean()) return { {"booleanValue", value.get<bool>()} };
    if (value.is_array()) {
        json arr;
        for (const auto& elem : value) arr["values"].push_back(ropweaver::toFirestoreValue(elem));
        return { {"arrayValue", arr} };
    }
    if (value.is_object()) {
        json map;
        for (auto& [k, v] : value.items()) map["fields"][k] = ropweaver::toFirestoreValue(v);
        return { {"mapValue", map} };
    }
    if (value.is_null()) return { {"nullValue", nullptr} };
    std::cerr << "[!] Unsupported Firestore value type.\n";
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
        json config;
        file >> config;
        
        // FIX: Retrieve keys using the case-sensitive names from firebase_config.json.
        firebaseUrl = config.value("firebase_url", ""); 
        apiKey = config.value("apiKey", ""); // CORRECTED: Now uses 'apiKey'

        // Check if required fields were found.
        if (firebaseUrl.empty() || apiKey.empty()) {
             std::cerr << "[x] Firebase configuration is incomplete. Check for missing 'firebase_url' or 'apiKey'.\n";
        }
        
    } catch (const std::exception& e) {
        std::cerr << "[x] Error parsing config JSON: " << e.what() << "\n";
        firebaseUrl.clear();
        apiKey.clear();
    }
}

bool FirebaseUploader::uploadReport(const std::string& jsonPath) {
    if (firebaseUrl.empty() || apiKey.empty()) {
        std::cerr << "[x] Firebase config not loaded properly.\n";
        return false;
    }

    std::ifstream file(jsonPath);
    if (!file.is_open()) {
        std::cerr << "[x] Failed to open report JSON file: " << jsonPath << "\n";
        return false;
    }

    json inputJson;
    try { file >> inputJson; }
    catch (const std::exception& e) { 
        std::cerr << "[x] Error parsing input JSON: " << e.what() << "\n"; 
        return false; 
    }

    json firestoreFormat = { {"fields", json::object()} };
    for (const auto& [key, value] : inputJson.items())
        firestoreFormat["fields"][key] = toFirestoreValue(value);

    return uploadToEndpoint(firebaseUrl + "?key=" + apiKey, firestoreFormat.dump());
}

bool FirebaseUploader::uploadReportFromData(const std::string& binaryName,
                                             const std::string& architecture,
                                             const std::string& jsonData) {
    if (firebaseUrl.empty() || apiKey.empty()) {
        std::cerr << "[x] Firebase config not loaded properly.\n";
        return false;
    }

    json reportJson;
    try { reportJson = json::parse(jsonData); } 
    catch (...) { reportJson = { {"raw", jsonData} }; } 

    reportJson["binary_name"] = binaryName;
    reportJson["architecture"] = architecture;
    
    // Format the in-memory JSON data for Firestore
    json firestoreFormat = { {"fields", json::object()} };
    for (const auto& [key, value] : reportJson.items())
        firestoreFormat["fields"][key] = toFirestoreValue(value);

    return uploadToEndpoint(firebaseUrl + "?key=" + apiKey, firestoreFormat.dump());
}

bool FirebaseUploader::uploadToEndpoint(const std::string& endpoint,
                                             const std::string& jsonData) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "[x] curl_easy_init() failed.\n";
        return false;
    }

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData.c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "[x] CURL failed: " << curl_easy_strerror(res) << "\n";
    } else {
        std::cout << "[+] Report successfully uploaded to Firestore.\n";
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return res == CURLE_OK;
}

} // namespace ropweaver