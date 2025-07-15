// firebase_uploader.cpp
#include "firebase_uploader.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <curl/curl.h>
#include "nlohmann/json.hpp"

FirebaseUploader::FirebaseUploader(const std::string& configPath) {
    loadConfig(configPath);
}

void FirebaseUploader::loadConfig(const std::string& configPath) {
    std::ifstream file(configPath);
    if (!file.is_open()) {
        std::cerr << "❌ Failed to open Firebase config file: " << configPath << "\n";
        return;
    }

    try {
        nlohmann::json config;
        file >> config;
        firebaseUrl = config.at("firebase_url").get<std::string>();
        apiKey = config.at("api_key").get<std::string>();
    } catch (const std::exception& e) {
        std::cerr << "❌ Error parsing config JSON: " << e.what() << "\n";
    }
}

bool FirebaseUploader::uploadReport(const std::string& jsonPath) {
    std::ifstream file(jsonPath);
    if (!file.is_open()) {
        std::cerr << "❌ Failed to open report JSON file: " << jsonPath << "\n";
        return false;
    }

    nlohmann::json inputJson;
    try {
        file >> inputJson;
    } catch (const std::exception& e) {
        std::cerr << "❌ Error parsing input JSON: " << e.what() << "\n";
        return false;
    }

    // Transform into Firestore API format
    nlohmann::json firestoreFormat = { {"fields", nlohmann::json::object()} };

    for (const auto& [key, value] : inputJson.items()) {
        if (value.is_string()) {
            firestoreFormat["fields"][key] = { { "stringValue", value.get<std::string>() } };
        } else if (value.is_number_integer()) {
            firestoreFormat["fields"][key] = { { "integerValue", std::to_string(value.get<int>()) } };
        } else if (value.is_number_float()) {
            firestoreFormat["fields"][key] = { { "doubleValue", value.get<double>() } };
        } else if (value.is_boolean()) {
            firestoreFormat["fields"][key] = { { "booleanValue", value.get<bool>() } };
        } else {
            std::cerr << "⚠️ Skipped unsupported field: " << key << "\n";
        }
    }

    std::string jsonPayload = firestoreFormat.dump();

    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "❌ curl_easy_init() failed.\n";
        return false;
    }

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    std::string fullUrl = firebaseUrl + "?key=" + apiKey;
    curl_easy_setopt(curl, CURLOPT_URL, fullUrl.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonPayload.c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "❌ CURL failed: " << curl_easy_strerror(res) << "\n";
    } else {
        std::cout << "✅ Report successfully uploaded to Firestore.\n";
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return res == CURLE_OK;
}
