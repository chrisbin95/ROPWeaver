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
        std::cerr << "❌ Failed to open Firebase config file.\n";
        return;
    }

    nlohmann::json config;
    file >> config;

    firebaseUrl = config["firebase_url"];
    apiKey = config["api_key"];
}

bool FirebaseUploader::uploadReport(const std::string& jsonPath) {
    std::ifstream file(jsonPath);
    if (!file.is_open()) {
        std::cerr << "❌ Failed to open report JSON file.\n";
        return false;
    }

    nlohmann::json inputJson;
    file >> inputJson;

    // Transform to Firestore-compatible structure
    nlohmann::json firestoreFormat = {
        {"fields", {}}
    };

    for (auto& el : inputJson.items()) {
        if (el.value().is_string()) {
            firestoreFormat["fields"][el.key()] = { { "stringValue", el.value() } };
        } else if (el.value().is_number_integer()) {
            firestoreFormat["fields"][el.key()] = { { "integerValue", std::to_string(el.value().get<int>()) } };
        } else if (el.value().is_number_float()) {
            firestoreFormat["fields"][el.key()] = { { "doubleValue", el.value().get<double>() } };
        }
        // You can add more type mappings here (e.g., booleanValue, timestampValue)
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

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        std::cerr << "❌ CURL failed: " << curl_easy_strerror(res) << std::endl;
    } else {
        std::cout << "✅ Report successfully uploaded to Firestore.\n";
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return res == CURLE_OK;
}
