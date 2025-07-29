#include "firebase_uploader.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <curl/curl.h>
#include "nlohmann/json.hpp"

using json = nlohmann::json;

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
        json config;
        file >> config;
        firebaseUrl = config.at("firebase_url").get<std::string>();
        apiKey = config.at("api_key").get<std::string>();
    } catch (const std::exception& e) {
        std::cerr << "❌ Error parsing config JSON: " << e.what() << "\n";
    }
}

// Recursively converts nlohmann::json to Firestore fieldValue
json toFirestoreValue(const json& value) {
    if (value.is_string()) {
        return { { "stringValue", value.get<std::string>() } };
    } else if (value.is_number_integer()) {
        return { { "integerValue", std::to_string(value.get<int>()) } };
    } else if (value.is_number_float()) {
        return { { "doubleValue", value.get<double>() } };
    } else if (value.is_boolean()) {
        return { { "booleanValue", value.get<bool>() } };
    } else if (value.is_array()) {
        json arr;
        for (const auto& elem : value) {
            arr["values"].push_back(toFirestoreValue(elem));
        }
        return { { "arrayValue", arr } };
    } else if (value.is_object()) {
        json map;
        for (auto& [k, v] : value.items()) {
            map["fields"][k] = toFirestoreValue(v);
        }
        return { { "mapValue", map } };
    } else if (value.is_null()) {
        return { { "nullValue", nullptr } };
    } else {
        std::cerr << "⚠️ Unsupported Firestore value type.\n";
        return {};
    }
}

bool FirebaseUploader::uploadReport(const std::string& jsonPath) {
    std::ifstream file(jsonPath);
    if (!file.is_open()) {
        std::cerr << "❌ Failed to open report JSON file: " << jsonPath << "\n";
        return false;
    }

    json inputJson;
    try {
        file >> inputJson;
    } catch (const std::exception& e) {
        std::cerr << "❌ Error parsing input JSON: " << e.what() << "\n";
        return false;
    }

    // Recursively convert to Firestore field values
    json firestoreFormat = { { "fields", json::object() } };
    for (const auto& [key, value] : inputJson.items()) {
        firestoreFormat["fields"][key] = toFirestoreValue(value);
    }

    std::string jsonPayload = firestoreFormat.dump(2);

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
