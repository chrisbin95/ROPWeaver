// firebase_uploader.h
#ifndef FIREBASE_UPLOADER_H
#define FIREBASE_UPLOADER_H

#include <string>

class FirebaseUploader {
public:
    // Constructor: loads config from JSON file
    explicit FirebaseUploader(const std::string& configPath);

    // Upload a local JSON file to Firestore (standard usage)
    bool uploadReport(const std::string& jsonPath);

    // Upload JSON content from raw strings (in-memory use case)
    bool uploadReportFromData(const std::string& binaryName,
                               const std::string& architecture,
                               const std::string& jsonData);

    // Upload arbitrary JSON to a custom Firestore endpoint (advanced control)
    bool uploadToEndpoint(const std::string& endpoint,
                          const std::string& jsonData);

private:
    std::string firebaseUrl;
    std::string apiKey;

    // Load Firebase config from JSON file
    void loadConfig(const std::string& configPath);
};

#endif // FIREBASE_UPLOADER_H
