#ifndef FIREBASE_UPLOADER_H
#define FIREBASE_UPLOADER_H

#include <string>

class FirebaseUploader {
public:
    explicit FirebaseUploader(const std::string& configPath);

    // Upload a complete JSON file (current)
    bool uploadReport(const std::string& jsonPath);

    // Upload raw JSON data
    bool uploadReportFromData(const std::string& binaryName,
                               const std::string& architecture,
                               const std::string& jsonData);

    // Upload to a specific path in Firebase
    bool uploadToEndpoint(const std::string& endpoint,
                          const std::string& jsonData);

private:
    std::string firebaseUrl;
    std::string apiKey;
    void loadConfig(const std::string& configPath);
};

#endif // FIREBASE_UPLOADER_H
