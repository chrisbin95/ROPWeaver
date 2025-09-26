// firebase/firebase_uploader.h

#ifndef ROPWEAVER_FIREBASE_UPLOADER_H
#define ROPWEAVER_FIREBASE_UPLOADER_H

#include <string>
#include "nlohmann/json.hpp"

namespace ropweaver {

// Forward declaration of the class
class FirebaseUploader;

// Helper function to convert standard JSON to Firestore's required structure
nlohmann::json toFirestoreValue(const nlohmann::json& value);

class FirebaseUploader {
public:
    // Constructor attempts to load configuration from the specified path
    FirebaseUploader(const std::string& configPath);
    
    // Uploads the contents of a local JSON report file
    bool uploadReport(const std::string& jsonPath);

    // Uploads in-memory data for more direct usage
    bool uploadReportFromData(const std::string& binaryName,
                              const std::string& architecture,
                              const std::string& jsonData);

private:
    std::string firebaseUrl;
    std::string apiKey;

    // Loads configuration details from the firebase_config.json file
    void loadConfig(const std::string& configPath);

    // Handles the actual CURL request to the Firestore endpoint
    bool uploadToEndpoint(const std::string& endpoint, const std::string& jsonData);
};

} // namespace ropweaver

#endif // ROPWEAVER_FIREBASE_UPLOADER_H