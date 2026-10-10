// firebase/firebase_uploader.h

#ifndef ROPWEAVER_FIREBASE_UPLOADER_H
#define ROPWEAVER_FIREBASE_UPLOADER_H

#include <string>
#include <vector>
#include "nlohmann/json.hpp"
#include "../core/gadget.h"

namespace ropweaver {

// Helper function to convert standard JSON to Firestore's required structure
nlohmann::json toFirestoreValue(const nlohmann::json& value);

class FirebaseUploader {
public:
    // Constructor attempts to load configuration from the specified path
    explicit FirebaseUploader(const std::string& configPath);
    
    // Checks if the configuration was loaded successfully
    bool isConfigured() const { return !firebaseUrl.empty() && !apiKey.empty(); }

    // Checks if a report document with the given docId already exists in Firestore
    bool reportExists(const std::string& docId);

    // Uploads the contents of a local JSON report file (optional docId for upsert)
    bool uploadReport(const std::string& jsonPath, const std::string& docId = "");

    // Uploads individual gadgets to the Firestore 'gadgets' collection
    bool uploadGadgets(const std::string& binaryName,
                       const std::string& architecture,
                       const std::string& binaryHash,
                       const std::string& reportId,
                       const std::vector<Gadget>& gadgets);

    // Uploads in-memory data for more direct usage
    bool uploadReportFromData(const std::string& binaryName,
                              const std::string& architecture,
                              const std::string& jsonData);

    // Getters for configuration state
    const std::string& getFirebaseUrl() const { return firebaseUrl; }
    const std::string& getApiKey() const { return apiKey; }
    const std::string& getProjectId() const { return projectId; }

private:
    std::string firebaseUrl;
    std::string apiKey;
    std::string projectId;

    // Loads configuration details from the firebase_config.json file
    void loadConfig(const std::string& configPath);

    // Handles the actual CURL request to the Firestore endpoint
    bool uploadToEndpoint(const std::string& endpoint, const std::string& jsonData);
    bool uploadToEndpointWithMethod(const std::string& endpoint, const std::string& jsonData, const std::string& method);
};

} // namespace ropweaver

#endif // ROPWEAVER_FIREBASE_UPLOADER_H