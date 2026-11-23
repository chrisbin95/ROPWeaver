// firebase/firebase_uploader.h

#ifndef ROPWEAVER_FIREBASE_UPLOADER_H
#define ROPWEAVER_FIREBASE_UPLOADER_H

#include <string>
#include <vector>
#include "nlohmann/json.hpp"
#include "../core/gadget.h"
#include "firebase_auth.h"

namespace ropweaver {

// Result structure for Firestore HTTP operations
struct UploadResult {
    bool success = false;
    long httpCode = 0;
    std::string response;
    int retryAttempts = 0;
    long retryAfterSeconds = 0;
};

#ifdef ERROR
#undef ERROR
#endif

// Result enumeration for document status lookups in Firestore
enum class ReportStatusResult {
    FOUND,      // Document exists and upload_status was parsed
    NOT_FOUND,  // Firestore explicitly returned HTTP 404
    ERROR       // Network failure, authentication failure, or unexpected HTTP status
};

// Helper function to convert standard JSON to Firestore's required structure
nlohmann::json toFirestoreValue(const nlohmann::json& value);

class FirebaseUploader {
public:
    // Constructor attempts to load configuration from candidate paths or embedded default
    explicit FirebaseUploader(const std::string& configPath = "");
    
    // Checks if the configuration was loaded successfully
    bool isConfigured() const { return !firebaseUrl.empty() && !apiKey.empty(); }

    // Resolves and strictly validates the Firestore base URL.
    // If FIRESTORE_EMULATOR_HOST is unset, returns "https://firestore.googleapis.com" (isEmulator = false).
    // If set to a valid loopback host (localhost, 127.0.0.1, [::1]), returns "http://" + host (isEmulator = true).
    // If set to an invalid host, scheme, or path, logs an error and returns an empty string.
    static std::string getFirestoreBaseUrl(bool& isEmulator, bool logError = true);

    // Checks if a report document with the given docId already exists in Firestore
    bool reportExists(const std::string& docId);

    // Checks if a report document exists and retrieves its upload_status ("in_progress" or "completed")
    // Returns FOUND (document exists), NOT_FOUND (explicit 404), or ERROR (network, auth, or server error)
    ReportStatusResult getReportStatus(const std::string& docId, std::string& statusOut);

    // Pure parsing helper for report status responses (for deterministic testing)
    static ReportStatusResult parseReportStatusResponse(int curlCode,
                                                       long httpCode,
                                                       const std::string& responseBody,
                                                       std::string& statusOut);

    // Updates the upload_status field of an existing report document ("in_progress" or "completed")
    bool updateReportStatus(const std::string& docId, const std::string& status);

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

    // Builds bounded Firestore document fields from a complete report JSON,
    // excluding the unbounded gadgets array to respect Firestore's 1 MiB document limit.
    static nlohmann::json buildReportDocumentFields(const nlohmann::json& inputJson);

    // Generates a collision-resistant deterministic gadget document ID incorporating
    // binary name, stable short binary hash, and gadget address.
    static std::string makeGadgetDocumentId(const std::string& binaryName,
                                            const std::string& binaryHash,
                                            uint64_t address);

    // Parses a Retry-After header string (supporting integer seconds or HTTP-date RFC 1123/850/asctime).
    // Caps the delay at maxCapSeconds (default 30s) and logs a warning when capped.
    static long parseRetryAfter(const std::string& headerValue,
                                long maxCapSeconds = 30,
                                std::chrono::system_clock::time_point now = std::chrono::system_clock::now());

    // Calculates exponential backoff delay with bounded jitter.
    // Base delay: 1s, max backoff: 16s, jitter: ±20%. If retryAfterSeconds > 0, returns retryAfterSeconds capped at 30s.
    static std::chrono::milliseconds calculateBackoffDelay(int retryAttempt,
                                                           long retryAfterSeconds = 0,
                                                           double baseDelaySeconds = 1.0,
                                                           double maxBackoffSeconds = 16.0,
                                                           double jitterFactor = 0.2);

    // Checks if a CURL error code is an approved transient network failure
    static bool isTransientCurlError(int curlCode);

    // Checks if an HTTP status code is transient (429, 500, 502, 503, 504)
    static bool isTransientHttpCode(long httpCode);

    // Executes a Firestore HTTP request with bounded retry and backoff logic
    UploadResult uploadToEndpointWithMethodEx(const std::string& endpoint,
                                             const std::string& jsonData,
                                             const std::string& method,
                                             const std::string& authToken = "",
                                             bool isEmulator = false,
                                             bool isIdempotent = true,
                                             std::chrono::milliseconds budgetDuration = std::chrono::seconds(60));

    // Getters for configuration and authentication state
    const std::string& getFirebaseUrl() const { return firebaseUrl; }
    const std::string& getApiKey() const { return apiKey; }
    const std::string& getProjectId() const { return projectId; }
    FirebaseAuth& getAuth() { return auth; }
    const FirebaseAuth& getAuth() const { return auth; }

private:
    std::string firebaseUrl;
    std::string apiKey;
    std::string projectId;
    FirebaseAuth auth;

    // Loads configuration details from the firebase_config.json file
    void loadConfig(const std::string& configPath);

    // Handles the actual CURL request to the Firestore endpoint
    bool uploadToEndpoint(const std::string& endpoint, const std::string& jsonData, bool isEmulator = false);
    bool uploadToEndpointWithMethod(const std::string& endpoint, const std::string& jsonData, const std::string& method, bool isEmulator = false);
};

} // namespace ropweaver

#endif // ROPWEAVER_FIREBASE_UPLOADER_H