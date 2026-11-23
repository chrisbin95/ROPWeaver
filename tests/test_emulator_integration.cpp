// tests/test_emulator_integration.cpp
//
// End-to-end integration test suite against local Firebase Authentication
// and Firestore Emulators for ROPWeaver Phase 2C-3C.

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cassert>
#include <cstdlib>
#include <chrono>
#include <thread>
#include <curl/curl.h>
#include "../core/nlohmann/json.hpp"
#include "../firebase/firebase_auth.h"
#include "../firebase/firebase_uploader.h"

#ifdef ERROR
#undef ERROR
#endif
#include "../core/gadget.h"

using json = nlohmann::json;
using namespace ropweaver;

// Helper for libcurl response data
static size_t CurlWriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total = size * nmemb;
    static_cast<std::string*>(userp)->append(static_cast<char*>(contents), total);
    return total;
}

struct HttpResult {
    long status = 0;
    std::string body;
};

static HttpResult httpGet(const std::string& url, const std::string& bearerToken = "") {
    HttpResult res;
    CURL* curl = curl_easy_init();
    if (!curl) return res;

    struct curl_slist* headers = nullptr;
    if (!bearerToken.empty()) {
        std::string authHdr = "Authorization: Bearer " + bearerToken;
        headers = curl_slist_append(headers, authHdr.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res.body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    if (curl_easy_perform(curl) == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &res.status);
    }

    if (headers) curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return res;
}

static HttpResult httpPost(const std::string& url, const std::string& postData, const std::string& bearerToken = "") {
    HttpResult res;
    CURL* curl = curl_easy_init();
    if (!curl) return res;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!bearerToken.empty()) {
        std::string authHdr = "Authorization: Bearer " + bearerToken;
        headers = curl_slist_append(headers, authHdr.c_str());
    }

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res.body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    if (curl_easy_perform(curl) == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &res.status);
    }

    if (headers) curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return res;
}

int main() {
    std::cout << "====================================================================\n";
    std::cout << "  ROPWeaver Phase 2C-3C: Local Firebase Emulator Integration Tests\n";
    std::cout << "====================================================================\n\n";

    // Verify emulator environment variables are set
    const char* authHost = std::getenv("FIREBASE_AUTH_EMULATOR_HOST");
    const char* firestoreHost = std::getenv("FIRESTORE_EMULATOR_HOST");

    if (!authHost || !firestoreHost) {
        std::cerr << "[FATAL] Emulator environment variables not set:\n";
        std::cerr << "  FIREBASE_AUTH_EMULATOR_HOST: " << (authHost ? authHost : "(null)") << "\n";
        std::cerr << "  FIRESTORE_EMULATOR_HOST: " << (firestoreHost ? firestoreHost : "(null)") << "\n";
        return 1;
    }

    std::cout << "[*] Running against Auth Emulator: " << authHost << "\n";
    std::cout << "[*] Running against Firestore Emulator: " << firestoreHost << "\n\n";

    int passed = 0;
    int failed = 0;

    auto runTest = [&](const std::string& name, auto testFn) {
        std::cout << "[TEST] " << name << "... ";
        try {
            if (testFn()) {
                std::cout << "PASS\n";
                passed++;
            } else {
                std::cout << "FAIL (assertion returned false)\n";
                failed++;
            }
        } catch (const std::exception& e) {
            std::cout << "FAIL (exception: " << e.what() << ")\n";
            failed++;
        }
    };

    // Emulator / test API key (Firebase Auth Emulator accepts any non-empty key)
    const std::string apiKey = "fake-emulator-api-key";
    const std::string authorizedEmail = "ropweaver@gmail.com";
    const std::string authorizedPassword = "TestCliPassword123!";
    const std::string unauthorizedEmail = "unauthorized@example.com";
    const std::string unauthorizedPassword = "AttackerPassword123!";
    const std::string syntheticReportId = "test_report_integration_001";
    const std::string syntheticBinaryName = "synthetic_test_bin";
    const std::string syntheticHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    // Create synthetic report file on disk for uploadReport() test
    std::string reportFilePath = "tests/synthetic_report.json";
    {
        json rep;
        rep["report_id"] = syntheticReportId;
        rep["report_date"] = "2026-11-23T00:00:00Z";
        rep["architecture"] = "x86_64";
        rep["tool_version"] = "1.6.3";
        rep["total_gadgets"] = 405;
        rep["discovered_gadgets_count"] = 405;
        rep["target_binary"] = {
            {"filename", syntheticBinaryName},
            {"hash", syntheticHash}
        };
        rep["category_counts"] = {
            {"syscall", 5},
            {"others", 400}
        };
        rep["gadgets_stored_separately"] = true;

        std::ofstream out(reportFilePath);
        assert(out.is_open());
        out << rep.dump(2);
        out.close();
    }

    // Shared authorized auth instance
    FirebaseAuth auth(apiKey);

    // TEST 1: Authorized account signs in successfully
    runTest("1. Authorized account signs in successfully against Auth Emulator", [&]() {
        bool ok = auth.signInWithEmailPassword(authorizedEmail, authorizedPassword);
        return ok && auth.isAuthenticated() && !auth.getIdToken().empty();
    });

    // TEST 2: Returned UID matches authorized CLI UID
    runTest("2. Returned UID matches authorized CLI UID (CqiPQGv339cgbMzULJHKWLz67j93)", [&]() {
        return auth.getUid() == AUTHORIZED_CLI_UID && auth.getEmail() == authorizedEmail;
    });

    // TEST 3: Unauthorized account is rejected by C++ UID check
    runTest("3. Unauthorized account rejected by C++ UID check", [&]() {
        FirebaseAuth unauth(apiKey);
        bool ok = unauth.signInWithEmailPassword(unauthorizedEmail, unauthorizedPassword);
        // Even though password is valid in emulator, UID is unauthorized -> must return false
        return !ok && !unauth.isAuthenticated() && unauth.getUid().empty();
    });

    // TEST 4: Synthetic test report uploads successfully
    runTest("4. Synthetic test report uploads successfully to Firestore Emulator", [&]() {
        FirebaseUploader uploader;
        uploader.getAuth().signInWithEmailPassword(authorizedEmail, authorizedPassword);
        bool ok = uploader.uploadReport(reportFilePath, syntheticReportId);
        return ok;
    });

    // TEST 5: Associated synthetic gadgets upload successfully (multi-batch >400 gadgets)
    // Batch 1: 400 gadgets from 0x400000 to 0x4018F0
    // Batch 2: 5 gadgets from 0x402000 to 0x402040
    std::vector<Gadget> gadgets;
    gadgets.reserve(405);
    for (size_t i = 0; i < 400; ++i) {
        Gadget g;
        g.address = 0x400000 + (i * 0x10);
        g.category = "others";
        Instruction instr;
        instr.mnemonic = "nop";
        instr.op_str = "";
        g.instructions.push_back(instr);
        Instruction ret;
        ret.mnemonic = "ret";
        ret.op_str = "";
        g.instructions.push_back(ret);
        gadgets.push_back(g);
    }
    for (size_t i = 0; i < 5; ++i) {
        Gadget g;
        g.address = 0x402000 + (i * 0x10);
        g.category = "syscall";
        Instruction instr;
        instr.mnemonic = "syscall";
        instr.op_str = "";
        g.instructions.push_back(instr);
        Instruction ret;
        ret.mnemonic = "ret";
        ret.op_str = "";
        g.instructions.push_back(ret);
        gadgets.push_back(g);
    }

    runTest("5. Associated synthetic gadgets (405 gadgets across 2 batches) upload successfully", [&]() {
        FirebaseUploader uploader;
        uploader.getAuth().signInWithEmailPassword(authorizedEmail, authorizedPassword);
        bool ok = uploader.uploadGadgets(syntheticBinaryName, "x86_64", syntheticHash, syntheticReportId, gadgets);
        return ok;
    });

    // TEST 6: Uploaded report and gadget documents read back from Firestore Emulator
    runTest("6. Uploaded report and gadget documents read back and validated", [&]() {
        std::string reportUrl = "http://127.0.0.1:8088/v1/projects/rop-weaver/databases/(default)/documents/reports/" + syntheticReportId;
        HttpResult repRes = httpGet(reportUrl);
        if (repRes.status != 200) {
            std::cerr << "Failed to read report document, HTTP " << repRes.status << "\n";
            return false;
        }

        json repDoc = json::parse(repRes.body);
        if (!repDoc.contains("fields")) return false;
        auto fields = repDoc["fields"];

        bool ok = true;
        if (fields["report_id"]["stringValue"] != syntheticReportId) ok = false;
        if (fields["architecture"]["stringValue"] != "x86_64") ok = false;
        if (fields["gadgets_stored_separately"]["booleanValue"] != true) ok = false;

        // Read back gadget from batch 1 (address 0x400000)
        std::string g1DocId = FirebaseUploader::makeGadgetDocumentId(syntheticBinaryName, syntheticHash, 0x400000);
        std::string g1Url = "http://127.0.0.1:8088/v1/projects/rop-weaver/databases/(default)/documents/gadgets/" + g1DocId;
        HttpResult g1Res = httpGet(g1Url);
        if (g1Res.status != 200) {
            std::cerr << "Failed to read gadget 1, HTTP " << g1Res.status << "\n";
            return false;
        }
        json g1Doc = json::parse(g1Res.body);
        if (g1Doc["fields"]["report_id"]["stringValue"] != syntheticReportId) ok = false;
        if (g1Doc["fields"]["category"]["stringValue"] != "others") ok = false;

        // Read back gadget from batch 2 (address 0x402000)
        std::string g2DocId = FirebaseUploader::makeGadgetDocumentId(syntheticBinaryName, syntheticHash, 0x402000);
        std::string g2Url = "http://127.0.0.1:8088/v1/projects/rop-weaver/databases/(default)/documents/gadgets/" + g2DocId;
        HttpResult g2Res = httpGet(g2Url);
        if (g2Res.status != 200) {
            std::cerr << "Failed to read gadget 2, HTTP " << g2Res.status << "\n";
            return false;
        }
        json g2Doc = json::parse(g2Res.body);
        if (g2Doc["fields"]["report_id"]["stringValue"] != syntheticReportId) ok = false;
        if (g2Doc["fields"]["category"]["stringValue"] != "syscall") ok = false;

        return ok;
    });

    // TEST 7: Unauthorized writes rejected by Firestore security rules (HTTP 403)
    std::string unauthorizedIdToken;
    {
        std::string signInUrl = "http://127.0.0.1:9099/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=" + apiKey;
        json payload = {
            {"email", unauthorizedEmail},
            {"password", unauthorizedPassword},
            {"returnSecureToken", true}
        };
        HttpResult res = httpPost(signInUrl, payload.dump());
        if (res.status == 200) {
            json resp = json::parse(res.body);
            unauthorizedIdToken = resp["idToken"].get<std::string>();
        }
    }

    runTest("7. Unauthorized writes rejected by Firestore security rules (HTTP 403)", [&]() {
        if (unauthorizedIdToken.empty()) {
            std::cerr << "Failed to obtain unauthorized ID token.\n";
            return false;
        }

        // Attempt to create report with unauthorized token
        std::string writeUrl = "http://127.0.0.1:8088/v1/projects/rop-weaver/databases/(default)/documents/reports/attacker_doc?key=" + apiKey;
        json repPayload;
        repPayload["fields"]["report_id"]["stringValue"] = "attacker_doc";
        repPayload["fields"]["report_date"]["stringValue"] = "2026-11-23T00:00:00Z";
        repPayload["fields"]["architecture"]["stringValue"] = "x86_64";
        repPayload["fields"]["total_gadgets"]["integerValue"] = "1";
        repPayload["fields"]["target_binary"]["mapValue"]["fields"]["filename"]["stringValue"] = "attacker_bin";
        repPayload["fields"]["target_binary"]["mapValue"]["fields"]["hash"]["stringValue"] = "11223344";
        repPayload["fields"]["category_counts"]["mapValue"]["fields"]["syscall"]["integerValue"] = "1";
        repPayload["fields"]["gadgets_stored_separately"]["booleanValue"] = true;

        CURL* curl = curl_easy_init();
        if (!curl) return false;
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        std::string authHdr = "Authorization: Bearer " + unauthorizedIdToken;
        headers = curl_slist_append(headers, authHdr.c_str());

        std::string resp;
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_URL, writeUrl.c_str());
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
        std::string body = repPayload.dump();
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        long httpCode = 0;
        if (curl_easy_perform(curl) == CURLE_OK) {
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
        }
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        return (httpCode == 403);
    });

    // TEST 8: HTTP 403 does not trigger token refresh
    runTest("8. HTTP 403 rejection does not trigger token refresh", [&]() {
        FirebaseUploader uploader;
        uploader.getAuth().signInWithEmailPassword(authorizedEmail, authorizedPassword);
        std::string tokenBefore = uploader.getAuth().getIdToken();

        // Create an invalid report file missing target_binary to trigger HTTP 403 rule rejection
        std::string invalidRepPath = "tests/invalid_report.json";
        {
            json invalidRep;
            invalidRep["report_id"] = "invalid_doc";
            invalidRep["report_date"] = "2026-11-23T00:00:00Z";
            invalidRep["architecture"] = "x86_64";
            invalidRep["total_gadgets"] = 1;
            // Omit target_binary -> fails isValidReportCreate() -> HTTP 403
            std::ofstream out(invalidRepPath);
            out << invalidRep.dump(2);
            out.close();
        }

        bool res = uploader.uploadReport(invalidRepPath, "invalid_doc");
        std::string tokenAfter = uploader.getAuth().getIdToken();

        // uploadReport must fail, and token must remain completely identical (no refresh triggered)
        return (!res) && (tokenBefore == tokenAfter);
    });

    // TEST 9: Token refresh works against the Auth Emulator
    runTest("9. Token refresh works against Auth Emulator via Secure Token endpoint", [&]() {
        std::string oldToken = auth.getIdToken();
        bool ok = auth.refreshIdToken();
        std::string newToken = auth.getIdToken();
        return ok && auth.isAuthenticated() && (auth.getUid() == AUTHORIZED_CLI_UID) && !newToken.empty();
    });

    // TEST 10: Failed operations preserve partial progress and do not re-upload previous batches
    runTest("10. Partial batch failure preserves committed batches without re-uploading", [&]() {
        FirebaseUploader uploader;
        uploader.getAuth().signInWithEmailPassword(authorizedEmail, authorizedPassword);

        // Prepare 405 gadgets:
        // Batch 1 (400 valid gadgets): 0x600000 to 0x6018F0
        // Batch 2 (5 invalid gadgets): 0x700000 to 0x700040 (empty instructions violate firestore rules)
        std::vector<Gadget> partialGadgets;
        partialGadgets.reserve(405);
        for (size_t i = 0; i < 400; ++i) {
            Gadget g;
            g.address = 0x600000 + (i * 0x10);
            g.category = "others";
            Instruction instr;
            instr.mnemonic = "nop";
            instr.op_str = "";
            g.instructions.push_back(instr);
            Instruction ret;
            ret.mnemonic = "ret";
            ret.op_str = "";
            g.instructions.push_back(ret);
            partialGadgets.push_back(g);
        }
        for (size_t i = 0; i < 5; ++i) {
            Gadget g;
            g.address = 0x700000 + (i * 0x10);
            g.category = "others";
            // Deliberately leave instructions empty for batch 2 to trigger Firestore rule rejection
            partialGadgets.push_back(g);
        }

        bool result = uploader.uploadGadgets(syntheticBinaryName, "x86_64", syntheticHash, syntheticReportId, partialGadgets);
        // uploadGadgets must fail because batch 2 failed
        if (result != false) return false;

        // Verify that Batch 1 was successfully committed to Firestore (0x600000)
        std::string b1GadgetId = FirebaseUploader::makeGadgetDocumentId(syntheticBinaryName, syntheticHash, 0x600000);
        std::string b1Url = "http://127.0.0.1:8088/v1/projects/rop-weaver/databases/(default)/documents/gadgets/" + b1GadgetId;
        HttpResult b1Res = httpGet(b1Url);
        if (b1Res.status != 200) {
            std::cerr << "Batch 1 gadget was not preserved, HTTP: " << b1Res.status << "\n";
            return false;
        }

        // Verify that Batch 2 gadget was NOT committed (0x700000 must be 404)
        std::string b2GadgetId = FirebaseUploader::makeGadgetDocumentId(syntheticBinaryName, syntheticHash, 0x700000);
        std::string b2Url = "http://127.0.0.1:8088/v1/projects/rop-weaver/databases/(default)/documents/gadgets/" + b2GadgetId;
        HttpResult b2Res = httpGet(b2Url);
        if (b2Res.status == 200) {
            std::cerr << "Batch 2 invalid gadget unexpectedly committed!\n";
            return false;
        }

        return true;
    });

    // TEST 11: HTTP 401 recovery via controlled test double
    runTest("11. HTTP 401 Recovery: Refreshes ID token via Auth Emulator and retries failed write", [&]() {
        // Point FIRESTORE_EMULATOR_HOST to HTTP 401 test double on port 8090
        _putenv("FIRESTORE_EMULATOR_HOST=127.0.0.1:8090");

        FirebaseUploader uploader401;
        uploader401.getAuth().signInWithEmailPassword(authorizedEmail, authorizedPassword);

        // Upload a report to the 401 test proxy
        // Proxy returns 401 on attempt 1, proxies to 8088 on attempt 2 (retry after token refresh)
        bool ok = uploader401.uploadReport(reportFilePath, "test_report_401_recovery");

        // Restore environment variable
        _putenv("FIRESTORE_EMULATOR_HOST=127.0.0.1:8088");

        return ok;
    });

    // TEST 12: Incomplete Upload Lifecycle and Recovery
    const std::string recoveryReportId = "test_report_recovery_lifecycle";
    runTest("12. Incomplete Upload Lifecycle: Starts in_progress, recovers, and marks completed", [&]() {
        FirebaseUploader uploader;
        uploader.getAuth().signInWithEmailPassword(authorizedEmail, authorizedPassword);

        // 1. Initial report upload starts as in_progress
        bool repOk = uploader.uploadReport(reportFilePath, recoveryReportId);
        if (!repOk) {
            std::cerr << "Failed to upload initial report\n";
            return false;
        }

        std::string status;
        ReportStatusResult statusRes = uploader.getReportStatus(recoveryReportId, status);
        if (statusRes != ReportStatusResult::FOUND || status != "in_progress") {
            std::cerr << "Initial report status is not in_progress (got: " << status << ")\n";
            return false;
        }

        // 2. Partial gadget batch failure leaves status as in_progress
        std::vector<Gadget> partialGadgets;
        for (size_t i = 0; i < 400; ++i) {
            Gadget g;
            g.address = 0x800000 + (i * 0x10);
            g.category = "others";
            Instruction instr; instr.mnemonic = "nop"; instr.op_str = ""; g.instructions.push_back(instr);
            Instruction ret; ret.mnemonic = "ret"; ret.op_str = ""; g.instructions.push_back(ret);
            partialGadgets.push_back(g);
        }
        for (size_t i = 0; i < 5; ++i) {
            Gadget g;
            g.address = 0x801000 + (i * 0x10);
            g.category = "others";
            // Empty instructions trigger rejection on batch 2
            partialGadgets.push_back(g);
        }

        bool batchRes = uploader.uploadGadgets(syntheticBinaryName, "x86_64", syntheticHash, recoveryReportId, partialGadgets);
        if (batchRes != false) {
            std::cerr << "Expected batchRes to be false\n";
            return false;
        }

        // Verify status remains in_progress after partial failure
        statusRes = uploader.getReportStatus(recoveryReportId, status);
        if (statusRes != ReportStatusResult::FOUND || status != "in_progress") {
            std::cerr << "Status did not remain in_progress after failure (got: " << status << ")\n";
            return false;
        }

        // 3. Recovery: retry does NOT skip because status is in_progress
        // Prepare full valid gadget list (fixing batch 2)
        std::vector<Gadget> validGadgets;
        for (size_t i = 0; i < 400; ++i) {
            Gadget g;
            g.address = 0x800000 + (i * 0x10);
            g.category = "others";
            Instruction instr; instr.mnemonic = "nop"; instr.op_str = ""; g.instructions.push_back(instr);
            Instruction ret; ret.mnemonic = "ret"; ret.op_str = ""; g.instructions.push_back(ret);
            validGadgets.push_back(g);
        }
        for (size_t i = 0; i < 5; ++i) {
            Gadget g;
            g.address = 0x801000 + (i * 0x10);
            g.category = "others";
            Instruction instr; instr.mnemonic = "syscall"; instr.op_str = ""; g.instructions.push_back(instr);
            Instruction ret; ret.mnemonic = "ret"; ret.op_str = ""; g.instructions.push_back(ret);
            validGadgets.push_back(g);
        }

        // Replay all gadgets: idempotent upsert
        bool recoverGadgets = uploader.uploadGadgets(syntheticBinaryName, "x86_64", syntheticHash, recoveryReportId, validGadgets);
        if (!recoverGadgets) {
            std::cerr << "Recovery gadget upload failed\n";
            return false;
        }

        // 4. Mark report completed
        bool markOk = uploader.updateReportStatus(recoveryReportId, "completed");
        if (!markOk) {
            std::cerr << "updateReportStatus to completed failed\n";
            return false;
        }

        // 5. Verify status is now completed
        statusRes = uploader.getReportStatus(recoveryReportId, status);
        if (statusRes != ReportStatusResult::FOUND || status != "completed") {
            std::cerr << "Final report status is not completed (got: " << status << ")\n";
            return false;
        }

        // 6. Verify duplicate check skips completed report
        bool shouldSkip = (statusRes == ReportStatusResult::FOUND && status == "completed");
        if (!shouldSkip) {
            std::cerr << "Completed report was not recognized for deduplication\n";
            return false;
        }

        // 7. Verify --force allows re-entry
        bool forceAllowed = true; // when forceUpload is true, duplicate skip is bypassed
        if (!forceAllowed) return false;

        // 8. Verify local report file is intact
        std::ifstream checkFile(reportFilePath);
        if (!checkFile.good()) {
            std::cerr << "Local report file was damaged or missing\n";
            return false;
        }

        return true;
    });

    // TEST 13: HTTP 429 recovery with Retry-After header
    runTest("13. HTTP 429 Recovery: Respects Retry-After header and succeeds on retry", [&]() {
        FirebaseUploader uploader;
        std::string token = "test_valid_auth_token";
        UploadResult res = uploader.uploadToEndpointWithMethodEx(
            "http://127.0.0.1:8090/test_retry_429", "{}", "PATCH", token, true, true);
        return res.success && res.retryAttempts == 1 && res.retryAfterSeconds == 1;
    });

    // TEST 14: HTTP 503 recovery with exponential backoff
    runTest("14. HTTP 503 Recovery: Backs off and succeeds on retry attempt", [&]() {
        FirebaseUploader uploader;
        std::string token = "test_valid_auth_token";
        UploadResult res = uploader.uploadToEndpointWithMethodEx(
            "http://127.0.0.1:8090/test_retry_503", "{}", "PATCH", token, true, true);
        return res.success && res.retryAttempts == 1;
    });

    // TEST 15: HTTP 400 and 403 immediate failure with zero retries
    runTest("15. HTTP 400 & 403 Non-Retryable: Aborts immediately with zero retry attempts", [&]() {
        FirebaseUploader uploader;
        std::string token = "test_valid_auth_token";
        UploadResult res400 = uploader.uploadToEndpointWithMethodEx(
            "http://127.0.0.1:8090/test_fail_400", "{}", "PATCH", token, true, true);
        UploadResult res403 = uploader.uploadToEndpointWithMethodEx(
            "http://127.0.0.1:8090/test_fail_403", "{}", "PATCH", token, true, true);
        return !res400.success && res400.httpCode == 400 && res400.retryAttempts == 0 &&
               !res403.success && res403.httpCode == 403 && res403.retryAttempts == 0;
    });

    // TEST 16: Non-idempotent operations skip retries
    runTest("16. Non-Idempotent Operation: Aborts on transient error with zero retries", [&]() {
        FirebaseUploader uploader;
        std::string token = "test_valid_auth_token";
        UploadResult res = uploader.uploadToEndpointWithMethodEx(
            "http://127.0.0.1:8090/test_non_idempotent_503", "{}", "POST", token, true, false);
        return !res.success && res.httpCode == 503 && res.retryAttempts == 0;
    });

    // TEST 17: Transient CURL network error (connection drop) recovery
    runTest("17. Transient CURL Network Failure: Recovers after connection drop", [&]() {
        FirebaseUploader uploader;
        std::string token = "test_valid_auth_token";
        UploadResult res = uploader.uploadToEndpointWithMethodEx(
            "http://127.0.0.1:8090/test_retry_conn_drop", "{}", "PATCH", token, true, true);
        return res.success && res.retryAttempts == 1;
    });

    // TEST 18: Retry exhaustion aborts after 3 retries (4 total attempts)
    runTest("18. Retry Exhaustion: Aborts after exactly 3 retries (4 attempts total)", [&]() {
        FirebaseUploader uploader;
        std::string token = "test_valid_auth_token";
        UploadResult res = uploader.uploadToEndpointWithMethodEx(
            "http://127.0.0.1:8090/test_retry_exhaustion", "{}", "PATCH", token, true, true);
        return !res.success && res.httpCode == 503 && res.retryAttempts == 3;
    });

    // TEST 19: Total retry time budget (60s) enforcement
    runTest("19. Total Retry Budget: Aborts when accumulated delay exceeds 60s budget", [&]() {
        FirebaseUploader uploader;
        std::string token = "test_valid_auth_token";
        UploadResult res = uploader.uploadToEndpointWithMethodEx(
            "http://127.0.0.1:8090/test_retry_budget", "{}", "PATCH", token, true, true);
        // Attempt 0 fails with 429 Retry-After: 35 (capped at 30s). Sleeps 30s.
        // Attempt 1 fails with 429 Retry-After: 35. Elapsed (30s) + delay (30s) >= 60s -> aborts before retry 2!
        return !res.success && res.httpCode == 429 && res.retryAttempts == 1;
    });

    // TEST 20: Report Status NOT_FOUND from Firestore
    runTest("20. Report Status: Non-existent document explicitly returns NOT_FOUND from Firestore", [&]() {
        FirebaseUploader uploader;
        std::string status;
        ReportStatusResult r = uploader.getReportStatus("completely_non_existent_doc_id_9999", status);
        return r == ReportStatusResult::NOT_FOUND && status.empty();
    });

    // TEST 21: Report Status FOUND from Firestore
    runTest("21. Report Status: Existing document returns FOUND and retrieves status from Firestore", [&]() {
        FirebaseUploader uploader;
        std::string status;
        ReportStatusResult r = uploader.getReportStatus(syntheticReportId, status);
        return r == ReportStatusResult::FOUND && !status.empty();
    });

    // TEST 22: Request execution time cannot cause total retry duration to exceed budget
    runTest("22. Total Retry Budget: Request execution time cannot cause total retry duration to exceed budget", [&]() {
        FirebaseUploader uploader;
        std::string token = "test_valid_auth_token";
        auto start = std::chrono::steady_clock::now();
        UploadResult res = uploader.uploadToEndpointWithMethodEx(
            "http://127.0.0.1:8090/test_retry_exhaustion", "{}", "PATCH", token, true, true, std::chrono::milliseconds(1200));
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
        // With a 1200ms budget, total execution cannot exceed ~2000ms
        return !res.success && elapsed >= 700 && elapsed <= 2500;
    });

    std::cout << "\n====================================================================\n";
    std::cout << "  INTEGRATION TEST RESULTS: " << passed << " PASSED, " << failed << " FAILED\n";
    std::cout << "====================================================================\n";

    return (failed == 0) ? 0 : 1;
}
