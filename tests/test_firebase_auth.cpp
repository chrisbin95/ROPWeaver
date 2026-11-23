// tests/test_firebase_auth.cpp

#include <iostream>
#include <cassert>
#include <string>
#include <cstdlib>
#include <curl/curl.h>
#include "../firebase/firebase_auth.h"
#include "../firebase/firebase_uploader.h"

#ifdef ERROR
#undef ERROR
#endif

using namespace ropweaver;

int main() {
    std::cout << "====================================================================\n";
    std::cout << "  ROPWeaver Unit Test: Firebase Authentication Component\n";
    std::cout << "====================================================================\n\n";

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

    // 1. Constants verification
    runTest("Authorized Configuration Constants", [&]() {
        bool ok = true;
        if (std::string(DEFAULT_AUTHORIZED_EMAIL) != "ropweaver@gmail.com") ok = false;
        if (std::string(AUTHORIZED_CLI_UID) != "CqiPQGv339cgbMzULJHKWLz67j93") ok = false;
        return ok;
    });

    // 2. Initial state
    runTest("Initial State is Unauthenticated", [&]() {
        FirebaseAuth auth("dummy_api_key");
        return !auth.isAuthenticated() && auth.isTokenExpiring(0) && auth.getUid().empty();
    });

    // 3. Injected Valid Tokens (Authorized UID)
    runTest("Injected Valid Tokens with Authorized UID", [&]() {
        FirebaseAuth auth("dummy_api_key");
        auth.injectTokensForTesting("mock_id_token_123", "mock_refresh_token_456", AUTHORIZED_CLI_UID, DEFAULT_AUTHORIZED_EMAIL, 3600);
        return auth.isAuthenticated() && !auth.isTokenExpiring(60) && auth.getUid() == AUTHORIZED_CLI_UID;
    });

    // 4. Token Expiry Check
    runTest("Token Expiring Detection", [&]() {
        FirebaseAuth auth("dummy_api_key");
        // Expiring in 30 seconds
        auth.injectTokensForTesting("mock_id_token_123", "mock_refresh_token_456", AUTHORIZED_CLI_UID, DEFAULT_AUTHORIZED_EMAIL, 30);
        // Window 60s should detect it as expiring
        bool expiringAt60 = auth.isTokenExpiring(60);
        // Window 10s should not detect it as expiring yet
        bool expiringAt10 = auth.isTokenExpiring(10);
        return expiringAt60 && !expiringAt10;
    });

    // 5. Strict UID Mismatch Rejection
    runTest("Strict UID Mismatch Rejection", [&]() {
        FirebaseAuth auth("dummy_api_key");
        // Inject with an unauthorized UID
        auth.injectTokensForTesting("mock_id_token_123", "mock_refresh_token_456", "unauthorized_attacker_uid_999", "attacker@evil.com", 3600);
        // Must reject!
        return !auth.isAuthenticated();
    });

    // 6. SignOut Resets State
    runTest("SignOut Clears In-Memory Tokens", [&]() {
        FirebaseAuth auth("dummy_api_key");
        auth.injectTokensForTesting("mock_id_token_123", "mock_refresh_token_456", AUTHORIZED_CLI_UID, DEFAULT_AUTHORIZED_EMAIL, 3600);
        if (!auth.isAuthenticated()) return false;
        auth.signOut();
        return !auth.isAuthenticated() && auth.getUid().empty();
    });

    // 7. Emulator URL Resolution: Default production URLs
    runTest("Default Production URL Resolution", [&]() {
#if defined(_WIN32)
        _putenv("FIREBASE_AUTH_EMULATOR_HOST=");
#else
        unsetenv("FIREBASE_AUTH_EMULATOR_HOST");
#endif
        bool isEmulator = false;
        std::string authUrl = FirebaseAuth::getAuthBaseUrl(isEmulator, false);
        std::string tokenUrl = FirebaseAuth::getSecureTokenBaseUrl(isEmulator, false);
        return !isEmulator && 
               authUrl == "https://identitytoolkit.googleapis.com" &&
               tokenUrl == "https://securetoken.googleapis.com";
    });

    // 8. Emulator URL Resolution: Loopback emulator host with microservice prefixes
    runTest("Emulator Host URL Resolution with Microservice Prefixes", [&]() {
#if defined(_WIN32)
        _putenv("FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099");
#else
        setenv("FIREBASE_AUTH_EMULATOR_HOST", "127.0.0.1:9099", 1);
#endif
        bool isEmulator = false;
        std::string authUrl = FirebaseAuth::getAuthBaseUrl(isEmulator, false);
        std::string tokenUrl = FirebaseAuth::getSecureTokenBaseUrl(isEmulator, false);

        // Reset env
#if defined(_WIN32)
        _putenv("FIREBASE_AUTH_EMULATOR_HOST=");
#else
        unsetenv("FIREBASE_AUTH_EMULATOR_HOST");
#endif
        return isEmulator && 
               authUrl == "http://127.0.0.1:9099/identitytoolkit.googleapis.com" &&
               tokenUrl == "http://127.0.0.1:9099/securetoken.googleapis.com";
    });

    // 9. Emulator URL Resolution: Rejection of non-loopback hosts
    runTest("Emulator Rejection of Non-Loopback Hosts", [&]() {
#if defined(_WIN32)
        _putenv("FIREBASE_AUTH_EMULATOR_HOST=evil-remote-host.com:9099");
#else
        setenv("FIREBASE_AUTH_EMULATOR_HOST", "evil-remote-host.com:9099", 1);
#endif
        bool isEmulator = false;
        std::string authUrl = FirebaseAuth::getAuthBaseUrl(isEmulator, false);

        // Reset env
#if defined(_WIN32)
        _putenv("FIREBASE_AUTH_EMULATOR_HOST=");
#else
        unsetenv("FIREBASE_AUTH_EMULATOR_HOST");
#endif
        return authUrl.empty();
    });

    // 10. Credential Resolution from Environment
    runTest("Credential Resolution from Environment", [&]() {
#if defined(_WIN32)
        _putenv("ROPWEAVER_FIREBASE_EMAIL=custom_cli@ropweaver.org");
        _putenv("ROPWEAVER_FIREBASE_PASSWORD=SuperSecretPass123!");
#else
        setenv("ROPWEAVER_FIREBASE_EMAIL", "custom_cli@ropweaver.org", 1);
        setenv("ROPWEAVER_FIREBASE_PASSWORD", "SuperSecretPass123!", 1);
#endif
        std::string email;
        std::string password;
        bool ok = FirebaseAuth::resolveCredentials(email, password);

        // Clean up env immediately
#if defined(_WIN32)
        _putenv("ROPWEAVER_FIREBASE_EMAIL=");
        _putenv("ROPWEAVER_FIREBASE_PASSWORD=");
#else
        unsetenv("ROPWEAVER_FIREBASE_EMAIL");
        unsetenv("ROPWEAVER_FIREBASE_PASSWORD");
#endif
        return ok && email == "custom_cli@ropweaver.org" && password == "SuperSecretPass123!";
    });

    // 11. Refresh Token: Reject Empty user_id in Response
    runTest("Refresh Response Rejects Empty user_id", [&]() {
        FirebaseAuth auth("dummy_api_key");
        // Start in valid authenticated state
        auth.injectTokensForTesting("old_id_token", "old_refresh_token", AUTHORIZED_CLI_UID, DEFAULT_AUTHORIZED_EMAIL, 3600);
        if (!auth.isAuthenticated()) return false;

        std::string mockResponseEmptyUid = R"({
            "id_token": "new_id_token_123",
            "refresh_token": "new_refresh_token_456",
            "user_id": "",
            "expires_in": "3600"
        })";

        bool result = auth.processRefreshTokenResponse(mockResponseEmptyUid, 200);
        // Must return false and invalidate authentication session
        return !result && !auth.isAuthenticated() && auth.getUid().empty();
    });

    // 12. Refresh Token: Reject Mismatched user_id in Response
    runTest("Refresh Response Rejects Mismatched user_id", [&]() {
        FirebaseAuth auth("dummy_api_key");
        auth.injectTokensForTesting("old_id_token", "old_refresh_token", AUTHORIZED_CLI_UID, DEFAULT_AUTHORIZED_EMAIL, 3600);
        if (!auth.isAuthenticated()) return false;

        std::string mockResponseMismatchedUid = R"({
            "id_token": "new_id_token_123",
            "refresh_token": "new_refresh_token_456",
            "user_id": "unauthorized_attacker_uid_999",
            "expires_in": "3600"
        })";

        bool result = auth.processRefreshTokenResponse(mockResponseMismatchedUid, 200);
        // Must return false and invalidate authentication session
        return !result && !auth.isAuthenticated() && auth.getUid().empty();
    });

    // 13. Refresh Token: Accept Authorized user_id and Update Both Tokens
    runTest("Refresh Response Accepts Authorized user_id and Updates Tokens", [&]() {
        FirebaseAuth auth("dummy_api_key");
        auth.injectTokensForTesting("old_id_token", "old_refresh_token", AUTHORIZED_CLI_UID, DEFAULT_AUTHORIZED_EMAIL, 3600);

        std::string mockResponseValid = std::string(R"({
            "id_token": "new_refreshed_id_token_789",
            "refresh_token": "new_refreshed_refresh_token_abc",
            "user_id": ")") + AUTHORIZED_CLI_UID + R"(",
            "expires_in": "3600"
        })";

        bool result = auth.processRefreshTokenResponse(mockResponseValid, 200);
        return result && auth.isAuthenticated() && 
               auth.getIdToken() == "new_refreshed_id_token_789" &&
               auth.getUid() == AUTHORIZED_CLI_UID;
    });

    // 14. Project ID Fallback Resolves to rop-weaver
    runTest("Uploader Project ID Fallback Resolves to rop-weaver", [&]() {
        FirebaseUploader uploader;
        return uploader.getProjectId() == "rop-weaver";
    });

    // 15. Retry-After: Integer seconds parsing
    runTest("Retry-After: Integer Seconds Parsing", [&]() {
        bool ok = true;
        if (FirebaseUploader::parseRetryAfter("5") != 5) ok = false;
        if (FirebaseUploader::parseRetryAfter("0") != 0) ok = false;
        if (FirebaseUploader::parseRetryAfter("") != 0) ok = false;
        if (FirebaseUploader::parseRetryAfter("   12   ") != 12) ok = false;
        if (FirebaseUploader::parseRetryAfter("-5") != 0) ok = false;
        return ok;
    });

    // 16. Retry-After: HTTP-date parsing
    runTest("Retry-After: HTTP-date Parsing (RFC 1123)", [&]() {
        // Construct reference time: Nov 6 1994 08:49:37 GMT
        std::tm tmNow = {};
        tmNow.tm_year = 94; // 1994
        tmNow.tm_mon = 10;  // Nov
        tmNow.tm_mday = 6;
        tmNow.tm_hour = 8;
        tmNow.tm_min = 49;
        tmNow.tm_sec = 37;
#if defined(_WIN32)
        time_t nowT = _mkgmtime(&tmNow);
#else
        time_t nowT = timegm(&tmNow);
#endif
        auto testNow = std::chrono::system_clock::from_time_t(nowT);

        // Date 10 seconds later: Nov 6 1994 08:49:47 GMT
        std::string dateStr10s = "Sun, 06 Nov 1994 08:49:47 GMT";
        long res10 = FirebaseUploader::parseRetryAfter(dateStr10s, 30, testNow);
        if (res10 != 10) return false;

        // Date in the past relative to now
        std::string datePast = "Sun, 06 Nov 1994 08:49:20 GMT";
        long resPast = FirebaseUploader::parseRetryAfter(datePast, 30, testNow);
        if (resPast != 0) return false;

        return true;
    });

    // 17. Retry-After: 120s value capped at 30s
    runTest("Retry-After: 120s Value Capped at 30s", [&]() {
        bool ok = true;
        if (FirebaseUploader::parseRetryAfter("120", 30) != 30) ok = false;
        if (FirebaseUploader::parseRetryAfter("300", 30) != 30) ok = false;
        if (FirebaseUploader::parseRetryAfter("25", 30) != 25) ok = false;
        return ok;
    });

    // 18. Backoff calculation and jitter bounds
    runTest("Exponential Backoff Calculation and Jitter Bounds", [&]() {
        bool ok = true;
        // Attempt 0: base 1s, bounded in [0.8s, 1.2s]
        for (int i = 0; i < 20; ++i) {
            auto d = FirebaseUploader::calculateBackoffDelay(0).count();
            if (d < 800 || d > 1200) ok = false;
        }
        // Attempt 1: base 2s, bounded in [1.6s, 2.4s]
        for (int i = 0; i < 20; ++i) {
            auto d = FirebaseUploader::calculateBackoffDelay(1).count();
            if (d < 1600 || d > 2400) ok = false;
        }
        // Attempt 2: base 4s, bounded in [3.2s, 4.8s]
        for (int i = 0; i < 20; ++i) {
            auto d = FirebaseUploader::calculateBackoffDelay(2).count();
            if (d < 3200 || d > 4800) ok = false;
        }
        // Attempt 3: base 8s, bounded in [6.4s, 9.6s]
        for (int i = 0; i < 20; ++i) {
            auto d = FirebaseUploader::calculateBackoffDelay(3).count();
            if (d < 6400 || d > 9600) ok = false;
        }
        // Attempt 4 & 5: capped base 16s, bounded in [12.8s, 19.2s]
        for (int i = 0; i < 20; ++i) {
            auto d4 = FirebaseUploader::calculateBackoffDelay(4).count();
            auto d5 = FirebaseUploader::calculateBackoffDelay(5).count();
            if (d4 < 12800 || d4 > 19200) ok = false;
            if (d5 < 12800 || d5 > 19200) ok = false;
        }
        // Explicit Retry-After
        if (FirebaseUploader::calculateBackoffDelay(0, 5).count() != 5000) ok = false;
        if (FirebaseUploader::calculateBackoffDelay(0, 45).count() != 30000) ok = false;

        return ok;
    });

    // 19. Transient HTTP codes and CURL errors filter
    runTest("Transient HTTP Codes and CURL Errors Filter", [&]() {
        bool ok = true;
        // HTTP codes
        if (!FirebaseUploader::isTransientHttpCode(429)) ok = false;
        if (!FirebaseUploader::isTransientHttpCode(500)) ok = false;
        if (!FirebaseUploader::isTransientHttpCode(502)) ok = false;
        if (!FirebaseUploader::isTransientHttpCode(503)) ok = false;
        if (!FirebaseUploader::isTransientHttpCode(504)) ok = false;
        if (FirebaseUploader::isTransientHttpCode(200)) ok = false;
        if (FirebaseUploader::isTransientHttpCode(400)) ok = false;
        if (FirebaseUploader::isTransientHttpCode(401)) ok = false;
        if (FirebaseUploader::isTransientHttpCode(403)) ok = false;
        if (FirebaseUploader::isTransientHttpCode(404)) ok = false;

        // CURL error codes
        if (!FirebaseUploader::isTransientCurlError(CURLE_OPERATION_TIMEDOUT)) ok = false;
        if (!FirebaseUploader::isTransientCurlError(CURLE_COULDNT_CONNECT)) ok = false;
        if (!FirebaseUploader::isTransientCurlError(CURLE_COULDNT_RESOLVE_HOST)) ok = false;
        if (!FirebaseUploader::isTransientCurlError(CURLE_RECV_ERROR)) ok = false;
        if (!FirebaseUploader::isTransientCurlError(CURLE_SEND_ERROR)) ok = false;
        if (!FirebaseUploader::isTransientCurlError(CURLE_PARTIAL_FILE)) ok = false;
        if (FirebaseUploader::isTransientCurlError(CURLE_OK)) ok = false;
        if (FirebaseUploader::isTransientCurlError(CURLE_SSL_CONNECT_ERROR)) ok = false;
        if (FirebaseUploader::isTransientCurlError(CURLE_URL_MALFORMAT)) ok = false;

        return ok;
    });

    // 20. Transient Authentication Network Failure Preserves Refresh Token
    runTest("Transient Network Failure During Token Refresh Preserves Refresh Token", [&]() {
        FirebaseAuth auth("dummy_api_key");
        const std::string mockRefreshToken = "preserve_me_valid_refresh_token_123";
        auth.injectTokensForTesting("expired_id_token", mockRefreshToken, AUTHORIZED_CLI_UID, DEFAULT_AUTHORIZED_EMAIL, 0);

        // Point emulator host to a non-listening loopback port
#if defined(_WIN32)
        _putenv("FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9998");
#else
        setenv("FIREBASE_AUTH_EMULATOR_HOST", "127.0.0.1:9998", 1);
#endif
        bool refreshSuccess = auth.refreshIdToken();

        // Reset env
#if defined(_WIN32)
        _putenv("FIREBASE_AUTH_EMULATOR_HOST=");
#else
        unsetenv("FIREBASE_AUTH_EMULATOR_HOST");
#endif

        // Must fail the network call, but NOT erase the refresh token
        bool preserved = (auth.getRefreshToken() == mockRefreshToken);
        return !refreshSuccess && preserved;
    });

    // 21. Confirmed Invalid Refresh Token Clears Authentication State
    runTest("Confirmed Invalid Refresh Token (HTTP 400) Clears Authentication State", [&]() {
        FirebaseAuth auth("dummy_api_key");
        auth.injectTokensForTesting("old_id_token", "invalid_refresh_token_xyz", AUTHORIZED_CLI_UID, DEFAULT_AUTHORIZED_EMAIL, 3600);
        if (!auth.isAuthenticated()) return false;

        std::string mockErrorResponse = R"({
            "error": {
                "code": 400,
                "message": "INVALID_REFRESH_TOKEN",
                "status": "INVALID_ARGUMENT"
            }
        })";

        bool result = auth.processRefreshTokenResponse(mockErrorResponse, 400);
        return !result && !auth.isAuthenticated() && auth.getRefreshToken().empty() && auth.getUid().empty();
    });

    // 22. Report Status Lookup: HTTP 404 returns NOT_FOUND
    runTest("Report Status: HTTP 404 Returns NOT_FOUND", [&]() {
        std::string status;
        ReportStatusResult r = FirebaseUploader::parseReportStatusResponse(CURLE_OK, 404, "{}", status);
        return r == ReportStatusResult::NOT_FOUND && status.empty();
    });

    // 23. Report Status Lookup: HTTP 401 returns ERROR
    runTest("Report Status: HTTP 401 Returns ERROR", [&]() {
        std::string status;
        ReportStatusResult r = FirebaseUploader::parseReportStatusResponse(CURLE_OK, 401, "{\"error\": \"unauth\"}", status);
        return r == ReportStatusResult::ERROR && status.empty();
    });

    // 24. Report Status Lookup: HTTP 403 returns ERROR
    runTest("Report Status: HTTP 403 Returns ERROR", [&]() {
        std::string status;
        ReportStatusResult r = FirebaseUploader::parseReportStatusResponse(CURLE_OK, 403, "{\"error\": \"forbidden\"}", status);
        return r == ReportStatusResult::ERROR && status.empty();
    });

    // 25. Report Status Lookup: HTTP 500 returns ERROR
    runTest("Report Status: HTTP 500 Returns ERROR", [&]() {
        std::string status;
        ReportStatusResult r = FirebaseUploader::parseReportStatusResponse(CURLE_OK, 500, "{\"error\": \"server error\"}", status);
        return r == ReportStatusResult::ERROR && status.empty();
    });

    // 26. Report Status Lookup: CURL Network Failure returns ERROR
    runTest("Report Status: CURL Network Failure Returns ERROR", [&]() {
        std::string status;
        ReportStatusResult r = FirebaseUploader::parseReportStatusResponse(CURLE_COULDNT_CONNECT, 0, "", status);
        return r == ReportStatusResult::ERROR && status.empty();
    });

    // 27. Report Status Lookup: Valid in_progress and completed return FOUND
    runTest("Report Status: Valid in_progress and completed Return FOUND", [&]() {
        std::string statusInProg;
        std::string jsonInProg = R"({"fields":{"upload_status":{"stringValue":"in_progress"}}})";
        ReportStatusResult r1 = FirebaseUploader::parseReportStatusResponse(CURLE_OK, 200, jsonInProg, statusInProg);

        std::string statusComp;
        std::string jsonComp = R"({"fields":{"upload_status":{"stringValue":"completed"}}})";
        ReportStatusResult r2 = FirebaseUploader::parseReportStatusResponse(CURLE_OK, 200, jsonComp, statusComp);

        // Legacy report without upload_status
        std::string statusLegacy;
        std::string jsonLegacy = R"({"fields":{"filename":{"stringValue":"test_bin"}}})";
        ReportStatusResult r3 = FirebaseUploader::parseReportStatusResponse(CURLE_OK, 200, jsonLegacy, statusLegacy);

        return r1 == ReportStatusResult::FOUND && statusInProg == "in_progress" &&
               r2 == ReportStatusResult::FOUND && statusComp == "completed" &&
               r3 == ReportStatusResult::FOUND && statusLegacy == "completed";
    });

    // 28. Retry Budget: Budget exhaustion before HTTP request aborts immediately
    runTest("Retry Budget: Budget Exhaustion Before Request Aborts Immediately", [&]() {
        FirebaseUploader uploader;
        // Pass 0ms budget: remaining budget <= 0 before attempt 0 begins
        auto res = uploader.uploadToEndpointWithMethodEx("http://127.0.0.1:9999/dummy", "{}", "PATCH", "", true, true, std::chrono::milliseconds(0));
        return !res.success && res.retryAttempts == 0;
    });

    // 29. Retry Budget: Request timeout constrained by remaining budget
    runTest("Retry Budget: Timeout Constrained by Remaining Budget (Cannot Exceed Budget)", [&]() {
        FirebaseUploader uploader;
        // Pass 500ms budget to an unreachable address: operation must abort within ~1.5s rather than default 15s request timeout
        auto start = std::chrono::steady_clock::now();
        auto res = uploader.uploadToEndpointWithMethodEx("http://127.0.0.1:9998/non_existent", "{}", "PATCH", "", true, true, std::chrono::milliseconds(500));
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();

        // Must fail and return within a fraction of normal 15s timeout
        return !res.success && elapsed < 3000;
    });

    std::cout << "\n====================================================================\n";
    std::cout << "  UNIT TEST RESULTS: " << passed << " PASSED, " << failed << " FAILED\n";
    std::cout << "====================================================================\n";

    return (failed == 0) ? 0 : 1;
}

