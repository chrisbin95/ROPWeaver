// firebase/firebase_auth.cpp

#include "firebase_auth.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <curl/curl.h>
#include "nlohmann/json.hpp"

#if defined(_WIN32)
#include <windows.h>
#include <io.h>
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

using json = nlohmann::json;
namespace fs = std::filesystem;

namespace ropweaver {

static fs::path getExeDir() {
#if defined(_WIN32)
    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(NULL, path, MAX_PATH) > 0) {
        return fs::path(path).parent_path();
    }
#endif
    return fs::current_path();
}

static size_t AuthWriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    if (!userp) return 0;
    static_cast<std::string*>(userp)->append(static_cast<char*>(contents), size * nmemb);
    return size * nmemb;
}

FirebaseAuth::FirebaseAuth(const std::string& apiKey)
    : apiKey(apiKey) {
}

bool FirebaseAuth::isAuthenticated() const {
    if (tokens.idToken.empty() || tokens.localId != AUTHORIZED_CLI_UID) {
        return false;
    }
    return !isTokenExpiring(0);
}

bool FirebaseAuth::isTokenExpiring(int windowSeconds) const {
    if (tokens.idToken.empty()) {
        return true;
    }
    auto now = std::chrono::steady_clock::now();
    return (tokens.expiryTime - std::chrono::seconds(windowSeconds)) <= now;
}

void FirebaseAuth::signOut() {
    tokens.idToken.clear();
    tokens.refreshToken.clear();
    tokens.localId.clear();
    tokens.email.clear();
    tokens.expiryTime = std::chrono::steady_clock::time_point{};
}

void FirebaseAuth::injectTokensForTesting(const std::string& idToken,
                                          const std::string& refreshToken,
                                          const std::string& uid,
                                          const std::string& email,
                                          int expiresInSeconds) {
    tokens.idToken = idToken;
    tokens.refreshToken = refreshToken;
    tokens.localId = uid;
    tokens.email = email;
    tokens.expiryTime = std::chrono::steady_clock::now() + std::chrono::seconds(expiresInSeconds);
}

static std::string extractValidLoopbackHost(const char* envVal, bool logError) {
    if (!envVal || envVal[0] == '\0') {
        return "";
    }

    std::string raw(envVal);
    size_t first = raw.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        if (logError) {
            std::cerr << "[x] Invalid FIREBASE_AUTH_EMULATOR_HOST: value cannot be whitespace only.\n";
        }
        return "";
    }
    size_t last = raw.find_last_not_of(" \t\r\n");
    std::string hostStr = raw.substr(first, (last - first + 1));

    // Basic loopback validation
    std::string hostPart = hostStr;
    size_t colonPos = hostStr.find(':');
    if (colonPos != std::string::npos) {
        hostPart = hostStr.substr(0, colonPos);
    }
    std::string hostLower = hostPart;
    std::transform(hostLower.begin(), hostLower.end(), hostLower.begin(), ::tolower);
    if (hostLower != "localhost" && hostLower != "127.0.0.1" && hostLower != "[::1]") {
        if (logError) {
            std::cerr << "[x] Invalid FIREBASE_AUTH_EMULATOR_HOST: '" << hostPart << "' is not a permitted loopback address (allowed: localhost, 127.0.0.1, [::1]).\n";
        }
        return "";
    }

    return hostStr;
}

std::string FirebaseAuth::getAuthBaseUrl(bool& isEmulator, bool logError) {
    isEmulator = false;
    const char* envVal = std::getenv("FIREBASE_AUTH_EMULATOR_HOST");
    if (!envVal || envVal[0] == '\0') {
        return "https://identitytoolkit.googleapis.com";
    }

    std::string hostStr = extractValidLoopbackHost(envVal, logError);
    if (hostStr.empty()) {
        return "";
    }

    isEmulator = true;
    return "http://" + hostStr + "/identitytoolkit.googleapis.com";
}

std::string FirebaseAuth::getSecureTokenBaseUrl(bool& isEmulator, bool logError) {
    isEmulator = false;
    const char* envVal = std::getenv("FIREBASE_AUTH_EMULATOR_HOST");
    if (!envVal || envVal[0] == '\0') {
        return "https://securetoken.googleapis.com";
    }

    std::string hostStr = extractValidLoopbackHost(envVal, logError);
    if (hostStr.empty()) {
        return "";
    }

    isEmulator = true;
    return "http://" + hostStr + "/securetoken.googleapis.com";
}

bool FirebaseAuth::executeHttpPost(const std::string& url,
                                   const std::string& postData,
                                   const std::string& contentType,
                                   std::string& responseOut,
                                   long& httpCodeOut,
                                   bool isEmulator) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "[x] curl_easy_init() failed in FirebaseAuth.\n";
        return false;
    }

    struct curl_slist* headers = nullptr;
    std::string ctHeader = "Content-Type: " + contentType;
    headers = curl_slist_append(headers, ctHeader.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
    char errbuf[CURL_ERROR_SIZE] = {0};
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);

    if (isEmulator) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    } else {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
#if defined(_WIN32)
#ifndef CURLSSLOPT_NATIVE_CA
#define CURLSSLOPT_NATIVE_CA (1L << 4)
#endif
        curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
#endif
        std::string exeCa = (getExeDir() / "curl-ca-bundle.crt").string();
        if (std::ifstream("curl-ca-bundle.crt").good()) {
            curl_easy_setopt(curl, CURLOPT_CAINFO, "curl-ca-bundle.crt");
        } else if (std::ifstream(exeCa).good()) {
            curl_easy_setopt(curl, CURLOPT_CAINFO, exeCa.c_str());
        } else if (std::ifstream("C:/msys64/mingw64/etc/ssl/certs/ca-bundle.crt").good()) {
            curl_easy_setopt(curl, CURLOPT_CAINFO, "C:/msys64/mingw64/etc/ssl/certs/ca-bundle.crt");
        }
    }

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, AuthWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseOut);

    CURLcode res = curl_easy_perform(curl);
    httpCodeOut = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCodeOut);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        std::cerr << "[x] Authentication network request failed: " << curl_easy_strerror(res) << "\n";
        if (errbuf[0] != '\0') {
            std::cerr << "[x] Detail: " << errbuf << "\n";
        }
        return false;
    }
    return true;
}

bool FirebaseAuth::signInWithEmailPassword(const std::string& email, const std::string& password) {
    if (apiKey.empty()) {
        std::cerr << "[x] Cannot authenticate: Firebase API key is not configured.\n";
        return false;
    }

    bool isEmulator = false;
    std::string baseUrl = getAuthBaseUrl(isEmulator);
    if (baseUrl.empty()) {
        std::cerr << "[x] Aborting authentication: invalid FIREBASE_AUTH_EMULATOR_HOST.\n";
        return false;
    }

    std::string url = baseUrl + "/v1/accounts:signInWithPassword?key=" + apiKey;

    json requestBody = {
        {"email", email},
        {"password", password},
        {"returnSecureToken", true}
    };

    std::string responseString;
    long httpCode = 0;
    if (!executeHttpPost(url, requestBody.dump(), "application/json", responseString, httpCode, isEmulator)) {
        signOut();
        return false;
    }

    if (httpCode == 200) {
        try {
            json resp = json::parse(responseString);
            std::string idToken = resp.value("idToken", "");
            std::string refreshToken = resp.value("refreshToken", "");
            std::string localId = resp.value("localId", "");
            std::string returnedEmail = resp.value("email", email);
            int expiresIn = 3600;
            if (resp.contains("expiresIn") && resp["expiresIn"].is_string()) {
                expiresIn = std::stoi(resp["expiresIn"].get<std::string>());
            }

            // CRITICAL SECURITY ENFORCEMENT:
            // Verify that the returned Firebase UID is exactly the authorized CLI UID.
            if (localId != AUTHORIZED_CLI_UID) {
                std::cerr << "[x] Authorization rejected: authenticated Firebase UID (" 
                          << localId << ") does not match authorized CLI UID ("
                          << AUTHORIZED_CLI_UID << ").\n"
                          << "[x] Uploads to Firestore are prohibited for this account.\n";
                signOut();
                return false;
            }

            tokens.idToken = idToken;
            tokens.refreshToken = refreshToken;
            tokens.localId = localId;
            tokens.email = returnedEmail;
            tokens.expiryTime = std::chrono::steady_clock::now() + std::chrono::seconds(expiresIn);

            std::cout << "[+] Authenticated successfully with Firebase as " << returnedEmail 
                      << " (UID: " << localId << ").\n";
            return true;
        } catch (const std::exception& e) {
            std::cerr << "[x] Failed to parse authentication response.\n";
            signOut();
            return false;
        }
    } else {
        std::string errMessage = "Unknown error";
        try {
            json errJson = json::parse(responseString);
            if (errJson.contains("error") && errJson["error"].contains("message")) {
                errMessage = errJson["error"]["message"].get<std::string>();
            }
        } catch (...) {}
        std::cerr << "[x] Firebase sign-in failed: " << errMessage << " (HTTP " << httpCode << ")\n";
        signOut();
        return false;
    }
}

bool FirebaseAuth::processRefreshTokenResponse(const std::string& responseString, long httpCode) {
    if (httpCode == 200) {
        try {
            json resp = json::parse(responseString);
            std::string newIdToken = resp.value("id_token", "");
            std::string newRefreshToken = resp.value("refresh_token", "");
            std::string userId = resp.value("user_id", "");
            int expiresIn = 3600;
            if (resp.contains("expires_in") && resp["expires_in"].is_string()) {
                expiresIn = std::stoi(resp["expires_in"].get<std::string>());
            }

            // MANDATORY UID VALIDATION:
            // The returned user_id must exactly equal AUTHORIZED_CLI_UID.
            // An empty or mismatched UID strictly invalidates the session and prevents uploads.
            if (userId.empty() || userId != AUTHORIZED_CLI_UID) {
                std::cerr << "[x] Authorization rejected after refresh: returned UID (" 
                          << (userId.empty() ? "<empty>" : userId)
                          << ") does not match authorized CLI UID ("
                          << AUTHORIZED_CLI_UID << ").\n";
                signOut();
                return false;
            }

            if (!newIdToken.empty()) {
                tokens.idToken = newIdToken;
                if (!newRefreshToken.empty()) {
                    tokens.refreshToken = newRefreshToken;
                }
                tokens.localId = userId;
                tokens.expiryTime = std::chrono::steady_clock::now() + std::chrono::seconds(expiresIn);
                return true;
            }
        } catch (...) {}
    }

    std::cerr << "[!] Token refresh failed (HTTP " << httpCode << "). Re-authentication required.\n";
    signOut();
    return false;
}

bool FirebaseAuth::refreshIdToken() {
    if (tokens.refreshToken.empty() || apiKey.empty()) {
        return false;
    }

    bool isEmulator = false;
    std::string baseUrl = getSecureTokenBaseUrl(isEmulator);
    if (baseUrl.empty()) {
        return false;
    }

    std::string url = baseUrl + "/v1/token?key=" + apiKey;

    CURL* curl = curl_easy_init();
    char* escapedRefreshToken = curl ? curl_easy_escape(curl, tokens.refreshToken.c_str(), static_cast<int>(tokens.refreshToken.length())) : nullptr;
    std::string postData = "grant_type=refresh_token&refresh_token=" + std::string(escapedRefreshToken ? escapedRefreshToken : tokens.refreshToken);
    if (escapedRefreshToken) curl_free(escapedRefreshToken);
    if (curl) curl_easy_cleanup(curl);

    std::string responseString;
    long httpCode = 0;
    if (!executeHttpPost(url, postData, "application/x-www-form-urlencoded", responseString, httpCode, isEmulator)) {
        std::cerr << "[!] Transient network failure during token refresh. Refresh token preserved.\n";
        return false;
    }

    return processRefreshTokenResponse(responseString, httpCode);
}

std::string FirebaseAuth::getIdToken(bool forceRefresh, int windowSeconds) {
    if (tokens.idToken.empty()) {
        std::string email;
        std::string password;
        if (!resolveCredentials(email, password)) {
            return "";
        }
        if (!signInWithEmailPassword(email, password)) {
            return "";
        }
        return tokens.idToken;
    }

    if (forceRefresh || isTokenExpiring(windowSeconds)) {
        if (!refreshIdToken()) {
            std::string email = tokens.email.empty() ? DEFAULT_AUTHORIZED_EMAIL : tokens.email;
            std::string password;
            if (resolveCredentials(email, password)) {
                if (signInWithEmailPassword(email, password)) {
                    return tokens.idToken;
                }
            }
            return "";
        }
    }
    return tokens.idToken;
}

std::string FirebaseAuth::readPasswordMasked(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string password;

#if defined(_WIN32)
    if (!_isatty(_fileno(stdin))) {
        std::getline(std::cin, password);
        return password;
    }

    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD oldMode = 0;
    if (GetConsoleMode(hStdin, &oldMode)) {
        DWORD newMode = oldMode & (~ENABLE_ECHO_INPUT);
        SetConsoleMode(hStdin, newMode);
        std::getline(std::cin, password);
        SetConsoleMode(hStdin, oldMode);
        std::cout << std::endl;
    } else {
        int ch = 0;
        while ((ch = _getch()) != '\r' && ch != '\n' && ch != EOF) {
            if (ch == '\b') {
                if (!password.empty()) {
                    password.pop_back();
                }
            } else if (ch >= 32 && ch <= 126) {
                password.push_back(static_cast<char>(ch));
            }
        }
        std::cout << std::endl;
    }
#else
    if (!isatty(STDIN_FILENO)) {
        std::getline(std::cin, password);
        return password;
    }

    termios oldt, newt;
    if (tcgetattr(STDIN_FILENO, &oldt) == 0) {
        newt = oldt;
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        std::getline(std::cin, password);
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        std::cout << std::endl;
    } else {
        std::getline(std::cin, password);
    }
#endif
    return password;
}

bool FirebaseAuth::resolveCredentials(std::string& email, std::string& password) {
    const char* envEmail = std::getenv("ROPWEAVER_FIREBASE_EMAIL");
    if (envEmail && envEmail[0] != '\0') {
        email = envEmail;
    } else if (email.empty()) {
        email = DEFAULT_AUTHORIZED_EMAIL;
    }

    const char* envPass = std::getenv("ROPWEAVER_FIREBASE_PASSWORD");
    if (envPass && envPass[0] != '\0') {
        password = envPass;
        return true;
    }

    bool isInteractive = false;
#if defined(_WIN32)
    isInteractive = (_isatty(_fileno(stdin)) != 0);
#else
    isInteractive = (isatty(STDIN_FILENO) != 0);
#endif

    if (isInteractive) {
        password = readPasswordMasked("Enter Firebase CLI password for " + email + ": ");
        if (!password.empty()) {
            return true;
        }
    }

    std::cerr << "[x] Firebase authentication required: please set ROPWEAVER_FIREBASE_PASSWORD environment variable or enter password interactively.\n";
    return false;
}

} // namespace ropweaver

