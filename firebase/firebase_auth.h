// firebase/firebase_auth.h

#ifndef ROPWEAVER_FIREBASE_AUTH_H
#define ROPWEAVER_FIREBASE_AUTH_H

#include <string>
#include <chrono>

namespace ropweaver {

// Hardcoded authorized configuration for the dedicated CLI account
constexpr const char* DEFAULT_AUTHORIZED_EMAIL = "ropweaver@gmail.com";
constexpr const char* AUTHORIZED_CLI_UID = "CqiPQGv339cgbMzULJHKWLz67j93";

struct AuthTokens {
    std::string idToken;
    std::string refreshToken;
    std::string localId; // Firebase UID
    std::string email;
    std::chrono::steady_clock::time_point expiryTime;
};

class FirebaseAuth {
public:
    explicit FirebaseAuth(const std::string& apiKey = "");
    ~FirebaseAuth() = default;

    // Sets or updates the Firebase Web API key
    void setApiKey(const std::string& key) { apiKey = key; }
    const std::string& getApiKey() const { return apiKey; }

    // Obtains a valid ID token. If not authenticated, triggers authentication.
    // If token is expiring within windowSeconds (default 60s) or forceRefresh is true, refreshes token.
    // Returns empty string on failure.
    std::string getIdToken(bool forceRefresh = false, int windowSeconds = 60);

    // Explicitly signs in using provided email and password via Identity Toolkit REST API.
    // Verifies that the returned UID matches AUTHORIZED_CLI_UID before storing tokens.
    bool signInWithEmailPassword(const std::string& email, const std::string& password);

    // Refreshes the ID token using the current refresh token via Secure Token REST API.
    bool refreshIdToken();

    // Processes the Secure Token REST API response (public for deterministic unit testing)
    bool processRefreshTokenResponse(const std::string& responseString, long httpCode);

    // Clears in-memory tokens and resets authentication state
    void signOut();

    // Checks if valid tokens are currently held and not expired
    bool isAuthenticated() const;

    // Checks if the token is expired or will expire within windowSeconds
    bool isTokenExpiring(int windowSeconds = 60) const;

    // Getter for authenticated UID, email, and refresh token
    const std::string& getUid() const { return tokens.localId; }
    const std::string& getEmail() const { return tokens.email; }
    const std::string& getRefreshToken() const { return tokens.refreshToken; }

    // Manually inject tokens (useful for testing and deterministic mock verification)
    void injectTokensForTesting(const std::string& idToken,
                                const std::string& refreshToken,
                                const std::string& uid,
                                const std::string& email,
                                int expiresInSeconds);

    // Resolves credentials from environment variables or interactive console prompt
    static bool resolveCredentials(std::string& email, std::string& password);

    // Prompts user for password with input masking on Windows and POSIX
    static std::string readPasswordMasked(const std::string& prompt);

    // Base URL resolution for Auth endpoints (supports FIREBASE_AUTH_EMULATOR_HOST)
    static std::string getAuthBaseUrl(bool& isEmulator, bool logError = true);
    static std::string getSecureTokenBaseUrl(bool& isEmulator, bool logError = true);

private:
    std::string apiKey;
    AuthTokens tokens;

    // Performs HTTPS POST using libcurl
    bool executeHttpPost(const std::string& url,
                         const std::string& postData,
                         const std::string& contentType,
                         std::string& responseOut,
                         long& httpCodeOut,
                         bool isEmulator);
};

} // namespace ropweaver

#endif // ROPWEAVER_FIREBASE_AUTH_H

