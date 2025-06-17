// firebase_uploader.h
#ifndef FIREBASE_UPLOADER_H
#define FIREBASE_UPLOADER_H

#include <string>

class FirebaseUploader {
public:
    FirebaseUploader(const std::string& configPath);
    bool uploadReport(const std::string& jsonPath);

private:
    std::string firebaseUrl;
    std::string apiKey;
    void loadConfig(const std::string& configPath);
};

#endif // FIREBASE_UPLOADER_H