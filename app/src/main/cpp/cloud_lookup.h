#pragma once
#ifndef CLOUD_LOOKUP_H
#define CLOUD_LOOKUP_H

#include "scanner.h"
#include <string>
#include <optional>
#include <functional>

namespace AntiVirus {

// ─────────────────────────────────────────────
//  Cloud API yanıt yapısı
// ─────────────────────────────────────────────
struct CloudResponse {
    bool        found;
    bool        networkError;
    std::string threatName;
    ThreatLevel threatLevel;
    std::string family;
    int         httpStatusCode;
    std::string rawJson;       // Debug amaçlı ham yanıt
};

// ─────────────────────────────────────────────
//  Cloud konfigürasyonu
// ─────────────────────────────────────────────
struct CloudConfig {
    std::string apiBaseUrl    = "https://api.yourantivirus.com/v1";
    std::string apiKey;                        // Uygulama API anahtarı
    int         timeoutSeconds       = 5;      // Bağlantı zaman aşımı
    int         maxRetries           = 2;
    bool        verifyCertificate    = true;   // SSL doğrulama (daima true!)
    bool        privacyMode          = true;   // true → sadece hash gönder, dosya değil
};

// ─────────────────────────────────────────────
//  CloudLookup: Android'de libcurl kullanır
//
//  Endpoint: POST /v1/lookup
//  Body: { "sha256": "...", "md5": "..." }
//  Response: { "found": true, "threat": {...} }
// ─────────────────────────────────────────────
class CloudLookup {
public:
    explicit CloudLookup(const CloudConfig& config);
    ~CloudLookup();

    // Tek hash sorgula
    CloudResponse lookup(const std::string& sha256, const std::string& md5 = "");

    // Toplu hash sorgula (batch API - daha verimli)
    std::vector<std::pair<std::string, CloudResponse>>
    lookupBatch(const std::vector<std::string>& sha256List);

    // İmza DB güncelleme: delta paketi indir
    // Döner: indirilen JSON dosyasının lokal yolu
    std::string downloadSignatureUpdate(const std::string& currentVersion);

    // Bağlantı testi
    bool ping();

private:
    CloudConfig m_config;
    void*       m_curlHandle = nullptr;  // CURL* (void* ile bağımlılığı gizliyoruz)

    // libcurl yardımcıları
    bool   initCurl();
    void   cleanupCurl();
    std::string performRequest(const std::string& endpoint,
                               const std::string& jsonBody);

    // JSON yardımcıları (bağımlılıksız mini parser)
    CloudResponse  parseResponse(const std::string& json);
    std::string    buildLookupBody(const std::string& sha256,
                                   const std::string& md5);

    // Write callback (libcurl için)
    static size_t writeCallback(void* ptr, size_t size,
                                size_t nmemb, std::string* data);
};

} // namespace AntiVirus

#endif // CLOUD_LOOKUP_H
