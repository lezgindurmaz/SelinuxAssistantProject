#pragma once
#ifndef CLOUD_LOOKUP_H
#define CLOUD_LOOKUP_H

#include "scanner.h"
#include <string>
#include <vector>
#include <optional>

namespace AntiVirus {

struct CloudResponse {
    bool        found = false;
    std::string sha256;
    std::string threatName;
    ThreatLevel threatLevel  = ThreatLevel::CLEAN;
    std::string family;
    float       confidence   = 0.0f;
    std::string source;
};

struct CloudConfig {
    std::string apiUrl      = "https://api.selinuxassistant.com/v1";
    std::string apiKey;
    int         timeoutSec  = 5;
    bool        privacyMode = true;   // hash-only, dosya adı gönderme
    bool        enabled     = false;  // Varsayılan: kapalı, Runtime'da açılabilir
};

// Android HttpURLConnection üzerinden bulut sorgusu.
// JNIEnv erişimi yokken (pure C++ thread) devre dışı kalır.
class CloudLookup {
public:
    explicit CloudLookup(const CloudConfig& config = CloudConfig{});

    std::optional<CloudResponse> lookupSHA256(const std::string& sha256);
    std::optional<CloudResponse> lookupMD5   (const std::string& md5);
    std::vector<CloudResponse>   lookupBatch (const std::vector<std::string>& hashes);

    bool isAvailable() const { return m_config.enabled; }
    void setEnabled(bool e)  { m_config.enabled = e;    }
    void setApiKey(const std::string& k) { m_config.apiKey = k; }

private:
    CloudConfig m_config;

    // JNI üzerinden Android HttpURLConnection çağrısı
    // env=nullptr ise stub döner
    std::string httpGet(const std::string& url) const;
    std::optional<CloudResponse> parseResponse(const std::string& json) const;
};

} // namespace AntiVirus
#endif // CLOUD_LOOKUP_H
