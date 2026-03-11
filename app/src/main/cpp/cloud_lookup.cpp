#include "cloud_lookup.h"
#include "mock_external.h"
#include <android/log.h>
#include <sstream>
#include <cstring>

#define LOG_TAG "AV_Cloud"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace AntiVirus {

// ══════════════════════════════════════════════════════
//  Constructor / Destructor
// ══════════════════════════════════════════════════════
CloudLookup::CloudLookup(const CloudConfig& config) : m_config(config) {
    initCurl();
}

CloudLookup::~CloudLookup() {
    cleanupCurl();
}

// ══════════════════════════════════════════════════════
//  libcurl init
// ══════════════════════════════════════════════════════
bool CloudLookup::initCurl() {
    CURL* curl = curl_easy_init();
    if (!curl) {
        LOGE("libcurl başlatılamadı!");
        return false;
    }
    m_curlHandle = curl;
    return true;
}

void CloudLookup::cleanupCurl() {
    if (m_curlHandle) {
        curl_easy_cleanup(static_cast<CURL*>(m_curlHandle));
        m_curlHandle = nullptr;
    }
}

// ══════════════════════════════════════════════════════
//  Write callback (libcurl → std::string)
// ══════════════════════════════════════════════════════
size_t CloudLookup::writeCallback(void* ptr, size_t size,
                                  size_t nmemb, std::string* data) {
    data->append(static_cast<char*>(ptr), size * nmemb);
    return size * nmemb;
}

// ══════════════════════════════════════════════════════
//  buildLookupBody  — Privacy mode: sadece hash gönder
// ══════════════════════════════════════════════════════
std::string CloudLookup::buildLookupBody(const std::string& sha256,
                                          const std::string& md5) {
    std::ostringstream json;
    json << "{"
         << "\"sha256\":\"" << sha256 << "\","
         << "\"md5\":\""    << md5    << "\""
         << "}";
    return json.str();
}

// ══════════════════════════════════════════════════════
//  performRequest  — HTTP POST
// ══════════════════════════════════════════════════════
std::string CloudLookup::performRequest(const std::string& endpoint,
                                         const std::string& jsonBody) {
    CURL* curl = static_cast<CURL*>(m_curlHandle);
    if (!curl) return "";

    std::string url       = m_config.apiBaseUrl + endpoint;
    std::string response;

    // Headers
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    std::string authHeader = "X-API-Key: " + m_config.apiKey;
    headers = curl_slist_append(headers, authHeader.c_str());

    curl_easy_setopt(curl, CURLOPT_URL,            url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,     headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,     jsonBody.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        m_config.timeoutSeconds);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);

    // ⚠️ SSL doğrulamasını ASLA kapatma
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, m_config.verifyCertificate ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, m_config.verifyCertificate ? 2L : 0L);

    // HTTP/2 tercihi
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);

    int retries = 0;
    CURLcode rc = CURLE_FAILED_INIT;
    while (retries <= m_config.maxRetries) {
        rc = curl_easy_perform(curl);
        if (rc == CURLE_OK) break;
        LOGW("HTTP isteği başarısız (deneme %d): %s", retries + 1, curl_easy_strerror(rc));
        ++retries;
    }

    curl_slist_free_all(headers);
    curl_easy_reset(curl);

    if (rc != CURLE_OK) return "";
    return response;
}

// ══════════════════════════════════════════════════════
//  parseResponse  — Basit JSON parse (bağımlılıksız)
//
//  Beklenen yanıt:
//  {
//    "found": true,
//    "threat": {
//      "name": "Trojan.AndroidOS.Agent.a",
//      "level": 2,
//      "family": "Agent"
//    }
//  }
// ══════════════════════════════════════════════════════
static std::string jsonGetStr(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos += search.size();
    size_t end = json.find('"', pos);
    return (end == std::string::npos) ? "" : json.substr(pos, end - pos);
}

static int jsonGetInt(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return -1;
    pos += search.size();
    return std::stoi(json.substr(pos));
}

static bool jsonGetBool(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return false;
    pos += search.size();
    return json.substr(pos, 4) == "true";
}

CloudResponse CloudLookup::parseResponse(const std::string& json) {
    CloudResponse resp;
    resp.networkError = false;
    resp.rawJson      = json;

    if (json.empty()) {
        resp.networkError = true;
        resp.found        = false;
        return resp;
    }

    resp.found = jsonGetBool(json, "found");
    if (resp.found) {
        resp.threatName  = jsonGetStr(json, "name");
        resp.family      = jsonGetStr(json, "family");
        int level        = jsonGetInt(json, "level");
        resp.threatLevel = (level >= 0 && level <= 3)
                         ? static_cast<ThreatLevel>(level)
                         : ThreatLevel::MALWARE;
    }
    return resp;
}

// ══════════════════════════════════════════════════════
//  lookup  — Tek hash sorgu
// ══════════════════════════════════════════════════════
CloudResponse CloudLookup::lookup(const std::string& sha256, const std::string& md5) {
    std::string body = buildLookupBody(sha256, md5);
    std::string raw  = performRequest("/lookup", body);
    return parseResponse(raw);
}

// ══════════════════════════════════════════════════════
//  lookupBatch  — Toplu sorgu (mobil veri tasarrufu)
// ══════════════════════════════════════════════════════
std::vector<std::pair<std::string, CloudResponse>>
CloudLookup::lookupBatch(const std::vector<std::string>& sha256List) {
    std::vector<std::pair<std::string, CloudResponse>> results;

    // JSON array oluştur
    std::ostringstream json;
    json << "{\"hashes\":[";
    for (size_t i = 0; i < sha256List.size(); ++i) {
        if (i > 0) json << ",";
        json << "\"" << sha256List[i] << "\"";
    }
    json << "]}";

    std::string raw = performRequest("/lookup/batch", json.str());

    // TODO: batch yanıtı parse et
    // Basit implementasyon: tek tek sorgula
    if (raw.empty()) {
        for (const auto& h : sha256List) {
            CloudResponse err;
            err.networkError = true;
            err.found        = false;
            results.emplace_back(h, err);
        }
    }

    return results;
}

// ══════════════════════════════════════════════════════
//  downloadSignatureUpdate
// ══════════════════════════════════════════════════════
std::string CloudLookup::downloadSignatureUpdate(const std::string& currentVersion) {
    std::string endpoint = "/signatures/delta?from=" + currentVersion;
    std::string raw      = performRequest(endpoint, "");

    if (raw.empty()) {
        LOGE("İmza güncellemesi indirilemedi.");
        return "";
    }

    // Geçici dosyaya yaz
    std::string tmpPath = "/data/data/com.yourapp/cache/sig_delta.json";
    FILE* f = fopen(tmpPath.c_str(), "w");
    if (f) { fwrite(raw.c_str(), 1, raw.size(), f); fclose(f); }
    LOGI("İmza delta indirildi: %zu byte", raw.size());
    return tmpPath;
}

// ══════════════════════════════════════════════════════
//  ping
// ══════════════════════════════════════════════════════
bool CloudLookup::ping() {
    std::string raw = performRequest("/health", "{}");
    return !raw.empty() && raw.find("\"ok\"") != std::string::npos;
}

} // namespace AntiVirus
