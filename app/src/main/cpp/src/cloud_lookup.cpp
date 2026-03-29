// ══════════════════════════════════════════════════════════════════
//  CloudLookup — libcurl bağımlılığı yok
//
//  HTTP: Android'in Java HttpURLConnection'ını JNI üzerinden çağırır.
//  JNI bağlamı yoksa (arka plan thread) stub döner → CLEAN.
//
//  Üretimde etkinleştirmek için:
//    1. CloudConfig::enabled = true
//    2. CloudConfig::apiKey doldur
//    3. Kotlin'den NativeEngine.cloudSetApiKey(key) çağır
// ══════════════════════════════════════════════════════════════════
#include "cloud_lookup.h"
#include <cstring>
#include <sstream>
#include <android/log.h>
#include <jni.h>

#define LOG_TAG "GX_Cloud"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)

// Global JavaVM — JNI_OnLoad'da set edilir
static JavaVM* g_jvm = nullptr;

#include "behavioral_analyzer.h"

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_jvm = vm;
    AntiVirus::BehavioralAnalyzer::initSelfProtection();  // Seccomp BPF yükle
    return JNI_VERSION_1_6;
}

namespace AntiVirus {

CloudLookup::CloudLookup(const CloudConfig& config) : m_config(config) {}

// ── Android HttpURLConnection ile senkron GET ─────────────────────
std::string CloudLookup::httpGet(const std::string& url) const {
    if (!m_config.enabled || m_config.apiKey.empty()) return "";
    if (!g_jvm) return "";

    JNIEnv* env = nullptr;
    bool attached = false;
    int rc = g_jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
    if (rc == JNI_EDETACHED) {
        if (g_jvm->AttachCurrentThread(&env, nullptr) != JNI_OK) return "";
        attached = true;
    }
    if (!env) return "";

    std::string result;

    // java.net.URL
    jclass    urlClass  = env->FindClass("java/net/URL");
    jmethodID urlInit   = env->GetMethodID(urlClass, "<init>", "(Ljava/lang/String;)V");
    jmethodID openConn  = env->GetMethodID(urlClass, "openConnection",
                                            "()Ljava/net/URLConnection;");
    jstring   jUrl      = env->NewStringUTF(url.c_str());
    jobject   urlObj    = env->NewObject(urlClass, urlInit, jUrl);
    env->DeleteLocalRef(jUrl);

    // java.net.HttpURLConnection
    jclass    httpClass    = env->FindClass("java/net/HttpURLConnection");
    jmethodID setReqMethod = env->GetMethodID(httpClass, "setRequestMethod",
                                               "(Ljava/lang/String;)V");
    jmethodID setConnTO    = env->GetMethodID(httpClass, "setConnectTimeout", "(I)V");
    jmethodID setReadTO    = env->GetMethodID(httpClass, "setReadTimeout",    "(I)V");
    jmethodID setReqProp   = env->GetMethodID(httpClass, "setRequestProperty",
                                              "(Ljava/lang/String;Ljava/lang/String;)V");
    jmethodID getCode      = env->GetMethodID(httpClass, "getResponseCode",   "()I");
    jmethodID getIS        = env->GetMethodID(httpClass, "getInputStream",
                                              "()Ljava/io/InputStream;");

    jobject conn = env->CallObjectMethod(urlObj, openConn);
    env->DeleteLocalRef(urlObj);
    if (!conn || env->ExceptionCheck()) {
        env->ExceptionClear();
        if (attached) g_jvm->DetachCurrentThread();
        return "";
    }

    jstring jGet = env->NewStringUTF("GET");
    env->CallVoidMethod(conn, setReqMethod, jGet);
    env->DeleteLocalRef(jGet);
    env->CallVoidMethod(conn, setConnTO, m_config.timeoutSec * 1000);
    env->CallVoidMethod(conn, setReadTO,  m_config.timeoutSec * 1000);

    // X-API-Key header
    jstring hKey = env->NewStringUTF("X-API-Key");
    jstring hVal = env->NewStringUTF(m_config.apiKey.c_str());
    env->CallVoidMethod(conn, setReqProp, hKey, hVal);
    env->DeleteLocalRef(hKey); env->DeleteLocalRef(hVal);

    jint code = env->CallIntMethod(conn, getCode);
    if (env->ExceptionCheck()) { env->ExceptionClear(); goto cleanup; }

    if (code == 200) {
        jobject is = env->CallObjectMethod(conn, getIS);
        if (is && !env->ExceptionCheck()) {
            // InputStreamReader → readLine loop
            jclass  isrClass  = env->FindClass("java/io/InputStreamReader");
            jmethodID isrInit = env->GetMethodID(isrClass, "<init>",
                                                  "(Ljava/io/InputStream;)V");
            jclass    brClass = env->FindClass("java/io/BufferedReader");
            jmethodID brInit  = env->GetMethodID(brClass,  "<init>",
                                                  "(Ljava/io/Reader;)V");
            jmethodID readLine= env->GetMethodID(brClass, "readLine",
                                                  "()Ljava/lang/String;");

            jobject isr = env->NewObject(isrClass, isrInit, is);
            jobject br  = env->NewObject(brClass,  brInit,  isr);
            env->DeleteLocalRef(isr);

            std::ostringstream sb;
            while (true) {
                jstring line = (jstring)env->CallObjectMethod(br, readLine);
                if (!line || env->ExceptionCheck()) { env->ExceptionClear(); break; }
                const char* chars = env->GetStringUTFChars(line, nullptr);
                if (chars) { sb << chars; env->ReleaseStringUTFChars(line, chars); }
                env->DeleteLocalRef(line);
            }
            env->DeleteLocalRef(br);
            env->DeleteLocalRef(is);
            result = sb.str();
        }
        if (env->ExceptionCheck()) env->ExceptionClear();
    } else {
        LOGW("Cloud API %d döndü: %s", (int)code, url.c_str());
    }

cleanup:
    env->DeleteLocalRef(conn);
    if (attached) g_jvm->DetachCurrentThread();
    return result;
}

// ── JSON parse (libjansson olmadan) ──────────────────────────────
std::optional<CloudResponse> CloudLookup::parseResponse(const std::string& json) const {
    if (json.empty() || json.find("\"found\":true") == std::string::npos)
        return std::nullopt;

    auto extract = [&](const std::string& key) -> std::string {
        std::string search = "\"" + key + "\":\"";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return "";
        pos += search.size();
        size_t end = json.find('"', pos);
        return (end == std::string::npos) ? "" : json.substr(pos, end - pos);
    };
    auto extractInt = [&](const std::string& key) -> int {
        std::string search = "\"" + key + "\":";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return 0;
        return atoi(json.c_str() + pos + search.size());
    };

    CloudResponse r;
    r.found      = true;
    r.sha256     = extract("sha256");
    r.threatName = extract("name");
    r.family     = extract("family");
    r.source     = extract("source");
    int lvl      = extractInt("level");
    r.threatLevel= static_cast<ThreatLevel>(lvl > 3 ? 2 : lvl);
    r.confidence = static_cast<float>(extractInt("confidence")) / 100.0f;
    return r;
}

std::optional<CloudResponse> CloudLookup::lookupSHA256(const std::string& sha256) {
    if (!m_config.enabled) return std::nullopt;
    std::string url = m_config.apiUrl + "/lookup?sha256=" + sha256;
    if (m_config.privacyMode) url += "&privacy=1";
    return parseResponse(httpGet(url));
}

std::optional<CloudResponse> CloudLookup::lookupMD5(const std::string& md5) {
    if (!m_config.enabled) return std::nullopt;
    std::string url = m_config.apiUrl + "/lookup?md5=" + md5;
    return parseResponse(httpGet(url));
}

std::vector<CloudResponse> CloudLookup::lookupBatch(const std::vector<std::string>& hashes) {
    std::vector<CloudResponse> results;
    if (!m_config.enabled) return results;
    for (const auto& h : hashes) {
        auto r = lookupSHA256(h);
        if (r) results.push_back(*r);
    }
    return results;
}

} // namespace AntiVirus
