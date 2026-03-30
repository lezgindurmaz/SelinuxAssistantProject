#include <jni.h>
#include "scanner.h"
#include "hash_engine.h"
#include <string>
#include <android/log.h>

using namespace AntiVirus;

// ══════════════════════════════════════════════════════
//  JNI Helper: std::string → jstring
// ══════════════════════════════════════════════════════
static jstring toJString(JNIEnv* env, const std::string& str) {
    return env->NewStringUTF(str.c_str());
}

// ══════════════════════════════════════════════════════
//  JNI Helper: jstring → std::string
// ══════════════════════════════════════════════════════
static std::string fromJString(JNIEnv* env, jstring jstr) {
    if (!jstr) return "";
    const char* chars = env->GetStringUTFChars(jstr, nullptr);
    std::string result = chars ? chars : "";
    env->ReleaseStringUTFChars(jstr, chars);
    return result;
}

// ──────────────────────────────────────────────────────
//  Kotlin/Java paket: com.selinuxassistant.guardx.engine.AVEngine
//
//  Kotlin tarafında:
//    external fun scanFile(path: String): String  // JSON döner
//    external fun hashFile(path: String): String
//    external fun scanDirectory(path: String, callback: ScanCallback): String
// ──────────────────────────────────────────────────────
extern "C" {

// ══════════════════════════════════════════════════════
//  hashFile  → JSON: { "sha256":"...", "md5":"..." }
// ══════════════════════════════════════════════════════
JNIEXPORT jstring JNICALL
Java_com_selinuxassistant_guardx_engine_NativeEngine_hashFile(
        JNIEnv* env, jobject /* this */, jstring jFilePath) {

    std::string path = fromJString(env, jFilePath);
    HashEngine engine;
    auto result = engine.hashFile(path, HashType::BOTH);

    std::string json;
    if (result.valid) {
        json = "{\"success\":true,"
               "\"sha256\":\"" + result.sha256 + "\","
               "\"md5\":\""    + result.md5    + "\"}";
    } else {
        json = "{\"success\":false,\"error\":\"" + result.error + "\"}";
    }
    return toJString(env, json);
}

// ══════════════════════════════════════════════════════
//  scanFile  → JSON: { "threatLevel":0, "threatName":"", "source":"clean" }
// ══════════════════════════════════════════════════════
JNIEXPORT jstring JNICALL
Java_com_selinuxassistant_guardx_engine_NativeEngine_scanFile(
        JNIEnv* env, jobject /* this */, jstring jFilePath) {

    std::string path = fromJString(env, jFilePath);

    ScanConfig config;
    config.useLocalDB     = true;
    config.useCloudLookup = true;

    Scanner scanner(config);
    auto result = scanner.scanFile(path);

    std::string json =
        "{\"success\":"      + std::string(result.scanSuccess ? "true" : "false") +
        ",\"threatLevel\":"  + std::to_string(static_cast<int>(result.threatLevel)) +
        ",\"threatName\":\""  + result.threatName + "\""
        ",\"source\":\""     + result.source + "\""
        ",\"scanTimeMs\":"   + std::to_string(result.scanTimeMs) +
        ",\"sha256\":\""     + result.hashes.sha256 + "\""
        ",\"md5\":\""        + result.hashes.md5    + "\""
        "}";

    return toJString(env, json);
}

// ══════════════════════════════════════════════════════
//  scanDirectory  → JSON array of results
//  progressCallback: Kotlin arayüzü, her dosyada çağrılır
// ══════════════════════════════════════════════════════
JNIEXPORT jstring JNICALL
Java_com_selinuxassistant_guardx_engine_NativeEngine_scanDirectory(
        JNIEnv* env, jobject thiz,
        jstring jDirPath, jobject jCallback) {

    std::string dirPath = fromJString(env, jDirPath);

    // Callback metot ID'sini al
    jclass  callbackClass  = env->GetObjectClass(jCallback);
    jmethodID onProgressId = env->GetMethodID(
        callbackClass, "onProgress",
        "(IILjava/lang/String;)V"   // (scanned, total, currentFile) → void
    );

    ScanConfig config;
    Scanner scanner(config);

    // Progress callback → Kotlin'e köprü
    auto progressFn = [&](uint32_t scanned, uint32_t total, const std::string& file) {
        jstring jFile = env->NewStringUTF(file.c_str());
        env->CallVoidMethod(jCallback, onProgressId,
            static_cast<jint>(scanned),
            static_cast<jint>(total),
            jFile);
        env->DeleteLocalRef(jFile);
    };

    auto results = scanner.scanDirectory(dirPath, progressFn);
    auto stats   = scanner.getLastStats();

    // JSON çıktısını oluştur
    std::string json = "{\"totalFiles\":"       + std::to_string(stats.totalFiles) +
                       ",\"cleanFiles\":"       + std::to_string(stats.cleanFiles) +
                       ",\"malwareFiles\":"     + std::to_string(stats.malwareFiles) +
                       ",\"criticalFiles\":"    + std::to_string(stats.criticalFiles) +
                       ",\"suspiciousFiles\":"  + std::to_string(stats.suspiciousFiles) +
                       ",\"totalTimeMs\":"      + std::to_string(stats.totalTimeMs) +
                       ",\"threats\":[";

    bool first = true;
    for (const auto& r : results) {
        if (r.threatLevel == ThreatLevel::CLEAN) continue;
        if (!first) json += ",";
        json += "{\"path\":\""        + r.filePath +
                "\",\"level\":"       + std::to_string(static_cast<int>(r.threatLevel)) +
                ",\"name\":\""        + r.threatName + "\""
                ",\"sha256\":\""      + r.hashes.sha256 + "\"}";
        first = false;
    }
    json += "]}";

    return toJString(env, json);
}

// ══════════════════════════════════════════════════════
//  cancelScan  — Kotlin thread'den çağrılabilir
// ══════════════════════════════════════════════════════
static Scanner* g_activeScanner = nullptr;

JNIEXPORT void JNICALL
Java_com_selinuxassistant_guardx_engine_NativeEngine_cancelScan(JNIEnv*, jobject) {
    if (g_activeScanner) {
        g_activeScanner->cancelScan();
    }
}

} // extern "C"
