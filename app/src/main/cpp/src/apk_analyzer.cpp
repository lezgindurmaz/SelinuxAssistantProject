#include "apk_analyzer.h"
#include "hash_engine.h"

#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <android/log.h>

// JNI
#include <jni.h>

#define LOG_TAG "AV_APK"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace AntiVirus {

// ══════════════════════════════════════════════════════════════════
//  ApkAnalyzer::analyze  — Ana giriş noktası
// ══════════════════════════════════════════════════════════════════
ApkReport ApkAnalyzer::analyze(const std::string& apkPath) {
    auto startTime = std::chrono::high_resolution_clock::now();

    ApkReport report{};
    report.apkPath = apkPath;

    // ── Dosya boyutu ────────────────────────────────────────────
    struct stat st;
    if (stat(apkPath.c_str(), &st) != 0) {
        LOGE("APK bulunamadı: %s", apkPath.c_str());
        report.verdict = "ERROR";
        return report;
    }
    report.fileSize = static_cast<uint64_t>(st.st_size);

    // ── Hash (SHA-256 + MD5) ─────────────────────────────────────
    HashEngine hasher;
    auto hashes = hasher.hashFile(apkPath, HashType::BOTH);
    report.sha256 = hashes.sha256;
    report.md5    = hashes.md5;

    // ── ZIP aç ──────────────────────────────────────────────────
    ZipReader zip(apkPath);
    if (!zip.open()) {
        LOGE("APK ZIP açılamadı: %s", apkPath.c_str());
        report.verdict = "ERROR";
        return report;
    }

    // ── AndroidManifest.xml ─────────────────────────────────────
    analyzeManifest(zip, report);

    // ── DEX dosyaları ────────────────────────────────────────────
    analyzeDex(zip, report);

    // ── İmza ────────────────────────────────────────────────────
    analyzeSignature(apkPath, report);

    // ── Dışa açık bileşen değerlendirmesi ───────────────────────
    assessExportedComponents(report);

    // ── Skor hesapla ─────────────────────────────────────────────
    computeScores(report);

    // ── Verdict ─────────────────────────────────────────────────
    if      (report.overallScore >= 70) report.verdict = "MALWARE";
    else if (report.overallScore >= 40) report.verdict = "SUSPICIOUS";
    else                                report.verdict = "CLEAN";

    auto endTime = std::chrono::high_resolution_clock::now();
    report.analysisDurationMs = std::chrono::duration<double, std::milli>(
        endTime - startTime).count();

    LOGI("APK analiz tamamlandı: %s → %s (skor=%u) [%.0fms]",
         apkPath.c_str(), report.verdict.c_str(),
         report.overallScore, report.analysisDurationMs);

    return report;
}

// ══════════════════════════════════════════════════════════════════
//  1. Manifest analizi
// ══════════════════════════════════════════════════════════════════
void ApkAnalyzer::analyzeManifest(ZipReader& zip, ApkReport& report) {
    auto raw = zip.extract("AndroidManifest.xml");
    if (raw.empty()) {
        LOGE("AndroidManifest.xml çıkarılamadı");
        return;
    }

    AXMLParser axml;
    if (!axml.parse(raw.data(), raw.size(), report.manifest)) {
        LOGE("AXML parse başarısız");
        return;
    }

    // İzinleri PermissionDB ile zenginleştir
    auto& db = PermissionDB::instance();
    std::vector<std::string> permNames;

    for (auto& pr : report.manifest.requestedPermissions) {
        auto enriched = db.lookup(pr.name);
        pr = enriched;
        permNames.push_back(pr.name);
        if (pr.risk == PermRisk::CRITICAL) ++report.criticalPermCount;
        else if (pr.risk == PermRisk::HIGH) ++report.highPermCount;
    }

    // Kombinasyon analizi — sonuçları findings olarak kaydet
    // (Manifest'e ayrı bir warnings alanı eklenebilir; şimdilik logluyoruz)
    auto combWarnings = db.checkCombinations(permNames);
    for (const auto& w : combWarnings) LOGW("İzin kombinasyon uyarısı: %s", w.c_str());

    LOGI("Manifest: pkg=%s target=%u perm=%zu comp=%zu",
         report.manifest.packageName.c_str(),
         report.manifest.targetSdkVersion,
         report.manifest.requestedPermissions.size(),
         report.manifest.components.size());
}

// ══════════════════════════════════════════════════════════════════
//  2. DEX analizi  —  classes.dex, classes2.dex, ... hepsini tara
// ══════════════════════════════════════════════════════════════════
void ApkAnalyzer::analyzeDex(ZipReader& zip, ApkReport& report) {
    DexAnalyzer dexAnalyzer;
    auto entries = zip.listEntries();

    for (const auto& entry : entries) {
        // DEX dosyaları: classes.dex, classes2.dex, classes3.dex, ...
        const std::string& name = entry.name;
        bool isDex = (name == "classes.dex") ||
                     (name.find("classes") == 0 && name.find(".dex") != std::string::npos);
        if (!isDex) continue;

        auto dexData = zip.extract(name);
        if (dexData.empty()) continue;

        auto findings = dexAnalyzer.analyze(dexData.data(), dexData.size(), name);
        report.dexFindings.insert(report.dexFindings.end(),
                                   findings.begin(), findings.end());
    }

    LOGI("DEX taraması: %zu bulgu", report.dexFindings.size());
}

// ══════════════════════════════════════════════════════════════════
//  3. APK İmza analizi
//  META-INF/CERT.RSA veya *.RSA dosyasından X.509 sertifika oku
//  (tam ASN.1 parser olmadan özet bilgi çıkar)
// ══════════════════════════════════════════════════════════════════
void ApkAnalyzer::analyzeSignature(const std::string& apkPath,
                                    ApkReport& report) {
    ZipReader zip(apkPath);
    if (!zip.open()) return;

    report.signature.isSigned = false;

    auto entries = zip.listEntries();
    for (const auto& entry : entries) {
        const auto& n = entry.name;
        // v1: META-INF/*.RSA veya *.DSA veya *.EC
        bool isSignature = (n.find("META-INF/") == 0) &&
                           (n.find(".RSA") != std::string::npos ||
                            n.find(".DSA") != std::string::npos ||
                            n.find(".EC")  != std::string::npos);
        if (!isSignature) continue;

        auto certData = zip.extract(n);
        if (certData.empty()) continue;

        report.signature.isSigned    = true;
        report.signature.sigScheme   = "v1";  // Daha derin analiz için v2/v3 APK Signing Block gerekir

        // Debug sertifika tespiti: "Android Debug" string'i içerip içermediğine bak
        std::string certStr(reinterpret_cast<const char*>(certData.data()),
                            certData.size());
        if (certStr.find("Android Debug") != std::string::npos ||
            certStr.find("androiddebugkey") != std::string::npos) {
            report.signature.isDebugCert = true;
            LOGW("Debug sertifikası tespit edildi!");
        }

        // v2/v3 APK Signing Block varlığını kontrol et
        // APK sonunda "APK Sig Block 42" magic'i arar
        // (ZIP EOCD'den geriye doğru taranır)
        {
            int fd = ::open(apkPath.c_str(), O_RDONLY);
            if (fd >= 0) {
                // Son 4096 byte'ı oku ve "APK Sig Block 42" ara
                char tail[4096];
                struct stat st; fstat(fd, &st);
                off_t off = (st.st_size > 4096) ? (st.st_size - 4096) : 0;
                lseek(fd, off, SEEK_SET);
                ssize_t n = read(fd, tail, sizeof(tail));
                ::close(fd);
                if (n > 0) {
                    std::string tailStr(tail, static_cast<size_t>(n));
                    if (tailStr.find("APK Sig Block 42") != std::string::npos) {
                        // v2 veya v3 imza mevcut
                        report.signature.sigScheme = "v2/v3";
                    }
                }
            }
        }
        break;  // İlk imzayla yetiniyoruz
    }

    if (!report.signature.isSigned) {
        LOGW("APK imzasız!");
    }
}

// ══════════════════════════════════════════════════════════════════
//  4. İzinsiz dışa açık bileşen tespiti
//  exported=true + permission="" → herhangi uygulama erişebilir
// ══════════════════════════════════════════════════════════════════
void ApkAnalyzer::assessExportedComponents(ApkReport& report) {
    report.exportedComponentCount = 0;
    report.exportedWithoutPermCount = 0;

    // Meşru exported bileşenler için whitelist (launcher activity vb.)
    static const char* SAFE_ACTIONS[] = {
        "android.intent.action.MAIN",
        "android.intent.action.VIEW",
        "android.intent.action.SEND",
        nullptr
    };

    for (const auto& comp : report.manifest.components) {
        if (!comp.exported) continue;
        ++report.exportedComponentCount;

        if (comp.permission.empty()) {
            // Meşru action içeriyor mu?
            bool hasSafeAction = false;
            for (int i = 0; SAFE_ACTIONS[i]; ++i) {
                for (const auto& action : comp.actions) {
                    if (action == SAFE_ACTIONS[i]) { hasSafeAction = true; break; }
                }
                if (hasSafeAction) break;
            }

            if (!hasSafeAction) {
                ++report.exportedWithoutPermCount;
                LOGW("İzinsiz dışa açık bileşen: %s (%s)",
                     comp.name.c_str(), comp.type.c_str());
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════════
//  5. Skor hesaplama
// ══════════════════════════════════════════════════════════════════
uint32_t ApkAnalyzer::scorePermissions(const ManifestInfo& manifest) {
    uint32_t score = 0;

    for (const auto& p : manifest.requestedPermissions) {
        switch (p.risk) {
            case PermRisk::CRITICAL: score += 20; break;
            case PermRisk::HIGH:     score += 10; break;
            case PermRisk::MEDIUM:   score +=  3; break;
            case PermRisk::LOW:      score +=  1; break;
            default: break;
        }
    }

    // Manifest bayrakları
    if (manifest.debuggable)           score += 15;
    if (manifest.usesCleartextTraffic) score += 10;
    if (!manifest.networkSecurityConfig &&
        manifest.requestedPermissions.size() > 5) score += 5;

    // Şüpheli action'lar
    score += static_cast<uint32_t>(manifest.suspiciousActions.size()) * 5;

    return std::min(score, 100u);
}

uint32_t ApkAnalyzer::scoreDexFindings(const std::vector<DexFinding>& findings) {
    uint32_t score = 0;
    for (const auto& f : findings) {
        score += f.severity * 3;
    }
    return std::min(score, 100u);
}

void ApkAnalyzer::computeScores(ApkReport& report) {
    report.permissionScore = scorePermissions(report.manifest);
    report.behaviorScore   = scoreDexFindings(report.dexFindings);

    // İmza skoru
    report.signatureScore = 0;
    if (!report.signature.isSigned)    report.signatureScore += 30;
    if (report.signature.isDebugCert)  report.signatureScore += 20;
    if (report.isRepackaged)           report.signatureScore += 40;

    // Bileşen skoru
    uint32_t compScore = report.exportedWithoutPermCount * 8;

    // Genel skor: ağırlıklı ortalama
    report.overallScore = (report.permissionScore * 35 +
                           report.behaviorScore   * 40 +
                           report.signatureScore  * 15 +
                           compScore              * 10) / 100;
    report.overallScore = std::min(report.overallScore, 100u);
}

// ══════════════════════════════════════════════════════════════════
//  JSON çıktısı
// ══════════════════════════════════════════════════════════════════
static std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        if (c == '"')  { out += "\\\""; }
        else if (c == '\\') { out += "\\\\"; }
        else if (c == '\n') { out += "\\n"; }
        else if (c < 0x20) {} // kontrol karakterlerini atla
        else out += c;
    }
    return out;
}

std::string ApkReport::toJSON() const {
    std::ostringstream j;
    j << "{"
      << "\"apkPath\":\""   << jsonEscape(apkPath)          << "\","
      << "\"sha256\":\""    << sha256                        << "\","
      << "\"md5\":\""       << md5                          << "\","
      << "\"fileSize\":"    << fileSize                      << ","
      << "\"verdict\":\""   << verdict                      << "\","
      << "\"overallScore\":" << overallScore                 << ","
      << "\"permScore\":"   << permissionScore               << ","
      << "\"behaviorScore\":" << behaviorScore               << ","
      << "\"sigScore\":"    << signatureScore                << ","
      << "\"analysisDurationMs\":" << analysisDurationMs     << ","

      // Manifest özeti
      << "\"manifest\":{"
      << "\"package\":\""   << jsonEscape(manifest.packageName)  << "\","
      << "\"versionName\":\""<< jsonEscape(manifest.versionName) << "\","
      << "\"versionCode\":" << manifest.versionCode              << ","
      << "\"minSdk\":"      << manifest.minSdkVersion            << ","
      << "\"targetSdk\":"   << manifest.targetSdkVersion         << ","
      << "\"debuggable\":"  << (manifest.debuggable ? "true":"false") << ","
      << "\"cleartext\":"   << (manifest.usesCleartextTraffic?"true":"false") << ","
      << "\"permCount\":"   << manifest.requestedPermissions.size() << ","
      << "\"criticalPerm\":" << criticalPermCount              << ","
      << "\"highPerm\":"    << highPermCount                   << ","
      << "\"compCount\":"   << manifest.components.size()      << ","
      << "\"exportedNoPermComp\":" << exportedWithoutPermCount << ","

      // İzin listesi
      << "\"permissions\":[";
    for (size_t i = 0; i < manifest.requestedPermissions.size(); ++i) {
        const auto& p = manifest.requestedPermissions[i];
        if (i) j << ",";
        j << "{\"name\":\""  << jsonEscape(p.name) << "\","
          << "\"risk\":"     << static_cast<int>(p.risk) << ","
          << "\"cat\":\""    << jsonEscape(p.category) << "\","
          << "\"desc\":\""   << jsonEscape(p.description) << "\"}";
    }
    j << "],"  // permissions

      // Şüpheli action'lar
      << "\"suspiciousActions\":[";
    for (size_t i = 0; i < manifest.suspiciousActions.size(); ++i) {
        if (i) j << ",";
        j << "\"" << jsonEscape(manifest.suspiciousActions[i]) << "\"";
    }
    j << "]},"  // manifest

      // İmza
      << "\"signature\":{"
      << "\"signed\":"    << (signature.isSigned    ? "true":"false") << ","
      << "\"scheme\":\""  << jsonEscape(signature.sigScheme)         << "\","
      << "\"debugCert\":" << (signature.isDebugCert  ? "true":"false") << "},"

      // DEX bulguları
      << "\"dexFindings\":[";
    for (size_t i = 0; i < dexFindings.size(); ++i) {
        const auto& f = dexFindings[i];
        if (i) j << ",";
        j << "{\"threat\":"   << static_cast<int>(f.threat)      << ","
          << "\"dex\":\""     << jsonEscape(f.dexFile)           << "\","
          << "\"severity\":"  << static_cast<int>(f.severity)    << ","
          << "\"desc\":\""    << jsonEscape(f.description)       << "\"}";
    }
    j << "]}";  // dexFindings + root

    return j.str();
}

} // namespace AntiVirus

// ══════════════════════════════════════════════════════════════════
//  JNI Bridge
//  Kotlin: com.selinuxassistant.guardx.engine.ApkAnalyzer
//    external fun analyzeApk(path: String): String
//    external fun analyzeInstalledApp(packageName: String): String
// ══════════════════════════════════════════════════════════════════
extern "C" {

JNIEXPORT jstring JNICALL
Java_com_selinuxassistant_guardx_engine_NativeEngine_analyzeApk(
        JNIEnv* env, jobject /*thiz*/, jstring jApkPath)
{
    const char* path = env->GetStringUTFChars(jApkPath, nullptr);
    if (!path) return env->NewStringUTF("{\"error\":\"null path\"}");

    AntiVirus::ApkAnalyzer analyzer;
    auto report = analyzer.analyze(std::string(path));
    env->ReleaseStringUTFChars(jApkPath, path);

    return env->NewStringUTF(report.toJSON().c_str());
}

// Yüklü bir uygulamanın APK'sını analiz et
// /data/app/<packageName>-<hash>/base.apk yolunu çöz
JNIEXPORT jstring JNICALL
Java_com_selinuxassistant_guardx_engine_NativeEngine_analyzeInstalledApp(
        JNIEnv* env, jobject /*thiz*/, jstring jPackageName)
{
    const char* pkg = env->GetStringUTFChars(jPackageName, nullptr);
    if (!pkg) return env->NewStringUTF("{\"error\":\"null package\"}");

    // /data/app altında paketin klasörünü ara
    std::string apkPath;
    DIR* dir = opendir("/data/app");
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            std::string dirName = entry->d_name;
            if (dirName.find(pkg) == 0) {
                apkPath = "/data/app/" + dirName + "/base.apk";
                struct stat st;
                if (stat(apkPath.c_str(), &st) == 0) break;
                apkPath.clear();
            }
        }
        closedir(dir);
    }

    env->ReleaseStringUTFChars(jPackageName, pkg);

    if (apkPath.empty()) {
        return env->NewStringUTF("{\"error\":\"APK bulunamadı\"}");
    }

    AntiVirus::ApkAnalyzer analyzer;
    auto report = analyzer.analyze(apkPath);
    return env->NewStringUTF(report.toJSON().c_str());
}

} // extern "C"
