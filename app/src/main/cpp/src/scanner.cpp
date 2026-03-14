#include "scanner.h"
#include "local_db.h"
#include "cloud_lookup.h"

#include <dirent.h>
#include <sys/stat.h>
#include <chrono>
#include <algorithm>
#include <cstring>
#include <android/log.h>

#define LOG_TAG "AV_Scanner"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace AntiVirus {

// ──────────────────────────────────────────────
//  Constructor
// ──────────────────────────────────────────────
Scanner::Scanner(const ScanConfig& config)
    : m_config(config), m_hashEngine()
{
    memset(&m_lastStats, 0, sizeof(m_lastStats));
}

// ──────────────────────────────────────────────
//  cancelScan
// ──────────────────────────────────────────────
void Scanner::cancelScan() {
    m_cancelRequested.store(true);
    LOGW("Tarama iptal isteği alındı.");
}

// ──────────────────────────────────────────────
//  shouldSkipFile
// ──────────────────────────────────────────────
bool Scanner::shouldSkipFile(const std::string& path, size_t fileSize) const {
    // Sistem dizinleri
    if (m_config.skipSystemFiles) {
        static const char* SKIP_PATHS[] = {
            "/proc/", "/sys/", "/dev/", "/acct/", nullptr
        };
        for (int i = 0; SKIP_PATHS[i]; ++i)
            if (path.find(SKIP_PATHS[i]) == 0) return true;
    }

    // Boyut sınırı
    if (fileSize > m_config.maxFileSizeBytes) {
        LOGW("Dosya boyut limitini aşıyor, atlanıyor: %s", path.c_str());
        return true;
    }

    // Uzantı kontrolü
    auto ext = path.substr(path.rfind('.') + 1);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

    for (const auto& skip : m_config.skipExtensions)
        if (ext == skip) return true;

    if (!m_config.targetExtensions.empty()) {
        bool found = false;
        for (const auto& target : m_config.targetExtensions)
            if (ext == target) { found = true; break; }
        if (!found) return true;
    }

    return false;
}

// ──────────────────────────────────────────────
//  isAPK
// ──────────────────────────────────────────────
bool Scanner::isAPK(const std::string& path) const {
    return path.size() > 4 &&
           path.substr(path.size() - 4) == ".apk";
}

// ──────────────────────────────────────────────
//  collectFiles  (recursive dizin tarama)
// ──────────────────────────────────────────────
std::vector<std::string> Scanner::collectFiles(const std::string& dirPath) const {
    std::vector<std::string> files;
    DIR* dir = opendir(dirPath.c_str());
    if (!dir) return files;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) continue;

        std::string fullPath = dirPath + "/" + entry->d_name;
        struct stat st;
        if (stat(fullPath.c_str(), &st) != 0) continue;

        if (S_ISREG(st.st_mode)) {
            files.push_back(fullPath);
        } else if (S_ISDIR(st.st_mode) && m_config.scanSubdirectories) {
            auto sub = collectFiles(fullPath);
            files.insert(files.end(), sub.begin(), sub.end());
        }
    }
    closedir(dir);
    return files;
}

// ──────────────────────────────────────────────
//  scanFile  — Tek dosya tarama (hibrit)
// ──────────────────────────────────────────────
ScanResult Scanner::scanFile(const std::string& filePath) {
    auto startTime = std::chrono::high_resolution_clock::now();
    ScanResult result;
    result.filePath    = filePath;
    result.scanSuccess = false;
    result.threatLevel = ThreatLevel::CLEAN;

    // Dosya bilgisi al
    struct stat st;
    if (stat(filePath.c_str(), &st) != 0) {
        result.error = "stat() başarısız";
        return result;
    }

    if (shouldSkipFile(filePath, static_cast<size_t>(st.st_size))) {
        result.scanSuccess = true;
        result.source      = "skipped";
        return result;
    }

    // APK ise özel tarama
    if (isAPK(filePath)) {
        return scanAPK(filePath);
    }

    // Hash hesapla
    result.hashes = m_hashEngine.hashFile(filePath, HashType::BOTH);
    if (!result.hashes.valid) {
        result.error = result.hashes.error;
        return result;
    }

    // ── 1. Lokal DB sorgusu ──────────────────
    if (m_config.useLocalDB) {
        LocalDB localDB("/data/data/com.selinuxassistant.guardx/files/signatures.db");
        if (localDB.open()) {
            auto record = localDB.lookupBySHA256(result.hashes.sha256);
            if (!record) record = localDB.lookupByMD5(result.hashes.md5);
            if (record) {
                result.threatLevel = record->threatLevel;
                result.threatName  = record->threatName;
                result.source      = "local_db";
                result.scanSuccess = true;
                goto scan_done;
            }
        }
    }

    // ── 2. Cloud sorgusu (local miss ise) ────
    if (m_config.useCloudLookup) {
        CloudConfig cloudCfg;
        CloudLookup cloud(cloudCfg);
        auto response = cloud.lookupSHA256(result.hashes.sha256);
        if (response.has_value() && response->found) {
            result.threatLevel = response->threatLevel;
            result.threatName  = response->threatName;
            result.source      = "cloud";
            result.scanSuccess = true;
            goto scan_done;
        }
    }

    // ── 3. Temiz ──────────────────────────────
    result.source      = "clean";
    result.scanSuccess = true;

scan_done:
    auto endTime = std::chrono::high_resolution_clock::now();
    result.scanTimeMs = std::chrono::duration<double, std::milli>(
        endTime - startTime).count();

    LOGI("Tarandı [%.1fms] %s → %d",
         result.scanTimeMs,
         filePath.c_str(),
         static_cast<int>(result.threatLevel));
    return result;
}

// ──────────────────────────────────────────────
//  scanDirectory
// ──────────────────────────────────────────────
std::vector<ScanResult> Scanner::scanDirectory(
    const std::string& dirPath,
    ProgressCallback   onProgress)
{
    m_cancelRequested.store(false);
    memset(&m_lastStats, 0, sizeof(m_lastStats));
    auto totalStart = std::chrono::high_resolution_clock::now();

    auto files = collectFiles(dirPath);
    m_lastStats.totalFiles = static_cast<uint32_t>(files.size());

    std::vector<ScanResult> results;
    results.reserve(files.size());

    uint32_t scanned = 0;
    for (const auto& file : files) {
        if (m_cancelRequested.load()) {
            LOGW("Tarama iptal edildi. %u/%u dosya tarandı.", scanned, m_lastStats.totalFiles);
            break;
        }

        if (onProgress)
            onProgress(scanned, m_lastStats.totalFiles, file);

        auto result = scanFile(file);
        results.push_back(result);
        ++scanned;

        // İstatistik güncelle
        switch (result.threatLevel) {
            case ThreatLevel::CLEAN:      ++m_lastStats.cleanFiles;      break;
            case ThreatLevel::SUSPICIOUS: ++m_lastStats.suspiciousFiles; break;
            case ThreatLevel::MALWARE:    ++m_lastStats.malwareFiles;    break;
            case ThreatLevel::CRITICAL:   ++m_lastStats.criticalFiles;   break;
        }
        if (!result.scanSuccess) ++m_lastStats.errorFiles;
    }

    auto totalEnd = std::chrono::high_resolution_clock::now();
    m_lastStats.totalTimeMs = std::chrono::duration<double, std::milli>(
        totalEnd - totalStart).count();

    LOGI("Dizin taraması bitti: %u dosya, %.0fms, %u tehdit",
         scanned, m_lastStats.totalTimeMs,
         m_lastStats.malwareFiles + m_lastStats.criticalFiles);
    return results;
}

// ──────────────────────────────────────────────
//  scanAPK  — Manifest + DEX hash + dış imza
// ──────────────────────────────────────────────
ScanResult Scanner::scanAPK(const std::string& apkPath) {
    // APK bir ZIP'tir; önce bütün dosyayı hash'le
    ScanResult result = scanFile(apkPath);  // hash + imza kontrolü
    if (result.threatLevel != ThreatLevel::CLEAN) return result;

    // Sonra DEX içeriğini kontrol et
    return checkAPKContents(apkPath);
}

// ──────────────────────────────────────────────
//  checkAPKContents (DEX hash'lerini ara)
// ──────────────────────────────────────────────
ScanResult Scanner::checkAPKContents(const std::string& apkPath) {
    ScanResult result;
    result.filePath    = apkPath;
    result.threatLevel = ThreatLevel::CLEAN;
    result.scanSuccess = true;
    result.source      = "apk_content_scan";

    // TODO: minizip veya libzip ile APK içini aç,
    //       classes.dex dosyalarını geçici belleğe yükle,
    //       her DEX'in hash'ini hesapla ve DB'de sorgula.
    //
    // Örnek akış:
    //   unzFile apk = unzOpen(apkPath.c_str());
    //   while (unzGoToNextFile(apk) == UNZ_OK) {
    //       char name[256]; unzGetCurrentFileInfo(...);
    //       if (strstr(name, ".dex")) { ... hash ... lookup ... }
    //   }
    //   unzClose(apk);

    LOGI("APK içerik taraması: %s", apkPath.c_str());
    return result;
}

} // namespace AntiVirus
