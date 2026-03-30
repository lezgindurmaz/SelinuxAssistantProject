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

Scanner::Scanner(const ScanConfig& config)
    : m_config(config), m_hashEngine()
{
    memset(&m_lastStats, 0, sizeof(m_lastStats));
}

void Scanner::cancelScan() {
    m_cancelRequested.store(true);
    LOGW("Tarama iptal isteği alındı.");
}

bool Scanner::shouldSkipFile(const std::string& path, size_t fileSize) const {
    if (m_config.skipSystemFiles) {
        static const char* SKIP_PATHS[] = {
            "/proc/", "/sys/", "/dev/", "/acct/", nullptr
        };
        for (int i = 0; SKIP_PATHS[i]; ++i)
            if (path.find(SKIP_PATHS[i]) == 0) return true;
    }
    if (fileSize > m_config.maxFileSizeBytes) {
        LOGW("Dosya boyut limitini aşıyor, atlanıyor: %s", path.c_str());
        return true;
    }
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

bool Scanner::isAPK(const std::string& path) const {
    return path.size() > 4 &&
           path.substr(path.size() - 4) == ".apk";
}

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

ScanResult Scanner::scanFile(const std::string& filePath, LocalDB* sharedDB) {
    auto startTime = std::chrono::high_resolution_clock::now();
    ScanResult result;
    result.filePath    = filePath;
    result.scanSuccess = false;
    result.threatLevel = ThreatLevel::CLEAN;

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
    if (isAPK(filePath)) {
        return scanAPK(filePath);
    }
    result.hashes = m_hashEngine.hashFile(filePath, HashType::BOTH);
    if (!result.hashes.valid) {
        result.error = result.hashes.error;
        return result;
    }
    if (m_config.useLocalDB) {
        LocalDB* db = sharedDB ? sharedDB : LocalDB::getGlobalInstance();
        if (db && db->isOpen()) {
            auto record = db->lookupBySHA256(result.hashes.sha256);
            if (!record) record = db->lookupByMD5(result.hashes.md5);
            if (record) {
                result.threatLevel = record->threatLevel;
                result.threatName  = record->threatName;
                result.source      = "local_db";
                result.scanSuccess = true;
                goto scan_done;
            }
        }
    }
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
    result.source      = "clean";
    result.scanSuccess = true;

scan_done:
    auto endTime = std::chrono::high_resolution_clock::now();
    result.scanTimeMs = std::chrono::duration<double, std::milli>(
        endTime - startTime).count();
    LOGI("Tarandı [%.1fms] %s → %d", result.scanTimeMs, filePath.c_str(), static_cast<int>(result.threatLevel));
    return result;
}

std::vector<ScanResult> Scanner::scanDirectory(const std::string& dirPath, ProgressCallback onProgress) {
    m_cancelRequested.store(false);
    memset(&m_lastStats, 0, sizeof(m_lastStats));
    auto totalStart = std::chrono::high_resolution_clock::now();
    auto files = collectFiles(dirPath);
    m_lastStats.totalFiles = static_cast<uint32_t>(files.size());
    std::vector<ScanResult> results;
    results.reserve(files.size());
    uint32_t scanned = 0;
    LocalDB* globalDB = LocalDB::getGlobalInstance();
    for (const auto& file : files) {
        if (m_cancelRequested.load()) break;
        if (onProgress) onProgress(scanned, m_lastStats.totalFiles, file);
        auto result = scanFile(file, globalDB);
        results.push_back(result);
        ++scanned;
        switch (result.threatLevel) {
            case ThreatLevel::CLEAN:      ++m_lastStats.cleanFiles;      break;
            case ThreatLevel::SUSPICIOUS: ++m_lastStats.suspiciousFiles; break;
            case ThreatLevel::MALWARE:    ++m_lastStats.malwareFiles;    break;
            case ThreatLevel::CRITICAL:   ++m_lastStats.criticalFiles;   break;
        }
        if (!result.scanSuccess) ++m_lastStats.errorFiles;
    }
    auto totalEnd = std::chrono::high_resolution_clock::now();
    m_lastStats.totalTimeMs = std::chrono::duration<double, std::milli>(totalEnd - totalStart).count();
    LOGI("Dizin taraması bitti: %u dosya, %.0fms, %u tehdit", scanned, m_lastStats.totalTimeMs, m_lastStats.malwareFiles + m_lastStats.criticalFiles);
    return results;
}

ScanResult Scanner::scanAPK(const std::string& apkPath) {
    ScanResult result = scanFile(apkPath);
    if (result.threatLevel != ThreatLevel::CLEAN) return result;
    return checkAPKContents(apkPath);
}

ScanResult Scanner::checkAPKContents(const std::string& apkPath) {
    ScanResult result;
    result.filePath    = apkPath;
    result.threatLevel = ThreatLevel::CLEAN;
    result.scanSuccess = true;
    result.source      = "apk_content_scan";
    LOGI("APK içerik taraması: %s", apkPath.c_str());
    return result;
}

} // namespace AntiVirus
