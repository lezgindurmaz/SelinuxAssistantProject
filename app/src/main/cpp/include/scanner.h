#pragma once
#ifndef SCANNER_H
#define SCANNER_H

#include "hash_engine.h"
#include <string>
#include <vector>
#include <functional>
#include <atomic>

namespace AntiVirus {

class LocalDB;

// ─────────────────────────────────────────────
//  Tehdit seviyesi
// ─────────────────────────────────────────────
enum class ThreatLevel {
    CLEAN       = 0,
    SUSPICIOUS  = 1,
    MALWARE     = 2,
    CRITICAL    = 3
};

// ─────────────────────────────────────────────
//  Tek dosya tarama sonucu
// ─────────────────────────────────────────────
struct ScanResult {
    std::string   filePath;
    HashResult    hashes;
    ThreatLevel   threatLevel;
    std::string   threatName;    // ör: "Trojan.AndroidOS.Agent.a"
    std::string   source;        // "local_db" | "cloud" | "clean"
    bool          scanSuccess;
    std::string   error;
    double        scanTimeMs;
};

// ─────────────────────────────────────────────
//  Toplu tarama istatistikleri
// ─────────────────────────────────────────────
struct ScanStats {
    uint32_t totalFiles;
    uint32_t cleanFiles;
    uint32_t suspiciousFiles;
    uint32_t malwareFiles;
    uint32_t criticalFiles;
    uint32_t errorFiles;
    double   totalTimeMs;
};

// ─────────────────────────────────────────────
//  Progress callback tipi
//  (UI katmanına ilerleme bildirmek için)
// ─────────────────────────────────────────────
using ProgressCallback = std::function<void(
    uint32_t    scanned,
    uint32_t    total,
    const std::string& currentFile
)>;

// ─────────────────────────────────────────────
//  Tarama konfigürasyonu
// ─────────────────────────────────────────────
struct ScanConfig {
    bool    scanSubdirectories  = true;
    bool    skipSystemFiles     = true;      // /proc, /sys vb. atla
    bool    useLocalDB          = true;
    bool    useCloudLookup      = true;
    bool    cloudFallbackOnly   = true;      // Cloud'u sadece local miss'te kullan
    size_t  maxFileSizeBytes    = 100 * 1024 * 1024; // 100 MB limit
    std::vector<std::string> skipExtensions;  // Atlanacak uzantılar
    std::vector<std::string> targetExtensions; // Sadece bunları tara (boşsa hepsi)
};

// ─────────────────────────────────────────────
//  Ana Scanner sınıfı
// ─────────────────────────────────────────────
class Scanner {
public:
    explicit Scanner(const ScanConfig& config = ScanConfig{});
    ~Scanner() = default;

    // Tek dosya tara
    ScanResult scanFile(const std::string& filePath, LocalDB* sharedDB = nullptr);

    // Dizin tara (recursive)
    std::vector<ScanResult> scanDirectory(
        const std::string&   dirPath,
        ProgressCallback     onProgress = nullptr
    );

    // APK dosyasını özel olarak tara (manifest + dex analizi)
    ScanResult scanAPK(const std::string& apkPath);

    // Taramayı durdur (başka thread'den çağrılabilir)
    void cancelScan();

    // İstatistikler
    ScanStats getLastStats() const { return m_lastStats; }

private:
    ScanConfig        m_config;
    HashEngine        m_hashEngine;
    ScanStats         m_lastStats;
    std::atomic<bool> m_cancelRequested{false};

    // Dahili yardımcılar
    bool   shouldSkipFile(const std::string& path, size_t fileSize) const;
    bool   isAPK         (const std::string& path) const;
    std::vector<std::string> collectFiles(const std::string& dirPath) const;

    // APK içi DEX hash kontrolü
    ScanResult checkAPKContents(const std::string& apkPath);
};

} // namespace AntiVirus

#endif // SCANNER_H
