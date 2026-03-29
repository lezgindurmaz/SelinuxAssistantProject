#pragma once
#ifndef ROOT_DETECTOR_H
#define ROOT_DETECTOR_H

#include <string>
#include <vector>
#include <cstdint>

namespace AntiVirus {

// ═══════════════════════════════════════════════════════════
//  Tespit kategorileri  (bitmask — birden fazla aynı anda olabilir)
// ═══════════════════════════════════════════════════════════
enum DetectionFlag : uint32_t {
    DETECT_NONE               = 0,

    // Root kanıtları
    DETECT_SU_BINARY          = (1u <<  0),  // su binary bulundu
    DETECT_ROOT_PACKAGES      = (1u <<  1),  // Magisk/SuperSU paketi
    DETECT_WRITABLE_SYSTEM    = (1u <<  2),  // /system yazılabilir mount
    DETECT_RW_SYSTEM_MOUNT    = (1u <<  3),  // /proc/mounts'da rw system
    DETECT_ROOT_CLOAKING      = (1u <<  4),  // Hide/cloak girişimi tespit
    DETECT_BUILD_PROPS        = (1u <<  5),  // ro.debuggable=1 vb.
    DETECT_DANGEROUS_PROPS    = (1u <<  6),  // test-keys, dev-keys
    DETECT_SHELL_ROOT_ACCESS  = (1u <<  7),  // id komutu root döndürdü

    // Bootloader
    DETECT_BOOTLOADER_UNLOCKED = (1u <<  8), // Bootloader açık
    DETECT_OEM_UNLOCK_ENABLED  = (1u <<  9), // OEM unlock aktif
    DETECT_AVB_DISABLED        = (1u << 10), // Android Verified Boot kapalı

    // Kernel bütünlüğü
    DETECT_KERNEL_TAINTED      = (1u << 11), // /proc/sys/kernel/tainted != 0
    DETECT_SELINUX_DISABLED    = (1u << 12), // SELinux permissive/disabled
    DETECT_KALLSYMS_EXPOSED    = (1u << 13), // /proc/kallsyms okunabilir
    DETECT_KERNEL_VERSION_MOD  = (1u << 14), // Kernel sürümünde şüpheli string
    DETECT_PROC_MODULES        = (1u << 15), // Yetkisiz kernel modülü
    DETECT_SECCOMP_DISABLED    = (1u << 16), // Seccomp filtresi yok

    // Hook framework'leri
    DETECT_FRIDA               = (1u << 17), // Frida agent/server
    DETECT_XPOSED              = (1u << 18), // Xposed Framework
    DETECT_MAGISK_HIDE         = (1u << 19), // MagiskHide / Zygisk
    DETECT_SUBSTRATE           = (1u << 20), // Cydia Substrate
    DETECT_MEMORY_HOOKS        = (1u << 21), // PLT/GOT hook in bellek
    DETECT_SUSPICIOUS_FDS      = (1u << 22), // /proc/self/fd şüpheli dosya
    DETECT_PTRACE_ATTACHED     = (1u << 23), // Debugger eklenmiş
    DETECT_MAPS_INJECTION      = (1u << 24), // /proc/self/maps şüpheli lib
};

// ═══════════════════════════════════════════════════════════
//  Risk seviyesi
// ═══════════════════════════════════════════════════════════
enum class RiskLevel {
    SAFE        = 0,  // Hiçbir şüpheli bulgu yok
    LOW         = 1,  // Tek zayıf kanıt (false positive olabilir)
    MEDIUM      = 2,  // Birden fazla zayıf veya tek güçlü kanıt
    HIGH        = 3,  // Root/hook kesinleşti
    CRITICAL    = 4   // Root + aktif hook aynı anda
};

// ═══════════════════════════════════════════════════════════
//  Tek bir kanıt kaydı
// ═══════════════════════════════════════════════════════════
struct Evidence {
    DetectionFlag flag;
    std::string   detail;   // Hangi dosya/prop/değer tetikledi
    uint8_t       weight;   // 1-10 arası güven ağırlığı
};

// ═══════════════════════════════════════════════════════════
//  Komple tespit raporu
// ═══════════════════════════════════════════════════════════
struct DetectionReport {
    uint32_t              flags;         // OR'lanmış DetectionFlag'ler
    RiskLevel             riskLevel;
    std::vector<Evidence> evidences;     // Her kanıt ayrı ayrı
    bool                  isRooted;      // Sonuç: root var mı?
    bool                  isHooked;      // Sonuç: hook var mı?
    bool                  bootloaderUnlocked;
    double                scanTimeMs;

    // JSON'a dönüştür (JNI bridge için)
    std::string toJSON() const;
};

// ═══════════════════════════════════════════════════════════
//  Dedektör konfigürasyonu  — false-positive dengesini ayarlar
// ═══════════════════════════════════════════════════════════
struct DetectorConfig {
    // Kaç puanın üstünde ROOTED sayalım?
    // Normal cihazda 0 puan; yanlış pozitifsizlik için 7+ öner
    uint8_t  rootThresholdScore     = 7;
    uint8_t  hookThresholdScore     = 6;

    // Developer cihaz toleransı
    // true → ADB açık / debuggable build'ler için puanı hafiflet
    bool     tolerateDeveloperDevice = false;

    // Çekirdek kontrollerini de yap (yavaş ama kapsamlı)
    bool     deepKernelCheck        = true;

    // /proc/kallsyms erişimi (root gerektirmeden erişilebiliyorsa şüpheli)
    bool     checkKallsyms          = true;
};

// ═══════════════════════════════════════════════════════════
//  Ana sınıf
// ═══════════════════════════════════════════════════════════
class RootDetector {
public:
    explicit RootDetector(const DetectorConfig& config = DetectorConfig{});
    ~RootDetector() = default;

    // Tüm kontrolleri çalıştır (asıl giriş noktası)
    DetectionReport fullScan();

    // Tekil kontroller (dilerse UI ayrı ayrı çağırabilir)
    void checkRootBinaries    (DetectionReport& report);
    void checkRootPackages    (DetectionReport& report);
    void checkBuildProperties (DetectionReport& report);
    void checkMountPoints     (DetectionReport& report);
    void checkBootloader      (DetectionReport& report);
    void checkKernelIntegrity (DetectionReport& report);
    void checkSELinux         (DetectionReport& report);
    void checkFrida           (DetectionReport& report);
    void checkXposed          (DetectionReport& report);
    void checkMagisk          (DetectionReport& report);
    void checkMemoryMaps      (DetectionReport& report);
    void checkFileDescriptors (DetectionReport& report);
    void checkPtrace          (DetectionReport& report);
    void checkKernelModules   (DetectionReport& report);
    void checkSeccomp         (DetectionReport& report);

private:
    DetectorConfig m_config;

    // Yardımcılar
    void addEvidence(DetectionReport& r, DetectionFlag flag,
                     const std::string& detail, uint8_t weight);

    bool   fileExists  (const std::string& path);
    bool   dirExists   (const std::string& path);
    bool   isReadable  (const std::string& path);
    std::string readFile       (const std::string& path, size_t maxBytes = 4096);
    std::string readSystemProp (const std::string& key);
    bool   containsString      (const std::string& haystack, const std::string& needle);

    RiskLevel   computeRiskLevel (const DetectionReport& r);
    uint32_t    computeTotalScore(const DetectionReport& r);
};

} // namespace AntiVirus

#endif // ROOT_DETECTOR_H
