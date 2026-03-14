#include "root_detector.h"

#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdio>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <errno.h>
#include <dlfcn.h>
#include <link.h>
#include <chrono>
#include <android/log.h>

// sys/system_properties.h (NDK)
#include <sys/system_properties.h>

#define LOG_TAG "AV_RootDet"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)

namespace AntiVirus {

// ══════════════════════════════════════════════════════════
//  Constructor
// ══════════════════════════════════════════════════════════
RootDetector::RootDetector(const DetectorConfig& config) : m_config(config) {}

// ══════════════════════════════════════════════════════════
//  Yardımcılar
// ══════════════════════════════════════════════════════════
bool RootDetector::fileExists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

bool RootDetector::dirExists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

bool RootDetector::isReadable(const std::string& path) {
    return access(path.c_str(), R_OK) == 0;
}

std::string RootDetector::readFile(const std::string& path, size_t maxBytes) {
    int fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW); // Sembolik link takip etme
    if (fd < 0) return "";
    std::string content(maxBytes, '\0');
    ssize_t n = read(fd, &content[0], maxBytes);
    close(fd);
    if (n <= 0) return "";
    content.resize(static_cast<size_t>(n));
    return content;
}

std::string RootDetector::readSystemProp(const std::string& key) {
    char value[PROP_VALUE_MAX] = {};
    __system_property_get(key.c_str(), value);
    return value;
}

bool RootDetector::containsString(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

void RootDetector::addEvidence(DetectionReport& r, DetectionFlag flag,
                                const std::string& detail, uint8_t weight) {
    r.flags |= static_cast<uint32_t>(flag);
    r.evidences.push_back({flag, detail, weight});
    LOGW("Kanıt [w=%d]: %s", weight, detail.c_str());
}

// ══════════════════════════════════════════════════════════
//  Puan hesaplama
// ══════════════════════════════════════════════════════════
uint32_t RootDetector::computeTotalScore(const DetectionReport& r) {
    uint32_t score = 0;
    for (const auto& e : r.evidences) score += e.weight;
    return score;
}

RiskLevel RootDetector::computeRiskLevel(const DetectionReport& r) {
    uint32_t score = computeTotalScore(r);
    bool hooked    = r.isHooked;
    bool rooted    = r.isRooted;

    if (score == 0)             return RiskLevel::SAFE;
    if (score < 5)              return RiskLevel::LOW;
    if (rooted && hooked)       return RiskLevel::CRITICAL;
    if (score >= m_config.rootThresholdScore) return RiskLevel::HIGH;
    return RiskLevel::MEDIUM;
}

// ══════════════════════════════════════════════════════════
//  toJSON
// ══════════════════════════════════════════════════════════
std::string DetectionReport::toJSON() const {
    std::ostringstream j;
    j << "{"
      << "\"flags\":"       << flags
      << ",\"riskLevel\":"  << static_cast<int>(riskLevel)
      << ",\"isRooted\":"   << (isRooted  ? "true" : "false")
      << ",\"isHooked\":"   << (isHooked  ? "true" : "false")
      << ",\"bootloaderUnlocked\":" << (bootloaderUnlocked ? "true" : "false")
      << ",\"scanTimeMs\":" << scanTimeMs
      << ",\"evidences\":[";
    for (size_t i = 0; i < evidences.size(); ++i) {
        if (i) j << ",";
        j << "{\"flag\":" << static_cast<uint32_t>(evidences[i].flag)
          << ",\"weight\":" << static_cast<int>(evidences[i].weight)
          << ",\"detail\":\"" << evidences[i].detail << "\"}";
    }
    j << "]}";
    return j.str();
}

// ══════════════════════════════════════════════════════════
//  fullScan  — Tüm kontrolleri sırayla çalıştır
// ══════════════════════════════════════════════════════════
DetectionReport RootDetector::fullScan() {
    auto startTime = std::chrono::high_resolution_clock::now();

    DetectionReport report;
    report.flags              = DETECT_NONE;
    report.isRooted           = false;
    report.isHooked           = false;
    report.bootloaderUnlocked = false;

    // ── Sıra önemli: önce kolay/hızlı, sonra derin ────────
    checkBuildProperties (report);  // 1. ro.* prop'lar
    checkRootBinaries    (report);  // 2. su binary'leri
    checkRootPackages    (report);  // 3. Magisk/SuperSU APK
    checkMountPoints     (report);  // 4. /proc/mounts
    checkBootloader      (report);  // 5. Bootloader lock durumu
    checkSELinux         (report);  // 6. SELinux enforce?
    checkFrida           (report);  // 7. Frida portları + maps
    checkXposed          (report);  // 8. Xposed kütüphaneleri
    checkMagisk          (report);  // 9. Magisk özel kontroller
    checkMemoryMaps      (report);  // 10. /proc/self/maps
    checkFileDescriptors (report);  // 11. /proc/self/fd
    checkPtrace          (report);  // 12. Debugger kontrolü
    if (m_config.deepKernelCheck) {
        checkKernelIntegrity(report); // 13. Kernel taint / versiyon
        checkKernelModules  (report); // 14. Yüklenmiş LKM'ler
        checkSeccomp        (report); // 15. Seccomp durumu
    }

    // ── Sonuç karar mekanizması ────────────────────────────
    uint32_t score = computeTotalScore(report);

    // Root kararı: eşiği geçmeli
    uint32_t rootScore = 0;
    uint32_t hookScore = 0;
    for (const auto& e : report.evidences) {
        uint32_t f = static_cast<uint32_t>(e.flag);
        if (f & (DETECT_SU_BINARY | DETECT_ROOT_PACKAGES | DETECT_WRITABLE_SYSTEM |
                 DETECT_RW_SYSTEM_MOUNT | DETECT_BUILD_PROPS | DETECT_DANGEROUS_PROPS |
                 DETECT_SHELL_ROOT_ACCESS | DETECT_BOOTLOADER_UNLOCKED |
                 DETECT_KERNEL_TAINTED | DETECT_PROC_MODULES | DETECT_MAGISK_HIDE))
            rootScore += e.weight;
        if (f & (DETECT_FRIDA | DETECT_XPOSED | DETECT_SUBSTRATE | DETECT_MEMORY_HOOKS |
                 DETECT_SUSPICIOUS_FDS | DETECT_PTRACE_ATTACHED | DETECT_MAPS_INJECTION))
            hookScore += e.weight;
    }

    report.isRooted = (rootScore >= m_config.rootThresholdScore);
    report.isHooked = (hookScore >= m_config.hookThresholdScore);

    // Bootloader unlocked → ayrı flag (root olmayan cihazda da olabilir)
    report.bootloaderUnlocked = (report.flags & DETECT_BOOTLOADER_UNLOCKED) != 0;

    report.riskLevel = computeRiskLevel(report);

    auto endTime = std::chrono::high_resolution_clock::now();
    report.scanTimeMs = std::chrono::duration<double, std::milli>(
        endTime - startTime).count();

    LOGI("RootDetector tamamlandı: score=%u rooted=%d hooked=%d risk=%d [%.1fms]",
         score, report.isRooted, report.isHooked,
         static_cast<int>(report.riskLevel), report.scanTimeMs);

    return report;
}

// ══════════════════════════════════════════════════════════
//  1. Build Properties
//     — ro.debuggable, ro.build.tags, ro.build.type vb.
//     — Yüksek ağırlık: sahte cihazda değiştirilemez
// ══════════════════════════════════════════════════════════
void RootDetector::checkBuildProperties(DetectionReport& report) {

    // ro.build.tags: "release-keys" olmalı
    auto tags = readSystemProp("ro.build.tags");
    if (!tags.empty() && tags != "release-keys") {
        // test-keys veya dev-keys → root/custom ROM kanıtı
        addEvidence(report, DETECT_DANGEROUS_PROPS,
                    "ro.build.tags=" + tags, 6);
    }

    // ro.debuggable: production'da daima "0"
    auto debuggable = readSystemProp("ro.debuggable");
    if (debuggable == "1") {
        uint8_t w = m_config.tolerateDeveloperDevice ? 2 : 5;
        addEvidence(report, DETECT_BUILD_PROPS,
                    "ro.debuggable=1", w);
    }

    // ro.build.type: "user" olmalı; "userdebug"/"eng" şüpheli
    auto buildType = readSystemProp("ro.build.type");
    if (buildType == "userdebug" || buildType == "eng") {
        uint8_t w = m_config.tolerateDeveloperDevice ? 1 : 4;
        addEvidence(report, DETECT_BUILD_PROPS,
                    "ro.build.type=" + buildType, w);
    }

    // ro.secure: "1" olmalı
    auto secure = readSystemProp("ro.secure");
    if (secure == "0") {
        addEvidence(report, DETECT_BUILD_PROPS, "ro.secure=0", 5);
    }

    // ro.adb.secure: ADB root erişimi
    auto adbSecure = readSystemProp("ro.adb.secure");
    if (adbSecure == "0") {
        uint8_t w = m_config.tolerateDeveloperDevice ? 1 : 3;
        addEvidence(report, DETECT_BUILD_PROPS, "ro.adb.secure=0", w);
    }

    // Magisk / custom ROM imzaları
    auto serialno = readSystemProp("ro.serialno");
    if (serialno.empty() || serialno == "unknown") {
        addEvidence(report, DETECT_BUILD_PROPS,
                    "ro.serialno boş/unknown", 2);
    }
}

// ══════════════════════════════════════════════════════════
//  2. Su Binary Taraması
//     — Standart PATH'lerin dışındaki konumlara da bak
//     — Sembolik link kontrol et (gizleme)
// ══════════════════════════════════════════════════════════
void RootDetector::checkRootBinaries(DetectionReport& report) {

    // Bilinen su konumları (kapsamlı liste)
    static const char* SU_PATHS[] = {
        "/su/bin/su",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/system/xbin/sudo",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/data/adb/su",
        "/dev/com.koushikdutta.superuser.daemon/",
        "/system/app/Superuser.apk",
        nullptr
    };

    for (int i = 0; SU_PATHS[i]; ++i) {
        struct stat st;
        // lstat → sembolik link'i takip etme (gizleme tespiti)
        if (lstat(SU_PATHS[i], &st) == 0) {
            bool isLink = S_ISLNK(st.st_mode);
            std::string detail = std::string(SU_PATHS[i]) +
                                 (isLink ? " [symlink]" : "");
            // Çalıştırılabilir mi? → daha yüksek ağırlık
            uint8_t w = (st.st_mode & S_IXUSR) ? 9 : 6;
            addEvidence(report, DETECT_SU_BINARY, detail, w);
        }
    }

    // Busybox varlığı (root cihazda çok yaygın)
    static const char* BUSYBOX_PATHS[] = {
        "/system/xbin/busybox",
        "/system/bin/busybox",
        "/data/adb/magisk/busybox",
        nullptr
    };
    for (int i = 0; BUSYBOX_PATHS[i]; ++i) {
        if (fileExists(BUSYBOX_PATHS[i])) {
            addEvidence(report, DETECT_SU_BINARY,
                        std::string("busybox: ") + BUSYBOX_PATHS[i], 4);
        }
    }

    // /sbin/magisk — doğrudan Magisk binary
    if (fileExists("/sbin/magisk") || fileExists("/data/adb/magisk")) {
        addEvidence(report, DETECT_SU_BINARY, "magisk binary tespit edildi", 10);
    }
}

// ══════════════════════════════════════════════════════════
//  3. Root Paket Kontrolleri
//     — Yüklü APK'lar /data/app altında aranır
//     — pm komutu KULLANILMAZ (root gizleme atlatır)
//     — Doğrudan dosya sistemi kontrolü
// ══════════════════════════════════════════════════════════
void RootDetector::checkRootPackages(DetectionReport& report) {

    // Bilinen kötü niyetli paket isimleri (dizin varlığı)
    static const char* BAD_PACKAGES[] = {
        "com.noshufou.android.su",
        "com.noshufou.android.su.elite",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.topjohnwu.magisk",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.ronin",
        "com.zhiqupk.root.global",
        "com.alephzain.framaroot",
        "com.koushikdutta.rommanager",
        "com.dimonvideo.luckypatcher",
        "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine",
        nullptr
    };

    static const char* DATA_APP = "/data/app";
    DIR* dir = opendir(DATA_APP);
    if (!dir) return;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        for (int i = 0; BAD_PACKAGES[i]; ++i) {
            // Paket ismiyle başlıyorsa (versiyon soneki olabilir)
            if (name.find(BAD_PACKAGES[i]) == 0) {
                addEvidence(report, DETECT_ROOT_PACKAGES,
                            "Zararlı paket: " + name, 8);
            }
        }
    }
    closedir(dir);
}

// ══════════════════════════════════════════════════════════
//  4. Mount Point Kontrolleri
//     — /proc/mounts oku
//     — /system, /vendor, /data mount seçeneklerini kontrol et
// ══════════════════════════════════════════════════════════
void RootDetector::checkMountPoints(DetectionReport& report) {
    std::ifstream mounts("/proc/mounts");
    if (!mounts.is_open()) return;

    std::string line;
    while (std::getline(mounts, line)) {
        // /system rw olarak mount'lanmış mı?
        if (line.find("/system") != std::string::npos &&
            line.find(" rw") != std::string::npos) {
            addEvidence(report, DETECT_RW_SYSTEM_MOUNT,
                        "/system rw mount: " + line.substr(0, 80), 8);
        }

        // /vendor rw — daha az olası ama şüpheli
        if (line.find("/vendor") != std::string::npos &&
            line.find(" rw") != std::string::npos) {
            addEvidence(report, DETECT_RW_SYSTEM_MOUNT,
                        "/vendor rw mount", 6);
        }

        // tmpfs üzerine mount (gizleme tekniği)
        if (line.find("tmpfs") != std::string::npos &&
            (line.find("/system") != std::string::npos ||
             line.find("/sbin")   != std::string::npos)) {
            addEvidence(report, DETECT_ROOT_CLOAKING,
                        "tmpfs overlay şüphesi: " + line.substr(0, 80), 7);
        }
    }

    // /system gerçekten yazılabilir mi? (çift kontrol)
    if (access("/system/xbin", W_OK) == 0) {
        addEvidence(report, DETECT_WRITABLE_SYSTEM,
                    "/system/xbin yazılabilir", 9);
    }
    if (access("/system/bin", W_OK) == 0) {
        addEvidence(report, DETECT_WRITABLE_SYSTEM,
                    "/system/bin yazılabilir", 9);
    }
}

} // namespace AntiVirus
