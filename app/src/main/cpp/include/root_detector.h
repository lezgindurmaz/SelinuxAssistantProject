#pragma once
#ifndef ROOT_DETECTOR_H
#define ROOT_DETECTOR_H

#include <string>
#include <vector>
#include <cstdint>

namespace AntiVirus {

// ═══════════════════════════════════════════════════════════
//  Tespit kategorileri  (bitmask)
// ═══════════════════════════════════════════════════════════
enum DetectionFlag : uint64_t {
    DETECT_NONE               = 0,

    // ── Temel root kanıtları ─────────────────────────────
    DETECT_SU_BINARY          = (1ULL <<  0),
    DETECT_ROOT_PACKAGES      = (1ULL <<  1),
    DETECT_WRITABLE_SYSTEM    = (1ULL <<  2),
    DETECT_RW_SYSTEM_MOUNT    = (1ULL <<  3),
    DETECT_ROOT_CLOAKING      = (1ULL <<  4),
    DETECT_BUILD_PROPS        = (1ULL <<  5),
    DETECT_DANGEROUS_PROPS    = (1ULL <<  6),
    DETECT_SHELL_ROOT_ACCESS  = (1ULL <<  7),

    // ── Bootloader ───────────────────────────────────────
    DETECT_BOOTLOADER_UNLOCKED = (1ULL <<  8),
    DETECT_OEM_UNLOCK_ENABLED  = (1ULL <<  9),
    DETECT_AVB_DISABLED        = (1ULL << 10),

    // ── Kernel bütünlüğü ─────────────────────────────────
    DETECT_KERNEL_TAINTED      = (1ULL << 11),
    DETECT_SELINUX_DISABLED    = (1ULL << 12),
    DETECT_KALLSYMS_EXPOSED    = (1ULL << 13),
    DETECT_KERNEL_VERSION_MOD  = (1ULL << 14),
    DETECT_PROC_MODULES        = (1ULL << 15),
    DETECT_SECCOMP_DISABLED    = (1ULL << 16),

    // ── Hook framework'leri ──────────────────────────────
    DETECT_FRIDA               = (1ULL << 17),
    DETECT_XPOSED              = (1ULL << 18),
    DETECT_MAGISK_HIDE         = (1ULL << 19),
    DETECT_SUBSTRATE           = (1ULL << 20),
    DETECT_MEMORY_HOOKS        = (1ULL << 21),
    DETECT_SUSPICIOUS_FDS      = (1ULL << 22),
    DETECT_PTRACE_ATTACHED     = (1ULL << 23),
    DETECT_MAPS_INJECTION      = (1ULL << 24),

    // ── Bellek Haritalama / Timing (v1.0.7) ──────────────
    DETECT_ANON_RWX_MAPPING    = (1ULL << 25),
    DETECT_SHAMIKO_COMPANION   = (1ULL << 26),
    DETECT_DELETED_LIB_MAPPED  = (1ULL << 27),
    DETECT_INLINE_HOOK         = (1ULL << 28),
    DETECT_SYSCALL_HOOK_TIMING = (1ULL << 29),
    DETECT_MAPS_GAP_ANOMALY    = (1ULL << 30),

    // ══ YENİ: Zygote Analizi (v1.0.8) ════════════════════
    // Zygote sürecinin maps'inde şüpheli kütüphane tespit edildi.
    DETECT_ZYGOTE_MAPS_DIRTY   = (1ULL << 31),
    // Zygote'un UID/GID durumu anormal.
    DETECT_ZYGOTE_STATE_ANOM   = (1ULL << 32),
    // Zygote üzerinde başka bir süreç izleme yapıyor (TracerPid != 0).
    DETECT_ZYGOTE_TRACED       = (1ULL << 33),

    // ══ YENİ: Derin Hook Analizi (v1.0.8) ════════════════
    // GOT (Global Offset Table) girişleri beklenen adres aralığının dışına işaret ediyor.
    DETECT_GOT_OVERWRITE       = (1ULL << 34),
    // Android linker namespace'i beklenmedik bir kütüphane yüklemiş.
    DETECT_LINKER_NS_ANOMALY   = (1ULL << 35),
    // Dobby veya ShadowHook kütüphanesinin karakteristik bellekteki imzaları tespit edildi.
    DETECT_DOBBY_SHADOWHOOK    = (1ULL << 36),
};

// ═══════════════════════════════════════════════════════════
//  Risk seviyesi
// ═══════════════════════════════════════════════════════════
enum class RiskLevel {
    SAFE        = 0,
    LOW         = 1,
    MEDIUM      = 2,
    HIGH        = 3,
    CRITICAL    = 4
};

// ═══════════════════════════════════════════════════════════
//  Tek kanıt kaydı
// ═══════════════════════════════════════════════════════════
struct Evidence {
    DetectionFlag flag;
    std::string   detail;
    uint8_t       weight;   // 1–10
};

// ═══════════════════════════════════════════════════════════
//  Komple tespit raporu
// ═══════════════════════════════════════════════════════════
struct DetectionReport {
    uint64_t              flags;
    RiskLevel             riskLevel;
    std::vector<Evidence> evidences;
    bool                  isRooted;
    bool                  isHooked;
    bool                  bootloaderUnlocked;
    double                scanTimeMs;

    std::string toJSON() const;
};

// ═══════════════════════════════════════════════════════════
//  Dedektör konfigürasyonu
// ═══════════════════════════════════════════════════════════
struct DetectorConfig {
    uint8_t  rootThresholdScore      = 7;
    uint8_t  hookThresholdScore      = 6;
    bool     tolerateDeveloperDevice = false;
    bool     deepKernelCheck         = true;
    bool     checkKallsyms           = true;

    // Zygote analizi — root olmadan erişim kısıtlı olabilir
    bool     checkZygote             = true;

    // GOT hook analizi kaç fonksiyonu kontrol etsin?
    uint32_t gotCheckDepth           = 12;

    // Timing kontrolü kaç iterasyon çalıştırsın?
    // Daha fazla = daha güvenilir ama yavaş.
    // Öneri: hızlı tarama için 200, derin tarama için 500.
    uint32_t timingIterations        = 200;

    // Timing eşiği: libc/doğrudan oran bu değeri aşarsa hook şüphesi.
    // 3.0 = libc çağrısı doğrudan syscall'dan 3x daha yavaş.
    // Çok düşük değer → false-positive; çok yüksek → kaçırma riski.
    // Öneri: 3.0–4.0 arası; 3.5 dengeli.
    float    timingHookRatio         = 3.5f;
};

// ═══════════════════════════════════════════════════════════
//  Ana sınıf
// ═══════════════════════════════════════════════════════════
class RootDetector {
public:
    explicit RootDetector(const DetectorConfig& config = DetectorConfig{});
    ~RootDetector() = default;

    DetectionReport fullScan();

    // Mevcut tekil kontroller
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
    void checkKernelSu        (DetectionReport& report);
    void checkAPatch          (DetectionReport& report);

    // ── YENİ kontroller ──────────────────────────────────
    // Gelişmiş bellek haritası analizi:
    //   - Anonim RWX bölge tespiti (ART/JIT filtreli)
    //   - Shamiko / Zygisk companion imzası
    //   - Silinmiş kütüphane eşlemesi
    //   - Harita boşluğu / satır sayısı anomalisi
    void checkMemoryMapsAdvanced (DetectionReport& report);

    // Syscall zamanlama analizi:
    //   - Inline PLT/GOT prologue hook tespiti
    //   - Doğrudan asm syscall vs. libc zamanlama karşılaştırması
    void checkSyscallTiming      (DetectionReport& report);

    // ── YENİ: Derin Zygote Analizi ──────────────────────
    void checkZygoteIntegrity (DetectionReport& report);

    // ── YENİ: Derin Hook Analizi ─────────────────────────
    void checkDeepHookAnalysis(DetectionReport& report);

private:
    DetectorConfig m_config;

    void addEvidence(DetectionReport& r, DetectionFlag flag,
                     const std::string& detail, uint8_t weight);

    bool        fileExists      (const std::string& path);
    bool        dirExists       (const std::string& path);
    bool        isReadable      (const std::string& path);
    std::string readFile        (const std::string& path, size_t maxBytes = 4096);
    std::string readSystemProp  (const std::string& key);
    bool        containsString  (const std::string& haystack, const std::string& needle);

    RiskLevel   computeRiskLevel  (const DetectionReport& r);
    uint32_t    computeTotalScore (const DetectionReport& r);

    // Zygote yardımcıları
    pid_t       findZygotePid     (bool prefer64 = true);
    std::string readProcFile      (pid_t pid, const char* file,
                                   size_t maxBytes = 65536);
};

} // namespace AntiVirus
#endif // ROOT_DETECTOR_H
