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
enum DetectionFlag : uint32_t {
    DETECT_NONE               = 0,

    // Root kanıtları
    DETECT_SU_BINARY          = (1u <<  0),
    DETECT_ROOT_PACKAGES      = (1u <<  1),
    DETECT_WRITABLE_SYSTEM    = (1u <<  2),
    DETECT_RW_SYSTEM_MOUNT    = (1u <<  3),
    DETECT_ROOT_CLOAKING      = (1u <<  4),
    DETECT_BUILD_PROPS        = (1u <<  5),
    DETECT_DANGEROUS_PROPS    = (1u <<  6),
    DETECT_SHELL_ROOT_ACCESS  = (1u <<  7),

    // Bootloader
    DETECT_BOOTLOADER_UNLOCKED = (1u <<  8),
    DETECT_OEM_UNLOCK_ENABLED  = (1u <<  9),
    DETECT_AVB_DISABLED        = (1u << 10),

    // Kernel bütünlüğü
    DETECT_KERNEL_TAINTED      = (1u << 11),
    DETECT_SELINUX_DISABLED    = (1u << 12),
    DETECT_KALLSYMS_EXPOSED    = (1u << 13),
    DETECT_KERNEL_VERSION_MOD  = (1u << 14),
    DETECT_PROC_MODULES        = (1u << 15),
    DETECT_SECCOMP_DISABLED    = (1u << 16),

    // Hook framework'leri
    DETECT_FRIDA               = (1u << 17),
    DETECT_XPOSED              = (1u << 18),
    DETECT_MAGISK_HIDE         = (1u << 19),
    DETECT_SUBSTRATE           = (1u << 20),
    DETECT_MEMORY_HOOKS        = (1u << 21),
    DETECT_SUSPICIOUS_FDS      = (1u << 22),
    DETECT_PTRACE_ATTACHED     = (1u << 23),
    DETECT_MAPS_INJECTION      = (1u << 24),

    // ══ YENİ: Bellek Haritalama (Memory Mapping) Tespitleri ══════
    //
    // Anonim RWX bölge — normal uygulamada ART/JIT dışında
    // yazılabilir+çalıştırılabilir anonim sayfa olmamalıdır.
    // Ağırlık 7: ART yüksek yük altında benzer bölgeler yaratabilir
    // (false-positive önlemi: dalvik/art etiketleri filtrelenir).
    DETECT_ANON_RWX_MAPPING    = (1u << 25),

    // Shamiko / Zygisk Companion imzası.
    // Shamiko, Zygisk modüllerini gizlemek için özel süreç ve
    // bellek düzenlemesi kullanır; maps'de kendine has kalıntı bırakır.
    // Ağırlık 10: son derece spesifik, neredeyse hiç false-positive yok.
    DETECT_SHAMIKO_COMPANION   = (1u << 26),

    // Silinmiş fakat hâlâ belleğe eşlenmiş kütüphane.
    // Hook yapan araçlar genellikle .so'yu diskten siler ama
    // çalışma zamanında eşlemeyi canlı tutar (gizleme tekniği).
    // Ağırlık 6: güncelleme/hot-patch sırasında meşru olabilir,
    // bu yüzden orta ağırlık verildi.
    DETECT_DELETED_LIB_MAPPED  = (1u << 27),

    // ══ YENİ: Syscall Timing Tespitleri ══════════════════════════
    //
    // Satır içi (inline) hook tespiti — PLT/GOT prologue analizi.
    // Hooked bir libc fonksiyonunun ilk talimatı standart AARCH64
    // AAPCS prologue'ü (stp x29,x30 veya sub sp,sp,#N) yerine
    // bir dal talimatı (B, BR, MOVZ x16 + BR) içerir.
    // Ağırlık 8: güçlü kanıt; ancak proguard/lto edilmiş vendor
    // kütüphaneleri prolog değiştirebilir → orta-yüksek.
    DETECT_INLINE_HOOK         = (1u << 28),

    // Zamanlama saldırısı (timing attack) ile hook tespiti.
    // Doğrudan syscall (inline assembly) ile libc sarmalayıcı
    // arasındaki medyan süre farkı eşiği aşarsa hook şüphesi.
    // Ağırlık 5: zamanlama ölçümleri gürültülüdür (CPU yükü,
    // termal kısıtlama, vDSO) — tek başına kesin kanıt değil.
    DETECT_SYSCALL_HOOK_TIMING = (1u << 29),

    // Maps tutarsızlığı — harita boşluğu / sayısı anomalisi.
    // Shamiko ve bazı bypass araçları bellek haritasından kendi
    // eşlemelerini silerek gizler; bu durum belirli sayfa
    // adreslerinde boşluk (gap) ya da beklenenden az satır bırakır.
    // Ağırlık 6: ortam bağımlı, destekleyici kanıt olarak kullan.
    DETECT_MAPS_GAP_ANOMALY    = (1u << 30),
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
    uint32_t              flags;
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
};

} // namespace AntiVirus
#endif // ROOT_DETECTOR_H
