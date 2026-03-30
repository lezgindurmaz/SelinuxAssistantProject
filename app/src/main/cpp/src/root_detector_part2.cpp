#include "root_detector.h"

#include <fstream>
#include <sstream>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/system_properties.h>
#include <android/log.h>
#include <dirent.h>

#define LOG_TAG "AV_KernelDet"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)

namespace AntiVirus {

// ══════════════════════════════════════════════════════════
//  5. Bootloader Durumu
//     Birden fazla bağımsız kaynaktan kontrol et:
//       a) ro.boot.verifiedbootstate
//       b) ro.boot.flash.locked
//       c) ro.boot.vbmeta.device_state
//       d) /sys/class/block/mmcblk0 flag'leri (bazı OEM'ler)
//     False-positive riski: bazı GSI/pixel cihazlar
//     unlocked ama rom imzalı olabilir. Bu nedenle ağırlık orta.
// ══════════════════════════════════════════════════════════
void RootDetector::checkBootloader(DetectionReport& report) {

    // a) Android Verified Boot durumu
    //    "green"  = kilitli + doğrulama tamam
    //    "yellow" = kilitli ama özel anahtar (3. parti ROM)
    //    "orange" = kilit açık
    //    "red"    = doğrulama BAŞARISIZ
    auto vbState = readSystemProp("ro.boot.verifiedbootstate");
    if (vbState == "orange") {
        addEvidence(report, DETECT_BOOTLOADER_UNLOCKED,
                    "ro.boot.verifiedbootstate=orange (bootloader açık)", 8);
    } else if (vbState == "yellow") {
        // Kilitli ama imzasız ROM → düşük ağırlık
        addEvidence(report, DETECT_BOOTLOADER_UNLOCKED,
                    "ro.boot.verifiedbootstate=yellow (özel anahtar)", 4);
    } else if (vbState == "red") {
        // Doğrulama hatası → kritik
        addEvidence(report, DETECT_BOOTLOADER_UNLOCKED,
                    "ro.boot.verifiedbootstate=red (AVB hatası!)", 10);
    }

    // b) Direkt flash.locked bayrağı
    auto flashLocked = readSystemProp("ro.boot.flash.locked");
    if (flashLocked == "0") {
        addEvidence(report, DETECT_BOOTLOADER_UNLOCKED,
                    "ro.boot.flash.locked=0", 7);
    }

    // c) vbmeta device state
    auto vbmeta = readSystemProp("ro.boot.vbmeta.device_state");
    if (vbmeta == "unlocked") {
        addEvidence(report, DETECT_BOOTLOADER_UNLOCKED,
                    "ro.boot.vbmeta.device_state=unlocked", 7);
    }

    // d) OEM unlock (kullanıcı enabled etmiş mi?)
    auto oemUnlock = readSystemProp("sys.oem_unlock_allowed");
    if (oemUnlock == "1") {
        addEvidence(report, DETECT_OEM_UNLOCK_ENABLED,
                    "sys.oem_unlock_allowed=1", 5);
    }

    // e) AVB (Android Verified Boot) özellikle devre dışı bırakılmış mı?
    //    /proc/cmdline içinde androidboot.veritymode bak
    auto cmdline = readFile("/proc/cmdline", 2048);
    if (!cmdline.empty()) {
        if (containsString(cmdline, "androidboot.veritymode=eio") ||
            containsString(cmdline, "androidboot.veritymode=disabled")) {
            addEvidence(report, DETECT_AVB_DISABLED,
                        "dm-verity devre dışı (/proc/cmdline)", 9);
        }
        if (containsString(cmdline, "androidboot.unlocked=1") ||
            containsString(cmdline, "bootloader=unlocked")) {
            addEvidence(report, DETECT_BOOTLOADER_UNLOCKED,
                        "Kernel cmdline: bootloader unlocked", 8);
        }
    }
}

// ══════════════════════════════════════════════════════════
//  6. SELinux Kontrolü
//     permissive → root/hook saldırıları çok daha kolay
//     disabled   → kritik sistem bütünlük sorunu
// ══════════════════════════════════════════════════════════
void RootDetector::checkSELinux(DetectionReport& report) {

    // /sys/fs/selinux/enforce: "1" = enforce, "0" = permissive
    auto enforce = readFile("/sys/fs/selinux/enforce", 4);
    if (!enforce.empty()) {
        if (enforce[0] == '0') {
            addEvidence(report, DETECT_SELINUX_DISABLED,
                        "SELinux permissive moda alınmış!", 9);
        }
    } else {
        // Dosya yoksa selinux tamamen disabled
        addEvidence(report, DETECT_SELINUX_DISABLED,
                    "/sys/fs/selinux/enforce erişilemiyor (disabled?)", 7);
    }

    // /sys/fs/selinux/status çift kontrol
    auto status = readFile("/sys/fs/selinux/status", 64);
    if (containsString(status, "enforcing=0")) {
        addEvidence(report, DETECT_SELINUX_DISABLED,
                    "SELinux status: enforcing=0", 8);
    }
}

// ══════════════════════════════════════════════════════════
//  7. Kernel Bütünlük Kontrolleri
//     a) /proc/sys/kernel/tainted — kernel "kirlenmiş" mi?
//     b) uname() ile kernel versiyon string analizi
//     c) /proc/kallsyms erişilebilirlik
//     d) /proc/cmdline şüpheli parametreler
// ══════════════════════════════════════════════════════════
void RootDetector::checkKernelIntegrity(DetectionReport& report) {

    // a) Tainted kernel bayrağı
    //    Bit anlamları (önemliler):
    //    Bit 0  (1)  = GPL olmayan modül yüklendi
    //    Bit 12 (4096) = Unsigned modül
    //    Bit 13 (8192) = Staging driver
    auto taintedStr = readFile("/proc/sys/kernel/tainted", 16);
    if (!taintedStr.empty()) {
        long tainted = strtol(taintedStr.c_str(), nullptr, 10);
        if (tainted != 0) {
            // Sadece bit 0 ve 12 → şüpheli
            // Bit 0: GPL olmayan modül (Magisk genellikle bunu tetikler)
            if (tainted & 0x1) {
                addEvidence(report, DETECT_KERNEL_TAINTED,
                            "Kernel tainted bit0: GPL-dışı modül yüklü", 8);
            }
            if (tainted & 0x1000) {  // bit 12
                addEvidence(report, DETECT_KERNEL_TAINTED,
                            "Kernel tainted bit12: imzasız modül", 9);
            }
            // Diğer bit kombinasyonları
            if (tainted & ~(0x1 | 0x1000 | 0x2000)) {
                addEvidence(report, DETECT_KERNEL_TAINTED,
                            "Kernel tainted=0x" + std::to_string(tainted), 7);
            }
        }
    }

    // b) Kernel versiyon string kontrolü
    struct utsname uts;
    if (uname(&uts) == 0) {
        std::string release = uts.release;
        std::string version = uts.version;

        // Custom kernel işaretleri
        static const char* CUSTOM_KERNEL_TAGS[] = {
            "kali", "nethunter", "ElementalX", "Franco",
            "sultan", "Magisk", "magisk",
            nullptr
        };
        for (int i = 0; CUSTOM_KERNEL_TAGS[i]; ++i) {
            if (containsString(release, CUSTOM_KERNEL_TAGS[i]) ||
                containsString(version, CUSTOM_KERNEL_TAGS[i])) {
                addEvidence(report, DETECT_KERNEL_VERSION_MOD,
                            "Custom kernel tespit edildi: " + release.substr(0, 64), 7);
                break;
            }
        }

        // Derleme zamanında kök olarak derleme (usul dışı)
        if (containsString(version, "#") &&
            containsString(version, "root@")) {
            addEvidence(report, DETECT_KERNEL_VERSION_MOD,
                        "Kernel root olarak derlendi: " + version.substr(0, 64), 5);
        }
    }

    // c) /proc/kallsyms — normal cihazda okunamamalı
    //    Okunabilirse kernel restrict_symbols kapalıdır
    if (m_config.checkKallsyms) {
        int fd = open("/proc/kallsyms", O_RDONLY | O_NOFOLLOW);
        if (fd >= 0) {
            char buf[64];
            ssize_t n = read(fd, buf, sizeof(buf));
            close(fd);
            if (n > 0 && buf[0] != '0') {
                // Gerçek adresler okunabildi (0000... değil)
                addEvidence(report, DETECT_KALLSYMS_EXPOSED,
                            "/proc/kallsyms: kernel sembolleri açık", 8);
            }
        }
    }
}

// ══════════════════════════════════════════════════════════
//  8. Yüklenmiş Kernel Modülleri
//     Normal Android'de /proc/modules boş olmalı
//     (GKI modülleri hariç)
// ══════════════════════════════════════════════════════════
void RootDetector::checkKernelModules(DetectionReport& report) {
    std::ifstream modules("/proc/modules");
    if (!modules.is_open()) return;

    // Meşru Android GKI modül isimleri
    static const char* LEGIT_MODULES[] = {
        "binder_linux", "ashmem_linux", "cfg80211",
        "mac80211", "bluetooth", nullptr
    };

    std::string line;
    int suspiciousCount = 0;
    while (std::getline(modules, line)) {
        if (line.empty()) continue;

        // Modül adını al (ilk kelime)
        std::string modName = line.substr(0, line.find(' '));

        bool legit = false;
        for (int i = 0; LEGIT_MODULES[i]; ++i) {
            if (modName == LEGIT_MODULES[i]) { legit = true; break; }
        }
        if (!legit) {
            ++suspiciousCount;
            if (suspiciousCount <= 3) {  // Çok fazla log'u önle
                addEvidence(report, DETECT_PROC_MODULES,
                            "Şüpheli kernel modülü: " + modName, 6);
            }
        }
    }

    if (suspiciousCount > 3) {
        addEvidence(report, DETECT_PROC_MODULES,
                    std::to_string(suspiciousCount) + " şüpheli modül toplam", 4);
    }
}

// ══════════════════════════════════════════════════════════
//  9. Seccomp Durumu
//     Normal Android süreçleri seccomp ile filtrelenir
//     Seccomp yoksa hook ya da root'a işaret edebilir
// ══════════════════════════════════════════════════════════
void RootDetector::checkSeccomp(DetectionReport& report) {
    // /proc/self/status içinde Seccomp satırı
    auto status = readFile("/proc/self/status", 4096);
    if (status.empty()) return;

    size_t pos = status.find("Seccomp:");
    if (pos == std::string::npos) {
        addEvidence(report, DETECT_SECCOMP_DISABLED,
                    "/proc/self/status: Seccomp satırı yok", 6);
        return;
    }

    // "Seccomp:\t2" → filter mode (normal)
    // "Seccomp:\t0" → disabled
    // "Seccomp:\t1" → strict (nadir)
    size_t valPos = status.find_first_not_of(" \t", pos + 8);
    if (valPos != std::string::npos) {
        char c = status[valPos];
        if (c == '0') {
            addEvidence(report, DETECT_SECCOMP_DISABLED,
                        "Seccomp=0: filtresiz! (hook/root riski)", 8);
        }
        // c == '2' normal, rapor etme
    }
}

} // namespace AntiVirus
