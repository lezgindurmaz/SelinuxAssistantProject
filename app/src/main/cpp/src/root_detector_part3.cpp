#include "root_detector.h"

#include <fstream>
#include <sstream>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <android/log.h>

#define LOG_TAG "AV_HookDet"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)

namespace AntiVirus {

// ══════════════════════════════════════════════════════════
//  10. Frida Tespiti
//      Frida en yaygın dinamik analiz ve hook aracı.
//      Çok katmanlı kontrol gerektirir çünkü gizlenmeye çalışır.
// ══════════════════════════════════════════════════════════
void RootDetector::checkFrida(DetectionReport& report) {

    // ── a) Frida'nın default TCP port'ları ──────────────
    // frida-server: 27042 (default)
    // frida-gadget: 27043
    static const uint16_t FRIDA_PORTS[] = { 27042, 27043, 0 };

    for (int i = 0; FRIDA_PORTS[i] != 0; ++i) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        // Non-blocking: bağlanamazsa hemen devam et
        struct timeval tv = {0, 200000}; // 200ms timeout
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons(FRIDA_PORTS[i]);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        if (connect(sock, reinterpret_cast<struct sockaddr*>(&addr),
                    sizeof(addr)) == 0) {
            // Bağlantı başarılı → Frida server çalışıyor
            // Frida'nın el sıkışma magic'ini kontrol et
            char banner[32] = {};
            recv(sock, banner, sizeof(banner) - 1, MSG_DONTWAIT);
            // Frida banner: "FRIDACLIENT..." veya başka imza içerir
            std::string bannerStr(banner);
            bool isFrida = containsString(bannerStr, "FRIDA") ||
                           containsString(bannerStr, "frida");
            close(sock);

            addEvidence(report, DETECT_FRIDA,
                        "Frida port " + std::to_string(FRIDA_PORTS[i]) +
                        (isFrida ? " [FRIDA banner]" : " [açık port]"), 9);
        } else {
            close(sock);
        }
    }

    // ── b) /proc/self/maps'de Frida kütüphaneleri ──────
    // frida-agent, frida-gadget, re.frida.* gibi isimler
    auto maps = readFile("/proc/self/maps", 65536);
    static const char* FRIDA_MAPS[] = {
        "frida-agent", "frida-gadget", "frida-helper",
        "re.frida.server", "linjector", nullptr
    };
    for (int i = 0; FRIDA_MAPS[i]; ++i) {
        if (containsString(maps, FRIDA_MAPS[i])) {
            addEvidence(report, DETECT_FRIDA,
                        std::string("maps'de Frida: ") + FRIDA_MAPS[i], 10);
        }
    }

    // ── c) Frida dosya sistemi kalıntıları ──────────────
    static const char* FRIDA_FILES[] = {
        "/data/local/tmp/frida-server",
        "/data/local/tmp/frida",
        "/sdcard/frida-server",
        "/system/lib/libfrida-agent.so",
        "/system/lib64/libfrida-agent.so",
        nullptr
    };
    for (int i = 0; FRIDA_FILES[i]; ++i) {
        if (fileExists(FRIDA_FILES[i])) {
            addEvidence(report, DETECT_FRIDA,
                        std::string("Frida dosyası: ") + FRIDA_FILES[i], 9);
        }
    }

    // ── d) /proc/self/fd üzerinden Frida pipe'ı ─────────
    // (checkFileDescriptors'da da kontrol edilir ama burada özel bak)
    DIR* fdDir = opendir("/proc/self/fd");
    if (fdDir) {
        struct dirent* entry;
        while ((entry = readdir(fdDir)) != nullptr) {
            char linkPath[64], targetPath[256];
            snprintf(linkPath, sizeof(linkPath), "/proc/self/fd/%s", entry->d_name);
            ssize_t len = readlink(linkPath, targetPath, sizeof(targetPath) - 1);
            if (len > 0) {
                targetPath[len] = '\0';
                if (strstr(targetPath, "frida") || strstr(targetPath, "linjector")) {
                    addEvidence(report, DETECT_FRIDA,
                                std::string("Frida fd: ") + targetPath, 10);
                }
            }
        }
        closedir(fdDir);
    }

    // ── e) Named pipe / socket kontrolü ─────────────────
    static const char* FRIDA_PIPES[] = {
        "/data/local/tmp/frida-socket",
        "/tmp/frida-*",
        nullptr
    };
    for (int i = 0; FRIDA_PIPES[i]; ++i) {
        struct stat st;
        if (stat(FRIDA_PIPES[i], &st) == 0) {
            if (S_ISSOCK(st.st_mode) || S_ISFIFO(st.st_mode)) {
                addEvidence(report, DETECT_FRIDA,
                            std::string("Frida socket: ") + FRIDA_PIPES[i], 9);
            }
        }
    }
}

// ══════════════════════════════════════════════════════════
//  11. Xposed Framework Tespiti
//      Xposed, Zygote'u hook'layarak tüm uygulamaları etkiler
// ══════════════════════════════════════════════════════════
void RootDetector::checkXposed(DetectionReport& report) {

    // ── a) Xposed .jar / .so dosyaları ──────────────────
    static const char* XPOSED_FILES[] = {
        "/system/framework/XposedBridge.jar",
        "/system/lib/libxposed_art.so",
        "/system/lib64/libxposed_art.so",
        "/system/xposed.prop",
        "/data/data/de.robv.android.xposed.installer",
        "/data/app/de.robv.android.xposed.installer",
        // EdXposed / LSPosed (modern Xposed fork)
        "/system/framework/edxp.jar",
        "/data/adb/lspd",
        "/data/misc/grave",
        nullptr
    };
    for (int i = 0; XPOSED_FILES[i]; ++i) {
        if (fileExists(XPOSED_FILES[i]) || dirExists(XPOSED_FILES[i])) {
            addEvidence(report, DETECT_XPOSED,
                        std::string("Xposed dosyası: ") + XPOSED_FILES[i], 9);
        }
    }

    // ── b) /proc/self/maps'de Xposed kütüphaneleri ──────
    auto maps = readFile("/proc/self/maps", 65536);
    static const char* XPOSED_MAPS[] = {
        "XposedBridge", "xposed", "edxp", "lspd",
        "de.robv.android", nullptr
    };
    for (int i = 0; XPOSED_MAPS[i]; ++i) {
        if (containsString(maps, XPOSED_MAPS[i])) {
            addEvidence(report, DETECT_XPOSED,
                        std::string("maps'de Xposed: ") + XPOSED_MAPS[i], 9);
        }
    }

    // ── c) Java stack analizi (JNI üzerinden) ───────────
    // XposedBridge.jar meşhur yığın izi bırakır
    // Bu kontrolü JNI bridge'de Java tarafında da yapmak gerekir:
    //   Thread.currentThread().getStackTrace() içinde
    //   "de.robv.android.xposed" geçiyorsa → Xposed aktif
    // C++ tarafında bunu doğrudan yapamayız; işaret olarak kaydedelim:

    // ── d) System property ile tespit ───────────────────
    auto xprop = readSystemProp("ro.xposed.version");
    if (!xprop.empty()) {
        addEvidence(report, DETECT_XPOSED,
                    "ro.xposed.version=" + xprop, 10);
    }
}

// ══════════════════════════════════════════════════════════
//  12. Magisk Özel Kontrolleri
//      MagiskHide / Zygisk gizleme mekanizmalarını da tespit et
// ══════════════════════════════════════════════════════════
void RootDetector::checkMagisk(DetectionReport& report) {

    // ── a) Magisk klasörleri / dosyaları ────────────────
    static const char* MAGISK_PATHS[] = {
        "/sbin/.magisk",
        "/dev/.magisk",
        "/dev/magisk",
        "/data/adb/magisk",
        "/data/adb/magisk.db",
        "/data/adb/magisk.img",
        "/cache/.disable_magisk",
        "/data/magisk.img",
        "/dev/magisk_merge",
        nullptr
    };
    for (int i = 0; MAGISK_PATHS[i]; ++i) {
        struct stat st;
        if (lstat(MAGISK_PATHS[i], &st) == 0) {
            addEvidence(report, DETECT_MAGISK_HIDE,
                        std::string("Magisk yolu: ") + MAGISK_PATHS[i], 9);
        }
    }

    // ── b) Magisk'in mount namespace gizlemesi ──────────
    // /proc/self/mountinfo içinde Magisk'in bind mount'ları kalıntı bırakır
    auto mountinfo = readFile("/proc/self/mountinfo", 32768);
    if (containsString(mountinfo, "magisk") ||
        containsString(mountinfo, "worker") ) {
        // "worker" Magisk'in tmpfs mount adı
        addEvidence(report, DETECT_MAGISK_HIDE,
                    "mountinfo'da Magisk kalıntısı", 8);
    }

    // ── c) Zygisk: /proc/<pid>/maps'de libzygisk ────────
    auto maps = readFile("/proc/self/maps", 65536);
    if (containsString(maps, "libzygisk") ||
        containsString(maps, "zygisk")) {
        addEvidence(report, DETECT_MAGISK_HIDE,
                    "maps'de Zygisk tespit edildi", 10);
    }

    // ── d) MagiskHide gizleme kontrolü ─────────────────
    // MagiskHide etkinse bazı dosyaları gizler.
    // Bunu test etmek için: normalde görünmesi gereken bir
    // dosyayı /proc/mounts vs /proc/self/mountinfo karşılaştır.
    auto mounts = readFile("/proc/mounts",    8192);
    auto mountI = readFile("/proc/self/mountinfo", 32768);

    // /system /proc/mounts'da varsa ama mountinfo'da yoksa → gizleme
    bool inMounts   = containsString(mounts, " /system ");
    bool inMountInfo = containsString(mountI, "/system");
    if (inMounts && !inMountInfo) {
        addEvidence(report, DETECT_MAGISK_HIDE,
                    "Mount namespace tutarsızlığı (gizleme şüphesi)", 7);
    }

    // ── e) /proc/net/unix üzerinden Magisk socket ───────
    auto unixSockets = readFile("/proc/net/unix", 32768);
    if (containsString(unixSockets, "@magisk") ||
        containsString(unixSockets, "magisk_")) {
        addEvidence(report, DETECT_MAGISK_HIDE,
                    "/proc/net/unix'de Magisk socket", 9);
    }
}

// ══════════════════════════════════════════════════════════
//  13. Bellek Haritası Analizi  (/proc/self/maps)
//      Bilinmeyen ve şüpheli .so dosyaları
// ══════════════════════════════════════════════════════════
void RootDetector::checkMemoryMaps(DetectionReport& report) {
    std::ifstream mapsFile("/proc/self/maps");
    if (!mapsFile.is_open()) return;

    // Şüpheli kütüphane imzaları (küçük harf)
    static const char* SUSPICIOUS_LIBS[] = {
        "substrate",       // Cydia Substrate
        "cydia",
        "jailbreak",
        "hook",            // Generic hook kütüphanesi
        "inject",
        "libhook",
        "libinject",
        "whale",           // Whale hook framework
        "andromeda",       // Andromeda framework
        "xhook",           // Facebook xHook
        "bhook",           // ByteDance bHook
        "shadowhook",
        nullptr
    };

    std::string line;
    while (std::getline(mapsFile, line)) {
        // Maps satırı: addr perm offset dev inode pathname
        // Sadece dosya yolu olan satırlara bak
        size_t pathStart = line.rfind('/');
        if (pathStart == std::string::npos) continue;

        std::string libPath = line.substr(pathStart);
        std::string libLower = libPath;
        for (char& c : libLower) c = tolower(c);

        for (int i = 0; SUSPICIOUS_LIBS[i]; ++i) {
            if (containsString(libLower, SUSPICIOUS_LIBS[i])) {
                addEvidence(report, DETECT_MAPS_INJECTION,
                            "Şüpheli kütüphane maps'de: " + libPath.substr(0, 80), 8);
                break; // Aynı satırdan çoklu kanıt üretme
            }
        }

        // /data/local/tmp altından yüklenen her şey şüpheli
        if (containsString(line, "/data/local/tmp/") &&
            containsString(line, ".so")) {
            addEvidence(report, DETECT_MAPS_INJECTION,
                        "tmp'den .so yüklendi: " + libPath.substr(0, 80), 7);
        }
    }
}

// ══════════════════════════════════════════════════════════
//  14. File Descriptor Taraması  (/proc/self/fd)
//      Beklenmedik pipe/socket/dosya → enjeksiyon kanıtı
// ══════════════════════════════════════════════════════════
void RootDetector::checkFileDescriptors(DetectionReport& report) {
    DIR* fdDir = opendir("/proc/self/fd");
    if (!fdDir) return;

    struct dirent* entry;
    int suspiciousFdCount = 0;

    while ((entry = readdir(fdDir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;

        char linkPath[64];
        char target[512] = {};
        snprintf(linkPath, sizeof(linkPath), "/proc/self/fd/%s", entry->d_name);
        ssize_t len = readlink(linkPath, target, sizeof(target) - 1);
        if (len <= 0) continue;
        target[len] = '\0';

        std::string t = target;

        // /data/local/tmp altından açık dosya
        if (containsString(t, "/data/local/tmp")) {
            ++suspiciousFdCount;
            addEvidence(report, DETECT_SUSPICIOUS_FDS,
                        "fd → /data/local/tmp: " + t.substr(0, 80), 6);
        }
        // Gizli dosyalar (nokta ile başlayan)
        if (t.find("/.") != std::string::npos) {
            ++suspiciousFdCount;
        }
        // Frida / Magisk socket'ları
        if (containsString(t, "frida") || containsString(t, "magisk")) {
            ++suspiciousFdCount;
            addEvidence(report, DETECT_SUSPICIOUS_FDS,
                        "Şüpheli fd hedefi: " + t.substr(0, 80), 9);
        }
    }
    closedir(fdDir);
}

// ══════════════════════════════════════════════════════════
//  15. Ptrace / Debugger Tespiti
//      TracerPid ≠ 0 → debugger eklenmiş
//      PTRACE_TRACEME → kendi kendini trace et (anti-debug)
// ══════════════════════════════════════════════════════════
void RootDetector::checkPtrace(DetectionReport& report) {

    // ── a) /proc/self/status → TracerPid ────────────────
    auto status = readFile("/proc/self/status", 4096);
    size_t pos  = status.find("TracerPid:");
    if (pos != std::string::npos) {
        size_t valPos = status.find_first_not_of(" \t", pos + 10);
        if (valPos != std::string::npos) {
            long tracerPid = strtol(status.c_str() + valPos, nullptr, 10);
            if (tracerPid != 0) {
                addEvidence(report, DETECT_PTRACE_ATTACHED,
                            "TracerPid=" + std::to_string(tracerPid) +
                            " — debugger bağlı!", 10);
            }
        }
    }

    // ── b) PTRACE_TRACEME dene ───────────────────────────
    // Eğer zaten izleniyorsa PTRACE_TRACEME hata döner (EPERM)
    // Bu erken döndüğü için ana kontrol /status üzerinden daha güvenilir
    errno = 0;
    long result = ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
    if (result == -1 && errno == EPERM) {
        // Zaten trace altındayız
        addEvidence(report, DETECT_PTRACE_ATTACHED,
                    "ptrace(TRACEME) EPERM → aktif debugger", 9);
    } else if (result == 0) {
        // Başarılı: kendi kendimizi trace ettik, hemen serbest bırak
        ptrace(PTRACE_DETACH, getpid(), nullptr, nullptr);
    }

    // ── c) Timing-based anti-debug ──────────────────────
    // Debugger single-step yaptığında belirgin gecikme oluşur
    // 1000 iterasyonluk döngü normalde <1ms sürmeli
    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    volatile int dummy = 0;
    for (int i = 0; i < 10000; ++i) dummy += i; // optimize edilmemesi için volatile
    clock_gettime(CLOCK_MONOTONIC, &t2);

    long elapsedMs = (t2.tv_sec  - t1.tv_sec)  * 1000 +
                     (t2.tv_nsec - t1.tv_nsec) / 1000000;

    if (elapsedMs > 100) {  // 100ms'den fazla → single-step şüphesi
        addEvidence(report, DETECT_PTRACE_ATTACHED,
                    "Timing anomali: " + std::to_string(elapsedMs) +
                    "ms (debugger şüphesi)", 5);
    }

    // ── d) PR_SET_DUMPABLE kontrolü ─────────────────────
    int dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    if (dumpable == 2) {
        // Suid-dumpable → olağandışı süreç durumu
        addEvidence(report, DETECT_PTRACE_ATTACHED,
                    "PR_GET_DUMPABLE=2 (suid-dumpable)", 4);
    }
}

} // namespace AntiVirus
