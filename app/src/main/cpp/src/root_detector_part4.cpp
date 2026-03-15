// ══════════════════════════════════════════════════════════════════════
//  root_detector_part4.cpp
//  Gelişmiş Bellek Haritalama Analizi + Syscall Zamanlama Tespiti
//
//  İki yeni kontrol:
//
//  1) checkMemoryMapsAdvanced()
//     /proc/self/maps'i satır satır parse ederek şunları arar:
//       a) Anonim RWX bölgeler  (dalvik/art etiketleri filtrelenir)
//       b) Shamiko / Zygisk companion kalıntıları
//       c) "(deleted)" etiketli hâlâ eşlenmiş .so dosyaları
//       d) Harita boşluğu / sayı anomalisi (Shamiko gizleme iz)
//
//  2) checkSyscallTiming()
//     İki aşamalı hook tespiti:
//       a) PLT/GOT prologue bayt analizi  (getpid, getuid, open)
//          ARM64'te normal prolog: stp x29,x30,[sp,#-N]! veya benzer
//          Hook prolog:            B <offset>  veya  MOV x16,#addr + BR
//       b) Inline asm doğrudan syscall ile libc sarmalayıcı zaman farkı
//          Medyan alınır; gürültü bastırılır; eşik aşılırsa uyarı verilir
//
//  FALSE-POSİTİF ÖNLEYİCİ TASARIM KARARLARI
//  ──────────────────────────────────────────
//  • Anonim RWX: yalnızca "dalvik"/"art"/"jit"/"ashmem"/"stack"/"heap"
//    etiketi OLMAYAN bölgeler işaretlenir; ART JIT cache kayıt dışı.
//  • Timing: warmup (50 iterasyon atılır) + medyan; eşik 3.5x olarak
//    ayarlanmıştır. Termal kısıtlama / yüksek CPU yükünde ratio
//    büyük ihtimalle 3.5x'i geçmez; hook genellikle 5x-20x ekler.
//  • Prologue: yalnızca iki ardışık talimatın ikisi de hook kalıbıyla
//    eşleşirse işaretlenir (tek opcode false-positive verebilir).
//  • (deleted): ".so (deleted)" ve ".so\x20(deleted)" her ikisi kontrol.
//  • Shamiko: yalnızca "companion" + ("zygisk" veya "shamiko") birlikte
//    bulunursa işaretlenir — tek kelime yeterli değil.
//  • Ağırlıklar:
//       DETECT_ANON_RWX_MAPPING    = 7   (ART cache riski hafifletildi)
//       DETECT_SHAMIKO_COMPANION   = 10  (yüksek özgüllük)
//       DETECT_DELETED_LIB_MAPPED  = 6   (hot-patch olabilir)
//       DETECT_INLINE_HOOK         = 8   (prologue değişimi güçlü kanıt)
//       DETECT_SYSCALL_HOOK_TIMING = 5   (gürültülü ölçüm — destekleyici)
//       DETECT_MAPS_GAP_ANOMALY    = 6   (ortam bağımlı)
// ══════════════════════════════════════════════════════════════════════

#include "root_detector.h"

#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cmath>
#include <vector>
#include <algorithm>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <android/log.h>

#define LOG_TAG "AV_MapsTiming"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)

namespace AntiVirus {

// ══════════════════════════════════════════════════════════════════════
//  Yardımcı: nanosaniye cinsinden monotonic zaman damgası
// ══════════════════════════════════════════════════════════════════════
static inline uint64_t ns_now() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL
         + static_cast<uint64_t>(ts.tv_nsec);
}

// ══════════════════════════════════════════════════════════════════════
//  Yardımcı: ARM64 doğrudan syscall (inline assembly)
//  PLT, GOT veya libc sarmalayıcısını ATLAR; hook erişimi yoktur.
//  ARM32 için SWI #0 varyantı kullanılır.
// ══════════════════════════════════════════════════════════════════════
#if defined(__aarch64__)

// SYS_getpid = 172 (ARM64)
static inline long direct_getpid() {
    register long x8  asm("x8")  = 172;
    register long x0  asm("x0");
    asm volatile("svc #0"
                 : "=r"(x0)
                 : "r"(x8)
                 : "memory", "cc");
    return x0;
}

// SYS_getuid = 174 (ARM64)
static inline long direct_getuid() {
    register long x8  asm("x8")  = 174;
    register long x0  asm("x0");
    asm volatile("svc #0"
                 : "=r"(x0)
                 : "r"(x8)
                 : "memory", "cc");
    return x0;
}

// SYS_gettid = 178 (ARM64)
static inline long direct_gettid() {
    register long x8  asm("x8")  = 178;
    register long x0  asm("x0");
    asm volatile("svc #0"
                 : "=r"(x0)
                 : "r"(x8)
                 : "memory", "cc");
    return x0;
}

#elif defined(__arm__)

// ARM32 EABI  (SYS_getpid=20, SYS_getuid=24, SYS_gettid=224)
// Note: In thumb mode, r7 is reserved. Use a clobber or different approach if needed.
// For simplicity in NDK, use the syscall() libc function or ensure ARM mode.
static inline long direct_getpid() {
    long res;
    asm volatile(
        "mov r7, #20\n"
        "swi #0\n"
        "mov %0, r0\n"
        : "=r"(res)
        :
        : "r0", "r7", "memory", "cc"
    );
    return res;
}
static inline long direct_getuid() {
    long res;
    asm volatile(
        "mov r7, #24\n"
        "swi #0\n"
        "mov %0, r0\n"
        : "=r"(res)
        :
        : "r0", "r7", "memory", "cc"
    );
    return res;
}
static inline long direct_gettid() {
    long res;
    asm volatile(
        "mov r7, #224\n"
        "swi #0\n"
        "mov %0, r0\n"
        : "=r"(res)
        :
        : "r0", "r7", "memory", "cc"
    );
    return res;
}

#else
// Desteklenmeyen ABI: stub
static inline long direct_getpid() { return getpid(); }
static inline long direct_getuid() { return getuid(); }
static inline long direct_gettid() { return gettid(); }
#endif

// ══════════════════════════════════════════════════════════════════════
//  Yardımcı: N ölçümün medyanını hesapla (vektörü kopyala)
// ══════════════════════════════════════════════════════════════════════
static uint64_t median_ns(std::vector<uint64_t> v) {
    if (v.empty()) return 0;
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

// ══════════════════════════════════════════════════════════════════════
//  Yardımcı: ARM64 talimat kodunun hook prologue olup olmadığını sorgula
//
//  Normal AAPCS64 fonksiyon başlangıcı:
//    stp x29, x30, [sp, #-N]!   enc: 0xA9BF7BFD (ve varyantları)
//    sub sp, sp, #N             enc: 0xD10003FF (ve varyantları)
//    nop / mov x16, #...        (vDSO / syscall stub)
//
//  Hook trampolinleri (Frida, Dobby, ShadowHook, vs.):
//    B <offset>          bits[31:26] = 000101  mask: 0xFC000000 val: 0x14000000
//    BL <offset>         bits[31:26] = 100101  mask: 0xFC000000 val: 0x94000000
//    BR xN               enc: 0xD61F0000 + (N<<5)
//    BLR xN              enc: 0xD63F0000 + (N<<5)
//    MOV x16, #imm16    enc: 0xD2800010 ile başlar (Dobby stub)
//    LDR x17, [pc, #N]  enc: 0x58000011 (büyük offset yükleme + BR)
//    ADRP + ADD + BR    (Android/Bionic stub — MEŞRU olabilir!)
//
//  İKİ ardışık talimat hook kalıbıyla eşleşirse güvenilir kanıt.
//  Tek talimat yeterli değil (false-positive riski yüksek).
// ══════════════════════════════════════════════════════════════════════
#if defined(__aarch64__) || defined(__arm__)

static bool is_hook_insn(uint32_t insn) {
    // B  offset
    if ((insn & 0xFC000000u) == 0x14000000u) return true;
    // BL offset  (fonksiyon başında BL alışılmadık ama hook için kullanılır)
    if ((insn & 0xFC000000u) == 0x94000000u) return true;
    // BR  xN   (N = herhangi bir register)
    if ((insn & 0xFFFFFC1Fu) == 0xD61F0000u) return true;
    // BLR xN
    if ((insn & 0xFFFFFC1Fu) == 0xD63F0000u) return true;
    // MOV x16, #imm  (Dobby / ShadowHook stub başlangıcı)
    if ((insn & 0xFFE00000u) == 0xD2800000u &&
        ((insn >> 5) & 0x1Fu) == 16u)         return true;
    // LDR x17, [pc, #N]  (büyük adres trampolin)
    if ((insn & 0xFF000000u) == 0x58000000u &&
        ((insn & 0x1Fu) == 17u))               return true;
    return false;
}

// Normal AAPCS64 prolog kalıpları (bunlar görünürse hook DEĞİL)
static bool is_normal_prolog(uint32_t insn) {
    // stp x29, x30, [sp, #-N]!  (N çeşitli olabilir, bit alanı sabit)
    //   bits[31:23]=10100110 1   bits[4:0]=11101
    if ((insn & 0xFF8003E0u) == 0xA9800000u &&
        (insn & 0x1Fu) == 29u)                 return true;
    // sub sp, sp, #imm12
    if ((insn & 0xFFC003FFu) == 0xD10003FFu)   return true;
    // nop
    if (insn == 0xD503201Fu)                   return true;
    // pacibsp (pointer authentication — modern Android kernels)
    if (insn == 0xD503233Fu)                   return true;
    // ret (thunk — çok kısa inline fonksiyon)
    if (insn == 0xD65F03C0u)                   return true;
    return false;
}

#else
// x86 / diğer mimariler: prologue analizi desteklenmiyor
static bool is_hook_insn(uint32_t)  { return false; }
static bool is_normal_prolog(uint32_t) { return false; }
#endif

// ══════════════════════════════════════════════════════════════════════
//  checkMemoryMapsAdvanced()
// ══════════════════════════════════════════════════════════════════════
void RootDetector::checkMemoryMapsAdvanced(DetectionReport& report) {

    std::ifstream mapsFile("/proc/self/maps");
    if (!mapsFile.is_open()) {
        LOGW("checkMemoryMapsAdvanced: /proc/self/maps açılamadı");
        return;
    }

    // ─── ART/JIT beyaz liste etiketleri ─────────────────────────────
    // Bu alt dizgeleri içeren anonim bölgeler meşrudur (ART/JVM çıktısı).
    static const char* LEGIT_ANON_LABELS[] = {
        "dalvik",
        "art ",
        "jit-code",
        "jit_code",
        "/dev/ashmem",
        "[stack",
        "[heap]",
        "[vdso]",
        "[vsyscall]",
        "[vectors]",
        "anonymous:",    // Bionic mmap etiket formatı
        "chromium",      // V8/Chromium JIT
        "bss",           // .bss segment (bazı loader'lar etiketler)
        nullptr
    };

    // ─── Shamiko / Zygisk companion kalıp çiftleri ──────────────────
    // Tek kelime yeterli değil; çift eşleşme gerekli.
    struct ShamikoPair { const char* a; const char* b; };
    static const ShamikoPair SHAMIKO_PATTERNS[] = {
        { "zygisk",    "companion"  },
        { "shamiko",   "companion"  },
        { "zygisk",    "shamiko"    },
        { "zygisk64",  "daemon"     },
        { "zygisk32",  "daemon"     },
        { "magisk",    "companion"  },
        { nullptr,     nullptr      }
    };

    int    totalLines      = 0;
    int    execLines       = 0;
    int    anonRwxCount    = 0;
    int    deletedSoCount  = 0;
    bool   shamiko         = false;
    bool   gapsReported    = false;

    // Önceki bölgenin bitiş adresi (gap tespiti için)
    uint64_t prevEnd       = 0;
    int      largeGapCount = 0;

    std::string line;
    // Tüm maps metnini de topla (Shamiko tespiti için birden fazla satıra ihtiyaç olabilir)
    std::string fullMaps;
    fullMaps.reserve(65536);

    while (std::getline(mapsFile, line)) {
        ++totalLines;
        fullMaps += line;
        fullMaps += '\n';

        // ── Satır parse: addr-addr perm offset dev inode [path] ──────
        // Format: "7f1234000-7f1244000 rwxp 00000000 00:00 0 [label]\n"
        uint64_t addrStart = 0, addrEnd = 0;
        char     perm[8]   = {};
        char     path[256] = {};
        // sscanf ile parse (güvenli — yeterli buffer)
        unsigned long start = 0, end = 0;
        int parsed = sscanf(line.c_str(),
                            "%lx-%lx %7s %*x %*x:%*x %*u %255[^\n]",
                            &start, &end, perm, path);
        addrStart = start;
        addrEnd = end;

        // ── a) Gap tespiti: büyük sıçrama → gizlenmiş bölge şüphesi ─
        if (prevEnd != 0 && addrStart > prevEnd) {
            uint64_t gap = addrStart - prevEnd;
            // 64 MB'dan büyük ve 8 GB'dan küçük bir boşluk şüpheli
            // (çok büyük gap = normal sanal adres alanı — atla)
            if (gap > (64ULL * 1024 * 1024) && gap < (8ULL * 1024 * 1024 * 1024)) {
                ++largeGapCount;
            }
        }
        if (addrEnd > prevEnd) prevEnd = addrEnd;

        if (parsed < 3) continue;

        bool isExec     = (perm[2] == 'x');
        bool isWrite    = (perm[1] == 'w');
        bool isAnon     = (parsed < 4 || path[0] == '\0');  // yol yok → anonim
        std::string pathStr(path);

        if (isExec) ++execLines;

        // ── b) Anonim RWX bölge tespiti ─────────────────────────────
        if (isExec && isWrite && isAnon) {
            // Meşru ART/JIT etiketlerini filtrele
            bool isLegitJit = false;
            for (int i = 0; LEGIT_ANON_LABELS[i]; ++i) {
                if (pathStr.find(LEGIT_ANON_LABELS[i]) != std::string::npos) {
                    isLegitJit = true;
                    break;
                }
            }

            if (!isLegitJit) {
                uint64_t regionSize = addrEnd - addrStart;
                // Küçük bölgeleri (<4KB) atla: vDSO / trampolin normaldir
                if (regionSize >= 4096) {
                    ++anonRwxCount;
                    char sizeStr[32];
                    snprintf(sizeStr, sizeof(sizeStr), "%.1f KB",
                             regionSize / 1024.0);
                    addEvidence(report, DETECT_ANON_RWX_MAPPING,
                                "Anonim RWX bölge: 0x" +
                                [&](){ char b[32];
                                       snprintf(b,sizeof(b),"%lx",
                                                (unsigned long)addrStart);
                                       return std::string(b); }() +
                                " boyut=" + sizeStr,
                                7);
                    LOGW("Anonim RWX: 0x%lx-0x%lx (%s)",
                         (unsigned long)addrStart,
                         (unsigned long)addrEnd, sizeStr);
                }
            }
        }

        // ── c) (deleted) .so tespiti ─────────────────────────────────
        if (isExec && !pathStr.empty()) {
            bool isDeleted = (pathStr.find(".so (deleted)") != std::string::npos ||
                              pathStr.find(".so\x20(deleted)") != std::string::npos);
            if (isDeleted && deletedSoCount == 0) {  // Bir kez raporla
                ++deletedSoCount;
                // Yalnızca /data altından silinen .so'lar şüpheli;
                // /system altındakiler güncelleme sırasında normal olabilir.
                bool fromData = (pathStr.find("/data/") != std::string::npos);
                addEvidence(report, DETECT_DELETED_LIB_MAPPED,
                            "Silinmiş ama eşlenmiş .so: " + pathStr.substr(0, 80),
                            fromData ? 7 : 5);
                LOGW("Deleted lib: %s", pathStr.substr(0,80).c_str());
            }
        }
    }
    mapsFile.close();

    // ── d) Shamiko / Zygisk companion çift-kalıp taraması ────────────
    std::string mapsLower = fullMaps;
    for (char& c : mapsLower) c = static_cast<char>(tolower(c));

    for (int i = 0; SHAMIKO_PATTERNS[i].a; ++i) {
        if (mapsLower.find(SHAMIKO_PATTERNS[i].a) != std::string::npos &&
            mapsLower.find(SHAMIKO_PATTERNS[i].b) != std::string::npos) {
            shamiko = true;
            addEvidence(report, DETECT_SHAMIKO_COMPANION,
                        std::string("Shamiko/Zygisk companion tespit: '") +
                        SHAMIKO_PATTERNS[i].a + "' + '" +
                        SHAMIKO_PATTERNS[i].b + "'",
                        10);
            LOGW("Shamiko companion: %s + %s",
                 SHAMIKO_PATTERNS[i].a, SHAMIKO_PATTERNS[i].b);
            break;  // Bir kez yeterli
        }
    }

    // /proc/net/unix üzerinden de companion socket kontrolü
    {
        std::ifstream unixSock("/proc/net/unix");
        std::string sockLine;
        while (std::getline(unixSock, sockLine)) {
            std::string sl = sockLine;
            for (char& c : sl) c = static_cast<char>(tolower(c));
            if (!shamiko &&
                sl.find("zygisk") != std::string::npos &&
                (sl.find("companion") != std::string::npos ||
                 sl.find("daemon")    != std::string::npos)) {
                shamiko = true;
                addEvidence(report, DETECT_SHAMIKO_COMPANION,
                            "Zygisk companion socket: /proc/net/unix'de bulundu",
                            10);
                break;
            }
        }
    }

    // ── e) Harita satır sayısı anomalisi ─────────────────────────────
    // Shamiko bazı bypass araçları, kendi eşlemelerini maps'den silerek
    // gizler. Sonuç: normal bir uygulama için beklenen minimum satır
    // sayısının altında maps görünür. Normal bir Android uygulaması
    // genellikle 50+ satır içerir; eğer <20 satır varsa gizleme şüpheli.
    // (Çok fazla satır normal: ART JIT, BOM, vs. yüzlerce ekleyebilir)
    if (totalLines > 0 && totalLines < 20 && !gapsReported) {
        gapsReported = true;
        addEvidence(report, DETECT_MAPS_GAP_ANOMALY,
                    "Anormal düşük maps satır sayısı: " +
                    std::to_string(totalLines) +
                    " (gizleme şüphesi)",
                    7);
        LOGW("maps satır sayısı: %d (şüpheli düşük)", totalLines);
    }

    // Büyük gap sayısı anomalisi
    if (largeGapCount >= 3) {
        addEvidence(report, DETECT_MAPS_GAP_ANOMALY,
                    "Maps'de " + std::to_string(largeGapCount) +
                    " büyük sanal adres boşluğu (Shamiko gizleme?)",
                    6);
        LOGW("Maps büyük gap sayısı: %d", largeGapCount);
    }

    LOGI("checkMemoryMapsAdvanced: %d satır, %d exec, anonRWX=%d, "
         "deletedSo=%d, shamiko=%d, gaps=%d",
         totalLines, execLines, anonRwxCount,
         deletedSoCount, (int)shamiko, largeGapCount);
}

// ══════════════════════════════════════════════════════════════════════
//  checkSyscallTiming()
//
//  İKİ AŞAMALI hook tespiti:
//
//  Aşama A — PLT/GOT Prologue Analizi
//  ────────────────────────────────────
//  libc içindeki getpid, getuid, open fonksiyonlarının makine koduna
//  doğrudan bakılır. Hook araçları (Frida, Dobby, ShadowHook, vb.)
//  orijinal ilk birkaç talimatı bir dal talimatıyla (B, BR, MOV+BR)
//  değiştirir. İki ardışık opcode ikisi de hook kalıbındaysa uyarı.
//
//  Aşama B — Zamanlama Karşılaştırması
//  ──────────────────────────────────────
//  getpid() örneği:
//    1) 50 warmup çağrısı yap (önbellek ısıtma)
//    2) N iterasyon: hem direct_getpid() (inline asm) hem getpid() ölç
//    3) Her iki dizinin medyanını al
//    4) Oran = median_libc / median_direct
//    5) Oran >= timingHookRatio ise hook şüphesi
//    6) Ek kontrol: return value tutarsızlığı (hook sahte PID döndürüyor mu?)
//
//  Aynı prosedür getuid() için de uygulanır.
//
//  FALSE-POSİTİF ÖNLEYİCİLER:
//  • Warmup sayesinde ilk çağrı cezası elenir.
//  • Medyan kullanımı ani CPU spike'larını etkisiz kılar.
//  • Eşik 3.5x yüksek tutulur: termal kısıtlama normalde
//    1.2–1.8x ek süre ekler; 3.5x'i geçmez.
//  • Toplam timing ölçüm süresi < 5ms (kullanıcıyı bloke etmez).
//  • Return value kontrolü; yanlış PID döndürülürse doğrudan işaretlenir.
// ══════════════════════════════════════════════════════════════════════
void RootDetector::checkSyscallTiming(DetectionReport& report) {

    // ── Aşama A: PLT Prologue Analizi ───────────────────────────────
#if defined(__aarch64__) || defined(__arm__)
    struct FnCheck {
        const char* name;      // dlsym için
        const char* libname;   // "libc.so" / "libdl.so"
    };

    static const FnCheck PROBE_FNS[] = {
        { "getpid",  "libc.so"  },
        { "getuid",  "libc.so"  },
        { "open",    "libc.so"  },
        { "openat",  "libc.so"  },
        { nullptr,   nullptr    }
    };

    int hookedFnCount = 0;

    for (int fi = 0; PROBE_FNS[fi].name; ++fi) {
        // dlsym ile fonksiyon adresini al
        void* fnPtr = dlsym(RTLD_DEFAULT, PROBE_FNS[fi].name);
        if (!fnPtr) continue;

        // İlk 8 bayt = 2 adet uint32_t talimat
        const uint32_t* code = reinterpret_cast<const uint32_t*>(fnPtr);

        // Bellek erişilebilir mi? (mmap PROT_READ kontrol)
        // Bu adres /proc/self/maps'de r-x ile listelenmiş olmalı;
        // crash riski düşük ama volatile ile okuyoruz.
        uint32_t insn0 = 0, insn1 = 0;
        // SIGBUS / SIGSEGV'den korunmak için okumayı erişim kontrollü yap
        {
            // Bellek erişimi güvenli mi? (basit heuristic)
            struct stat dummy_st;
            // Alternatif: /proc/self/maps'de bu adresi ara
            // Şimdilik doğrudan oku — normal .so için güvenli
            const volatile uint32_t* vcode =
                reinterpret_cast<const volatile uint32_t*>(fnPtr);
            insn0 = vcode[0];
            insn1 = vcode[1];
        }

        bool insn0IsHook    = is_hook_insn(insn0);
        bool insn1IsHook    = is_hook_insn(insn1);
        bool insn0IsNormal  = is_normal_prolog(insn0);

        // Karar:
        //   • İlk talimat normal prolog → hook yok (güvenle geç)
        //   • İki talimat ikisi de hook kalıbı → güvenilir hook kanıtı
        //   • Sadece birinci hook kalıbı → zayıf kanıt, puansız logla

        if (!insn0IsNormal && insn0IsHook && insn1IsHook) {
            ++hookedFnCount;
            char detail[128];
            snprintf(detail, sizeof(detail),
                     "Inline hook: %s prologue 0x%08x 0x%08x (dal talimatı)",
                     PROBE_FNS[fi].name, insn0, insn1);
            addEvidence(report, DETECT_INLINE_HOOK, detail, 8);
            LOGW("%s", detail);
        } else if (!insn0IsNormal && insn0IsHook) {
            // Zayıf kanıt — yalnızca logla, kanıt ekleme
            LOGI("Şüpheli prologue (tek opcode): %s 0x%08x",
                 PROBE_FNS[fi].name, insn0);
        }
    }
    (void)hookedFnCount;
#endif // __aarch64__ || __arm__

    // ── Aşama B: Zamanlama Karşılaştırması ──────────────────────────
    //
    // getpid() ve getuid() için ölçüm yapıyoruz.
    // Bu iki syscall:
    //   a) Çok hızlıdır (ARM64'te vDSO ile ~50-200 ns)
    //   b) Side-effect yoktur (güvenli tekrar çağırma)
    //   c) Hook araçlarının sık hedef aldığı fonksiyonlardır
    //      (root tespiti engellemek için getuid() = 0 döndürme)

    const uint32_t WARMUP_N = 50;
    const uint32_t MEASURE_N = static_cast<uint32_t>(m_config.timingIterations);
    const float    RATIO_THR  = m_config.timingHookRatio;

    std::vector<uint64_t> direct_times, libc_times;
    direct_times.reserve(MEASURE_N);
    libc_times.reserve(MEASURE_N);

    // Warmup: önbelleği ısıt, JIT derlemeyi tetikle
    volatile long warmup = 0;
    for (uint32_t i = 0; i < WARMUP_N; ++i) {
        warmup += direct_getpid();
        warmup += getpid();
        warmup += direct_getuid();
        warmup += getuid();
    }
    (void)warmup;

    // Ölçüm
    for (uint32_t i = 0; i < MEASURE_N; ++i) {
        // ── Direct ──────────────────────────────────────────────────
        uint64_t t0 = ns_now();
        volatile long r_direct = direct_getpid();
        uint64_t t1 = ns_now();
        direct_times.push_back(t1 - t0);

        // ── Libc sarmalayıcı ─────────────────────────────────────────
        uint64_t t2 = ns_now();
        volatile long r_libc = getpid();
        uint64_t t3 = ns_now();
        libc_times.push_back(t3 - t2);

        // ── Return value tutarlılık kontrolü ─────────────────────────
        // Eğer hook sahte bir değer döndürüyorsa burada yakalanır.
        // getpid() sonucu her iki yolda da aynı olmalı.
        if (r_direct != r_libc) {
            char detail[128];
            snprintf(detail, sizeof(detail),
                     "getpid() return tutarsızlığı: direct=%ld libc=%ld — hook sahte PID!",
                     (long)r_direct, (long)r_libc);
            addEvidence(report, DETECT_INLINE_HOOK, detail, 10);
            LOGW("%s", detail);
            break;  // Yeterli kanıt, ölçüme devam etme
        }
    }

    // getuid() için de return value kontrolü
    {
        long uid_direct = direct_getuid();
        long uid_libc   = getuid();
        if (uid_direct != uid_libc) {
            char detail[128];
            snprintf(detail, sizeof(detail),
                     "getuid() return tutarsızlığı: direct=%ld libc=%ld — hook sahte UID!",
                     uid_direct, uid_libc);
            addEvidence(report, DETECT_INLINE_HOOK, detail, 10);
            LOGW("%s", detail);
        }
    }

    // Medyan hesapla
    uint64_t med_direct = median_ns(direct_times);
    uint64_t med_libc   = median_ns(libc_times);

    LOGI("Timing: direct_median=%.0f ns  libc_median=%.0f ns  ratio=%.2f",
         (double)med_direct, (double)med_libc,
         med_direct > 0 ? (double)med_libc / med_direct : 0.0);

    // Sıfırdan kaçın
    if (med_direct == 0) {
        LOGW("direct_median=0, zamanlama analizi atlandı");
        return;
    }

    float ratio = static_cast<float>(med_libc) / static_cast<float>(med_direct);

    // Eşiği aştıysa ve fark mutlak olarak da anlamlıysa raporla
    // (300 ns'den az mutlak farklar gürültü olabilir)
    bool absDiffSignificant = (med_libc > med_direct + 300);

    if (ratio >= RATIO_THR && absDiffSignificant) {
        char detail[192];
        snprintf(detail, sizeof(detail),
                 "Syscall zamanlama anomalisi: direct=%.0f ns  libc=%.0f ns  "
                 "oran=%.1fx (eşik=%.1fx) — hook overhead şüphesi",
                 (double)med_direct, (double)med_libc,
                 (double)ratio, (double)RATIO_THR);
        addEvidence(report, DETECT_SYSCALL_HOOK_TIMING, detail, 5);
        LOGW("%s", detail);
    }

    // Aşırı yüksek oran (>8x) — daha güçlü kanıt
    if (ratio >= 8.0f && absDiffSignificant) {
        char detail[192];
        snprintf(detail, sizeof(detail),
                 "Çok yüksek timing oranı: %.1fx — aktif hook kuvvetle şüpheli",
                 (double)ratio);
        addEvidence(report, DETECT_SYSCALL_HOOK_TIMING, detail, 7);
        LOGW("%s", detail);
    }
}

} // namespace AntiVirus
