#include "behavioral_analyzer.h"

#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/bpf.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cstdio>
#include <errno.h>
#include <android/log.h>

#define LOG_TAG "AV_Seccomp"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ══════════════════════════════════════════════════════════════════
//  SeccompMonitor
//
//  Amaç: Kendi uygulamamızı bir seccomp BPF filtresiyle koruya
//  ve belirlediğimiz tehlikeli syscall'ları TRAP sinyaline
//  dönüştürerek yakalayabiliriz (SECCOMP_RET_TRAP).
//
//  Kullanım:
//    1. Filter yükle (tek seferlik, uygulama başlangıcında)
//    2. SIGSYS handler kur
//    3. Zararlı syscall denendiyse → loglama + engelleme
//
//  NOT: Bu öz-koruma mekanizmasıdır; başka süreçleri izlemez.
//       Başka süreçler için ptrace_monitor.cpp kullanın.
// ══════════════════════════════════════════════════════════════════

namespace AntiVirus {

// ──────────────────────────────────────────────────────────────────
//  BPF makroları  (linux/filter.h'da da var; burada netleştiriyoruz)
// ──────────────────────────────────────────────────────────────────
#define BPF_STMT(code, k)        { static_cast<uint16_t>(code), 0, 0, k }
#define BPF_JUMP(code, k, jt,jf) { static_cast<uint16_t>(code), jt, jf, k }

// seccomp_data yapısı içindeki offsetler
#define OFF_NR      (offsetof(struct seccomp_data, nr))
#define OFF_ARCH    (offsetof(struct seccomp_data, arch))
#define OFF_ARG0    (offsetof(struct seccomp_data, args[0]))
#define OFF_ARG1    (offsetof(struct seccomp_data, args[1]))
#define OFF_ARG2    (offsetof(struct seccomp_data, args[2]))

// ──────────────────────────────────────────────────────────────────
//  SIGSYS handler — SECCOMP_RET_TRAP tetiklendiğinde çağrılır
// ──────────────────────────────────────────────────────────────────
static void sigsysHandler(int sig, siginfo_t* info, void* ucontext) {
    (void)sig;
    (void)ucontext;

    if (info->si_code != SYS_SECCOMP) return;

    int  syscallNr  = info->si_syscall;
    const char* name = syscallName(static_cast<uint32_t>(syscallNr), isArm64());

    LOGW("SECCOMP TRAP: syscall=%d (%s) arch=0x%x",
         syscallNr, name, info->si_arch);

    // Burada: JNI callback ile Kotlin katmanına bildir
    // Bu implementasyonda sadece logluyoruz.
    // Production'da: event queue'a ekle → UI thread'e ilet
}

// ──────────────────────────────────────────────────────────────────
//  Seccomp BPF filtresi yükle
//
//  Strateji: Tehlikeli syscall'lara SECCOMP_RET_TRAP döndür.
//  Diğer tüm syscall'lara SECCOMP_RET_ALLOW.
//
//  BPF programı şu mantığı izler:
//    1. Arch kontrolü (ARM64 mı ARM32 mi?)
//    2. Syscall numarası kontrolü
//    3. Tehlikeli ise → TRAP
//    4. Değilse    → ALLOW
// ──────────────────────────────────────────────────────────────────
static bool installSeccompFilter() {

    // Önce PR_SET_NO_NEW_PRIVS gerekli
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        LOGE("PR_SET_NO_NEW_PRIVS başarısız: %s", strerror(errno));
        return false;
    }

    // ARM64 mimarisini doğrula (cross-arch saldırılarını engelle)
#if defined(__aarch64__)
    uint32_t expectedArch = AUDIT_ARCH_AARCH64;
#elif defined(__arm__)
    uint32_t expectedArch = AUDIT_ARCH_ARM;
#else
    uint32_t expectedArch = AUDIT_ARCH_X86_64;
#endif

    // ── BPF program ──────────────────────────────────────────────
    // ARM64 için tehlikeli syscall numaraları
    static const uint32_t DANGEROUS_NRS[] = {
        // 101,  // ptrace (Behavior monitor için izin verildi)
        105,  // setuid
        106,  // setgid
        117,  // setresuid
        119,  // setresgid
        126,  // capset
        155,  // pivot_root
        175,  // init_module
        176,  // delete_module
        272,  // unshare
        308,  // setns
        311,  // process_vm_writev ← en kritik
        313,  // finit_module
        319,  // memfd_create
        321,  // bpf
        323,  // userfaultfd
        425,  // io_uring_setup
    };
    static const size_t N = sizeof(DANGEROUS_NRS) / sizeof(DANGEROUS_NRS[0]);

    // Her tehlikeli syscall için 2 talimat: yükle + karşılaştır
    // + genel çerçeve talimatları
    const size_t filterLen = 4 + N * 2 + 1;

    std::vector<sock_filter> filter;
    filter.reserve(filterLen);

    // 1. Arch kontrolü: yanlış arch ise öldür
    filter.push_back(BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, OFF_ARCH));
    filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                               expectedArch,
                               0, static_cast<uint8_t>(N * 2 + 1)));

    // 2. Syscall numarasını yükle
    filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR));

    // 3. Her tehlikeli syscall için karşılaştırma
    //    Eşleşirse → TRAP (jt=0 → sonraki talimat = TRAP)
    //    Eşleşmezse → bir sonraki karşılaştırmaya atla
    for (size_t i = 0; i < N; ++i) {
        uint8_t jf = static_cast<uint8_t>(N - i - 1) * 2 + 1;
        // Eşleşirse: 0 atla (TRAP'a düş)
        // Eşleşmezse: jf atla (sonraki karşılaştırma veya ALLOW)
        filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                   DANGEROUS_NRS[i], 0, jf));
        filter.push_back(BPF_STMT(BPF_RET | BPF_K,
                                   SECCOMP_RET_TRAP));  // ← TRAP
    }

    // 4. Hepsini geçtiyse: izin ver
    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    struct sock_fprog prog = {
        static_cast<unsigned short>(filter.size()),
        filter.data()
    };

    long ret = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
    if (ret != 0) {
        LOGE("seccomp filtresi yüklenemedi: %s", strerror(errno));
        return false;
    }

    LOGI("Seccomp filtresi yüklendi: %zu talimat, %zu tehlikeli syscall izleniyor",
         filter.size(), N);
    return true;
}

// ──────────────────────────────────────────────────────────────────
//  SIGSYS sinyal handler'ını kur
// ──────────────────────────────────────────────────────────────────
static bool installSigsysHandler() {
    struct sigaction sa{};
    sa.sa_sigaction = sigsysHandler;
    sa.sa_flags     = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGSYS, &sa, nullptr) != 0) {
        LOGE("SIGSYS handler kurulamadı: %s", strerror(errno));
        return false;
    }
    LOGI("SIGSYS handler kuruldu.");
    return true;
}

// ──────────────────────────────────────────────────────────────────
//  Herkese açık init fonksiyonu
//  Uygulama başlangıcında (JNI_OnLoad içinde) çağrılmalı
// ──────────────────────────────────────────────────────────────────
bool BehavioralAnalyzer::initSelfProtection() {
    if (!installSigsysHandler()) return false;
    if (!installSeccompFilter()) return false;
    LOGI("Öz-koruma aktif.");
    return true;
}

// ──────────────────────────────────────────────────────────────────
//  Seccomp destekleniyor mu? (Eski Android versiyonları için)
// ──────────────────────────────────────────────────────────────────
bool isSeccompSupported() {
    // PR_SET_NO_NEW_PRIVS + seccomp → Android 5.0+ (API 21)
    long ret = syscall(__NR_seccomp, SECCOMP_GET_ACTION_AVAIL,
                       0, reinterpret_cast<void*>(SECCOMP_RET_TRAP));
    return ret == 0 || (ret == -1 && errno == EINVAL);
}

} // namespace AntiVirus

// ──────────────────────────────────────────────────────────────────
