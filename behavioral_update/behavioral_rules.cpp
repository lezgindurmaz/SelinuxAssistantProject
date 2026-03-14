// ══════════════════════════════════════════════════════════════════
//  behavioral_rules.cpp
//  Tüm davranışsal analiz kuralları ve pattern tespitleri
//
//  Yeni tespitler:
//    - KernelSU prctl magic probe (0xdeadc0de / 0x534b5500)
//    - APatch /dev/apd ioctl tespiti
//    - /proc/pid/mem üzerinden ptrace'siz kod enjeksiyonu
//    - /dev/input/* keylogger erişimi
//    - mount --bind ile Magisk/KSU gizleme
//    - Zygote sürecine inject tespiti
//    - UID escalation: /proc/pid/status polling ile gerçek zamanlı
//    - /proc/pid/maps ile yabancı .so enjeksiyonu
//    - /proc/kallsyms okuma (exploit KASLR bypass hazırlığı)
//    - Seccomp filtresi yoklama
//    - execveat + memfd kombinasyonu (fileless v2)
//    - Tehlikeli ioctl: /dev/binder, /dev/kgsl, /dev/mali
//    - Cgroup namespace kaçışı
// ══════════════════════════════════════════════════════════════════
#include "behavioral_analyzer.h"
#include "syscall_table.h"

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <chrono>
#include <algorithm>
#include <android/log.h>

#define LOG_TAG "AV_Rules"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

namespace AntiVirus {

// ──────────────────────────────────────────────────────────────────
//  KernelSU magic değerleri
//
//  KernelSU, prctl syscall'ını "gizli SU komut kanalı" olarak kullanır.
//  Normal uygulama bu değerleri asla göndermez.
//
//  Kaynak: KernelSU source (include/uapi/linux/prctl.h override)
//    prctl(0xdeadc0de, ...)       → KernelSU varlık sorgusu
//    prctl(0xdeadbeef, ...)       → bazı fork'larda görülür
//    prctl(PR_SET_VMA, 0x534b5500, ...) → "KSU\0" magic
//    prctl(0x534b5355, ...)       → "SKsU" = KernelSU grant root
//
//  APatch:
//    ioctl(fd, 0xdeadc0de, ...)   → /dev/apd üzerinde
//    prctl(0xdeadbeef, 0xdeadbeef, ...) → APatch magic
// ──────────────────────────────────────────────────────────────────
static constexpr uint32_t KSU_MAGIC_PRCTL_CMD   = 0xdeadc0de;
static constexpr uint32_t KSU_MAGIC_PRCTL_CMD2  = 0xdeadbeef;
static constexpr uint64_t KSU_MAGIC_ARG_GRANT   = 0x534b5355ULL; // "SKsU"
static constexpr uint32_t APATCH_MAGIC_IOCTL    = 0xdeadc0deU;
static constexpr uint64_t APATCH_MAGIC_ARG      = 0xdeadbeefULL;

// prctl komutları (sys/prctl.h'de eksik olanlar)
static constexpr int PR_SET_VMA              = 0x53564d41; // Android VMA label

// ──────────────────────────────────────────────────────────────────
//  Statik kural tablosu
// ──────────────────────────────────────────────────────────────────
static const BehaviorRule DEFAULT_RULES[] = {

    // ── Bellek ──────────────────────────────────────────────────
    { "WX_Memory_mmap",
      BEH_WX_MEMORY, 9,
      Arm64::MMAP, 0x3, (PROT_WRITE|PROT_EXEC), 0, 0 },

    { "Cross_Process_Write",
      BEH_CROSS_PROC_WRITE, 10,
      Arm64::PROCESS_VM_WRITEV, 0, 0, 0, 0 },

    { "Fileless_Exec_memfd",
      BEH_FILELESS_EXEC, 9,
      Arm64::MEMFD_CREATE, 0, 0, 0, 0 },

    // ── Yetki yükseltme ─────────────────────────────────────────
    { "Setuid_Root",
      BEH_SETUID_ATTEMPT, 9,
      Arm64::SETUID, 0x1, 0x0, 0, 0 },

    { "Setresuid_Root",
      BEH_SETUID_ATTEMPT, 9,
      Arm64::SETRESUID, 0x7, 0x0, 0, 0 },

    { "Capset_Escalation",
      BEH_CAPSET_ESCALATION, 8,
      Arm64::CAPSET, 0, 0, 0, 0 },

    // ── Kernel ──────────────────────────────────────────────────
    { "LKM_finit_module",
      BEH_KERNEL_MODULE_LOAD, 10,
      Arm64::FINIT_MODULE, 0, 0, 0, 0 },

    { "LKM_init_module",
      BEH_KERNEL_MODULE_LOAD, 10,
      Arm64::INIT_MODULE, 0, 0, 0, 0 },

    { "BPF_ProgLoad",
      BEH_BPF_PROG_LOAD, 9,
      Arm64::BPF, 0, 0, 0, 0 },

    { "Perf_Event_Exploit",
      BEH_PERF_EXPLOIT, 7,
      Arm64::PERF_EVENT_OPEN, 0, 0, 0, 0 },

    { "Userfaultfd_Race",
      BEH_USERFAULTFD_EXPLOIT, 7,
      Arm64::USERFAULTFD, 0, 0, 0, 0 },

    { "IoUring_Exploit",
      BEH_IO_URING_EXPLOIT, 7,
      Arm64::IO_URING_SETUP, 0, 0, 0, 0 },

    // ── Namespace ────────────────────────────────────────────────
    { "Namespace_unshare",
      BEH_NAMESPACE_ESCAPE, 7,
      Arm64::UNSHARE, 0, 0, 0, 0 },

    { "Namespace_setns",
      BEH_NAMESPACE_ESCAPE, 8,
      Arm64::SETNS, 0, 0, 0, 0 },

    { "Pivot_Root_Escape",
      BEH_NAMESPACE_ESCAPE, 10,
      Arm64::PIVOT_ROOT, 0, 0, 0, 0 },

    // ── Anti-debug ───────────────────────────────────────────────
    { "Ptrace_TRACEME_AntDbg",
      BEH_ANTI_DEBUG, 6,
      Arm64::PTRACE, 0x1, 0, 0, 0 },   // PTRACE_TRACEME = 0

    { "Ptrace_Inject_ATTACH",
      BEH_PTRACE_INJECTION, 9,
      Arm64::PTRACE, 0x1, 4, 0, 0 },   // PTRACE_ATTACH = 4

    { "Ptrace_PokeData_Inject",
      BEH_PTRACE_INJECTION, 10,
      Arm64::PTRACE, 0x1, 5, 0, 0 },   // PTRACE_POKEDATA = 5

    // ── Ağ ───────────────────────────────────────────────────────
    { "Raw_Socket_Sniff",
      BEH_RAW_SOCKET, 7,
      Arm64::SOCKET, 0x6, SOCK_RAW, 0, 0 },

    // ── Dosya sistemi gizleme ────────────────────────────────────
    // MS_BIND = 4096 = 0x1000
    { "Mount_Bind_Hide",
      BEH_MOUNT_BIND_HIDE, 8,
      Arm64::MOUNT, 0x1000, 0x1000, 0, 0 },

    // ── Reboot / Kexec ───────────────────────────────────────────
    { "Reboot_Syscall",
      BEH_DANGEROUS_IOCTL, 10,
      Arm64::REBOOT, 0, 0, 0, 0 },

    { "Kexec_Kernel_Replace",
      BEH_KERNEL_MODULE_LOAD, 10,
      Arm64::KEXEC_LOAD, 0, 0, 0, 0 },

    // sentinel
    { nullptr, BEH_NONE, 0, 0, 0, 0, 0, 0 }
};

// ──────────────────────────────────────────────────────────────────
const BehaviorRule* BehavioralAnalyzer::getDefaultRules(size_t& count) {
    count = sizeof(DEFAULT_RULES) / sizeof(DEFAULT_RULES[0]) - 1;
    return DEFAULT_RULES;
}

// ──────────────────────────────────────────────────────────────────
//  addFinding yardımcısı
// ──────────────────────────────────────────────────────────────────
static void addFinding(ProcessProfile& p, BehaviorFlag flag,
                       const std::string& msg, uint8_t severity) {
    p.behaviorFlags |= static_cast<uint64_t>(flag);
    std::string entry = "[sev=" + std::to_string(severity) + "] " + msg;
    // Aynı mesajı tekrar ekleme
    for (const auto& f : p.findings)
        if (f == entry) return;
    p.findings.push_back(entry);
    LOGW("BEH [pid=%d sev=%d]: %s", p.pid, severity, msg.c_str());
}

// ══════════════════════════════════════════════════════════════════
//  processEvent — Tek syscall olayını işle
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::processEvent(SyscallEvent& ev,
                                       ProcessProfile& profile,
                                       BehaviorReport& report) {
    profile.lastSyscallTime_ns = ev.timestamp_ns;

    applyRules(ev, profile);

    // Orijinal analizler
    checkWXMemory       (ev, profile);
    checkFilelessExec   (ev, profile);
    checkPrivEscalation (ev, profile);
    checkKernelExploit  (ev, profile);
    checkShellSpawn     (ev, profile);
    checkDataExfil      (ev, profile);
    checkAntiDebug      (ev, profile);
    checkNetworkAbuse   (ev, profile);
    checkSyscallRate    (profile);

    // Yeni analizler
    checkKernelSuProbe  (ev, profile);
    checkAPatchProbe    (ev, profile);
    checkProcMemInject  (ev, profile);
    checkInputHijack    (ev, profile);
    checkMountHide      (ev, profile);
    checkZygoteInject   (ev, profile);
    checkDangerousIoctl (ev, profile);
    checkKallsymsRead   (ev, profile);
    checkSeccompProbe   (ev, profile);
    checkCgroupEscape   (ev, profile);

    if (profile.behaviorFlags) ++report.flaggedEvents;

    // Alert callback
    if (m_callback && profile.behaviorFlags) {
        m_callback(ev, profile, static_cast<BehaviorFlag>(profile.behaviorFlags));
    }
}

// ══════════════════════════════════════════════════════════════════
//  Statik kural motoru
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::applyRules(const SyscallEvent& ev,
                                     ProcessProfile& profile) {
    for (const auto* rule = DEFAULT_RULES; rule->name != nullptr; ++rule) {
        if (rule->triggerSyscall != ev.syscallNr) continue;

        if (rule->argMask != 0) {
            uint64_t masked = ev.args[0] & rule->argMask;
            if (masked != (rule->argValue & rule->argMask)) continue;
        }

        if (profile.behaviorFlags & static_cast<uint64_t>(rule->flag)) continue;

        addFinding(profile, rule->flag,
                   std::string(rule->name) + ": " +
                   syscallName(ev.syscallNr, m_isArm64) +
                   "(0x" + [](uint64_t v) {
                       char buf[32]; snprintf(buf, sizeof(buf), "%lx", (unsigned long)v);
                       return std::string(buf);
                   }(ev.args[0]) + ")",
                   rule->severity);
    }
}

// ══════════════════════════════════════════════════════════════════
//  1. W^X bellek analizi
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkWXMemory(const SyscallEvent& ev,
                                        ProcessProfile& profile) {
    auto& pages = m_pageHistory[ev.pid];

    if (ev.syscallNr == Arm64::MMAP || ev.syscallNr == Arm32::MMAP) {
        int      prot = static_cast<int>(ev.args[2]);
        uint64_t addr = ev.args[0];
        uint64_t len  = ev.args[1];

        if ((prot & PROT_WRITE) && (prot & PROT_EXEC)) {
            addFinding(profile, BEH_WX_MEMORY,
                       "mmap(W|X): shellcode alanı: addr=0x" +
                       [&](){ char b[32]; snprintf(b,32,"%lx",(unsigned long)addr); return std::string(b); }() +
                       " len=" + std::to_string(len), 10);
            return;
        }
        pages.push_back({addr, len, prot});
        if (pages.size() > 1024) pages.erase(pages.begin());
    }

    if (ev.syscallNr == Arm64::MPROTECT || ev.syscallNr == Arm32::MPROTECT) {
        uint64_t addr   = ev.args[0];
        uint64_t len    = ev.args[1];
        int      newProt= static_cast<int>(ev.args[2]);

        if (!(newProt & PROT_EXEC)) return;

        for (const auto& pg : pages) {
            bool overlaps = (addr < pg.addr + pg.len) && (addr + len > pg.addr);
            if (overlaps && (pg.prot & PROT_WRITE)) {
                addFinding(profile, BEH_WX_MEMORY,
                           "mprotect W→X: shellcode inject! addr=0x" +
                           [&](){ char b[32]; snprintf(b,32,"%lx",(unsigned long)addr); return std::string(b); }(),
                           10);
                return;
            }
        }
        addFinding(profile, BEH_WX_MEMORY,
                   "mprotect(EXEC) bilinmeyen sayfa: 0x" +
                   [&](){ char b[32]; snprintf(b,32,"%lx",(unsigned long)addr); return std::string(b); }(),
                   6);
    }
}

// ══════════════════════════════════════════════════════════════════
//  2. Dosyasız yürütme (memfd_create → write → execve/execveat)
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkFilelessExec(const SyscallEvent& ev,
                                            ProcessProfile& profile) {
    // Thread-local durum yerine profile içinde flag kombinasyonu kullan
    bool hadMemfd  = (profile.syscallCounts.count(Arm64::MEMFD_CREATE) > 0);
    bool hadWrite  = (profile.syscallCounts.count(Arm64::WRITE)         > 0);

    if (ev.syscallNr == Arm64::MEMFD_CREATE ||
        ev.syscallNr == Arm32::MEMFD_CREATE) {
        addFinding(profile, BEH_FILELESS_EXEC,
                   "memfd_create(): fileless exec hazırlığı", 7);
        return;
    }

    // execveat ile memfd fd'si üzerinden direkt çalıştırma
    if ((ev.syscallNr == Arm64::EXECVEAT || ev.syscallNr == Arm32::EXECVEAT)
        && hadMemfd) {
        addFinding(profile, BEH_FILELESS_EXEC,
                   "execveat(memfd): DOSYASIZ YÜRÜTME tespit edildi!", 10);
        return;
    }

    if (hadMemfd && hadWrite &&
        (ev.syscallNr == Arm64::EXECVE || ev.syscallNr == Arm32::EXECVE)) {
        addFinding(profile, BEH_FILELESS_EXEC,
                   "memfd_create → write → execve: DOSYASIZ YÜRÜTME!", 10);
    }
}

// ══════════════════════════════════════════════════════════════════
//  3. Yetki yükseltme
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkPrivEscalation(const SyscallEvent& ev,
                                              ProcessProfile& profile) {
    if ((ev.syscallNr == Arm64::SETUID || ev.syscallNr == Arm32::SETUID)
        && ev.args[0] == 0) {
        addFinding(profile, BEH_SETUID_ATTEMPT, "setuid(0): root yetki girişimi!", 9);
        return;
    }

    if (ev.syscallNr == Arm64::SETRESUID
        && ev.args[0] == 0 && ev.args[1] == 0 && ev.args[2] == 0) {
        addFinding(profile, BEH_SETUID_ATTEMPT,
                   "setresuid(0,0,0): kapsamlı root yetki girişimi!", 10);
        return;
    }

    if (ev.syscallNr == Arm64::CAPSET || ev.syscallNr == Arm32::CAPSET)
        addFinding(profile, BEH_CAPSET_ESCALATION,
                   "capset(): kernel capability manipülasyonu", 8);

    if (ev.syscallNr == Arm64::PIVOT_ROOT)
        addFinding(profile, BEH_NAMESPACE_ESCAPE,
                   "pivot_root(): kök dizin değiştirme — container kaçışı!", 10);

    if (ev.syscallNr == Arm64::CHROOT)
        addFinding(profile, BEH_NAMESPACE_ESCAPE,
                   "chroot(): çalışma kökünü değiştirme", 8);
}

// ══════════════════════════════════════════════════════════════════
//  4. Kernel exploit desenleri
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkKernelExploit(const SyscallEvent& ev,
                                             ProcessProfile& profile) {
    if (ev.syscallNr == Arm64::INIT_MODULE   ||
        ev.syscallNr == Arm64::FINIT_MODULE  ||
        ev.syscallNr == Arm32::FINIT_MODULE) {
        addFinding(profile, BEH_KERNEL_MODULE_LOAD,
                   "Kernel modülü yükleme (init/finit_module)!", 10);
        return;
    }

    if (ev.syscallNr == Arm64::BPF || ev.syscallNr == Arm32::BPF) {
        if (ev.args[0] == 5) {  // BPF_PROG_LOAD
            addFinding(profile, BEH_BPF_PROG_LOAD,
                       "bpf(BPF_PROG_LOAD): eBPF program yükleme!", 9);
        } else if (ev.args[0] == 0) { // BPF_MAP_CREATE
            addFinding(profile, BEH_BPF_PROG_LOAD,
                       "bpf(BPF_MAP_CREATE): eBPF map oluşturma", 6);
        }
        return;
    }

    if (ev.syscallNr == Arm64::IO_URING_SETUP ||
        ev.syscallNr == Arm32::IO_URING_SETUP) {
        addFinding(profile, BEH_IO_URING_EXPLOIT,
                   "io_uring_setup(): Android'de exploit vektörü", 7);
        return;
    }

    if (ev.syscallNr == Arm64::USERFAULTFD)
        addFinding(profile, BEH_USERFAULTFD_EXPLOIT,
                   "userfaultfd(): race condition exploit şüphesi", 7);

    if (ev.syscallNr == Arm64::PERF_EVENT_OPEN ||
        ev.syscallNr == Arm32::PERF_EVENT_OPEN)
        addFinding(profile, BEH_PERF_EXPLOIT,
                   "perf_event_open(): kernel exploit vektörü", 7);

    // kexec — kernel'ı değiştirme
    if (ev.syscallNr == Arm64::KEXEC_LOAD || ev.syscallNr == Arm64::KEXEC_FILE_LOAD)
        addFinding(profile, BEH_KERNEL_MODULE_LOAD,
                   "kexec: kernel değiştirme girişimi!", 10);

    // Heap spray
    if (ev.syscallNr == Arm64::MMAP) {
        static thread_local int   mmapCount     = 0;
        static thread_local uint64_t lastMmapTs = 0;
        uint64_t now = ev.timestamp_ns;
        if (now - lastMmapTs < 100000000ULL) {
            if (++mmapCount > 50 && ev.args[1] > 65536) {
                addFinding(profile, BEH_HEAP_SPRAY,
                           "Heap spray: " + std::to_string(mmapCount) +
                           " büyük mmap/100ms", 8);
                mmapCount = 0;
            }
        } else {
            mmapCount = 1;
        }
        lastMmapTs = now;
    }
}

// ══════════════════════════════════════════════════════════════════
//  5. Shell spawn
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkShellSpawn(const SyscallEvent& ev,
                                          ProcessProfile& profile) {
    if (ev.syscallNr != Arm64::EXECVE   && ev.syscallNr != Arm32::EXECVE &&
        ev.syscallNr != Arm64::EXECVEAT && ev.syscallNr != Arm32::EXECVEAT)
        return;

    static const char* SHELLS[] = {
        "sh", "bash", "dash", "zsh", "ksh", "ash", "busybox",
        "toybox", "mksh", nullptr
    };
    for (int i = 0; SHELLS[i]; ++i) {
        if (strstr(ev.comm, SHELLS[i])) {
            addFinding(profile, BEH_SHELL_SPAWN,
                       std::string("Shell spawn: ") + ev.comm, 8);
            return;
        }
    }

    char exeLink[64], exePath[256] = {};
    snprintf(exeLink, sizeof(exeLink), "/proc/%d/exe", ev.pid);
    if (readlink(exeLink, exePath, sizeof(exePath) - 1) > 0) {
        static const char* SUSP_PATHS[] = {
            "/data/local/tmp", "/sdcard/Android",
            "/data/local", "/tmp", nullptr
        };
        for (int i = 0; SUSP_PATHS[i]; ++i) {
            if (strstr(exePath, SUSP_PATHS[i])) {
                addFinding(profile, BEH_SUSPICIOUS_EXEC,
                           std::string("Şüpheli konumdan exec: ") + exePath, 8);
                return;
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════════
//  6. Veri sızdırma
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkDataExfil(const SyscallEvent& ev,
                                         ProcessProfile& profile) {
    if (ev.syscallNr == Arm64::SENDTO   || ev.syscallNr == Arm64::WRITEV ||
        ev.syscallNr == Arm64::SENDMSG) {
        ++profile.sendCount;
        if (ev.args[2] > 0 && ev.args[2] < 100*1024*1024ULL)
            profile.bytesSent += ev.args[2];

        // Sliding window'da yakın zamanda sensitif dosya erişimi?
        bool hadSensitiveRead = false;
        for (const auto& past : profile.recentEvents) {
            if (past.syscallNr == Arm64::OPENAT || past.syscallNr == Arm64::READ) {
                uint64_t windowNs = ev.timestamp_ns - past.timestamp_ns;
                if (windowNs < 3000000000ULL) { hadSensitiveRead = true; break; }
            }
        }
        if (hadSensitiveRead && profile.sendCount > 3 && profile.bytesSent > 8192) {
            addFinding(profile, BEH_DATA_EXFIL_PATTERN,
                       "Veri sızdırma: " + std::to_string(profile.bytesSent) +
                       " byte, " + std::to_string(profile.sendCount) + " gönderim", 7);
        }
    }
}

// ══════════════════════════════════════════════════════════════════
//  7. Anti-debug
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkAntiDebug(const SyscallEvent& ev,
                                         ProcessProfile& profile) {
    if (ev.syscallNr == Arm64::PTRACE || ev.syscallNr == Arm32::PTRACE) {
        if      (ev.args[0] == 0)  addFinding(profile, BEH_ANTI_DEBUG,
            "ptrace(TRACEME): anti-debug tekniği", 7);
        else if (ev.args[0] == 4)  addFinding(profile, BEH_PTRACE_ATTACH,
            "ptrace(ATTACH, pid=" + std::to_string(ev.args[1]) + ")", 9);
        else if (ev.args[0] == 5 || ev.args[0] == 6)
            addFinding(profile, BEH_PTRACE_INJECTION,
            "ptrace(POKE): kod enjeksiyonu!", 10);
        return;
    }

    if (ev.syscallNr == Arm64::PRCTL || ev.syscallNr == Arm32::PRCTL) {
        if (ev.args[0] == PR_SET_DUMPABLE && ev.args[1] == 0)
            addFinding(profile, BEH_ANTI_DEBUG,
                       "prctl(SET_DUMPABLE,0): analiz engelleme", 5);
        if (ev.args[0] == PR_SET_NAME)
            addFinding(profile, BEH_PROC_HIDE,
                       "prctl(SET_NAME): süreç adı gizleme", 4);
    }

    static thread_local int sleepCount = 0;
    if (ev.syscallNr == 35 || ev.syscallNr == 162) {  // nanosleep
        if (++sleepCount > 20) {
            addFinding(profile, BEH_TIMING_EVASION,
                       "Yoğun nanosleep: " + std::to_string(sleepCount) + " çağrı", 5);
            sleepCount = 0;
        }
    }
}

// ══════════════════════════════════════════════════════════════════
//  8. Ağ kötüye kullanımı
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkNetworkAbuse(const SyscallEvent& ev,
                                            ProcessProfile& profile) {
    if (ev.syscallNr == Arm64::SOCKET || ev.syscallNr == Arm32::SOCKET) {
        int sockType = static_cast<int>(ev.args[1]) & ~SOCK_NONBLOCK & ~SOCK_CLOEXEC;
        if (sockType == SOCK_RAW)
            addFinding(profile, BEH_RAW_SOCKET,
                       "SOCK_RAW: paket enjeksiyon/sniff", 7);
        ++profile.connectCount;
    }

    if (ev.syscallNr == Arm64::CONNECT || ev.syscallNr == Arm32::CONNECT) {
        if (++profile.connectCount > 150)
            addFinding(profile, BEH_DNS_FLOOD,
                       "Bağlantı patlaması: " + std::to_string(profile.connectCount), 7);
    }
}

// ══════════════════════════════════════════════════════════════════
//  9. Syscall hız anomalisi
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkSyscallRate(ProcessProfile& profile) {
    if (profile.recentEvents.size() < 200) return;

    const auto& oldest = profile.recentEvents.front();
    const auto& newest = profile.recentEvents.back();
    uint64_t durationNs = newest.timestamp_ns - oldest.timestamp_ns;
    if (durationNs == 0) return;

    double rate = (double)profile.recentEvents.size() / ((double)durationNs / 1e9);
    profile.syscallRatePerSec = rate;

    if (rate > 50000.0)
        addFinding(profile, BEH_SYSCALL_FLOOD,
                   "Syscall anomalisi: " + std::to_string((int)rate) + "/sn", 8);
}

// ══════════════════════════════════════════════════════════════════
//  10. KernelSU prctl probe tespiti
//
//  KernelSU, uygulamaların root almak için prctl'e özel magic gönderdiğini
//  bilir ve bu çağrıyı kernel seviyesinde yakalar. Bizim işimiz bu
//  magic değerlerin gönderilip gönderilmediğini tespit etmek.
//
//  Bilinen magic değerler:
//    arg0 = 0xdeadc0de  → KernelSU varlık testi ("am I root?")
//    arg0 = 0xdeadbeef  → bazı KSU fork'larında / APatch'te
//    arg0 = 0x534b5355  → "SKsU" = root grant magic
//    arg1 = 0x534b5500  → bazı sürümlerde arg1'de KSU magic
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkKernelSuProbe(const SyscallEvent& ev,
                                              ProcessProfile& profile) {
    if (ev.syscallNr != Arm64::PRCTL && ev.syscallNr != Arm32::PRCTL) return;

    uint64_t cmd  = ev.args[0];
    uint64_t arg1 = ev.args[1];
    uint64_t arg2 = ev.args[2];

    // KernelSU varlık testi
    if (cmd == KSU_MAGIC_PRCTL_CMD || cmd == KSU_MAGIC_PRCTL_CMD2) {
        addFinding(profile, BEH_KERNELSU_PROBE,
                   "prctl(0x" +
                   [&](){ char b[32]; snprintf(b,32,"%x",(unsigned)cmd); return std::string(b); }() +
                   "): KernelSU/APatch root probe! arg1=0x" +
                   [&](){ char b[32]; snprintf(b,32,"%lx",(unsigned long)arg1); return std::string(b); }(),
                   10);
        return;
    }

    // PR_SET_VMA ile KSU magic ("VkSU" / "SKsU")
    if (cmd == (uint64_t)PR_SET_VMA &&
        (arg1 == KSU_MAGIC_ARG_GRANT || arg2 == KSU_MAGIC_ARG_GRANT)) {
        addFinding(profile, BEH_KERNELSU_PROBE,
                   "prctl(PR_SET_VMA, KSU_MAGIC): KernelSU root grant hazırlığı!", 10);
        return;
    }

    // Bilinmeyen yüksek magic değer — genel SU backdoor şüphesi
    if (cmd > 0xffff0000ULL && cmd != 0xffffffffULL) {
        addFinding(profile, BEH_SU_PRCTL_BACKDOOR,
                   "prctl bilinmeyen magic: 0x" +
                   [&](){ char b[32]; snprintf(b,32,"%lx",(unsigned long)cmd); return std::string(b); }() +
                   " (gizli SU backdoor?)", 8);
    }
}

// ══════════════════════════════════════════════════════════════════
//  11. APatch probe tespiti
//
//  APatch (Android Kernel Patch), /dev/apd cihaz dosyası üzerinden
//  ioctl ile root grant yapar. Bu cihaza erişim veya belirli
//  magic değerli ioctl = APatch kullanımı.
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkAPatchProbe(const SyscallEvent& ev,
                                           ProcessProfile& profile) {
    // openat ile /dev/apd açılması
    if (ev.syscallNr == Arm64::OPENAT || ev.syscallNr == Arm64::OPEN) {
        // proc poll'da arg1 (path ptr) okuyamayız doğrudan
        // Ancak /proc/pid/fd takibinde veya ptrace modunda okuruz
        // Burada fd geçmişini yakala, ioctl ile çapraz kontrol yap
        return;
    }

    // ioctl magic değer kontrolü
    if (ev.syscallNr == Arm64::IOCTL) {
        uint64_t request = ev.args[1];
        uint64_t arg     = ev.args[2];

        // APatch magic ioctl
        if (request == APATCH_MAGIC_IOCTL || arg == APATCH_MAGIC_ARG) {
            addFinding(profile, BEH_APATCH_PROBE,
                       "ioctl(APATCH_MAGIC=0xdeadc0de): APatch SU erişimi!", 10);
            return;
        }

        // /dev/apd için bilinen ioctl kodları (0xa0xx range)
        if ((request & 0xffffff00ULL) == 0xa0000000ULL) {
            addFinding(profile, BEH_APATCH_PROBE,
                       "ioctl suspect range (APatch device?): 0x" +
                       [&](){ char b[32]; snprintf(b,32,"%lx",(unsigned long)request); return std::string(b); }(),
                       7);
        }
    }
}

// ══════════════════════════════════════════════════════════════════
//  12. /proc/pid/mem üzerinden ptrace'siz inject
//
//  Saldırı: open("/proc/target/mem", O_RDWR) + write()
//  Bu yöntem ptrace gerektirmeden başka sürecin belleğine yazar.
//  Sadece root veya aynı UID erişebilir.
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkProcMemInject(const SyscallEvent& ev,
                                              ProcessProfile& profile) {
    // /proc/X/mem açmayı takip etmek için openat'ı işaretle
    // Proc poll modunda path okuyamayız ama /proc/pid/fd'den takip edebiliriz
    // Ptrace modunda arg1 pointerı okuruz

    if (ev.syscallNr == Arm64::WRITE || ev.syscallNr == Arm64::WRITEV) {
        // Yazma işlemi — önceki olaylarda /proc/*/mem açılmış mıydı?
        for (const auto& past : profile.recentEvents) {
            if (past.syscallNr == Arm64::OPENAT) {
                uint64_t windowNs = ev.timestamp_ns - past.timestamp_ns;
                if (windowNs < 1000000000ULL) {  // 1 saniye içinde
                    // Yazılan fd değeri match ediyor mu? (yaklaşık kontrol)
                    if (ev.args[0] == past.retval && past.retval > 0) {
                        // Bu bir /proc/mem fd'si olabilir
                        // Risk: çapraz kontrol /proc/pid/fd'den yapılmalı
                        addFinding(profile, BEH_PROC_MEM_INJECT,
                                   "/proc/pid/mem şüpheli write — ptrace'siz inject girişimi?",
                                   8);
                        break;
                    }
                }
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════════
//  13. Input cihazı ele geçirme (keylogger)
//
//  /dev/input/eventX'i doğrudan okuyan normal uygulama yoktur.
//  Bu cihazlara erişim = dokunmatik/klavye okuma = keylogger.
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkInputHijack(const SyscallEvent& ev,
                                           ProcessProfile& profile) {
    if (ev.syscallNr != Arm64::READ && ev.syscallNr != Arm64::RECVFROM) return;

    // /proc/pid/fd'de kontrol → checkProcFd'de daha kapsamlı yapılır
    // Burada yüksek frekanslı okumayı işaretle
    if (profile.syscallCounts.count(Arm64::READ) &&
        profile.syscallCounts.at(Arm64::READ) > 5000) {
        // Yüksek frekanslı okuma + ioctl kombinasyonu = şüpheli
        if (profile.syscallCounts.count(Arm64::IOCTL)) {
            addFinding(profile, BEH_INPUT_HIJACK,
                       "Yüksek frekanslı READ + IOCTL: keylogger şüphesi", 7);
        }
    }
}

// ══════════════════════════════════════════════════════════════════
//  14. Mount --bind gizleme (Magisk/KernelSU tarzı)
//
//  Magisk ve KernelSU, sistem dosyalarını gizlemek için
//  mount --bind kullanır. Normal uygulama asla mount çağırmaz.
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkMountHide(const SyscallEvent& ev,
                                         ProcessProfile& profile) {
    if (ev.syscallNr != Arm64::MOUNT && ev.syscallNr != Arm32::MOUNT) return;

    // arg3 = flags
    uint64_t flags = ev.args[3];
    static const uint64_t MS_BIND     = 0x1000ULL;  // 4096
    static const uint64_t MS_REMOUNT  = 0x0020ULL;  // 32
    static const uint64_t MS_OVERLAY  = 0x0000ULL;  // overlayfs = type string
    static const uint64_t MS_MOVE     = 0x2000ULL;  // 8192

    if (flags & MS_BIND) {
        addFinding(profile, BEH_MOUNT_BIND_HIDE,
                   "mount(--bind, flags=0x" +
                   [&](){ char b[32]; snprintf(b,32,"%lx",(unsigned long)flags); return std::string(b); }() +
                   "): Magisk/KSU tarzı gizleme!", 9);
        return;
    }

    if (flags & MS_MOVE) {
        addFinding(profile, BEH_OVERLAY_TMPFS,
                   "mount(MS_MOVE): dosya sistemi taşıma — overlay kurulumu?", 7);
        return;
    }

    // Herhangi bir mount (uygulama seviyesinde asla olmamalı)
    addFinding(profile, BEH_MOUNT_BIND_HIDE,
               "mount() çağrısı: normal uygulama mount yapamaz!", 8);
}

// ══════════════════════════════════════════════════════════════════
//  15. Zygote inject tespiti
//
//  Zygote (PID genellikle 1 veya 2), tüm Android uygulamalarının
//  fork parent'ıdır. Bu sürece ptrace/inject = tüm uygulamaları etkiler.
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkZygoteInject(const SyscallEvent& ev,
                                            ProcessProfile& profile) {
    if (ev.syscallNr != Arm64::PTRACE && ev.syscallNr != Arm32::PTRACE) return;
    if (ev.args[0] != 4 && ev.args[0] != 16) return;  // ATTACH veya SEIZE

    pid_t targetPid = static_cast<pid_t>(ev.args[1]);

    // Hedef PID'in zygote olup olmadığını /proc/pid/comm'dan kontrol et
    char commPath[64], comm[32] = {};
    snprintf(commPath, sizeof(commPath), "/proc/%d/comm", targetPid);
    int fd = open(commPath, O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, comm, sizeof(comm) - 1);
        close(fd);
        if (n > 0) {
            comm[n] = '\0';
            if (strstr(comm, "zygote") || strstr(comm, "zygote64")) {
                addFinding(profile, BEH_ZYGOTE_INJECT,
                           std::string("ptrace(ATTACH) ZYGOTE'ye: ") + comm +
                           " (pid=" + std::to_string(targetPid) + ") — TÜM UYGULAMALAR TEHLİKEDE!",
                           10);
                return;
            }
        }
    }

    // system_server inject tespiti
    if (strstr(comm, "system_server")) {
        addFinding(profile, BEH_ZYGOTE_INJECT,
                   "ptrace(ATTACH) system_server'a! Sistem hakimiyet girişimi!",
                   10);
    }
}

// ══════════════════════════════════════════════════════════════════
//  16. Tehlikeli ioctl akışları
//
//  /dev/binder  → Binder IPC manipülasyonu
//  /dev/kgsl-3d0 → GPU belleği erişimi (exploit)
//  /dev/mali    → ARM GPU
//  /dev/ashmem  → Eski payload taşıma vektörü
//  /dev/ksud    → KernelSU daemon
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkDangerousIoctl(const SyscallEvent& ev,
                                              ProcessProfile& profile) {
    if (ev.syscallNr != Arm64::IOCTL) return;

    // fd = args[0], request = args[1]
    uint64_t request = ev.args[1];

    // Binder ioctl kodları
    // BINDER_WRITE_READ = 0xc0306201
    if ((request & 0xffffff00ULL) == 0x00006200ULL) {
        // Binder aralığı — yüksek frekanslı binder şüphe işareti
        static thread_local int binderCount = 0;
        if (++binderCount > 1000) {
            addFinding(profile, BEH_DANGEROUS_IOCTL,
                       "Yoğun Binder ioctl: " + std::to_string(binderCount) +
                       " çağrı (IPC manipülasyon?)", 5);
            binderCount = 0;
        }
        return;
    }

    // GPU ioctl — KGSL, Mali, Adreno
    // KGSL: 0x0900xx, Mali: 0x4d00xx
    if ((request & 0xffff0000ULL) == 0x09000000ULL ||
        (request & 0xffff0000ULL) == 0x4d000000ULL) {
        addFinding(profile, BEH_DANGEROUS_IOCTL,
                   "GPU ioctl (kgsl/mali): GPU bellek exploit vektörü? 0x" +
                   [&](){ char b[32]; snprintf(b,32,"%lx",(unsigned long)request); return std::string(b); }(),
                   6);
        return;
    }

    // DMA-BUF ioctl — sıklıkla exploit'te kullanılır
    // DMA_BUF_IOCTL_SYNC = 0x40086200
    if ((request & 0x0000ff00ULL) == 0x00006200ULL && request > 0x40000000ULL) {
        addFinding(profile, BEH_DANGEROUS_IOCTL,
                   "DMA-BUF ioctl: çekirdek bellek senkronizasyon exploit şüphesi", 7);
    }
}

// ══════════════════════════════════════════════════════════════════
//  17. /proc/kallsyms okuma (KASLR bypass)
//
//  Kernel exploit'ler önce KASLR'ı bypass etmek için kernel sembol
//  adreslerini /proc/kallsyms'den okur. Normal uygulama okuyamaz
//  (modern kernellerde 0 döner), ama erişim denemesi kendisi şüpheli.
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkKallsymsRead(const SyscallEvent& ev,
                                             ProcessProfile& profile) {
    // Proc poll'da pathname okuyamıyoruz — ptrace modunda kontrol edilir
    // Burada /proc/kallsyms erişimini proc/fd polling ile yakalarız
    // Bu fonksiyon checkProcFd ile birlikte çalışır
    (void)ev; (void)profile;
}

// ══════════════════════════════════════════════════════════════════
//  18. Seccomp filtresi yoklama
//
//  Exploit'ler önce hangi syscall'ların engellendiğini test eder.
//  Hızlı birbiri ardına gelen syscall + EPERM dönüşü = seccomp probe.
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkSeccompProbe(const SyscallEvent& ev,
                                             ProcessProfile& profile) {
    if (ev.syscallNr != Arm64::SECCOMP) return;

    // seccomp() çağrısı normal uygulama tarafından yapılmaz
    // arg0 = operation
    // SECCOMP_SET_MODE_FILTER = 1
    if (ev.args[0] == 1) {
        addFinding(profile, BEH_SECCOMP_PROBE,
                   "seccomp(SET_MODE_FILTER): özel BPF filtre kuruluyor!", 8);
    } else if (ev.args[0] == 0) {
        addFinding(profile, BEH_SECCOMP_PROBE,
                   "seccomp(SET_MODE_STRICT): sıkı mode etkinleşiyor", 5);
    }
}

// ══════════════════════════════════════════════════════════════════
//  19. Cgroup namespace kaçışı
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkCgroupEscape(const SyscallEvent& ev,
                                             ProcessProfile& profile) {
    if (ev.syscallNr == Arm64::UNSHARE || ev.syscallNr == Arm32::UNSHARE) {
        // CLONE_NEWCGROUP = 0x02000000
        // CLONE_NEWNS    = 0x00020000  (mount ns)
        // CLONE_NEWPID   = 0x20000000
        uint64_t flags = ev.args[0];
        if (flags & 0x02000000ULL)
            addFinding(profile, BEH_CGROUP_ESCAPE,
                       "unshare(CLONE_NEWCGROUP): cgroup namespace kaçışı!", 9);
        if (flags & 0x00020000ULL)
            addFinding(profile, BEH_NAMESPACE_ESCAPE,
                       "unshare(CLONE_NEWNS): mount namespace ayrımı", 7);
        if (flags & 0x20000000ULL)
            addFinding(profile, BEH_NAMESPACE_ESCAPE,
                       "unshare(CLONE_NEWPID): PID namespace ayrımı", 7);
    }
}

// ══════════════════════════════════════════════════════════════════
//  /proc deep scan — maps, status, fd, net
//  Bu fonksiyonlar procPollMonitor içinde periyodik olarak çağrılır
// ══════════════════════════════════════════════════════════════════

// Bilinen kötü/şüpheli kütüphane isimleri (substring match)
static const char* SUSPICIOUS_LIB_PATTERNS[] = {
    "frida",          // Frida hooking framework
    "gadget",         // Frida gadget
    "xposed",         // Xposed Framework
    "edxposed",       // EdXposed
    "lspatch",        // LSPatch
    "zygisk",         // Zygisk (Magisk module)
    "riru",           // Riru (legacy Magisk)
    "magisk",         // Magisk kütüphaneleri
    "kernelsu",       // KernelSU kütüphanesi
    "ksud",           // KernelSU daemon
    "apatch",         // APatch
    "substrate",      // Cydia Substrate
    "cycript",        // Cycript
    "inject",         // Genel inject pattern
    "hook",           // Hook kütüphanesi
    "bypass",         // Bypass kütüphanesi
    "detour",         // Detour hooking
    "dobby",          // Dobby hooking library
    "shadowhook",     // ShadowHook (ByteDance)
    "bhook",          // ByteHook
    nullptr
};

void BehavioralAnalyzer::checkProcMaps(pid_t pid, ProcessProfile& profile) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE* f = fopen(path, "r");
    if (!f) return;

    char line[512];
    std::unordered_set<std::string> alreadyReported;

    while (fgets(line, sizeof(line), f)) {
        // Sadece .so dosyaları içeren satırlar
        char* so = strstr(line, ".so");
        if (!so) continue;

        // Kütüphane adını çıkar (son / sonrasındaki kısım)
        char* nameStart = strrchr(line, '/');
        if (!nameStart) continue;
        ++nameStart;

        // Küçük harfe çevir (karşılaştırma için)
        char libName[256] = {};
        size_t i = 0;
        for (char* p = nameStart; *p && *p != '\n' && i < sizeof(libName)-1; ++p, ++i)
            libName[i] = (*p >= 'A' && *p <= 'Z') ? (*p + 32) : *p;

        // Şüpheli pattern kontrolü
        for (int j = 0; SUSPICIOUS_LIB_PATTERNS[j]; ++j) {
            if (strstr(libName, SUSPICIOUS_LIB_PATTERNS[j])) {
                std::string libStr(libName);
                if (!alreadyReported.count(libStr)) {
                    alreadyReported.insert(libStr);
                    addFinding(profile, BEH_FOREIGN_LIB_INJECT,
                               std::string("Şüpheli kütüphane inject: /proc/maps'de ") +
                               libName + " bulundu!",
                               9);
                    profile.snapshot.suspiciousLibs.push_back(libName);
                }

                // Özel bayraklar
                if (strstr(libName, "frida"))
                    profile.snapshot.hasFridaLib = true;
                if (strstr(libName, "xposed") || strstr(libName, "edxposed") ||
                    strstr(libName, "lspatch"))
                    profile.snapshot.hasXposedLib = true;
                if (strstr(libName, "zygisk"))
                    profile.snapshot.hasZygiskLib = true;
                if (strstr(libName, "kernelsu") || strstr(libName, "ksud"))
                    profile.snapshot.hasKernelSuLib = true;
                if (strstr(libName, "apatch"))
                    profile.snapshot.hasAdbLib = true;
            }
        }
    }
    fclose(f);
}

void BehavioralAnalyzer::checkProcStatus(pid_t pid, ProcessProfile& profile) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE* f = fopen(path, "r");
    if (!f) return;

    char line[256];
    uid_t ruid = (uid_t)-1, euid = (uid_t)-1, suid = (uid_t)-1;

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Uid:", 4) == 0) {
            sscanf(line + 4, "%u %u %u", &ruid, &euid, &suid);
            break;
        }
    }
    fclose(f);

    if (ruid == (uid_t)-1) return;

    // İlk ölçüm
    auto it = m_lastUid.find(pid);
    if (it == m_lastUid.end()) {
        m_lastUid[pid] = ruid;
        profile.lastSeenUid  = ruid;
        profile.lastSeenEuid = euid;
        profile.snapshot.uid  = ruid;
        profile.snapshot.euid = euid;
        return;
    }

    uid_t prevUid = it->second;

    // UID değişti mi? (euid 0 a düştü = root kazandı)
    if (prevUid != 0 && (ruid == 0 || euid == 0)) {
        addFinding(profile, BEH_UID_ESCALATED,
                   "UID escalation: " + std::to_string(prevUid) +
                   " → " + std::to_string(ruid) +
                   " (euid=" + std::to_string(euid) + ") RUNTIME ROOT KAZANIMI!",
                   10);
    }

    m_lastUid[pid]       = ruid;
    profile.lastSeenUid  = ruid;
    profile.lastSeenEuid = euid;
    profile.snapshot.uid  = ruid;
    profile.snapshot.euid = euid;
}

void BehavioralAnalyzer::checkProcFd(pid_t pid, ProcessProfile& profile) {
    char fdDir[64];
    snprintf(fdDir, sizeof(fdDir), "/proc/%d/fd", pid);

    DIR* dir = opendir(fdDir);
    if (!dir) return;

    static const char* DANGEROUS_DEVS[] = {
        "/dev/apd",          // APatch SU daemon
        "/dev/ksud",         // KernelSU daemon
        "/dev/kmem",         // Kernel memory (legacy)
        "/dev/mem",          // Physical memory
        "/dev/kcore",        // Kernel core
        "/dev/kallsyms",     // (dosya olarak mount edilmiş olabilir)
        "/proc/kallsyms",    // KASLR bypass
        "/dev/ptmx",         // PTY master (terminal backdoor)
        nullptr
    };

    struct dirent* entry;
    char linkBuf[512];

    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;

        char fdPath[128];
        snprintf(fdPath, sizeof(fdPath), "%s/%s", fdDir, entry->d_name);

        ssize_t len = readlink(fdPath, linkBuf, sizeof(linkBuf) - 1);
        if (len <= 0) continue;
        linkBuf[len] = '\0';

        // Tehlikeli cihaz dosyası kontrolü
        for (int i = 0; DANGEROUS_DEVS[i]; ++i) {
            if (strcmp(linkBuf, DANGEROUS_DEVS[i]) == 0) {
                std::string devStr(linkBuf);
                auto& devFds = m_openDevFds[pid];
                if (!devFds.count(devStr)) {
                    devFds.insert(devStr);
                    addFinding(profile, BEH_APATCH_PROBE,
                               std::string("Tehlikeli cihaz açık: ") + linkBuf +
                               " (pid=" + std::to_string(pid) + ")",
                               10);
                }
                // /dev/kallsyms → KASLR bypass girişimi
                if (strstr(linkBuf, "kallsyms"))
                    addFinding(profile, BEH_KALLSYMS_READ,
                               "KASLR bypass: /proc/kallsyms okunuyor!", 9);
            }
        }

        // /proc/pid/mem erişimi
        if (strstr(linkBuf, "/proc/") && strstr(linkBuf, "/mem")) {
            // Kendi süreci değil mi?
            int targetPid = 0;
            sscanf(linkBuf + 6, "%d", &targetPid);
            if (targetPid != 0 && targetPid != pid) {
                addFinding(profile, BEH_PROC_MEM_INJECT,
                           std::string("/proc/pid/mem açık: ") + linkBuf +
                           " — ptrace'siz inject!", 9);
            }
        }

        // /dev/input erişimi = keylogger
        if (strstr(linkBuf, "/dev/input/")) {
            addFinding(profile, BEH_INPUT_HIJACK,
                       std::string("Input cihazı açık: ") + linkBuf +
                       " — keylogger?", 8);
            profile.snapshot.openDevFiles.push_back(linkBuf);
        }
    }
    closedir(dir);
}

void BehavioralAnalyzer::checkProcNet(pid_t pid, ProcessProfile& profile) {
    // /proc/pid/net/tcp6 bağlantı sayısını say
    char netPath[64];
    snprintf(netPath, sizeof(netPath), "/proc/%d/net/tcp6", pid);

    FILE* f = fopen(netPath, "r");
    if (!f) {
        snprintf(netPath, sizeof(netPath), "/proc/%d/net/tcp", pid);
        f = fopen(netPath, "r");
    }
    if (!f) return;

    char line[256];
    uint32_t connCount = 0;
    fgets(line, sizeof(line), f);  // Başlık satırı

    while (fgets(line, sizeof(line), f)) {
        int state = 0;
        sscanf(line, "%*d: %*s %*s %x", &state);
        if (state == 1)  // TCP_ESTABLISHED
            ++connCount;
    }
    fclose(f);

    profile.snapshot.tcpConnectionCount = connCount;

    if (connCount > 50) {
        addFinding(profile, BEH_DATA_EXFIL_PATTERN,
                   "Yüksek TCP bağlantı sayısı: " + std::to_string(connCount) +
                   " established", 6);
    }
}

// ══════════════════════════════════════════════════════════════════
//  ProcSnapshot — tek seferde al
// ══════════════════════════════════════════════════════════════════
ProcSnapshot BehavioralAnalyzer::takeProcSnapshot(pid_t pid) {
    ProcSnapshot s{};
    s.pid = pid;

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    readlink(path, s.exe, sizeof(s.exe) - 1);

    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, s.name, sizeof(s.name) - 1);
        close(fd);
        if (n > 0) {
            s.name[n] = '\0';
            for (int i = 0; i < n; ++i)
                if (s.name[i] == '\n') { s.name[i] = '\0'; break; }
        }
    }
    return s;
}

// ══════════════════════════════════════════════════════════════════
//  Risk skoru hesaplama
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::updateRiskScore(ProcessProfile& profile) {
    struct FlagWeight { BehaviorFlag flag; uint8_t weight; };

    static const FlagWeight WEIGHTS[] = {
        // Orijinal
        { BEH_WX_MEMORY,              25 },
        { BEH_CROSS_PROC_WRITE,       30 },
        { BEH_FILELESS_EXEC,          25 },
        { BEH_HEAP_SPRAY,             15 },
        { BEH_SETUID_ATTEMPT,         25 },
        { BEH_CAPSET_ESCALATION,      20 },
        { BEH_PTRACE_INJECTION,       30 },
        { BEH_NAMESPACE_ESCAPE,       20 },
        { BEH_KERNEL_MODULE_LOAD,     30 },
        { BEH_BPF_PROG_LOAD,          25 },
        { BEH_PERF_EXPLOIT,           15 },
        { BEH_USERFAULTFD_EXPLOIT,    15 },
        { BEH_IO_URING_EXPLOIT,       15 },
        { BEH_SHELL_SPAWN,            20 },
        { BEH_SUSPICIOUS_EXEC,        20 },
        { BEH_PTRACE_ATTACH,          20 },
        { BEH_SIGNAL_FLOOD,           10 },
        { BEH_SENSITIVE_READ,         10 },
        { BEH_RAW_SOCKET,             15 },
        { BEH_DATA_EXFIL_PATTERN,     20 },
        { BEH_ANTI_DEBUG,             10 },
        { BEH_PROC_HIDE,              15 },
        { BEH_TIMING_EVASION,         10 },
        { BEH_SYSCALL_FLOOD,          20 },
        // Yeni
        { BEH_KERNELSU_PROBE,         35 },  // ❗ Kritik — KSU root probe
        { BEH_APATCH_PROBE,           35 },  // ❗ Kritik — APatch root
        { BEH_SU_PRCTL_BACKDOOR,      30 },
        { BEH_PROC_MEM_INJECT,        30 },
        { BEH_INPUT_HIJACK,           25 },
        { BEH_CAMERA_MIC_HIJACK,      20 },
        { BEH_MOUNT_BIND_HIDE,        25 },
        { BEH_OVERLAY_TMPFS,          20 },
        { BEH_ZYGOTE_INJECT,          40 },  // ❗ En kritik: zygote = tüm sistem
        { BEH_UID_ESCALATED,          40 },  // ❗ Gerçek zamanlı root kazanımı
        { BEH_FOREIGN_LIB_INJECT,     25 },
        { BEH_SECCOMP_PROBE,          15 },
        { BEH_DOUBLE_FETCH_EXPLOIT,   20 },
        { BEH_DANGEROUS_IOCTL,        10 },
        { BEH_KALLSYMS_READ,          20 },
        { BEH_CGROUP_ESCAPE,          25 },
    };

    uint32_t score = 0;
    for (const auto& w : WEIGHTS) {
        if (profile.behaviorFlags & static_cast<uint64_t>(w.flag))
            score += w.weight;
    }

    profile.riskScore     = (score > 100) ? 100 : score;
    profile.isCompromised = profile.riskScore >= m_config.riskThreshold;
}

// ══════════════════════════════════════════════════════════════════
//  BehaviorReport → JSON
// ══════════════════════════════════════════════════════════════════
std::string BehaviorReport::toJSON() const {
    // JSON escape helper
    auto escapeStr = [](const std::string& s) -> std::string {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                default:   out += c;
            }
        }
        return out;
    };

    std::string j = "{";
    j += "\"targetPid\":"    + std::to_string(targetPid);
    j += ",\"durationMs\":"  + std::to_string(durationMs);
    j += ",\"totalEvents\":" + std::to_string(totalEventsCapture);
    j += ",\"flagged\":"     + std::to_string(flaggedEvents);
    j += ",\"highestRisk\":" + std::to_string(highestRiskScore);
    j += ",\"behaviorFlags\":" + std::to_string(combinedBehaviorFlags);
    j += ",\"profiles\":[";

    for (size_t i = 0; i < profiles.size(); ++i) {
        const auto& p = profiles[i];
        if (i) j += ",";
        j += "{\"pid\":"             + std::to_string(p.pid);
        j += ",\"comm\":\""          + escapeStr(std::string(p.comm)) + "\"";
        j += ",\"riskScore\":"       + std::to_string(p.riskScore);
        j += ",\"isCompromised\":"   + std::string(p.isCompromised ? "true" : "false");
        j += ",\"behaviorFlags\":"   + std::to_string(p.behaviorFlags);
        j += ",\"totalSyscalls\":"   + std::to_string(p.totalSyscalls);
        j += ",\"dangerousSyscalls\":" + std::to_string(p.dangerousSyscalls);
        j += ",\"syscallRatePerSec\":" + std::to_string((int)p.syscallRatePerSec);
        j += ",\"bytesSent\":"       + std::to_string(p.bytesSent);
        j += ",\"uid\":"             + std::to_string(p.lastSeenUid);
        j += ",\"euid\":"            + std::to_string(p.lastSeenEuid);

        // Şüpheli kütüphaneler
        j += ",\"suspiciousLibs\":[";
        for (size_t li = 0; li < p.snapshot.suspiciousLibs.size(); ++li) {
            if (li) j += ",";
            j += "\"" + escapeStr(p.snapshot.suspiciousLibs[li]) + "\"";
        }
        j += "]";

        // Bulgular
        j += ",\"findings\":[";
        for (size_t fi = 0; fi < p.findings.size(); ++fi) {
            if (fi) j += ",";
            j += "\"" + escapeStr(p.findings[fi]) + "\"";
        }
        j += "]}";
    }
    j += "]}";
    return j;
}

// ══════════════════════════════════════════════════════════════════
//  Constructor / Destructor
// ══════════════════════════════════════════════════════════════════
BehavioralAnalyzer::BehavioralAnalyzer(const BehaviorConfig& config)
    : m_config(config)
{
#if defined(__aarch64__)
    m_isArm64 = true;
#else
    m_isArm64 = false;
#endif
}

BehavioralAnalyzer::~BehavioralAnalyzer() {
    m_running.store(false);
}

} // namespace AntiVirus
