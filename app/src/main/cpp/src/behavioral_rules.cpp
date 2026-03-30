#include "behavioral_analyzer.h"
#include "syscall_table.h"

#include <cstring>
#include <cstdio>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <netinet/in.h>
#include <unistd.h>
#include <chrono>
#include <android/log.h>

#define LOG_TAG "AV_Rules"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)

namespace AntiVirus {

// ══════════════════════════════════════════════════════════════════
//  Statik kural tablosu
//  Her kural: belirli bir syscall + argüman koşulu = davranış bayrağı
// ══════════════════════════════════════════════════════════════════
static const BehaviorRule DEFAULT_RULES[] = {
    // ── Bellek ──────────────────────────────────────────
    {
        "WX_Memory",
        BEH_WX_MEMORY, 9,
        Arm64::MMAP,
        0x3, // arg2 mask (prot)
        PROT_WRITE | PROT_EXEC,  // her ikisi de set → shellcode
        0, 0
    },
    {
        "Cross_Process_Write",
        BEH_CROSS_PROC_WRITE, 10,
        Arm64::PROCESS_VM_WRITEV,
        0, 0, 0, 0
    },
    {
        "Fileless_Exec_memfd",
        BEH_FILELESS_EXEC, 9,
        Arm64::MEMFD_CREATE,
        0, 0, 0, 0
    },

    // ── Yetki yükseltme ──────────────────────────────────
    {
        "Setuid_Root",
        BEH_SETUID_ATTEMPT, 9,
        Arm64::SETUID,
        0x1,   // arg0 mask
        0x0,   // arg0 value = 0 (root)
        0, 0
    },
    {
        "Setresuid_Root",
        BEH_SETUID_ATTEMPT, 9,
        Arm64::SETRESUID,
        0x7,   // arg0|arg1|arg2
        0x0,
        0, 0
    },
    {
        "Capset_Escalation",
        BEH_CAPSET_ESCALATION, 8,
        Arm64::CAPSET,
        0, 0, 0, 0
    },

    // ── Kernel ──────────────────────────────────────────
    {
        "LKM_Load_finit",
        BEH_KERNEL_MODULE_LOAD, 10,
        Arm64::FINIT_MODULE,
        0, 0, 0, 0
    },
    {
        "LKM_Load_init",
        BEH_KERNEL_MODULE_LOAD, 10,
        Arm64::INIT_MODULE,
        0, 0, 0, 0
    },
    {
        "BPF_ProgLoad",
        BEH_BPF_PROG_LOAD, 9,
        Arm64::BPF,
        0, 0, 0, 0
    },
    {
        "Perf_Event_Exploit",
        BEH_PERF_EXPLOIT, 7,
        Arm64::PERF_EVENT_OPEN,
        0, 0, 0, 0
    },
    {
        "Userfaultfd",
        BEH_USERFAULTFD_EXPLOIT, 7,
        Arm64::USERFAULTFD,
        0, 0, 0, 0
    },
    {
        "IoUring_Setup",
        BEH_IO_URING_EXPLOIT, 7,
        Arm64::IO_URING_SETUP,
        0, 0, 0, 0
    },
    {
        "Namespace_Escape_unshare",
        BEH_NAMESPACE_ESCAPE, 7,
        Arm64::UNSHARE,
        0, 0, 0, 0
    },
    {
        "Namespace_Escape_setns",
        BEH_NAMESPACE_ESCAPE, 8,
        Arm64::SETNS,
        0, 0, 0, 0
    },

    // ── Anti-debug ───────────────────────────────────────
    {
        "Ptrace_TraceME_AntiDebug",
        BEH_ANTI_DEBUG, 6,
        Arm64::PTRACE,
        0x1,    // arg0 (request) mask
        0,      // PTRACE_TRACEME = 0
        0, 0
    },
    {
        "Ptrace_Inject",
        BEH_PTRACE_INJECTION, 9,
        Arm64::PTRACE,
        0x1,
        4,      // PTRACE_ATTACH = 4
        0, 0
    },
    {
        "Ptrace_PokeData",
        BEH_PTRACE_INJECTION, 10,
        Arm64::PTRACE,
        0x1,
        5,      // PTRACE_POKEDATA = 5
        0, 0
    },

    // ── Ağ ──────────────────────────────────────────────
    {
        "Raw_Socket",
        BEH_RAW_SOCKET, 7,
        Arm64::SOCKET,
        0x6,    // arg1 (type) mask
        SOCK_RAW,
        0, 0
    },
    // sentinel
    { nullptr, BEH_NONE, 0, 0, 0, 0, 0, 0 }
};

// ──────────────────────────────────────────────────────────────────
const BehaviorRule* BehavioralAnalyzer::getDefaultRules(size_t& count) {
    count = sizeof(DEFAULT_RULES) / sizeof(DEFAULT_RULES[0]) - 1;
    return DEFAULT_RULES;
}

// ══════════════════════════════════════════════════════════════════
//  addFinding yardımcısı
// ══════════════════════════════════════════════════════════════════
static void addFinding(ProcessProfile& p, BehaviorFlag flag,
                       const std::string& msg, uint8_t severity) {
    p.behaviorFlags |= static_cast<uint64_t>(flag);
    p.findings.push_back("[s=" + std::to_string(severity) + "] " + msg);
    LOGW("BEH [pid=%d, sev=%d]: %s", p.pid, severity, msg.c_str());
}

// ══════════════════════════════════════════════════════════════════
//  processEvent  — Tek syscall olayını işle
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::processEvent(SyscallEvent& ev,
                                       ProcessProfile& profile,
                                       BehaviorReport& report) {
    profile.lastSyscallTime_ns = ev.timestamp_ns;

    // Statik kural motoru
    applyRules(ev, profile);

    // Dinamik pattern analizleri
    checkWXMemory       (ev, profile);
    checkFilelessExec   (ev, profile);
    checkPrivEscalation (ev, profile);
    checkKernelExploit  (ev, profile);
    checkShellSpawn     (ev, profile);
    checkDataExfil      (ev, profile);
    checkAntiDebug      (ev, profile);
    checkNetworkAbuse   (ev, profile);
    checkSyscallRate    (profile);

    // Alert callback
    if (m_callback && profile.behaviorFlags) {
        for (const auto& e : profile.recentEvents) {
            // Son tetiklenen flag'i bul ve callback'e gönder
        }
    }

    if (profile.behaviorFlags) ++report.flaggedEvents;
}

// ══════════════════════════════════════════════════════════════════
//  Statik kural motoru (tablo tabanlı)
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::applyRules(const SyscallEvent& ev,
                                     ProcessProfile& profile) {
    for (const auto* rule = DEFAULT_RULES; rule->name != nullptr; ++rule) {
        if (rule->triggerSyscall != ev.syscallNr) continue;

        // Argüman kontrolü
        if (rule->argMask != 0) {
            // Hangi argümanı kontrol ediyoruz? arg0 mı arg1 mi?
            // Basit: arg0'ı mask+value ile kontrol et
            uint64_t masked = ev.args[0] & rule->argMask;
            if (masked != (rule->argValue & rule->argMask)) continue;
        }

        // Zaten bu flag kayıtlıysa tekrar ekleme
        if (profile.behaviorFlags & static_cast<uint64_t>(rule->flag)) continue;

        addFinding(profile, rule->flag,
                   std::string(rule->name) + " — " +
                   syscallName(ev.syscallNr, m_isArm64) +
                   "(arg0=0x" + std::to_string(ev.args[0]) + ")",
                   rule->severity);
    }
}

// ══════════════════════════════════════════════════════════════════
//  1. W^X bellek analizi  (mmap / mprotect zinciri)
//
//  Saldırı deseni:
//    mmap(PROT_WRITE)   → shellcode yaz
//    mprotect(PROT_EXEC) → çalıştır
//
//  Tespit: Daha önce WRITE olan sayfa EXEC yapıldıysa → alarm
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkWXMemory(const SyscallEvent& ev,
                                        ProcessProfile& profile) {
    auto& pages = m_pageHistory[ev.pid];

    if (ev.syscallNr == Arm64::MMAP || ev.syscallNr == Arm32::MMAP) {
        int prot  = static_cast<int>(ev.args[2]);
        uint64_t addr = ev.args[0];
        uint64_t len  = ev.args[1];

        if ((prot & PROT_WRITE) && (prot & PROT_EXEC)) {
            // Doğrudan W+X → shellcode hazırlığı
            addFinding(profile, BEH_WX_MEMORY,
                       "mmap(PROT_WRITE|PROT_EXEC): addr=0x" +
                       std::to_string(addr) + " len=" + std::to_string(len),
                       10);
            return;
        }

        // Geçmişe kaydet
        pages.push_back({addr, len, prot});
        if (pages.size() > 512) pages.erase(pages.begin());  // Sınırla
    }

    if (ev.syscallNr == Arm64::MPROTECT || ev.syscallNr == Arm32::MPROTECT) {
        uint64_t addr = ev.args[0];
        uint64_t len  = ev.args[1];
        int newProt   = static_cast<int>(ev.args[2]);

        if (!(newProt & PROT_EXEC)) return;  // EXEC yok, sorun değil

        // Bu adres daha önce WRITE olarak mmap'lendi mi?
        for (const auto& pg : pages) {
            bool overlaps = (addr < pg.addr + pg.len) &&
                            (addr + len > pg.addr);
            if (overlaps && (pg.prot & PROT_WRITE)) {
                addFinding(profile, BEH_WX_MEMORY,
                           "mprotect W→X geçişi: addr=0x" +
                           std::to_string(addr) +
                           " (önceki prot=" + std::to_string(pg.prot) + ")",
                           10);
                return;
            }
        }
        // Bilinmeyen sayfa → orta şüphe
        addFinding(profile, BEH_WX_MEMORY,
                   "mprotect(PROT_EXEC) bilinmeyen sayfa: 0x" +
                   std::to_string(addr), 6);
    }
}

// ══════════════════════════════════════════════════════════════════
//  2. Dosyasız yürütme (memfd_create → fexecve)
//
//  Saldırı deseni:
//    memfd_create("", MFD_CLOEXEC)  → anonim dosya
//    write(fd, elf_payload, size)   → ELF yaz
//    fexecve(fd, argv, envp)        → belleğe yükle + çalıştır
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkFilelessExec(const SyscallEvent& ev,
                                            ProcessProfile& profile) {
    static thread_local bool hadMemfd = false;
    static thread_local bool hadWrite = false;

    if (ev.syscallNr == Arm64::MEMFD_CREATE ||
        ev.syscallNr == Arm32::MEMFD_CREATE) {
        hadMemfd = true;
        hadWrite = false;
        addFinding(profile, BEH_FILELESS_EXEC,
                   "memfd_create() çağrıldı (fileless exec hazırlığı)", 7);
        return;
    }

    if (hadMemfd && ev.syscallNr == Arm64::WRITE) {
        hadWrite = true;  // memfd'ye yazıyorlar
        return;
    }

    // execve sonrası fexecve (fd üzerinden exec)
    if (hadMemfd && hadWrite &&
        (ev.syscallNr == Arm64::EXECVE || ev.syscallNr == Arm32::EXECVE)) {
        addFinding(profile, BEH_FILELESS_EXEC,
                   "memfd_create → write → execve zinciri: DOSYASIZ YÜRÜTME!",
                   10);
        hadMemfd = false;
        hadWrite = false;
    }
}

// ══════════════════════════════════════════════════════════════════
//  3. Yetki yükseltme
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkPrivEscalation(const SyscallEvent& ev,
                                              ProcessProfile& profile) {
    // setuid(0) — root olmaya çalışma
    if ((ev.syscallNr == Arm64::SETUID || ev.syscallNr == Arm32::SETUID) &&
         ev.args[0] == 0) {
        addFinding(profile, BEH_SETUID_ATTEMPT,
                   "setuid(0) çağrıldı: root yetki girişimi!", 9);
        return;
    }

    // setresuid(0, 0, 0) — effective + saved UID değiştirme
    if (ev.syscallNr == Arm64::SETRESUID &&
        ev.args[0] == 0 && ev.args[1] == 0 && ev.args[2] == 0) {
        addFinding(profile, BEH_SETUID_ATTEMPT,
                   "setresuid(0,0,0): kapsamlı root yetki girişimi!", 10);
        return;
    }

    // capset — yetkileri manipüle etme
    if (ev.syscallNr == Arm64::CAPSET || ev.syscallNr == Arm32::CAPSET) {
        addFinding(profile, BEH_CAPSET_ESCALATION,
                   "capset() çağrıldı: kernel capability manipülasyonu", 8);
    }

    // pivot_root — container kaçışı
    if (ev.syscallNr == Arm64::PIVOT_ROOT) {
        addFinding(profile, BEH_NAMESPACE_ESCAPE,
                   "pivot_root(): kök dizin değiştirme girişimi!", 10);
    }
}

// ══════════════════════════════════════════════════════════════════
//  4. Kernel exploit desenleri
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkKernelExploit(const SyscallEvent& ev,
                                             ProcessProfile& profile) {
    // LKM yükleme
    if (ev.syscallNr == Arm64::INIT_MODULE   ||
        ev.syscallNr == Arm64::FINIT_MODULE  ||
        ev.syscallNr == Arm32::FINIT_MODULE) {
        addFinding(profile, BEH_KERNEL_MODULE_LOAD,
                   "Kernel modülü yükleme girişimi (init/finit_module)!", 10);
        return;
    }

    // BPF program yükleme (sıradan uygulama kullanamaz)
    if (ev.syscallNr == Arm64::BPF || ev.syscallNr == Arm32::BPF) {
        // arg0 = cmd; BPF_PROG_LOAD = 5
        if (ev.args[0] == 5) {
            addFinding(profile, BEH_BPF_PROG_LOAD,
                       "bpf(BPF_PROG_LOAD): kernel eBPF program yükleme!", 9);
        }
        return;
    }

    // io_uring — Android'de normal uygulama kullanmamalı
    if (ev.syscallNr == Arm64::IO_URING_SETUP ||
        ev.syscallNr == Arm32::IO_URING_SETUP) {
        addFinding(profile, BEH_IO_URING_EXPLOIT,
                   "io_uring_setup(): exploit vektörü şüphesi", 7);
        return;
    }

    // userfaultfd — race condition exploit için kullanılır
    if (ev.syscallNr == Arm64::USERFAULTFD) {
        addFinding(profile, BEH_USERFAULTFD_EXPLOIT,
                   "userfaultfd(): race condition exploit şüphesi", 7);
        return;
    }

    // perf_event_open — privileged olmayan erişim
    if (ev.syscallNr == Arm64::PERF_EVENT_OPEN ||
        ev.syscallNr == Arm32::PERF_EVENT_OPEN) {
        addFinding(profile, BEH_PERF_EXPLOIT,
                   "perf_event_open(): kernel exploit vektörü (CVE-xxxx)", 7);
        return;
    }

    // Heap spray tespiti: çok fazla büyük mmap
    if (ev.syscallNr == Arm64::MMAP) {
        static thread_local int mmapCount = 0;
        static thread_local uint64_t lastMmapTime = 0;

        uint64_t now = ev.timestamp_ns;
        if (now - lastMmapTime < 100000000ULL) {  // 100ms içinde
            ++mmapCount;
            if (mmapCount > 50 && ev.args[1] > 65536) {
                addFinding(profile, BEH_HEAP_SPRAY,
                           "Heap spray şüphesi: " +
                           std::to_string(mmapCount) +
                           " büyük mmap/100ms", 8);
                mmapCount = 0;
            }
        } else {
            mmapCount = 1;
        }
        lastMmapTime = now;
    }
}

// ══════════════════════════════════════════════════════════════════
//  5. Shell spawn ve şüpheli execve
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkShellSpawn(const SyscallEvent& ev,
                                          ProcessProfile& profile) {
    if (ev.syscallNr != Arm64::EXECVE && ev.syscallNr != Arm32::EXECVE) return;

    // arg0 = pathname pointer
    // readString ile okumak ptrace gerektiriyor; proc poll'da comm'a bak
    const char* comm = ev.comm;

    static const char* SHELLS[] = {
        "sh", "bash", "dash", "zsh", "ksh", "ash", "busybox", nullptr
    };
    for (int i = 0; SHELLS[i]; ++i) {
        if (strstr(comm, SHELLS[i])) {
            addFinding(profile, BEH_SHELL_SPAWN,
                       std::string("Shell spawn tespit edildi: ") + comm, 8);
            return;
        }
    }

    // /data/local/tmp'den çalıştırma
    // (comm yetersizse; ptrace modunda arg0'ı da oku)
    // Proc poll modunda en iyi yöntem: /proc/pid/exe kontrolü
    char exeLink[64], exePath[256] = {};
    snprintf(exeLink, sizeof(exeLink), "/proc/%d/exe", ev.pid);
    readlink(exeLink, exePath, sizeof(exePath) - 1);
    if (strstr(exePath, "/data/local/tmp") ||
        strstr(exePath, "/sdcard") ||
        strstr(exePath, "/data/data")) {
        addFinding(profile, BEH_SUSPICIOUS_EXEC,
                   std::string("Şüpheli konumdan exec: ") + exePath, 8);
    }
}

// ══════════════════════════════════════════════════════════════════
//  6. Veri sızdırma deseni (sensitif okuma → hemen ağ gönderimi)
//
//  Saldırı: contacts/sms DB oku → sendto()
//  Sliding window: Son N olayda okuma + ağ var mı?
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkDataExfil(const SyscallEvent& ev,
                                         ProcessProfile& profile) {
    static const char* SENSITIVE_PATHS[] = {
        "/data/data/com.android.providers.contacts",
        "/data/data/com.android.providers.telephony",
        "/data/user/0/com.android.providers",
        "mmssms.db", "contacts2.db", "telephony.db",
        nullptr
    };

    if (ev.syscallNr == Arm64::OPENAT || ev.syscallNr == Arm64::OPEN) {
        // proc poll'da arg1'deki path'i okuyamayız (pointer)
        // Ancak şüpheli süreçleri /proc/fd üzerinden takip ederiz
        return;
    }

    // Ağ gönderimi + yakın zamanda sensitif dosya açılmış mı?
    if (ev.syscallNr == Arm64::SENDTO || ev.syscallNr == Arm64::WRITEV) {
        ++profile.sendCount;
        profile.bytesSent += ev.args[2];  // len parametresi

        // Sliding window'da hassas dosya erişimi var mı?
        for (const auto& past : profile.recentEvents) {
            if (past.syscallNr == Arm64::OPENAT ||
                past.syscallNr == Arm64::READ) {
                uint64_t windowNs = ev.timestamp_ns - past.timestamp_ns;
                if (windowNs < 2000000000ULL) {  // 2 saniye içinde
                    // Şüpheli desen
                    if (profile.sendCount > 5) {
                        addFinding(profile, BEH_DATA_EXFIL_PATTERN,
                                   "Veri sızdırma şüphesi: " +
                                   std::to_string(profile.bytesSent) +
                                   " byte gönderildi, sensitif dosya erişimi yakın zamanda",
                                   7);
                    }
                    break;
                }
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════════
//  7. Anti-debug ve analiz kaçınma
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkAntiDebug(const SyscallEvent& ev,
                                         ProcessProfile& profile) {
    // ptrace(PTRACE_TRACEME) — kendini trace et (debugger engelleme)
    if (ev.syscallNr == Arm64::PTRACE || ev.syscallNr == Arm32::PTRACE) {
        if (ev.args[0] == 0) {  // PTRACE_TRACEME = 0
            addFinding(profile, BEH_ANTI_DEBUG,
                       "ptrace(PTRACE_TRACEME): anti-debug tekniği", 7);
        }
        if (ev.args[0] == 4) {  // PTRACE_ATTACH — başka sürece bağlan
            addFinding(profile, BEH_PTRACE_ATTACH,
                       "ptrace(PTRACE_ATTACH, pid=" +
                       std::to_string(ev.args[1]) + ")", 9);
        }
        if (ev.args[0] == 5 || ev.args[0] == 6) {  // PTRACE_POKETEXT/DATA
            addFinding(profile, BEH_PTRACE_INJECTION,
                       "ptrace(POKE*): başka sürece kod enjeksiyonu!", 10);
        }
    }

    // prctl(PR_SET_DUMPABLE, 0) — core dump kapat (analizi engelle)
    if (ev.syscallNr == Arm64::PRCTL || ev.syscallNr == Arm32::PRCTL) {
        if (ev.args[0] == PR_SET_DUMPABLE && ev.args[1] == 0) {
            addFinding(profile, BEH_ANTI_DEBUG,
                       "prctl(PR_SET_DUMPABLE, 0): analiz engelleme", 5);
        }
        // prctl(PR_SET_NAME) — süreç adını gizleme
        if (ev.args[0] == PR_SET_NAME) {
            addFinding(profile, BEH_PROC_HIDE,
                       "prctl(PR_SET_NAME): süreç adı değiştirme (gizleme?)", 4);
        }
    }

    // Yoğun nanosleep → timing evasion
    static thread_local int sleepCount = 0;
    if (ev.syscallNr == 35 /* nanosleep */ || ev.syscallNr == 162 /* nanosleep arm32 */) {
        ++sleepCount;
        if (sleepCount > 20) {
            addFinding(profile, BEH_TIMING_EVASION,
                       "Yoğun nanosleep: " + std::to_string(sleepCount) +
                       " kez (timing evasion şüphesi)", 5);
            sleepCount = 0;
        }
    }
}

// ══════════════════════════════════════════════════════════════════
//  8. Ağ kötüye kullanımı
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkNetworkAbuse(const SyscallEvent& ev,
                                            ProcessProfile& profile) {
    // SOCK_RAW — paket enjeksiyonu / sniffing
    if (ev.syscallNr == Arm64::SOCKET || ev.syscallNr == Arm32::SOCKET) {
        int sockType = static_cast<int>(ev.args[1]) & ~SOCK_NONBLOCK & ~SOCK_CLOEXEC;
        if (sockType == SOCK_RAW) {
            addFinding(profile, BEH_RAW_SOCKET,
                       "SOCK_RAW soketi açıldı: paket enjeksiyon/sniff şüphesi", 7);
        }
        ++profile.connectCount;
    }

    // Ayrıcalıklı port bağlama (< 1024)
    if (ev.syscallNr == Arm64::BIND) {
        uint16_t port = 0;
        // arg1 = sockaddr*, args[2] = addrlen
        // ptrace modunda sockaddr'ı okuyabiliriz
        // proc poll modunda port bilgisine erişemeyiz doğrudan
        // /proc/net/tcp kontrol edelim
        (void)port;  // TODO: ptrace modunda implement et
    }

    // Bağlantı patlaması (kısa sürede çok fazla connect)
    if (ev.syscallNr == Arm64::CONNECT || ev.syscallNr == Arm32::CONNECT) {
        ++profile.connectCount;
        if (profile.connectCount > 100) {
            addFinding(profile, BEH_DNS_FLOOD,
                       "Bağlantı patlaması: " +
                       std::to_string(profile.connectCount) +
                       " connect() çağrısı", 7);
            profile.connectCount = 0;
        }
    }
}

// ══════════════════════════════════════════════════════════════════
//  9. Syscall hız anomalisi
//     Normal uygulama saniyede yüzlerce syscall yapar.
//     Binlerce/saniye → fuzzer veya exploit döngüsü
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::checkSyscallRate(ProcessProfile& profile) {
    if (profile.recentEvents.size() < 100) return;

    const auto& oldest = profile.recentEvents.front();
    const auto& newest = profile.recentEvents.back();
    uint64_t durationNs = newest.timestamp_ns - oldest.timestamp_ns;
    if (durationNs == 0) return;

    double rate = (double)profile.recentEvents.size()
                / ((double)durationNs / 1e9);
    profile.syscallRatePerSec = rate;

    if (rate > 50000.0) {  // 50K+ syscall/saniye → olağandışı
        addFinding(profile, BEH_SYSCALL_FLOOD,
                   "Syscall hız anomalisi: " +
                   std::to_string(static_cast<int>(rate)) +
                   "/sn (exploit/fuzzer?)", 8);
    }
}

// ══════════════════════════════════════════════════════════════════
//  Risk skoru hesaplama
//  Her BehaviorFlag → ağırlık → toplam puan (0–100)
// ══════════════════════════════════════════════════════════════════
void BehavioralAnalyzer::updateRiskScore(ProcessProfile& profile) {
    struct FlagWeight {
        BehaviorFlag flag;
        uint8_t      weight;  // 0–100 ölçeğinde katkı
    };

    static const FlagWeight WEIGHTS[] = {
        { BEH_WX_MEMORY,           25 },
        { BEH_CROSS_PROC_WRITE,    30 },
        { BEH_FILELESS_EXEC,       25 },
        { BEH_HEAP_SPRAY,          15 },
        { BEH_SETUID_ATTEMPT,      25 },
        { BEH_CAPSET_ESCALATION,   20 },
        { BEH_PTRACE_INJECTION,    30 },
        { BEH_NAMESPACE_ESCAPE,    20 },
        { BEH_KERNEL_MODULE_LOAD,  30 },
        { BEH_BPF_PROG_LOAD,       25 },
        { BEH_PERF_EXPLOIT,        15 },
        { BEH_USERFAULTFD_EXPLOIT, 15 },
        { BEH_IO_URING_EXPLOIT,    15 },
        { BEH_SHELL_SPAWN,         20 },
        { BEH_SUSPICIOUS_EXEC,     20 },
        { BEH_PTRACE_ATTACH,       20 },
        { BEH_SIGNAL_FLOOD,        10 },
        { BEH_SENSITIVE_READ,      10 },
        { BEH_INOTIFY_SENSITIVE,   10 },
        { BEH_RAW_SOCKET,          15 },
        { BEH_DATA_EXFIL_PATTERN,  20 },
        { BEH_ANTI_DEBUG,          10 },
        { BEH_PROC_HIDE,           15 },
        { BEH_TIMING_EVASION,      10 },
        { BEH_SYSCALL_FLOOD,       20 },
    };

    uint32_t score = 0;
    for (const auto& w : WEIGHTS) {
        if (profile.behaviorFlags & static_cast<uint64_t>(w.flag)) {
            score += w.weight;
        }
    }

    profile.riskScore    = score > 100 ? 100 : score;
    profile.isCompromised = profile.riskScore >= m_config.riskThreshold;
}

// ══════════════════════════════════════════════════════════════════
//  BehaviorReport → JSON
// ══════════════════════════════════════════════════════════════════
std::string BehaviorReport::toJSON() const {
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
        j += "{\"pid\":"          + std::to_string(p.pid);
        j += ",\"comm\":\""       + std::string(p.comm) + "\"";
        j += ",\"riskScore\":"    + std::to_string(p.riskScore);
        j += ",\"isCompromised\":" + std::string(p.isCompromised ? "true" : "false");
        j += ",\"behaviorFlags\":" + std::to_string(p.behaviorFlags);
        j += ",\"totalSyscalls\":" + std::to_string(p.totalSyscalls);
        j += ",\"dangerousSyscalls\":" + std::to_string(p.dangerousSyscalls);
        j += ",\"syscallRatePerSec\":" + std::to_string(static_cast<int>(p.syscallRatePerSec));
        j += ",\"bytesSent\":"    + std::to_string(p.bytesSent);
        j += ",\"findings\":[";
        for (size_t f = 0; f < p.findings.size(); ++f) {
            if (f) j += ",";
            j += "\"" + p.findings[f] + "\"";
        }
        j += "]}";
    }
    j += "]}";
    return j;
}

// ══════════════════════════════════════════════════════════════════
//  Constructor
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
