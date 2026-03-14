#pragma once
#ifndef BEHAVIORAL_ANALYZER_H
#define BEHAVIORAL_ANALYZER_H

#include "syscall_table.h"
#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <atomic>
#include <cstdint>
#include <ctime>

namespace AntiVirus {

// ══════════════════════════════════════════════════════════════════
//  Davranış kategorileri (bitmask)
//  Bit 0–27  : Orijinal bayraklar
//  Bit 28–47 : Yeni / KernelSU / APatch / gelişmiş tespitler
// ══════════════════════════════════════════════════════════════════
enum BehaviorFlag : uint64_t {
    BEH_NONE                  = 0,

    // ── Bellek manipülasyonu ─────────────────────────────────────
    BEH_WX_MEMORY             = (1ULL <<  0), // mmap/mprotect PROT_WRITE|EXEC
    BEH_CROSS_PROC_WRITE      = (1ULL <<  1), // process_vm_writev başka süreç
    BEH_FILELESS_EXEC         = (1ULL <<  2), // memfd_create + fexecve
    BEH_HEAP_SPRAY            = (1ULL <<  3), // Anormal büyüklükte mmap dizisi

    // ── Yetki yükseltme ──────────────────────────────────────────
    BEH_SETUID_ATTEMPT        = (1ULL <<  4), // setuid(0)
    BEH_CAPSET_ESCALATION     = (1ULL <<  5), // capset yetki artırma
    BEH_PTRACE_INJECTION      = (1ULL <<  6), // ptrace ile inject
    BEH_NAMESPACE_ESCAPE      = (1ULL <<  7), // unshare/setns/pivot_root

    // ── Kernel exploit ───────────────────────────────────────────
    BEH_KERNEL_MODULE_LOAD    = (1ULL <<  8), // init_module / finit_module
    BEH_BPF_PROG_LOAD         = (1ULL <<  9), // bpf(BPF_PROG_LOAD)
    BEH_PERF_EXPLOIT          = (1ULL << 10), // perf_event_open
    BEH_USERFAULTFD_EXPLOIT   = (1ULL << 11), // userfaultfd race
    BEH_IO_URING_EXPLOIT      = (1ULL << 12), // io_uring

    // ── Süreç manipülasyonu ──────────────────────────────────────
    BEH_SHELL_SPAWN           = (1ULL << 13), // sh/bash/dash exec
    BEH_SUSPICIOUS_EXEC       = (1ULL << 14), // /data/local/tmp exec
    BEH_PTRACE_ATTACH         = (1ULL << 15), // Başka süreci izle
    BEH_SIGNAL_FLOOD          = (1ULL << 16), // Yoğun kill()

    // ── Dosya sistemi ────────────────────────────────────────────
    BEH_SENSITIVE_READ        = (1ULL << 17), // /proc/*/mem okuma
    BEH_INOTIFY_SENSITIVE     = (1ULL << 18), // Hassas dizileri izleme
    BEH_HIDDEN_FILE_ACCESS    = (1ULL << 19), // Gizli yollar

    // ── Ağ ───────────────────────────────────────────────────────
    BEH_RAW_SOCKET            = (1ULL << 20), // SOCK_RAW
    BEH_BIND_PRIVILEGED_PORT  = (1ULL << 21), // Port < 1024
    BEH_DNS_FLOOD             = (1ULL << 22), // Anormal DNS
    BEH_DATA_EXFIL_PATTERN    = (1ULL << 23), // Okuma → ağ gönderimi

    // ── Anti-analiz ──────────────────────────────────────────────
    BEH_ANTI_DEBUG            = (1ULL << 24), // ptrace(TRACEME), prctl hide
    BEH_PROC_HIDE             = (1ULL << 25), // /proc/self manipülasyonu
    BEH_TIMING_EVASION        = (1ULL << 26), // nanosleep evasion
    BEH_SYSCALL_FLOOD         = (1ULL << 27), // Syscall hız anomalisi

    // ══ YENİ TESPİTLER ══════════════════════════════════════════

    // ── KernelSU / APatch / root araçları ───────────────────────
    // KernelSU, prctl'i özel magic değerlerle "gizli komut" olarak kullanır.
    // Bu syscall'lar normal uygulamada asla görülmez.
    BEH_KERNELSU_PROBE        = (1ULL << 28), // prctl(0xdeadc0de/magic) KSU sorgusu
    BEH_APATCH_PROBE          = (1ULL << 29), // /dev/apd ioctl (APatch SU)
    BEH_SU_PRCTL_BACKDOOR     = (1ULL << 30), // Bilinmeyen prctl magic (genel SU)

    // ── /proc tabanlı enjeksiyon ─────────────────────────────────
    // ptrace kullanmadan /proc/pid/mem üzerine yazma = stealth inject
    BEH_PROC_MEM_INJECT       = (1ULL << 31), // /proc/pid/mem write

    // ── Cihaz dosyası kötüye kullanımı ──────────────────────────
    BEH_INPUT_HIJACK          = (1ULL << 32), // /dev/input/* okuma = keylogger
    BEH_CAMERA_MIC_HIJACK     = (1ULL << 33), // kamera/mikrofon ioctl yetkisiz

    // ── Dosya sistemi gizleme (Magisk/KernelSU tarzı) ────────────
    BEH_MOUNT_BIND_HIDE       = (1ULL << 34), // mount --bind ile overlay gizleme
    BEH_OVERLAY_TMPFS         = (1ULL << 35), // tmpfs mount + üzerine yazma

    // ── Zygote / uygulama enjeksiyonu ────────────────────────────
    BEH_ZYGOTE_INJECT         = (1ULL << 36), // zygote sürecine bağlanma

    // ── UID/GID değişim tespiti (/proc/status polling) ───────────
    BEH_UID_ESCALATED         = (1ULL << 37), // Çalışma zamanında UID 0'a düştü

    // ── Yabancı kütüphane enjeksiyonu (/proc/maps'den) ───────────
    BEH_FOREIGN_LIB_INJECT   = (1ULL << 38), // /proc/maps'de beklendik dışı .so

    // ── Seccomp atlatma ─────────────────────────────────────────
    BEH_SECCOMP_PROBE         = (1ULL << 39), // seccomp filtresi yoklama

    // ── Double-fetch / TOCTOU exploit ────────────────────────────
    BEH_DOUBLE_FETCH_EXPLOIT  = (1ULL << 40), // aynı adresi hızlı çift okuma

    // ── Overlay saldırı hazırlığı ────────────────────────────────
    BEH_SCREEN_OVERLAY_SETUP  = (1ULL << 41), // TYPE_APPLICATION_OVERLAY pencere + erişilebilirlik

    // ── Tehlikeli ioctl akışı ────────────────────────────────────
    BEH_DANGEROUS_IOCTL       = (1ULL << 42), // /dev/binder, /dev/kgsl, vb. yetkisiz ioctl

    // ── Çekirdek sembol okuma ────────────────────────────────────
    BEH_KALLSYMS_READ         = (1ULL << 43), // /proc/kallsyms okuma (exploit hazırlığı)

    // ── İzleme karşı tedbirler ────────────────────────────────────
    BEH_INOTIFY_SELF_WATCH    = (1ULL << 44), // Kendi dizinini izleme (AV kaçınma)

    // ── Cgroup / namespace saldırısı ─────────────────────────────
    BEH_CGROUP_ESCAPE         = (1ULL << 45), // cgroup namespace kaçışı
};

// ══════════════════════════════════════════════════════════════════
//  Tek syscall olayı
// ══════════════════════════════════════════════════════════════════
struct SyscallEvent {
    uint64_t  timestamp_ns;
    pid_t     pid;
    pid_t     tid;
    uint32_t  syscallNr;
    uint64_t  args[6];
    long      retval;
    bool      isEntry;
    char      comm[16];
};

// ══════════════════════════════════════════════════════════════════
//  Davranış deseni (kural tanımı)
// ══════════════════════════════════════════════════════════════════
struct BehaviorRule {
    const char*  name;
    BehaviorFlag flag;
    uint8_t      severity;       // 1–10
    uint32_t     triggerSyscall;
    uint64_t     argMask;
    uint64_t     argValue;
    uint32_t     precedingSyscall;
    uint32_t     windowMs;
};

// ══════════════════════════════════════════════════════════════════
//  /proc deep scan sonucu
// ══════════════════════════════════════════════════════════════════
struct ProcSnapshot {
    pid_t    pid;
    uid_t    uid;
    uid_t    euid;
    uid_t    suid;
    char     name[256];
    char     exe[256];
    bool     hasKernelSuLib;     // maps'de ksu/apatch kütüphanesi
    bool     hasAdbLib;
    bool     hasFridaLib;
    bool     hasXposedLib;
    bool     hasZygiskLib;
    std::vector<std::string> suspiciousLibs;
    std::vector<std::string> openDevFiles; // /dev/* açık fd'ler
    uint32_t tcpConnectionCount;
    uint32_t udpConnectionCount;
};

// ══════════════════════════════════════════════════════════════════
//  Süreç davranış profili
// ══════════════════════════════════════════════════════════════════
struct ProcessProfile {
    pid_t    pid;
    char     comm[16];
    char     exePath[256];

    std::unordered_map<uint32_t, uint64_t> syscallCounts;
    uint64_t totalSyscalls;
    uint64_t dangerousSyscalls;

    uint64_t behaviorFlags;

    std::deque<SyscallEvent>   recentEvents;

    uint32_t riskScore;
    bool     isCompromised;
    std::vector<std::string> findings;

    uint32_t connectCount;
    uint32_t sendCount;
    uint64_t bytesSent;

    uint64_t startTime_ns;
    uint64_t lastSyscallTime_ns;
    double   syscallRatePerSec;

    // Yeni alanlar
    uid_t    lastSeenUid;        // UID değişimi izleme
    uid_t    lastSeenEuid;
    ProcSnapshot snapshot;       // /proc deep scan sonucu
};

// ══════════════════════════════════════════════════════════════════
//  Analiz raporu
// ══════════════════════════════════════════════════════════════════
struct BehaviorReport {
    pid_t    targetPid;
    uint32_t durationMs;
    uint64_t totalEventsCapture;
    uint64_t flaggedEvents;

    std::vector<ProcessProfile> profiles;

    pid_t    mostSuspiciousPid;
    uint32_t highestRiskScore;
    uint64_t combinedBehaviorFlags;

    std::string toJSON() const;
};

// ══════════════════════════════════════════════════════════════════
//  İzleme yöntemi
// ══════════════════════════════════════════════════════════════════
enum class MonitorMethod {
    PTRACE_ATTACH,
    PTRACE_FORK,
    PROC_POLL,
    SECCOMP_SELF,
};

// ══════════════════════════════════════════════════════════════════
//  Analiz konfigürasyonu
// ══════════════════════════════════════════════════════════════════
struct BehaviorConfig {
    MonitorMethod method          = MonitorMethod::PROC_POLL;
    uint32_t      durationMs      = 5000;
    uint32_t      pollIntervalUs  = 3000;   // 3ms (daha duyarlı)
    uint32_t      windowSize      = 512;    // Daha geniş sliding window
    uint32_t      riskThreshold   = 30;
    bool          followChildren  = true;
    bool          captureArgs     = true;
    bool          deepProcScan    = true;   // /proc/maps + /proc/status izle
    std::vector<pid_t> targetPids;
};

using BehaviorCallback = std::function<void(
    const SyscallEvent&,
    const ProcessProfile&,
    BehaviorFlag
)>;

// ══════════════════════════════════════════════════════════════════
//  Ana Davranışsal Analiz Motoru
// ══════════════════════════════════════════════════════════════════
class BehavioralAnalyzer {
public:
    explicit BehavioralAnalyzer(const BehaviorConfig& config = BehaviorConfig{});
    ~BehavioralAnalyzer();

    BehaviorReport analyzeProcess(pid_t pid);
    BehaviorReport analyzeCommand(const std::string& cmd,
                                   const std::vector<std::string>& args);
    BehaviorReport scanAllProcesses();

    void setCallback(BehaviorCallback cb) { m_callback = cb; }
    void stop() { m_running.store(false); }

    static const BehaviorRule* getDefaultRules(size_t& count);

private:
    BehaviorConfig    m_config;
    BehaviorCallback  m_callback;
    std::atomic<bool> m_running{false};
    bool              m_isArm64;

    // İzleme motorları
    BehaviorReport ptraceMonitor(pid_t tracee);
    BehaviorReport procPollMonitor(const std::vector<pid_t>& pids);

    // Olay işleme
    void processEvent(SyscallEvent& ev,
                      ProcessProfile& profile,
                      BehaviorReport& report);
    void applyRules(const SyscallEvent& ev, ProcessProfile& profile);
    void updateRiskScore(ProcessProfile& profile);

    // Yardımcılar
    bool   attachProcess    (pid_t pid);
    void   detachProcess    (pid_t pid);
    bool   readSyscallEntry (pid_t pid, SyscallEvent& ev);
    bool   readProcSyscall  (pid_t pid, SyscallEvent& ev);
    char*  readString       (pid_t pid, uint64_t addr, char* buf, size_t len);
    void   fillComm         (pid_t pid, SyscallEvent& ev);

    // /proc deep scan
    ProcSnapshot  takeProcSnapshot(pid_t pid);
    void          checkProcMaps   (pid_t pid, ProcessProfile& profile);
    void          checkProcStatus (pid_t pid, ProcessProfile& profile);
    void          checkProcFd     (pid_t pid, ProcessProfile& profile);
    void          checkProcNet    (pid_t pid, ProcessProfile& profile);

    // ── Orijinal pattern analizleri ─────────────────────────────
    void checkWXMemory       (const SyscallEvent& ev, ProcessProfile& p);
    void checkFilelessExec   (const SyscallEvent& ev, ProcessProfile& p);
    void checkPrivEscalation (const SyscallEvent& ev, ProcessProfile& p);
    void checkKernelExploit  (const SyscallEvent& ev, ProcessProfile& p);
    void checkShellSpawn     (const SyscallEvent& ev, ProcessProfile& p);
    void checkDataExfil      (const SyscallEvent& ev, ProcessProfile& p);
    void checkAntiDebug      (const SyscallEvent& ev, ProcessProfile& p);
    void checkNetworkAbuse   (const SyscallEvent& ev, ProcessProfile& p);
    void checkSyscallRate    (ProcessProfile& p);

    // ── YENİ pattern analizleri ─────────────────────────────────
    void checkKernelSuProbe  (const SyscallEvent& ev, ProcessProfile& p);
    void checkAPatchProbe    (const SyscallEvent& ev, ProcessProfile& p);
    void checkProcMemInject  (const SyscallEvent& ev, ProcessProfile& p);
    void checkInputHijack    (const SyscallEvent& ev, ProcessProfile& p);
    void checkMountHide      (const SyscallEvent& ev, ProcessProfile& p);
    void checkZygoteInject   (const SyscallEvent& ev, ProcessProfile& p);
    void checkDangerousIoctl (const SyscallEvent& ev, ProcessProfile& p);
    void checkKallsymsRead   (const SyscallEvent& ev, ProcessProfile& p);
    void checkSeccompProbe   (const SyscallEvent& ev, ProcessProfile& p);
    void checkCgroupEscape   (const SyscallEvent& ev, ProcessProfile& p);

    struct PageInfo { uint64_t addr; uint64_t len; int prot; };
    std::unordered_map<pid_t, std::vector<PageInfo>> m_pageHistory;

    // Son UID değerleri (UID escalation tespiti için)
    std::unordered_map<pid_t, uid_t> m_lastUid;

    // Açık fd geçmişi (apatch /dev/apd tespiti için)
    std::unordered_map<pid_t, std::unordered_set<std::string>> m_openDevFds;
};

} // namespace AntiVirus
#endif // BEHAVIORAL_ANALYZER_H
