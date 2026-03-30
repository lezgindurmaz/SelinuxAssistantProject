#pragma once
#ifndef BEHAVIORAL_ANALYZER_H
#define BEHAVIORAL_ANALYZER_H

#include "syscall_table.h"
#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <functional>
#include <atomic>
#include <cstdint>
#include <ctime>

namespace AntiVirus {

// ══════════════════════════════════════════════════════════════════
//  Davranış kategorileri (bitmask)
// ══════════════════════════════════════════════════════════════════
enum BehaviorFlag : uint64_t {
    BEH_NONE                  = 0,

    // Bellek manipülasyonu
    BEH_WX_MEMORY             = (1ULL <<  0), // mmap/mprotect PROT_WRITE|EXEC
    BEH_CROSS_PROC_WRITE      = (1ULL <<  1), // process_vm_writev başka süreç
    BEH_FILELESS_EXEC         = (1ULL <<  2), // memfd_create + fexecve
    BEH_HEAP_SPRAY            = (1ULL <<  3), // Anormal büyüklükte mmap dizisi

    // Yetki yükseltme
    BEH_SETUID_ATTEMPT        = (1ULL <<  4), // setuid(0) girişimi
    BEH_CAPSET_ESCALATION     = (1ULL <<  5), // capset ile yetki artırma
    BEH_PTRACE_INJECTION      = (1ULL <<  6), // ptrace ile başka sürece inject
    BEH_NAMESPACE_ESCAPE      = (1ULL <<  7), // unshare/setns ile ns kaçışı

    // Kernel exploit
    BEH_KERNEL_MODULE_LOAD    = (1ULL <<  8), // init_module / finit_module
    BEH_BPF_PROG_LOAD         = (1ULL <<  9), // bpf(BPF_PROG_LOAD)
    BEH_PERF_EXPLOIT          = (1ULL << 10), // perf_event_open yetkisiz
    BEH_USERFAULTFD_EXPLOIT   = (1ULL << 11), // userfaultfd race condition
    BEH_IO_URING_EXPLOIT      = (1ULL << 12), // io_uring yetkisiz kullanım

    // Süreç manipülasyonu
    BEH_SHELL_SPAWN           = (1ULL << 13), // sh/bash/dash exec
    BEH_SUSPICIOUS_EXEC       = (1ULL << 14), // /data/local/tmp'den exec
    BEH_PTRACE_ATTACH         = (1ULL << 15), // Başka süreci izleme
    BEH_SIGNAL_FLOOD          = (1ULL << 16), // Yoğun kill() gönderimi

    // Dosya sistemi
    BEH_SENSITIVE_READ        = (1ULL << 17), // /proc/*/mem, /dev/kmem okuma
    BEH_INOTIFY_SENSITIVE     = (1ULL << 18), // Hassas dizileri izleme
    BEH_HIDDEN_FILE_ACCESS    = (1ULL << 19), // Nokta ile başlayan gizli yollar

    // Ağ
    BEH_RAW_SOCKET            = (1ULL << 20), // SOCK_RAW soket açma
    BEH_BIND_PRIVILEGED_PORT  = (1ULL << 21), // 1024'ün altında port
    BEH_DNS_FLOOD             = (1ULL << 22), // Anormal DNS sorgusu
    BEH_DATA_EXFIL_PATTERN    = (1ULL << 23), // Okuma → hemen ağ gönderimi

    // Anti-analiz
    BEH_ANTI_DEBUG            = (1ULL << 24), // ptrace(TRACEME), prctl hide
    BEH_PROC_HIDE             = (1ULL << 25), // /proc/self dizin manipülasyonu
    BEH_TIMING_EVASION        = (1ULL << 26), // nanosleep ile analizi yavaşlatma
    BEH_SYSCALL_FLOOD         = (1ULL << 27), // Saniyede normalin üstünde syscall
};

// ══════════════════════════════════════════════════════════════════
//  Tek syscall olayı
// ══════════════════════════════════════════════════════════════════
struct SyscallEvent {
    uint64_t  timestamp_ns;    // CLOCK_MONOTONIC nanosaniye
    pid_t     pid;
    pid_t     tid;
    uint32_t  syscallNr;
    uint64_t  args[6];         // Syscall argümanları
    long      retval;          // Dönüş değeri (-1 = henüz bitmedi)
    bool      isEntry;         // true = giriş, false = çıkış
    char      comm[16];        // /proc/pid/comm (süreç adı)
};

// ══════════════════════════════════════════════════════════════════
//  Davranış deseni (kural tanımı)
// ══════════════════════════════════════════════════════════════════
struct BehaviorRule {
    const char*  name;
    BehaviorFlag flag;
    uint8_t      severity;     // 1–10
    // Tetikleyici: syscall numarası + argüman maskesi
    uint32_t     triggerSyscall;
    uint64_t     argMask;      // Hangi argümanlara bakılacak (bitmask)
    uint64_t     argValue;     // Beklenen argüman değeri
    // Dizi bazlı kural: bu syscall'dan önce hangisi gelmeliydi?
    uint32_t     precedingSyscall; // 0 = dizi şartı yok
    uint32_t     windowMs;         // Kaç ms içinde olmalıydı
};

// ══════════════════════════════════════════════════════════════════
//  Süreç davranış profili
// ══════════════════════════════════════════════════════════════════
struct ProcessProfile {
    pid_t    pid;
    char     comm[16];
    char     exePath[256];

    // Syscall istatistikleri
    std::unordered_map<uint32_t, uint64_t> syscallCounts;
    uint64_t totalSyscalls;
    uint64_t dangerousSyscalls;

    // Tespit edilen bayraklar
    uint64_t behaviorFlags;    // BehaviorFlag bitmask

    // Olay geçmişi (son N olay — sliding window)
    std::deque<SyscallEvent>   recentEvents;

    // Risk metrikler
    uint32_t riskScore;        // 0–100
    bool     isCompromised;
    std::vector<std::string> findings;  // İnsan okunabilir bulgular

    // Ağ aktivitesi
    uint32_t connectCount;
    uint32_t sendCount;
    uint64_t bytesSent;

    // Timing
    uint64_t startTime_ns;
    uint64_t lastSyscallTime_ns;
    double   syscallRatePerSec;
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

    // En tehlikeli süreç
    pid_t    mostSuspiciousPid;
    uint32_t highestRiskScore;
    uint64_t combinedBehaviorFlags;

    std::string toJSON() const;
};

// ══════════════════════════════════════════════════════════════════
//  İzleme yöntemi
// ══════════════════════════════════════════════════════════════════
enum class MonitorMethod {
    METHOD_PTRACE_ATTACH,   // Çalışan sürece ptrace ile bağlan
    METHOD_PTRACE_FORK,     // Çocuk süreci izle (kendi çocuğumuz)
    METHOD_PROC_POLL,       // /proc/PID/syscall polling (düşük overhead)
    METHOD_SECCOMP_SELF,    // Kendi sürecimize seccomp + SECCOMP_RET_TRACE
};

// ══════════════════════════════════════════════════════════════════
//  Analiz konfigürasyonu
// ══════════════════════════════════════════════════════════════════
struct BehaviorConfig {
    MonitorMethod method          = MonitorMethod::METHOD_PROC_POLL;
    uint32_t      durationMs      = 5000;    // Kaç ms izle
    uint32_t      pollIntervalUs  = 5000;    // Proc polling aralığı (µs)
    uint32_t      windowSize      = 256;     // Sliding window olay sayısı
    uint32_t      riskThreshold   = 30;      // Bu puanın üstü alert
    bool          followChildren  = true;    // fork edilen çocukları da izle
    bool          captureArgs     = true;    // Syscall argümanları kaydet
    std::vector<pid_t> targetPids;           // Boşsa tüm erişilebilir süreçler
};

// ══════════════════════════════════════════════════════════════════
//  Event callback tipi
// ══════════════════════════════════════════════════════════════════
using BehaviorCallback = std::function<void(
    const SyscallEvent&,
    const ProcessProfile&,
    BehaviorFlag            // Tetiklenen kural
)>;

// ══════════════════════════════════════════════════════════════════
//  Ana Davranışsal Analiz Motoru
// ══════════════════════════════════════════════════════════════════
class BehavioralAnalyzer {
public:
    explicit BehavioralAnalyzer(const BehaviorConfig& config = BehaviorConfig{});
    ~BehavioralAnalyzer();

    // Çalışan bir süreci belirli süre boyunca izle
    BehaviorReport analyzeProcess(pid_t pid);

    // Kendi çocuğumuzu izle (PTRACE_FORK yöntemi)
    // cmd'yi çalıştırır, biter veya süre dolana kadar izler
    BehaviorReport analyzeCommand(const std::string& cmd,
                                   const std::vector<std::string>& args);

    // Sistem geneli tarama: /proc altındaki tüm erişilebilir süreçler
    BehaviorReport scanAllProcesses();

    // Gerçek zamanlı callback kaydet (alert)
    void setCallback(BehaviorCallback cb) { m_callback = cb; }

    // İzlemeyi durdur (başka thread'den)
    void stop() { m_running.store(false); }

    // Kural seti
    static const BehaviorRule* getDefaultRules(size_t& count);

    // Öz-koruma
    static bool initSelfProtection();

private:
    BehaviorConfig   m_config;
    BehaviorCallback m_callback;
    std::atomic<bool> m_running{false};
    bool             m_isArm64;

    // Ptrace izleme motoru
    BehaviorReport ptraceMonitor(pid_t tracee);

    // /proc polling motoru
    BehaviorReport procPollMonitor(const std::vector<pid_t>& pids);

    // Olay işleme
    void processEvent(SyscallEvent& ev,
                      ProcessProfile& profile,
                      BehaviorReport& report);

    // Kural motoru
    void applyRules(const SyscallEvent& ev, ProcessProfile& profile);

    // Risk skoru hesapla
    void updateRiskScore(ProcessProfile& profile);

    // Yardımcılar
    bool   attachProcess    (pid_t pid);
    void   detachProcess    (pid_t pid);
    bool   readSyscallEntry (pid_t pid, SyscallEvent& ev);
    bool   readProcSyscall  (pid_t pid, SyscallEvent& ev);
    char*  readString       (pid_t pid, uint64_t addr, char* buf, size_t len);
    void   fillComm         (pid_t pid, SyscallEvent& ev);

    // Pattern analizler (özel kurallar)
    void checkWXMemory       (const SyscallEvent& ev, ProcessProfile& p);
    void checkFilelessExec   (const SyscallEvent& ev, ProcessProfile& p);
    void checkPrivEscalation (const SyscallEvent& ev, ProcessProfile& p);
    void checkKernelExploit  (const SyscallEvent& ev, ProcessProfile& p);
    void checkShellSpawn     (const SyscallEvent& ev, ProcessProfile& p);
    void checkDataExfil      (const SyscallEvent& ev, ProcessProfile& p);
    void checkAntiDebug      (const SyscallEvent& ev, ProcessProfile& p);
    void checkNetworkAbuse   (const SyscallEvent& ev, ProcessProfile& p);
    void checkSyscallRate    (ProcessProfile& p);

    // Mprotect geçmişi: hangi sayfa önceden yazılabilirdi?
    struct PageInfo { uint64_t addr; uint64_t len; int prot; };
    std::unordered_map<pid_t, std::vector<PageInfo>> m_pageHistory;
};

} // namespace AntiVirus

#endif // BEHAVIORAL_ANALYZER_H
