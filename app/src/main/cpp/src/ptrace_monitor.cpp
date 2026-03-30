#include "behavioral_analyzer.h"
#include "syscall_table.h"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>        // struct user_regs_struct (ARM64)
#include <sys/uio.h>         // PTRACE_GETREGSET
#include <sys/prctl.h>
#include <elf.h>             // NT_PRSTATUS
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <cstring>
#include <cstdio>
#include <dirent.h>
#include <errno.h>
#include <chrono>
#include <thread>
#include <android/log.h>

#define LOG_TAG "AV_PTrace"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace AntiVirus {

// ══════════════════════════════════════════════════════════════════
//  ARM64 register yapısı (user_regs_struct aarch64)
//  NDK bunu her zaman tanımlamaz; elle tanımlıyoruz.
// ══════════════════════════════════════════════════════════════════
struct AArch64Regs {
    uint64_t regs[31];   // x0–x30
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

// ARM32 register yapısı
struct Arm32Regs {
    uint32_t regs[18];   // r0–r15 + cpsr + ...
};

// ──────────────────────────────────────────────────────────────────
//  Helper: /proc/pid/comm oku
// ──────────────────────────────────────────────────────────────────
void BehavioralAnalyzer::fillComm(pid_t pid, SyscallEvent& ev) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { ev.comm[0] = '?'; ev.comm[1] = '\0'; return; }
    ssize_t n = read(fd, ev.comm, sizeof(ev.comm) - 1);
    close(fd);
    if (n > 0) {
        ev.comm[n] = '\0';
        // newline'ı kaldır
        for (int i = 0; i < n; ++i)
            if (ev.comm[i] == '\n') { ev.comm[i] = '\0'; break; }
    }
}

// ──────────────────────────────────────────────────────────────────
//  Helper: tracee'nin belleğinden string oku
//  ptrace(PTRACE_PEEKDATA) ile 8 byte 8 byte okur
// ──────────────────────────────────────────────────────────────────
char* BehavioralAnalyzer::readString(pid_t pid, uint64_t addr,
                                      char* buf, size_t len) {
    size_t i = 0;
    while (i < len - 1) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid,
                           reinterpret_cast<void*>(addr + i), nullptr);
        if (errno) break;
        memcpy(buf + i, &word, sizeof(word));
        // Null byte var mı?
        for (size_t j = 0; j < sizeof(long); ++j) {
            if (buf[i + j] == '\0') goto done;
        }
        i += sizeof(long);
    }
done:
    buf[i < len ? i : len - 1] = '\0';
    return buf;
}

// ──────────────────────────────────────────────────────────────────
//  ptrace ile sürece bağlan
// ──────────────────────────────────────────────────────────────────
bool BehavioralAnalyzer::attachProcess(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) != 0) {
        LOGE("ptrace(ATTACH, %d) başarısız: %s", pid, strerror(errno));
        return false;
    }
    // Bağlantının tamamlanmasını bekle
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        LOGE("waitpid(%d) hatası: %s", pid, strerror(errno));
        return false;
    }
    // PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACESYSGOOD
    // → Fork edilen çocukları da otomatik izle
    // → Syscall stop'larında SIGTRAP|0x80 sinyali (daha kolay ayırt edilir)
    long opts = PTRACE_O_TRACESYSGOOD
              | PTRACE_O_TRACEFORK
              | PTRACE_O_TRACEVFORK
              | PTRACE_O_TRACECLONE
              | PTRACE_O_TRACEEXEC;
    ptrace(PTRACE_SETOPTIONS, pid, nullptr, reinterpret_cast<void*>(opts));
    LOGI("ptrace bağlandı: pid=%d", pid);
    return true;
}

// ──────────────────────────────────────────────────────────────────
//  Bağlantıyı kes
// ──────────────────────────────────────────────────────────────────
void BehavioralAnalyzer::detachProcess(pid_t pid) {
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    LOGI("ptrace ayrıldı: pid=%d", pid);
}

// ──────────────────────────────────────────────────────────────────
//  ARM64 register'larından syscall bilgisi çıkar
// ──────────────────────────────────────────────────────────────────
bool BehavioralAnalyzer::readSyscallEntry(pid_t pid, SyscallEvent& ev) {
    ev.pid        = pid;
    ev.tid        = pid;  // Thread ID (ayrıca doldurulabilir)
    ev.retval     = -1;
    ev.isEntry    = true;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ev.timestamp_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    fillComm(pid, ev);

    if (m_isArm64) {
        // ARM64: PTRACE_GETREGSET + NT_PRSTATUS
        AArch64Regs regs{};
        struct iovec iov = { &regs, sizeof(regs) };
        if (ptrace(PTRACE_GETREGSET, pid,
                   reinterpret_cast<void*>(NT_PRSTATUS), &iov) != 0) {
            LOGE("PTRACE_GETREGSET başarısız pid=%d: %s", pid, strerror(errno));
            return false;
        }
        // ARM64 syscall convention:
        //   x8  = syscall numarası
        //   x0–x5 = argümanlar
        //   x0  = dönüş değeri (exit'te)
        ev.syscallNr = static_cast<uint32_t>(regs.regs[8]);
        for (int i = 0; i < 6; ++i)
            ev.args[i] = regs.regs[i];   // x0–x5

    } else {
        // ARM32: PTRACE_GETREGSET + NT_PRSTATUS
        Arm32Regs regs{};
        struct iovec iov = { &regs, sizeof(regs) };
        if (ptrace(PTRACE_GETREGSET, pid,
                   reinterpret_cast<void*>(NT_PRSTATUS), &iov) != 0)
            return false;
        // ARM32 EABI: r7 = syscall nr, r0–r5 = args
        ev.syscallNr = regs.regs[7];
        for (int i = 0; i < 6; ++i)
            ev.args[i] = regs.regs[i];   // r0–r5
    }
    return true;
}

// ══════════════════════════════════════════════════════════════════
//  Ana ptrace izleme döngüsü
//
//  Akış:
//    1. Sürece bağlan
//    2. PTRACE_SYSCALL ile devam et → her syscall entry/exit'te dur
//    3. Register'ları oku → SyscallEvent oluştur
//    4. Kural motoruna gönder
//    5. Süre dolana kadar veya süreç bitene kadar tekrar
// ══════════════════════════════════════════════════════════════════
BehaviorReport BehavioralAnalyzer::ptraceMonitor(pid_t tracee) {
    BehaviorReport report{};
    report.targetPid = tracee;

    if (!attachProcess(tracee)) {
        LOGE("Süreç izlenemedi: %d", tracee);
        return report;
    }

    // Profil oluştur
    ProcessProfile profile{};
    profile.pid = tracee;
    fillComm(tracee, reinterpret_cast<SyscallEvent&>(profile));  // comm al

    auto startTime = std::chrono::steady_clock::now();
    auto deadline  = startTime + std::chrono::milliseconds(m_config.durationMs);

    // Her iki ptrace duruşu çifti bir syscall'dır (entry + exit)
    std::unordered_map<pid_t, bool> inSyscall;  // pid → entry mi bekliyoruz
    m_running.store(true);

    while (m_running.load() && std::chrono::steady_clock::now() < deadline) {
        // Süreci bir sonraki syscall durağına kadar devam ettir
        if (ptrace(PTRACE_SYSCALL, tracee, nullptr, nullptr) != 0) {
            if (errno == ESRCH) break;  // Süreç bitti
            LOGW("PTRACE_SYSCALL hatası: %s", strerror(errno));
            break;
        }

        int   status;
        pid_t stoppedPid = waitpid(-1, &status, __WALL);
        if (stoppedPid < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // Süreç bitti
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (stoppedPid == tracee) break;
            continue;
        }

        // Yeni fork edilen çocuk → izlemeye al
        if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK << 8)) ||
            status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
            unsigned long childPid;
            ptrace(PTRACE_GETEVENTMSG, stoppedPid, nullptr, &childPid);
            LOGI("Yeni çocuk tespit edildi: %lu (ebeveyn: %d)", childPid, stoppedPid);
            // Çocuğu da izleme listesine al (waitpid -1 zaten yakalar)
            inSyscall[static_cast<pid_t>(childPid)] = false;
            // Çocuğa da seçenekleri uygula
            long opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK
                      | PTRACE_O_TRACECLONE    | PTRACE_O_TRACEEXEC;
            ptrace(PTRACE_SETOPTIONS, childPid, nullptr,
                   reinterpret_cast<void*>(opts));
            ptrace(PTRACE_SYSCALL,    childPid, nullptr, nullptr);
            continue;
        }

        // Sadece syscall dur sinyallerini işle (SIGTRAP|0x80)
        if (!WIFSTOPPED(status)) continue;
        int sig = WSTOPSIG(status);
        if (sig != (SIGTRAP | 0x80)) {
            // Başka sinyal: ilet ve devam et
            ptrace(PTRACE_SYSCALL, stoppedPid, nullptr,
                   reinterpret_cast<void*>(sig & ~0x80));
            continue;
        }

        // Syscall entry mi exit mi?
        bool& waitingEntry = inSyscall[stoppedPid];
        SyscallEvent ev{};
        if (!readSyscallEntry(stoppedPid, ev)) continue;

        if (!waitingEntry) {
            // Entry: syscall başlıyor
            ev.isEntry    = true;
            waitingEntry  = true;
            ++report.totalEventsCapture;
            ++profile.totalSyscalls;
            ++profile.syscallCounts[ev.syscallNr];

            if (isDangerousSyscall(ev.syscallNr, m_isArm64))
                ++profile.dangerousSyscalls;

            // Sliding window'a ekle
            if (profile.recentEvents.size() >= m_config.windowSize)
                profile.recentEvents.pop_front();
            profile.recentEvents.push_back(ev);

            // Kural motorunu çalıştır
            processEvent(ev, profile, report);

            LOGI("[%d] ENTRY %s(%lu, %lu, %lu)",
                 stoppedPid,
                 syscallName(ev.syscallNr, m_isArm64),
                 ev.args[0], ev.args[1], ev.args[2]);

        } else {
            // Exit: syscall tamamlandı, dönüş değerini oku
            ev.isEntry = false;
            waitingEntry = false;

            if (m_isArm64) {
                AArch64Regs regs{};
                struct iovec iov = { &regs, sizeof(regs) };
                if (ptrace(PTRACE_GETREGSET, stoppedPid,
                           reinterpret_cast<void*>(NT_PRSTATUS), &iov) == 0)
                    ev.retval = static_cast<long>(regs.regs[0]);  // x0
            } else {
                Arm32Regs regs{};
                struct iovec iov = { &regs, sizeof(regs) };
                if (ptrace(PTRACE_GETREGSET, stoppedPid,
                           reinterpret_cast<void*>(NT_PRSTATUS), &iov) == 0)
                    ev.retval = static_cast<long>(regs.regs[0]);  // r0
            }
        }
    }

    m_running.store(false);
    detachProcess(tracee);

    // Raporu tamamla
    report.durationMs = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count());

    updateRiskScore(profile);
    report.profiles.push_back(profile);
    report.mostSuspiciousPid  = tracee;
    report.highestRiskScore   = profile.riskScore;
    report.combinedBehaviorFlags = profile.behaviorFlags;

    return report;
}

// ══════════════════════════════════════════════════════════════════
//  /proc/PID/syscall polling  (ptrace gerektirmeyen hafif yöntem)
//
//  Format: "syscall_nr arg0 arg1 arg2 arg3 arg4 arg5 sp pc"
//  Süreç uyurken "S (sleeping)" döner.
// ══════════════════════════════════════════════════════════════════
bool BehavioralAnalyzer::readProcSyscall(pid_t pid, SyscallEvent& ev) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/syscall", pid);

    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;

    char buf[256] = {};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return false;

    buf[n] = '\0';
    if (buf[0] == 'r') return false;  // "running"
    if (buf[0] == '-') return false;  // "-1 (not in syscall)"

    uint64_t nr, a0, a1, a2, a3, a4, a5, sp, pc;
    int parsed = sscanf(buf, "%llu %llx %llx %llx %llx %llx %llx %llx %llx",
                        &nr, &a0, &a1, &a2, &a3, &a4, &a5, &sp, &pc);
    if (parsed < 1) return false;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ev.timestamp_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    ev.pid       = pid;
    ev.syscallNr = static_cast<uint32_t>(nr);
    ev.args[0]   = a0; ev.args[1] = a1; ev.args[2] = a2;
    ev.args[3]   = a3; ev.args[4] = a4; ev.args[5] = a5;
    ev.retval    = -1;
    ev.isEntry   = true;
    fillComm(pid, ev);
    return true;
}

// ══════════════════════════════════════════════════════════════════
//  /proc polling ile çoklu süreç izleme
// ══════════════════════════════════════════════════════════════════
BehaviorReport BehavioralAnalyzer::procPollMonitor(
        const std::vector<pid_t>& pids)
{
    BehaviorReport report{};
    if (pids.empty()) return report;

    // Her süreç için profil hazırla
    std::unordered_map<pid_t, ProcessProfile> profiles;
    for (pid_t pid : pids) {
        ProcessProfile p{};
        p.pid = pid;
        profiles[pid] = p;
    }

    m_running.store(true);
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(m_config.durationMs);

    // Son görülen syscall'ı takip et (aynı olay tekrar sayılmasın)
    std::unordered_map<pid_t, uint32_t> lastSyscall;

    while (m_running.load() &&
           std::chrono::steady_clock::now() < deadline) {

        for (pid_t pid : pids) {
            SyscallEvent ev{};
            if (!readProcSyscall(pid, ev)) continue;

            // Tekrar eden aynı syscall'ı filtrele
            auto& last = lastSyscall[pid];
            if (last == ev.syscallNr) continue;
            last = ev.syscallNr;

            auto& profile = profiles[pid];
            ++profile.totalSyscalls;
            ++profile.syscallCounts[ev.syscallNr];
            ++report.totalEventsCapture;

            if (isDangerousSyscall(ev.syscallNr, m_isArm64))
                ++profile.dangerousSyscalls;

            if (profile.recentEvents.size() >= m_config.windowSize)
                profile.recentEvents.pop_front();
            profile.recentEvents.push_back(ev);

            processEvent(ev, profile, report);
        }

        usleep(m_config.pollIntervalUs);
    }

    m_running.store(false);

    // Profilleri raporla
    pid_t  maxPid   = 0;
    uint32_t maxScore = 0;
    for (auto& [pid, p] : profiles) {
        updateRiskScore(p);
        if (p.riskScore > maxScore) {
            maxScore = p.riskScore;
            maxPid   = pid;
        }
        report.combinedBehaviorFlags |= p.behaviorFlags;
        report.profiles.push_back(p);
    }
    report.mostSuspiciousPid = maxPid;
    report.highestRiskScore  = maxScore;
    return report;
}

// ══════════════════════════════════════════════════════════════════
//  Sistem geneli tarama: /proc altındaki tüm erişilebilir PID'ler
// ══════════════════════════════════════════════════════════════════
BehaviorReport BehavioralAnalyzer::scanAllProcesses() {
    std::vector<pid_t> pids;
    DIR* dir = opendir("/proc");
    if (!dir) return BehaviorReport{};

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        // Sadece sayısal dizin adları (PID'ler)
        bool isNum = true;
        for (char* p = entry->d_name; *p; ++p)
            if (*p < '0' || *p > '9') { isNum = false; break; }
        if (!isNum) continue;

        pid_t pid = static_cast<pid_t>(atoi(entry->d_name));
        if (pid <= 0 || pid == getpid()) continue;  // Kendimizi atla

        // Erişilebilir mi? (aynı UID veya root gerekir)
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/syscall", pid);
        if (access(path, R_OK) == 0) pids.push_back(pid);
    }
    closedir(dir);

    LOGI("Erişilebilir %zu süreç bulundu, polling başlıyor.", pids.size());
    return procPollMonitor(pids);
}

// ══════════════════════════════════════════════════════════════════
//  Komut satırı çalıştır + izle  (PTRACE_FORK yöntemi)
//  En kapsamlı yöntem: her syscall'ı yakalar, argümanları okur
// ══════════════════════════════════════════════════════════════════
BehaviorReport BehavioralAnalyzer::analyzeCommand(
        const std::string& cmd, const std::vector<std::string>& args)
{
    pid_t child = fork();
    if (child < 0) {
        LOGE("fork() başarısız");
        return BehaviorReport{};
    }

    if (child == 0) {
        // Çocuk: ebeveynin trace etmesine izin ver
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        raise(SIGSTOP);  // Ebeveyn hazır olana kadar dur

        // execve ile komutu çalıştır
        std::vector<const char*> argv;
        argv.push_back(cmd.c_str());
        for (const auto& a : args) argv.push_back(a.c_str());
        argv.push_back(nullptr);
        execv(cmd.c_str(), const_cast<char**>(argv.data()));
        _exit(127);  // execv başarısız olursa
    }

    // Ebeveyn: çocuğun SIGSTOP'unu bekle
    int status;
    waitpid(child, &status, 0);

    // ptrace seçeneklerini ayarla ve izlemeye başla
    long opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK
              | PTRACE_O_TRACECLONE    | PTRACE_O_TRACEEXEC;
    ptrace(PTRACE_SETOPTIONS, child, nullptr, reinterpret_cast<void*>(opts));

    // İlk PTRACE_SYSCALL ile devam ettir
    ptrace(PTRACE_SYSCALL, child, nullptr, nullptr);

    return ptraceMonitor(child);
}

// ══════════════════════════════════════════════════════════════════
//  analyzeProcess  — Giriş noktası
// ══════════════════════════════════════════════════════════════════
BehaviorReport BehavioralAnalyzer::analyzeProcess(pid_t pid) {
    switch (m_config.method) {
        case MonitorMethod::METHOD_PTRACE_ATTACH:
            return ptraceMonitor(pid);
        case MonitorMethod::METHOD_PROC_POLL:
        default:
            return procPollMonitor({pid});
    }
}

} // namespace AntiVirus
