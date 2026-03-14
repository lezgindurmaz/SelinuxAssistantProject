// ══════════════════════════════════════════════════════════════════
//  ptrace_monitor.cpp
//  ptrace izleme + /proc polling motoru
//
//  Değişiklikler:
//    - procPollMonitor: deepProcScan aktifse /proc/maps + /proc/status
//      + /proc/fd + /proc/net periyodik olarak taranır
//    - Her 10 polling turu bir kez deep scan yapılır (overhead önlemi)
//    - ptraceMonitor: execveat syscall desteği, arg okuma iyileştirmesi
//    - fillComm → Thread-safe hale getirildi
// ══════════════════════════════════════════════════════════════════
#include "behavioral_analyzer.h"
#include "syscall_table.h"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/prctl.h>
#include <elf.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <errno.h>
#include <chrono>
#include <thread>
#include <android/log.h>

#define LOG_TAG "AV_PTrace"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace AntiVirus {

// ── Register yapıları ────────────────────────────────────────────
struct AArch64Regs {
    uint64_t regs[31];  // x0–x30
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

struct Arm32Regs {
    uint32_t regs[18];  // r0–r15 + cpsr + ...
};

// ──────────────────────────────────────────────────────────────────
//  fillComm: /proc/pid/comm'dan thread-safe okuma
// ──────────────────────────────────────────────────────────────────
void BehavioralAnalyzer::fillComm(pid_t pid, SyscallEvent& ev) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        snprintf(ev.comm, sizeof(ev.comm), "pid%d", (int)pid);
        return;
    }
    ssize_t n = read(fd, ev.comm, sizeof(ev.comm) - 1);
    close(fd);
    if (n > 0) {
        ev.comm[n] = '\0';
        for (int i = 0; i < n; ++i)
            if (ev.comm[i] == '\n') { ev.comm[i] = '\0'; break; }
    } else {
        snprintf(ev.comm, sizeof(ev.comm), "pid%d", (int)pid);
    }
}

// ──────────────────────────────────────────────────────────────────
//  readString: tracee belleğinden string oku (ptrace PEEKDATA)
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
//  attachProcess
// ──────────────────────────────────────────────────────────────────
bool BehavioralAnalyzer::attachProcess(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) != 0) {
        LOGE("ptrace(ATTACH, %d): %s", pid, strerror(errno));
        return false;
    }
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        LOGE("waitpid(%d): %s", pid, strerror(errno));
        return false;
    }
    long opts = PTRACE_O_TRACESYSGOOD
              | PTRACE_O_TRACEFORK
              | PTRACE_O_TRACEVFORK
              | PTRACE_O_TRACECLONE
              | PTRACE_O_TRACEEXEC;
    ptrace(PTRACE_SETOPTIONS, pid, nullptr, reinterpret_cast<void*>(opts));
    LOGI("ptrace bağlandı: pid=%d", pid);
    return true;
}

void BehavioralAnalyzer::detachProcess(pid_t pid) {
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    LOGI("ptrace ayrıldı: pid=%d", pid);
}

// ──────────────────────────────────────────────────────────────────
//  readSyscallEntry: register'lardan syscall bilgisi al
// ──────────────────────────────────────────────────────────────────
bool BehavioralAnalyzer::readSyscallEntry(pid_t pid, SyscallEvent& ev) {
    ev.pid     = pid;
    ev.tid     = pid;
    ev.retval  = -1;
    ev.isEntry = true;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ev.timestamp_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    fillComm(pid, ev);

    if (m_isArm64) {
        AArch64Regs regs{};
        struct iovec iov = { &regs, sizeof(regs) };
        if (ptrace(PTRACE_GETREGSET, pid,
                   reinterpret_cast<void*>(NT_PRSTATUS), &iov) != 0) {
            LOGE("PTRACE_GETREGSET pid=%d: %s", pid, strerror(errno));
            return false;
        }
        // ARM64: x8 = syscall nr, x0-x5 = args, x0 = return
        ev.syscallNr = static_cast<uint32_t>(regs.regs[8]);
        for (int i = 0; i < 6; ++i) ev.args[i] = regs.regs[i];
    } else {
        Arm32Regs regs{};
        if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) != 0) return false;
        // ARM32 EABI: r7 = nr, r0-r5 = args
        ev.syscallNr = regs.regs[7];
        for (int i = 0; i < 6; ++i) ev.args[i] = regs.regs[i];
    }
    return true;
}

// ══════════════════════════════════════════════════════════════════
//  ptraceMonitor — Ana ptrace izleme döngüsü
// ══════════════════════════════════════════════════════════════════
BehaviorReport BehavioralAnalyzer::ptraceMonitor(pid_t tracee) {
    BehaviorReport report{};
    report.targetPid = tracee;

    if (!attachProcess(tracee)) {
        LOGE("Süreç izlenemedi: %d", tracee);
        return report;
    }

    ProcessProfile profile{};
    profile.pid = tracee;
    {
        SyscallEvent dummy{};
        fillComm(tracee, dummy);
        memcpy(profile.comm, dummy.comm, sizeof(profile.comm));
    }

    auto startTime = std::chrono::steady_clock::now();
    auto deadline  = startTime + std::chrono::milliseconds(m_config.durationMs);

    std::unordered_map<pid_t, bool> inSyscall;
    m_running.store(true);

    while (m_running.load() && std::chrono::steady_clock::now() < deadline) {
        if (ptrace(PTRACE_SYSCALL, tracee, nullptr, nullptr) != 0) {
            if (errno == ESRCH) break;
            LOGW("PTRACE_SYSCALL: %s", strerror(errno));
            break;
        }

        int   status;
        pid_t stoppedPid = waitpid(-1, &status, __WALL);
        if (stoppedPid < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (stoppedPid == tracee) break;
            continue;
        }

        // Fork/clone eventi → çocuğu izlemeye al
        if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK  << 8)) ||
            status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8)) ||
            status >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK << 8))) {
            unsigned long childPid;
            ptrace(PTRACE_GETEVENTMSG, stoppedPid, nullptr, &childPid);
            LOGI("Çocuk: %lu (ebeveyn: %d)", childPid, stoppedPid);
            inSyscall[static_cast<pid_t>(childPid)] = false;
            long opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK
                      | PTRACE_O_TRACECLONE    | PTRACE_O_TRACEEXEC;
            ptrace(PTRACE_SETOPTIONS, childPid, nullptr, reinterpret_cast<void*>(opts));
            ptrace(PTRACE_SYSCALL,    childPid, nullptr, nullptr);
            continue;
        }

        if (!WIFSTOPPED(status)) continue;
        int sig = WSTOPSIG(status);

        // Sadece syscall durağı
        if (sig != (SIGTRAP | 0x80)) {
            ptrace(PTRACE_SYSCALL, stoppedPid, nullptr,
                   reinterpret_cast<void*>(sig & ~0x80));
            continue;
        }

        bool& waitingEntry = inSyscall[stoppedPid];
        SyscallEvent ev{};
        if (!readSyscallEntry(stoppedPid, ev)) continue;

        if (!waitingEntry) {
            ev.isEntry   = true;
            waitingEntry = true;
            ++report.totalEventsCapture;
            ++profile.totalSyscalls;
            ++profile.syscallCounts[ev.syscallNr];

            if (isDangerousSyscall(ev.syscallNr, m_isArm64))
                ++profile.dangerousSyscalls;

            // execve/execveat → pathname'i oku (ptrace sayesinde mümkün)
            if ((ev.syscallNr == Arm64::EXECVE  || ev.syscallNr == Arm32::EXECVE ||
                 ev.syscallNr == Arm64::EXECVEAT || ev.syscallNr == Arm32::EXECVEAT)) {
                char pathBuf[256] = {};
                uint64_t pathAddr = (ev.syscallNr == Arm64::EXECVEAT)
                                    ? ev.args[1]   // execveat: fd, pathname, ...
                                    : ev.args[0];  // execve: pathname, ...
                readString(stoppedPid, pathAddr, pathBuf, sizeof(pathBuf));
                if (pathBuf[0]) {
                    LOGW("[%d] exec: %s", stoppedPid, pathBuf);
                    // exePath'i profile'a yaz
                    snprintf(profile.exePath, sizeof(profile.exePath), "%s", pathBuf);
                }
            }

            // prctl → KernelSU magic tespiti için arg'ları logla
            if (ev.syscallNr == Arm64::PRCTL || ev.syscallNr == Arm32::PRCTL) {
                LOGD("[%d] prctl(0x%lx, 0x%lx, ...)",
                     stoppedPid, (unsigned long)ev.args[0], (unsigned long)ev.args[1]);
            }

            if (profile.recentEvents.size() >= m_config.windowSize)
                profile.recentEvents.pop_front();
            profile.recentEvents.push_back(ev);

            processEvent(ev, profile, report);

        } else {
            ev.isEntry   = false;
            waitingEntry = false;

            if (m_isArm64) {
                AArch64Regs regs{};
                struct iovec iov = { &regs, sizeof(regs) };
                if (ptrace(PTRACE_GETREGSET, stoppedPid,
                           reinterpret_cast<void*>(NT_PRSTATUS), &iov) == 0) {
                    ev.retval = static_cast<long>(regs.regs[0]);  // x0
                    // KernelSU probe sonucu: prctl magic döndü mü?
                    if ((ev.syscallNr == Arm64::PRCTL) && ev.retval == 0 &&
                        (profile.behaviorFlags & (uint64_t)BEH_KERNELSU_PROBE)) {
                        addFinding(profile, BEH_KERNELSU_PROBE,
                            "prctl KSU magic BAŞARILI döndü (retval=0): KernelSU AKTİF!",
                            10);
                    }
                }
            } else {
                Arm32Regs regs{};
                if (ptrace(PTRACE_GETREGS, stoppedPid, nullptr, &regs) == 0)
                    ev.retval = static_cast<long>(regs.regs[0]);
            }
        }
    }

    m_running.store(false);
    detachProcess(tracee);

    report.durationMs = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count());

    // Deep scan (ptrace modunda da çalıştır)
    if (m_config.deepProcScan) {
        checkProcMaps  (tracee, profile);
        checkProcStatus(tracee, profile);
        checkProcFd    (tracee, profile);
        checkProcNet   (tracee, profile);
    }

    updateRiskScore(profile);
    report.profiles.push_back(profile);
    report.mostSuspiciousPid     = tracee;
    report.highestRiskScore      = profile.riskScore;
    report.combinedBehaviorFlags = profile.behaviorFlags;

    return report;
}

// ══════════════════════════════════════════════════════════════════
//  readProcSyscall — /proc/pid/syscall polling
// ══════════════════════════════════════════════════════════════════
bool BehavioralAnalyzer::readProcSyscall(pid_t pid, SyscallEvent& ev) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/syscall", pid);

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;

    char buf[256] = {};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return false;

    buf[n] = '\0';
    if (buf[0] == 'r' || buf[0] == '-') return false;  // running / not in syscall

    uint64_t nr, a0, a1, a2, a3, a4, a5;
    int parsed = sscanf(buf, "%lu %lx %lx %lx %lx %lx %lx",
                        &nr, &a0, &a1, &a2, &a3, &a4, &a5);
    if (parsed < 1) return false;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ev.timestamp_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    ev.pid       = pid;
    ev.tid       = pid;
    ev.syscallNr = static_cast<uint32_t>(nr);
    ev.args[0]   = a0; ev.args[1] = a1; ev.args[2] = a2;
    ev.args[3]   = a3; ev.args[4] = a4; ev.args[5] = a5;
    ev.retval    = -1;
    ev.isEntry   = true;
    fillComm(pid, ev);
    return true;
}

// ══════════════════════════════════════════════════════════════════
//  procPollMonitor — /proc polling ile çoklu süreç izleme
//
//  Yeni özellikler:
//    - Her 10 turda bir deep scan (/proc/maps, /proc/status, /proc/fd)
//    - Yinelenen aynı syscall filtresi (sadece değişimi kaydet)
//    - poll interval'i yapılandırılabilir
// ══════════════════════════════════════════════════════════════════
BehaviorReport BehavioralAnalyzer::procPollMonitor(
        const std::vector<pid_t>& pids)
{
    BehaviorReport report{};
    if (pids.empty()) return report;

    std::unordered_map<pid_t, ProcessProfile> profiles;
    for (pid_t pid : pids) {
        ProcessProfile p{};
        p.pid = pid;
        p.lastSeenUid  = (uid_t)-1;
        p.lastSeenEuid = (uid_t)-1;
        // Başlangıç snapshot
        p.snapshot = takeProcSnapshot(pid);
        profiles[pid] = p;
    }

    m_running.store(true);
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(m_config.durationMs);

    std::unordered_map<pid_t, uint32_t> lastSyscall;
    int pollTurn = 0;
    // Deep scan her DEEP_SCAN_INTERVAL turda bir
    static const int DEEP_SCAN_INTERVAL = 10;

    while (m_running.load() && std::chrono::steady_clock::now() < deadline) {

        for (pid_t pid : pids) {
            // Süreç hâlâ var mı?
            char checkPath[64];
            snprintf(checkPath, sizeof(checkPath), "/proc/%d", pid);
            if (access(checkPath, F_OK) != 0) continue;

            SyscallEvent ev{};
            if (!readProcSyscall(pid, ev)) continue;

            // Aynı syscall filtreleme (değişim bazlı kayıt)
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

        // Deep scan: /proc/maps + /proc/status + /proc/fd + /proc/net
        if (m_config.deepProcScan && (++pollTurn % DEEP_SCAN_INTERVAL == 0)) {
            for (pid_t pid : pids) {
                auto it = profiles.find(pid);
                if (it == profiles.end()) continue;
                auto& profile = it->second;

                checkProcStatus(pid, profile);  // UID değişimi (hızlı)
                checkProcFd    (pid, profile);  // Tehlikeli /dev fd'ler

                // Daha yavaş: maps ve net yalnızca risk varsa
                if (pollTurn % (DEEP_SCAN_INTERVAL * 5) == 0) {
                    checkProcMaps(pid, profile);  // Inject .so
                    checkProcNet (pid, profile);  // TCP bağlantıları
                }
            }
        }

        usleep(m_config.pollIntervalUs);
    }

    m_running.store(false);

    pid_t    maxPid   = 0;
    uint32_t maxScore = 0;
    for (auto& [pid, p] : profiles) {
        // Final deep scan
        if (m_config.deepProcScan) {
            checkProcMaps  (pid, p);
            checkProcStatus(pid, p);
            checkProcFd    (pid, p);
        }
        updateRiskScore(p);
        if (p.riskScore > maxScore) { maxScore = p.riskScore; maxPid = pid; }
        report.combinedBehaviorFlags |= p.behaviorFlags;
        report.profiles.push_back(p);
    }
    report.mostSuspiciousPid = maxPid;
    report.highestRiskScore  = maxScore;
    return report;
}

// ══════════════════════════════════════════════════════════════════
//  scanAllProcesses — /proc altındaki tüm erişilebilir PID'ler
// ══════════════════════════════════════════════════════════════════
BehaviorReport BehavioralAnalyzer::scanAllProcesses() {
    std::vector<pid_t> pids;
    DIR* dir = opendir("/proc");
    if (!dir) return BehaviorReport{};

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        bool isNum = true;
        for (char* p = entry->d_name; *p; ++p)
            if (*p < '0' || *p > '9') { isNum = false; break; }
        if (!isNum) continue;

        pid_t pid = static_cast<pid_t>(atoi(entry->d_name));
        if (pid <= 0 || pid == getpid()) continue;

        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/syscall", pid);
        if (access(path, R_OK) == 0) pids.push_back(pid);
    }
    closedir(dir);

    LOGI("Erişilebilir %zu süreç, polling başlıyor", pids.size());
    return procPollMonitor(pids);
}

// ══════════════════════════════════════════════════════════════════
//  analyzeCommand — Fork + izle
// ══════════════════════════════════════════════════════════════════
BehaviorReport BehavioralAnalyzer::analyzeCommand(
        const std::string& cmd, const std::vector<std::string>& args)
{
    pid_t child = fork();
    if (child < 0) { LOGE("fork() başarısız"); return BehaviorReport{}; }

    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        raise(SIGSTOP);

        std::vector<const char*> argv;
        argv.push_back(cmd.c_str());
        for (const auto& a : args) argv.push_back(a.c_str());
        argv.push_back(nullptr);
        execv(cmd.c_str(), const_cast<char**>(argv.data()));
        _exit(127);
    }

    int status;
    waitpid(child, &status, 0);
    long opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK
              | PTRACE_O_TRACECLONE    | PTRACE_O_TRACEEXEC;
    ptrace(PTRACE_SETOPTIONS, child, nullptr, reinterpret_cast<void*>(opts));
    ptrace(PTRACE_SYSCALL,    child, nullptr, nullptr);

    return ptraceMonitor(child);
}

// ══════════════════════════════════════════════════════════════════
//  analyzeProcess — Giriş noktası
// ══════════════════════════════════════════════════════════════════
BehaviorReport BehavioralAnalyzer::analyzeProcess(pid_t pid) {
    switch (m_config.method) {
        case MonitorMethod::PTRACE_ATTACH:
            return ptraceMonitor(pid);
        case MonitorMethod::PROC_POLL:
        default:
            return procPollMonitor({pid});
    }
}

// ──────────────────────────────────────────────────────────────────
//  addFinding: behavioral_rules.cpp'de de kullanılıyor,
//  burada static olmadığından sadece friend erişimi gerekiyor.
//  behavioral_rules.cpp'deki static addFinding yeterlidir.
// ──────────────────────────────────────────────────────────────────
static void addFinding(ProcessProfile& p, BehaviorFlag flag,
                       const std::string& msg, uint8_t severity) {
    p.behaviorFlags |= static_cast<uint64_t>(flag);
    std::string entry = "[sev=" + std::to_string(severity) + "] " + msg;
    for (const auto& f : p.findings)
        if (f == entry) return;
    p.findings.push_back(entry);
    __android_log_print(ANDROID_LOG_WARN, LOG_TAG,
                        "BEH [pid=%d sev=%d]: %s", p.pid, severity, msg.c_str());
}

} // namespace AntiVirus
