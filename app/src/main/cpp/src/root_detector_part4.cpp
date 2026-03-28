#include "root_detector.h"

#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cmath>
#include <vector>
#include <algorithm>
#include <unordered_set>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <time.h>
#include <android/log.h>
#include <dirent.h>

#define LOG_TAG "AV_ZygHook"
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
// ══════════════════════════════════════════════════════════════════════
#if defined(__aarch64__)

static inline long direct_getpid() {
    register long x8  asm("x8")  = 172;
    register long x0  asm("x0");
    asm volatile("svc #0" : "=r"(x0) : "r"(x8) : "memory", "cc");
    return x0;
}

static inline long direct_getuid() {
    register long x8  asm("x8")  = 174;
    register long x0  asm("x0");
    asm volatile("svc #0" : "=r"(x0) : "r"(x8) : "memory", "cc");
    return x0;
}

#elif defined(__arm__)

static inline long direct_getpid() {
    long res;
    asm volatile("mov r7, #20\nswi #0\nmov %0, r0\n" : "=r"(res) :: "r0", "r7", "memory", "cc");
    return res;
}
static inline long direct_getuid() {
    long res;
    asm volatile("mov r7, #24\nswi #0\nmov %0, r0\n" : "=r"(res) :: "r0", "r7", "memory", "cc");
    return res;
}

#else
static inline long direct_getpid() { return getpid(); }
static inline long direct_getuid() { return getuid(); }
#endif

static uint64_t median_ns(std::vector<uint64_t> v) {
    if (v.empty()) return 0;
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

#if defined(__aarch64__) || defined(__arm__)
static bool is_hook_insn(uint32_t insn) {
    if ((insn & 0xFC000000u) == 0x14000000u) return true;
    if ((insn & 0xFC000000u) == 0x94000000u) return true;
    if ((insn & 0xFFFFFC1Fu) == 0xD61F0000u) return true;
    if ((insn & 0xFFFFFC1Fu) == 0xD63F0000u) return true;
    if ((insn & 0xFFE00000u) == 0xD2800000u && ((insn >> 5) & 0x1Fu) == 16u) return true;
    if ((insn & 0xFF000000u) == 0x58000000u && ((insn & 0x1Fu) == 17u)) return true;
    return false;
}
static bool is_normal_prolog(uint32_t insn) {
    if ((insn & 0xFF8003E0u) == 0xA9800000u && (insn & 0x1Fu) == 29u) return true;
    if ((insn & 0xFFC003FFu) == 0xD10003FFu) return true;
    if (insn == 0xD503201Fu) return true;
    if (insn == 0xD503233Fu) return true;
    if (insn == 0xD65F03C0u) return true;
    return false;
}
#else
static bool is_hook_insn(uint32_t)  { return false; }
static bool is_normal_prolog(uint32_t) { return false; }
#endif

void RootDetector::checkMemoryMapsAdvanced(DetectionReport& report) {
    std::ifstream mapsFile("/proc/self/maps");
    if (!mapsFile.is_open()) return;
    static const char* LEGIT_ANON_LABELS[] = { "dalvik", "art ", "jit-code", "jit_code", "/dev/ashmem", "[stack", "[heap]", "[vdso]", "[vsyscall]", "[vectors]", "anonymous:", "chromium", "bss", nullptr };
    struct ShamikoPair { const char* a; const char* b; };
    static const ShamikoPair SHAMIKO_PATTERNS[] = { { "zygisk", "companion" }, { "shamiko", "companion" }, { "zygisk", "shamiko" }, { "magisk", "companion" }, { nullptr, nullptr } };
    int totalLines = 0, anonRwxCount = 0, deletedSoCount = 0, largeGapCount = 0;
    uint64_t prevEnd = 0;
    std::string line, fullMaps;
    while (std::getline(mapsFile, line)) {
        totalLines++; fullMaps += line + "\n";
        uint64_t addrStart = 0, addrEnd = 0;
        char perm[8] = {}, path[256] = {};
        unsigned long start = 0, end = 0;
        int parsed = sscanf(line.c_str(), "%lx-%lx %7s %*x %*x:%*x %*u %255[^\n]", &start, &end, perm, path);
        addrStart = start; addrEnd = end;
        if (prevEnd != 0 && addrStart > prevEnd) {
            uint64_t gap = addrStart - prevEnd;
            if (gap > (64ULL * 1024 * 1024) && gap < (8ULL * 1024 * 1024 * 1024)) largeGapCount++;
        }
        prevEnd = addrEnd;
        if (parsed < 3) continue;
        bool isExec = (perm[2] == 'x'), isWrite = (perm[1] == 'w'), isAnon = (parsed < 4 || path[0] == '\0');
        if (isExec && isWrite && isAnon) {
            bool isLegit = false;
            for (int i = 0; LEGIT_ANON_LABELS[i]; ++i) if (strstr(path, LEGIT_ANON_LABELS[i])) { isLegit = true; break; }
            if (!isLegit && (addrEnd - addrStart) >= 4096) {
                anonRwxCount++;
                addEvidence(report, DETECT_ANON_RWX_MAPPING, "Anonim RWX bölge: 0x" + std::to_string(addrStart), 7);
            }
        }
        if (isExec && strstr(path, ".so (deleted)")) {
            if (deletedSoCount++ == 0) addEvidence(report, DETECT_DELETED_LIB_MAPPED, "Silinmiş ama eşlenmiş .so", 6);
        }
    }
    for (int i = 0; SHAMIKO_PATTERNS[i].a; ++i) if (containsString(fullMaps, SHAMIKO_PATTERNS[i].a) && containsString(fullMaps, SHAMIKO_PATTERNS[i].b)) {
        addEvidence(report, DETECT_SHAMIKO_COMPANION, "Shamiko/Zygisk companion", 10); break;
    }
    if (totalLines > 0 && totalLines < 20) addEvidence(report, DETECT_MAPS_GAP_ANOMALY, "Anormal düşük maps satırı", 7);
    if (largeGapCount >= 3) addEvidence(report, DETECT_MAPS_GAP_ANOMALY, "Büyük adres boşlukları", 6);
}

void RootDetector::checkSyscallTiming(DetectionReport& report) {
#if defined(__aarch64__) || defined(__arm__)
    const char* probeFns[] = { "getpid", "getuid", "open", nullptr };
    for (int i = 0; probeFns[i]; ++i) {
        void* fnPtr = dlsym(RTLD_DEFAULT, probeFns[i]);
        if (!fnPtr) continue;
        const uint32_t* code = reinterpret_cast<const uint32_t*>(fnPtr);
        if (!is_normal_prolog(code[0]) && is_hook_insn(code[0]) && is_hook_insn(code[1]))
            addEvidence(report, DETECT_INLINE_HOOK, std::string("Inline hook: ") + probeFns[i], 8);
    }
#endif
    std::vector<uint64_t> d_times, l_times;
    for (int i = 0; i < 50; ++i) { direct_getpid(); getpid(); }
    for (uint32_t i = 0; i < m_config.timingIterations; ++i) {
        uint64_t t0 = ns_now(); direct_getpid(); d_times.push_back(ns_now() - t0);
        uint64_t t1 = ns_now(); getpid(); l_times.push_back(ns_now() - t1);
    }
    float ratio = (float)median_ns(l_times) / (float)median_ns(d_times);
    if (ratio >= m_config.timingHookRatio) addEvidence(report, DETECT_SYSCALL_HOOK_TIMING, "Syscall timing anomalisi", 5);
}

void RootDetector::checkKernelSu(DetectionReport& report) {
    if (prctl(0xdeadc0de, 0, 0, 0, 0) >= 0) addEvidence(report, DETECT_SU_BINARY, "KernelSU prctl probe", 10);
    if (access("/data/adb/ksu", F_OK) == 0) addEvidence(report, DETECT_SU_BINARY, "KernelSU dizini", 9);
}

void RootDetector::checkAPatch(DetectionReport& report) {
    if (prctl(0xdeadbeef, 0xdeadbeef, 0, 0, 0) >= 0) addEvidence(report, DETECT_SU_BINARY, "APatch prctl probe", 10);
    if (access("/dev/apd", F_OK) == 0) addEvidence(report, DETECT_SU_BINARY, "APatch cihazı", 10);
}

// ── Zygote ve Derin Hook Analizi (v1.0.8) ──────────────────────────

std::string RootDetector::readProcFile(pid_t pid, const char* file, size_t maxBytes) {
    char path[128]; snprintf(path, sizeof(path), "/proc/%d/%s", (int)pid, file);
    return readFile(path, maxBytes);
}

pid_t RootDetector::findZygotePid(bool prefer64) {
    DIR* dir = opendir("/proc"); if (!dir) return -1;
    pid_t f32 = -1, f64 = -1; struct dirent* entry;
    while ((entry = readdir(dir))) {
        pid_t pid = (pid_t)atoi(entry->d_name); if (pid <= 1) continue;
        char p[64]; snprintf(p, 64, "/proc/%d/cmdline", (int)pid);
        int fd = open(p, O_RDONLY); if (fd < 0) continue;
        char cmd[64] = {}; read(fd, cmd, 63); close(fd);
        if (strcmp(cmd, "zygote64") == 0) f64 = pid;
        else if (strcmp(cmd, "zygote") == 0) f32 = pid;
    }
    closedir(dir); return (prefer64 && f64 > 0) ? f64 : (f64 > 0 ? f64 : f32);
}

void RootDetector::checkZygoteIntegrity(DetectionReport& report) {
    pid_t pid = findZygotePid(); if (pid <= 0) return;
    std::string status = readProcFile(pid, "status", 4096);
    if (status.find("TracerPid:\t0") == std::string::npos && status.find("TracerPid:") != std::string::npos)
        addEvidence(report, DETECT_ZYGOTE_TRACED, "Zygote izleniyor!", 10);
    std::string maps = readProcFile(pid, "maps", 65536);
    if (!maps.empty()) {
        static const char* bad[] = { "frida", "xposed", "zygisk", "lspd", "magisk", nullptr };
        for (int i = 0; bad[i]; ++i) if (containsString(maps, bad[i])) {
            addEvidence(report, DETECT_ZYGOTE_MAPS_DIRTY, std::string("Zygote maps kirli: ") + bad[i], 10); break;
        }
    }
}

void RootDetector::checkDeepHookAnalysis(DetectionReport& report) {
    struct { const char* n; void* p; } fns[] = { {"getpid", (void*)getpid}, {"getuid", (void*)getuid}, {nullptr, nullptr} };
    for (int i = 0; fns[i].n; ++i) {
        Dl_info info; if (!dladdr(fns[i].p, &info)) continue;
        struct PhdrData { const char* lib; uint64_t b, e; bool f; } pd { info.dli_fname, 0, 0, false };
        dl_iterate_phdr([](dl_phdr_info* info2, size_t, void* data) -> int {
            auto* p = (PhdrData*)data; if (!info2->dlpi_name || !strstr(p->lib, info2->dlpi_name)) return 0;
            p->b = info2->dlpi_addr; p->e = p->b;
            for (int j = 0; j < info2->dlpi_phnum; ++j) if (info2->dlpi_phdr[j].p_type == PT_LOAD) {
                uint64_t se = p->b + info2->dlpi_phdr[j].p_vaddr + info2->dlpi_phdr[j].p_memsz;
                if (se > p->e) p->e = se;
            }
            p->f = true; return 1;
        }, &pd);
        if (pd.f && ((uint64_t)fns[i].p < pd.b || (uint64_t)fns[i].p >= pd.e))
            addEvidence(report, DETECT_GOT_OVERWRITE, std::string("GOT hook: ") + fns[i].n, 9);
    }
}

} // namespace AntiVirus
