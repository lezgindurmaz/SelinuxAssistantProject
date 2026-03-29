#include "syscall_table.h"
#include <cstring>

namespace AntiVirus {

// ══════════════════════════════════════════════════════════════════
//  ARM64 syscall tablosu  (nr, isim, risk_skoru)
//  Risk: 0 = zararsız, 10 = kritik
// ══════════════════════════════════════════════════════════════════
struct SyscallInfo {
    uint32_t    nr;
    const char* name;
    uint8_t     risk;   // 0–10
};

static const SyscallInfo ARM64_TABLE[] = {
    //  nr    isim                      risk
    {   0, "read",                        0 },
    {   1, "write",                       0 },
    {   2, "open",                        1 },
    {   3, "close",                       0 },
    {   8, "lseek",                       0 },
    {   9, "mmap",                        3 },  // PROT_EXEC kontrolü gerekir
    {  10, "mprotect",                    4 },  // W→X geçişi kritik
    {  11, "munmap",                      0 },
    {  12, "brk",                         0 },
    {  13, "rt_sigaction",                1 },
    {  14, "rt_sigprocmask",              1 },
    {  16, "ioctl",                       2 },
    {  19, "readv",                       0 },
    {  20, "writev",                      0 },
    {  41, "socket",                      2 },
    {  42, "connect",                     3 },
    {  43, "accept",                      2 },
    {  44, "sendto",                      3 },
    {  45, "recvfrom",                    2 },
    {  49, "bind",                        3 },
    {  50, "listen",                      2 },
    {  56, "clone",                       4 },
    {  57, "fork",                        3 },
    {  58, "vfork",                       4 },
    {  59, "execve",                      5 },  // Her zaman dikkatle izle
    {  60, "exit",                        0 },
    {  61, "wait4",                       0 },
    {  62, "kill",                        5 },
    {  72, "fcntl",                       1 },
    { 101, "ptrace",                      9 },  // ❗ Her kullanım şüpheli
    { 102, "getuid",                      0 },
    { 103, "syslog",                      2 },
    { 105, "setuid",                      8 },  // ❗ root almaya çalışma
    { 106, "setgid",                      8 },  // ❗
    { 117, "setresuid",                   8 },  // ❗
    { 118, "getresuid",                   1 },
    { 119, "setresgid",                   8 },  // ❗
    { 125, "capget",                      1 },
    { 126, "capset",                      8 },  // ❗ yetki manipülasyonu
    { 155, "pivot_root",                 10 },  // ❗ container escape
    { 157, "prctl",                       4 },
    { 175, "init_module",                10 },  // ❗ LKM yükleme
    { 176, "delete_module",               8 },  // ❗
    { 254, "inotify_add_watch",           2 },
    { 257, "openat",                      1 },
    { 272, "unshare",                     7 },  // ❗ namespace ayrımı
    { 298, "perf_event_open",             7 },  // ❗ sıklıkla exploit vektörü
    { 300, "fanotify_init",               3 },
    { 308, "setns",                       7 },  // ❗ namespace atlama
    { 310, "process_vm_readv",            8 },  // ❗ başka süreci oku
    { 311, "process_vm_writev",          10 },  // ❗ başka sürece yaz (inject)
    { 313, "finit_module",               10 },  // ❗ LKM yükleme (dosyadan)
    { 317, "seccomp",                     5 },
    { 319, "memfd_create",                7 },  // ❗ fileless execution için
    { 321, "bpf",                         9 },  // ❗ kernel BPF program
    { 323, "userfaultfd",                 7 },  // ❗ race condition exploit
    { 425, "io_uring_setup",              7 },  // ❗ exploit vektörü
    { 426, "io_uring_enter",              5 },
    { 427, "io_uring_register",           6 },
    { 0xFFFFFFFF, nullptr,                0 },  // sentinel
};

static const SyscallInfo ARM32_TABLE[] = {
    {   2, "fork",                        3 },
    {   3, "read",                        0 },
    {   4, "write",                       0 },
    {   5, "open",                        1 },
    {   6, "close",                       0 },
    {  11, "execve",                      5 },
    {  23, "setuid",                      8 },
    {  26, "ptrace",                      9 },
    {  37, "kill",                        5 },
    {  46, "setgid",                      8 },
    {  90, "mmap",                        3 },
    { 125, "mprotect",                    4 },
    { 172, "prctl",                       4 },
    { 185, "capset",                      8 },
    { 281, "socket",                      2 },
    { 283, "connect",                     3 },
    { 364, "perf_event_open",             7 },
    { 376, "process_vm_readv",            8 },
    { 377, "process_vm_writev",          10 },
    { 379, "finit_module",               10 },
    { 385, "memfd_create",                7 },
    { 386, "bpf",                         9 },
    { 0xFFFFFFFF, nullptr,                0 },
};

// ──────────────────────────────────────────────────────────────────
//  Arama yardımcısı
// ──────────────────────────────────────────────────────────────────
static const SyscallInfo* findSyscall(uint32_t nr, bool arm64) {
    const SyscallInfo* table = arm64 ? ARM64_TABLE : ARM32_TABLE;
    for (int i = 0; table[i].name != nullptr; ++i) {
        if (table[i].nr == nr) return &table[i];
    }
    return nullptr;
}

// ──────────────────────────────────────────────────────────────────
//  Public API
// ──────────────────────────────────────────────────────────────────
const char* syscallName(uint32_t nr, bool arm64) {
    auto* info = findSyscall(nr, arm64);
    return info ? info->name : "unknown";
}

bool isDangerousSyscall(uint32_t nr, bool arm64) {
    auto* info = findSyscall(nr, arm64);
    return info && info->risk >= 7;
}

uint8_t syscallRiskScore(uint32_t nr, bool arm64) {
    auto* info = findSyscall(nr, arm64);
    return info ? info->risk : 0;
}

} // namespace AntiVirus
