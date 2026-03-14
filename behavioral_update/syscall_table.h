#pragma once
#ifndef SYSCALL_TABLE_H
#define SYSCALL_TABLE_H

#include <cstdint>
#include <string>

namespace AntiVirus {

// ══════════════════════════════════════════════════════════════════
//  ARM64 (aarch64) : syscall nr → x8
//  ARM32 (eabi)    : syscall nr → r7
// ══════════════════════════════════════════════════════════════════

namespace Arm64 {
    // ── Temel I/O ────────────────────────────────────────────────
    static constexpr uint32_t READ              =   0;
    static constexpr uint32_t WRITE             =   1;
    static constexpr uint32_t OPEN              =   2;
    static constexpr uint32_t CLOSE             =   3;
    static constexpr uint32_t STAT              =   4;
    static constexpr uint32_t FSTAT             =   5;
    static constexpr uint32_t LSTAT             =   6;
    static constexpr uint32_t LSEEK             =   8;

    // ── Bellek ───────────────────────────────────────────────────
    static constexpr uint32_t MMAP              =   9;
    static constexpr uint32_t MPROTECT          =  10;
    static constexpr uint32_t MUNMAP            =  11;
    static constexpr uint32_t BRK               =  12;
    static constexpr uint32_t MREMAP            =  25;
    static constexpr uint32_t MADVISE           =  28;
    static constexpr uint32_t MSYNC             =  26;

    // ── Sinyal ───────────────────────────────────────────────────
    static constexpr uint32_t RT_SIGACTION      =  13;
    static constexpr uint32_t RT_SIGPROCMASK    =  14;
    static constexpr uint32_t RT_SIGTIMEDWAIT   = 128;

    // ── Dosya / dizin ────────────────────────────────────────────
    static constexpr uint32_t IOCTL             =  16;
    static constexpr uint32_t READV             =  19;
    static constexpr uint32_t WRITEV            =  20;
    static constexpr uint32_t ACCESS            =  21;
    static constexpr uint32_t CHDIR             =  80;
    static constexpr uint32_t CHROOT            =  51;    // container escape
    static constexpr uint32_t GETCWD            =  79;
    static constexpr uint32_t OPENAT            = 257;
    static constexpr uint32_t FACCESSAT         = 269;   // KernelSU hooklar bunu
    static constexpr uint32_t INOTIFY_ADD_WATCH = 254;
    static constexpr uint32_t INOTIFY_INIT1     = 294;
    static constexpr uint32_t FANOTIFY_INIT     = 300;
    static constexpr uint32_t FANOTIFY_MARK     = 301;

    // ── Dosya sistemi ─────────────────────────────────────────────
    static constexpr uint32_t MOUNT             = 165;   // Magisk/KSU bind mount
    static constexpr uint32_t UMOUNT2           = 166;
    static constexpr uint32_t PIVOT_ROOT        = 155;   // container escape
    static constexpr uint32_t CHROOT_NR         =  51;   // alias

    // ── Ağ ───────────────────────────────────────────────────────
    static constexpr uint32_t SOCKET            =  41;
    static constexpr uint32_t CONNECT           =  42;
    static constexpr uint32_t ACCEPT            =  43;
    static constexpr uint32_t SENDTO            =  44;
    static constexpr uint32_t RECVFROM          =  45;
    static constexpr uint32_t BIND              =  49;
    static constexpr uint32_t LISTEN            =  50;
    static constexpr uint32_t SENDMSG           =  46;
    static constexpr uint32_t RECVMSG           =  47;
    static constexpr uint32_t SHUTDOWN          =  48;

    // ── Süreç ────────────────────────────────────────────────────
    static constexpr uint32_t CLONE             =  56;
    static constexpr uint32_t FORK              =  57;
    static constexpr uint32_t VFORK             =  58;
    static constexpr uint32_t EXECVE            =  59;
    static constexpr uint32_t EXECVEAT          = 322;   // dirfd'li execve
    static constexpr uint32_t EXIT              =  60;
    static constexpr uint32_t EXIT_GROUP        = 231;
    static constexpr uint32_t WAIT4             =  61;
    static constexpr uint32_t WAITID            = 247;
    static constexpr uint32_t KILL              =  62;
    static constexpr uint32_t TGKILL            = 234;
    static constexpr uint32_t FCNTL             =  72;

    // ── Yetki / kimlik ───────────────────────────────────────────
    static constexpr uint32_t PTRACE            = 101;   // ❗ kritik
    static constexpr uint32_t GETUID            = 102;
    static constexpr uint32_t SYSLOG            = 103;
    static constexpr uint32_t SETUID            = 105;   // ❗ root almaya çalışma
    static constexpr uint32_t SETGID            = 106;   // ❗
    static constexpr uint32_t GETEUID           = 107;
    static constexpr uint32_t GETGID            = 104;
    static constexpr uint32_t GETEGID           = 108;
    static constexpr uint32_t SETRESUID         = 117;   // ❗
    static constexpr uint32_t SETRESGID         = 119;   // ❗
    static constexpr uint32_t GETRESUID         = 118;
    static constexpr uint32_t CAPGET            = 125;
    static constexpr uint32_t CAPSET            = 126;   // ❗ capability manipülasyon
    static constexpr uint32_t PRCTL             = 157;   // ❗ KernelSU magic burada
    static constexpr uint32_t ARCH_PRCTL        = 158;

    // ── Namespace / cgroup ───────────────────────────────────────
    static constexpr uint32_t UNSHARE           = 272;   // ❗ namespace ayrımı
    static constexpr uint32_t SETNS             = 308;   // ❗ namespace atlama
    static constexpr uint32_t CLONE3            = 435;

    // ── Kernel exploit ───────────────────────────────────────────
    static constexpr uint32_t INIT_MODULE       = 175;   // ❗ LKM
    static constexpr uint32_t FINIT_MODULE      = 313;   // ❗ LKM
    static constexpr uint32_t DELETE_MODULE     = 176;
    static constexpr uint32_t BPF               = 321;   // ❗ eBPF prog
    static constexpr uint32_t PERF_EVENT_OPEN   = 298;   // ❗ exploit vektörü
    static constexpr uint32_t USERFAULTFD       = 323;   // ❗ race condition
    static constexpr uint32_t IO_URING_SETUP    = 425;   // ❗ exploit vektörü
    static constexpr uint32_t IO_URING_ENTER    = 426;
    static constexpr uint32_t IO_URING_REGISTER = 427;
    static constexpr uint32_t SECCOMP           = 317;   // seccomp filter kur
    static constexpr uint32_t MEMFD_CREATE      = 319;   // ❗ fileless exec
    static constexpr uint32_t PROCESS_VM_READV  = 310;   // ❗ başka süreci oku
    static constexpr uint32_t PROCESS_VM_WRITEV = 311;   // ❗ başka sürece yaz
    static constexpr uint32_t PKEY_MPROTECT     = 329;
    static constexpr uint32_t COPY_FILE_RANGE   = 326;
    static constexpr uint32_t GETRANDOM         = 278;

    // ── Diğer ────────────────────────────────────────────────────
    static constexpr uint32_t SETSID            = 112;
    static constexpr uint32_t REBOOT            = 169;   // ❗ cihaz yeniden başlatma
    static constexpr uint32_t KEXEC_LOAD        = 246;   // ❗ kernel değiştirme
    static constexpr uint32_t KEXEC_FILE_LOAD   = 320;   // ❗
    static constexpr uint32_t LANDLOCK_CREATE   = 444;
    static constexpr uint32_t LANDLOCK_ADD      = 445;
    static constexpr uint32_t LANDLOCK_RESTRICT = 446;
} // namespace Arm64

namespace Arm32 {
    static constexpr uint32_t READ              =   3;
    static constexpr uint32_t WRITE             =   4;
    static constexpr uint32_t OPEN              =   5;
    static constexpr uint32_t CLOSE             =   6;
    static constexpr uint32_t FORK              =   2;
    static constexpr uint32_t EXECVE            =  11;
    static constexpr uint32_t PTRACE            =  26;
    static constexpr uint32_t KILL              =  37;
    static constexpr uint32_t SETUID            =  23;
    static constexpr uint32_t SETGID            =  46;
    static constexpr uint32_t MMAP              =  90;
    static constexpr uint32_t MPROTECT          = 125;
    static constexpr uint32_t MOUNT             =  21;   // ARM32 mount
    static constexpr uint32_t UMOUNT2           =  52;
    static constexpr uint32_t CHROOT            =  61;
    static constexpr uint32_t SOCKET            = 281;
    static constexpr uint32_t CONNECT           = 283;
    static constexpr uint32_t SENDTO            = 290;
    static constexpr uint32_t PRCTL             = 172;
    static constexpr uint32_t CAPSET            = 185;
    static constexpr uint32_t PROCESS_VM_READV  = 376;
    static constexpr uint32_t PROCESS_VM_WRITEV = 377;
    static constexpr uint32_t MEMFD_CREATE      = 385;
    static constexpr uint32_t FINIT_MODULE      = 379;
    static constexpr uint32_t BPF               = 386;
    static constexpr uint32_t IO_URING_SETUP    = 425;
    static constexpr uint32_t PERF_EVENT_OPEN   = 364;
    static constexpr uint32_t UNSHARE           = 337;
    static constexpr uint32_t SETNS             = 375;
    static constexpr uint32_t EXECVEAT          = 387;
    static constexpr uint32_t SECCOMP           = 383;
    static constexpr uint32_t GETRANDOM         = 384;
} // namespace Arm32

// ──────────────────────────────────────────────────────────────────
inline bool isArm64() {
#if defined(__aarch64__)
    return true;
#else
    return false;
#endif
}

const char* syscallName(uint32_t nr, bool arm64 = true);
bool        isDangerousSyscall(uint32_t nr, bool arm64 = true);
uint8_t     syscallRiskScore(uint32_t nr, bool arm64 = true);

} // namespace AntiVirus
#endif // SYSCALL_TABLE_H
