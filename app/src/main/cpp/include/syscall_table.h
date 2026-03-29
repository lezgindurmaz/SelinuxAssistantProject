#pragma once
#ifndef SYSCALL_TABLE_H
#define SYSCALL_TABLE_H

#include <cstdint>
#include <string>

namespace AntiVirus {

// ══════════════════════════════════════════════════════════════════
//  Android'de iki ABI mevcuttur:
//    ARM64 (aarch64) : AAPCS64 — syscall numarası x8 register'ında
//    ARM32 (arm)     : EABI    — syscall numarası r7 register'ında
//
//  Numara → isim çözümlemesi her iki ABI için ayrı tutulur.
// ══════════════════════════════════════════════════════════════════

// ──────────────────────────────────────────────────────────────────
//  ARM64 Syscall Numaraları (Linux 5.x, Android GKI ile uyumlu)
// ──────────────────────────────────────────────────────────────────
namespace Arm64 {
    static constexpr uint32_t READ              =   0;
    static constexpr uint32_t WRITE             =   1;
    static constexpr uint32_t OPEN              =   2;  // openat tercih edilir
    static constexpr uint32_t CLOSE             =   3;
    static constexpr uint32_t MMAP              =   9;
    static constexpr uint32_t MPROTECT          =  10;
    static constexpr uint32_t MUNMAP            =  11;
    static constexpr uint32_t BRK               =  12;
    static constexpr uint32_t RT_SIGACTION      =  13;
    static constexpr uint32_t IOCTL             =  16;
    static constexpr uint32_t READV             =  19;
    static constexpr uint32_t WRITEV            =  20;
    static constexpr uint32_t SOCKET            =  41;
    static constexpr uint32_t CONNECT           =  42;
    static constexpr uint32_t ACCEPT            =  43;
    static constexpr uint32_t SENDTO            =  44;
    static constexpr uint32_t RECVFROM          =  45;
    static constexpr uint32_t BIND              =  49;
    static constexpr uint32_t LISTEN            =  50;
    static constexpr uint32_t CLONE             =  56;  // fork() içerir
    static constexpr uint32_t FORK              =  57;
    static constexpr uint32_t VFORK             =  58;
    static constexpr uint32_t EXECVE            =  59;
    static constexpr uint32_t EXIT              =  60;
    static constexpr uint32_t WAIT4             =  61;
    static constexpr uint32_t KILL              =  62;
    static constexpr uint32_t FCNTL             =  72;
    static constexpr uint32_t PTRACE            = 101;
    static constexpr uint32_t GETUID            = 102;
    static constexpr uint32_t SYSLOG            = 103;
    static constexpr uint32_t SETUID            = 105;
    static constexpr uint32_t SETGID            = 106;
    static constexpr uint32_t CAPGET            = 125;
    static constexpr uint32_t CAPSET            = 126;
    static constexpr uint32_t RT_SIGTIMEDWAIT   = 128;
    static constexpr uint32_t PRCTL             = 157;
    static constexpr uint32_t ARCH_PRCTL        = 158;
    static constexpr uint32_t SETRESUID         = 117;
    static constexpr uint32_t SETRESGID         = 119;
    static constexpr uint32_t GETRESUID         = 118;
    static constexpr uint32_t OPENAT            = 257;
    static constexpr uint32_t PERF_EVENT_OPEN   = 298;
    static constexpr uint32_t PROCESS_VM_READV  = 310;
    static constexpr uint32_t PROCESS_VM_WRITEV = 311;  // ❗ cross-process write
    static constexpr uint32_t SECCOMP           = 317;
    static constexpr uint32_t MEMFD_CREATE      = 319;  // ❗ fileless exec
    static constexpr uint32_t USERFAULTFD       = 323;
    static constexpr uint32_t COPY_FILE_RANGE   = 326;
    static constexpr uint32_t PKEY_MPROTECT     = 329;
    static constexpr uint32_t IO_URING_SETUP    = 425;  // ❗ exploit vektörü
    static constexpr uint32_t IO_URING_ENTER    = 426;
    static constexpr uint32_t BPF               = 321;  // ❗ kernel prog yükleme
    static constexpr uint32_t FINIT_MODULE      = 313;  // ❗ LKM yükleme
    static constexpr uint32_t INIT_MODULE       = 175;  // ❗ LKM yükleme
    static constexpr uint32_t DELETE_MODULE     = 176;
    static constexpr uint32_t INOTIFY_ADD_WATCH = 254;
    static constexpr uint32_t FANOTIFY_INIT     = 300;
    static constexpr uint32_t FANOTIFY_MARK     = 301;
    static constexpr uint32_t PIVOT_ROOT        = 155;
    static constexpr uint32_t CHROOT            =  61;  // arm32'de farklı
    static constexpr uint32_t UNSHARE           = 272;  // namespace ayrımı
    static constexpr uint32_t SETNS             = 308;
} // namespace Arm64

// ──────────────────────────────────────────────────────────────────
//  ARM32 Syscall Numaraları (EABI, Android 32-bit)
// ──────────────────────────────────────────────────────────────────
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
    static constexpr uint32_t SOCKET            = 281;
    static constexpr uint32_t CONNECT           = 283;
    static constexpr uint32_t PRCTL             = 172;
    static constexpr uint32_t CAPSET            = 185;
    static constexpr uint32_t PROCESS_VM_READV  = 376;
    static constexpr uint32_t PROCESS_VM_WRITEV = 377;
    static constexpr uint32_t MEMFD_CREATE      = 385;
    static constexpr uint32_t FINIT_MODULE      = 379;
    static constexpr uint32_t BPF               = 386;
    static constexpr uint32_t IO_URING_SETUP    = 425;
    static constexpr uint32_t PERF_EVENT_OPEN   = 364;
} // namespace Arm32

// ──────────────────────────────────────────────────────────────────
//  Runtime ABI tespiti + unified lookup
// ──────────────────────────────────────────────────────────────────
inline bool isArm64() {
#if defined(__aarch64__)
    return true;
#else
    return false;
#endif
}

// Syscall numarasından okunabilir isim döndür
const char* syscallName(uint32_t nr, bool arm64 = true);

// Tehlikeli olarak işaretlenmiş syscall mı?
bool isDangerousSyscall(uint32_t nr, bool arm64 = true);

// Risk skoru (0 = zararsız, 10 = kritik)
uint8_t syscallRiskScore(uint32_t nr, bool arm64 = true);

} // namespace AntiVirus

#endif // SYSCALL_TABLE_H
