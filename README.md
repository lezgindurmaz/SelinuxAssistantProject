# GuardX Antivirus

GuardX is a powerful, native-core Android antivirus and system integrity protection tool. It combines high-performance C++ scanning with modern Android security APIs.

## Key Features

- **Multi-Engine Scanning**: Hybrid scanning using local signature database and cloud-based lookup.
- **System Integrity Verification**:
    - **TEE Hardware Attestation**: Verified boot and bootloader status checks via Android KeyStore.
    - **Google Play Integrity**: Deep device and app integrity verdicts.
- **Behavioral Monitor**: Real-time syscall analysis using ptrace and /proc polling to detect code injection, privilege escalation, and suspicious activity.
- **Root & Hook Detection**: Multi-layered checks for su binaries, KernelSU, APatch, and common hooking frameworks.
- **Self-Protection**: Integrated Seccomp-BPF filters to prevent tampering with the app process.

## Technical Details

- **Language**: Kotlin (UI & Service), C++17 (Core Engine)
- **UI Framework**: Jetpack Compose with Material 3
- **NDK**: High-performance native analysis and kernel-level checks.
- **Package Name**: `com.selinuxassistant.guardx`

## Building

To build the project, use the Gradle wrapper:
```bash
./gradlew assembleDebug
```

## Disclaimer
This project is for educational and security research purposes.
