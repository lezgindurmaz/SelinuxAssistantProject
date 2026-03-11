# SelinuxAssistant

A mobile application to defend your device with advanced scanning and root detection capabilities.

## Features
- **Fast Virus Scanning:** Efficiently scans files and directories for malware.
- **Deep Root Detection:** Uses kernel-level checks to identify if a device is rooted or compromised.
- **Modern UI:** Built with Jetpack Compose for a sleek and responsive user experience.
- **Native Core:** High-performance C++ engine for deep analysis.

## Project Structure
- `app/src/main/cpp`: C++ core engine and JNI bridge.
- `app/src/main/kotlin`: Android application code (UI and Service layer).
- `app/src/main/res`: Android resources.

## Build
To build the project, use Android Studio or the Gradle wrapper:
```bash
gradle assembleDebug
```

## Release
The latest APK can be found in the [Releases](https://github.com/lezgindurmaz/SelinuxAssistantProject/releases) section.
