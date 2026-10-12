# SelinuxAssistant

An Android application prototype for device-integrity checks, root detection, and file scanning. It combines a Jetpack Compose interface with a native C++ engine through JNI.

## Features described by this project
- File and directory scanning through the native engine.
- Root and bootloader checks.
- Compose-based Android UI.

## Project structure
- `app/src/main/cpp`: native C++ engine and JNI bridge.
- `app/src/main/kotlin`: Android UI and service layer.
- `app/src/main/res`: Android resources.

## Build

Open the project in Android Studio and sync its Gradle project. This repository does **not** include the Gradle wrapper; for a terminal build, install compatible Android/NDK/CMake tooling and a system Gradle, then run:

```bash
gradle assembleDebug
```

## Releases and version status

Published builds and historical source bundles are listed on the [Releases page](https://github.com/lezgindurmaz/SelinuxAssistantProject/releases). The current Android build configuration says `versionName 1.0` / `versionCode 1`, while the latest release tag is `2.0` and its asset is named `GuardX-final-3.zip`. The release label, asset name, and current app identity do not establish an unambiguous version mapping; no version number has been changed here.

> This repository and the other GuardX/SelinuxAssistant repositories currently contain different code and release histories. Their versions should not be treated as interchangeable until a canonical source repository is selected.
