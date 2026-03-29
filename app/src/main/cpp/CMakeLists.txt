cmake_minimum_required(VERSION 3.22.1)
project(guardx_engine VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Tüm kaynak dosyalar — harici bağımlılık yok ──────────────────
set(ENGINE_SOURCES
    src/hash_engine.cpp
    src/scanner.cpp
    src/local_db.cpp
    src/cloud_lookup.cpp
    src/root_detector_part1.cpp
    src/root_detector_part2.cpp
    src/root_detector_part3.cpp
    src/syscall_table.cpp
    src/ptrace_monitor.cpp
    src/behavioral_rules.cpp
    src/seccomp_monitor.cpp
    src/zip_reader.cpp
    src/axml_parser.cpp
    src/permission_db.cpp
    src/dex_analyzer.cpp
    src/apk_analyzer.cpp
    src/jni_bridge.cpp
    src/jni_root_bridge.cpp
    src/jni_behavior_bridge.cpp
    src/db_manager.cpp
)

add_library(guardx_engine SHARED ${ENGINE_SOURCES})

target_include_directories(guardx_engine PRIVATE include)

# ── Android NDK sistem kütüphaneleri (hepsi built-in) ────────────
find_library(log-lib     log)
find_library(android-lib android)
find_library(z-lib       z)

target_link_libraries(guardx_engine
    ${log-lib}      # __android_log_print
    ${android-lib}  # AAsset, ANativeWindow
    ${z-lib}        # zlib (APK deflate decompress)
)

# ── Güvenlik ve optimizasyon bayrakları ──────────────────────────
target_compile_options(guardx_engine PRIVATE
    -O2
    -fvisibility=hidden
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -Wformat
    -Wformat-security
    -DANDROID_STL=c++_shared
)

target_link_options(guardx_engine PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
)
