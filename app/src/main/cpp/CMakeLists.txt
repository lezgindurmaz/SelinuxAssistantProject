cmake_minimum_required(VERSION 3.22.1)
project(selinux_assistant LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(selinux_assistant SHARED
    jni_bridge.cpp
    jni_root_bridge.cpp
    hash_engine.cpp
    scanner.cpp
    local_db.cpp
    cloud_lookup.cpp
    root_detector_part1.cpp
    root_detector_part2.cpp
    root_detector_part3.cpp
)

find_library(log-lib log)
find_library(android-lib android)

target_link_libraries(selinux_assistant
    ${log-lib}
    ${android-lib}
)
