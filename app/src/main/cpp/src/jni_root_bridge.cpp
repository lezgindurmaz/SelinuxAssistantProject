#include <jni.h>
#include "root_detector.h"
#include <string>
#include <android/log.h>

using namespace AntiVirus;

extern "C" {

// ══════════════════════════════════════════════════════════
//  Kotlin arayüzü:
//    com.selinuxassistant.guardx.engine.RootDetector
//
//  Kotlin tanımları:
//    external fun fullScan(
//        deepKernel: Boolean,
//        tolerateDev: Boolean
//    ): String  // JSON döner
//
//    external fun quickScan(): String  // Sadece hızlı kontroller
// ══════════════════════════════════════════════════════════

JNIEXPORT jstring JNICALL
Java_com_selinuxassistant_guardx_engine_NativeEngine_rootFullScan(
        JNIEnv* env, jobject /* this */,
        jboolean deepKernel,
        jboolean tolerateDev)
{
    DetectorConfig config;
    config.deepKernelCheck         = deepKernel;
    config.tolerateDeveloperDevice = tolerateDev;
    config.checkKallsyms           = true;

    RootDetector detector(config);
    DetectionReport report = detector.fullScan();

    return env->NewStringUTF(report.toJSON().c_str());
}

JNIEXPORT jstring JNICALL
Java_com_selinuxassistant_guardx_engine_NativeEngine_rootQuickScan(
        JNIEnv* env, jobject /* this */)
{
    DetectorConfig config;
    config.deepKernelCheck = false;  // Sadece hızlı kontroller

    RootDetector detector(config);

    DetectionReport report;
    report.flags     = DETECT_NONE;
    report.isRooted  = false;
    report.isHooked  = false;
    report.bootloaderUnlocked = false;

    detector.checkBuildProperties(report);
    detector.checkRootBinaries   (report);
    detector.checkSELinux        (report);
    detector.checkBootloader     (report);
    detector.checkFrida          (report);
    detector.checkMagisk         (report);
    detector.checkPtrace         (report);

    return env->NewStringUTF(report.toJSON().c_str());
}

// Kotlin tarafında boolean sorgular için ek kolaylık metotları
JNIEXPORT jboolean JNICALL
Java_com_selinuxassistant_guardx_engine_NativeEngine_isRooted(JNIEnv*, jobject) {
    RootDetector detector;
    auto report = detector.fullScan();
    return static_cast<jboolean>(report.isRooted);
}

JNIEXPORT jboolean JNICALL
Java_com_selinuxassistant_guardx_engine_NativeEngine_isBootloaderUnlocked(JNIEnv*, jobject) {
    DetectorConfig config;
    config.deepKernelCheck = false;
    RootDetector detector(config);
    DetectionReport report;
    report.flags = DETECT_NONE;
    report.isRooted = false; report.isHooked = false;
    report.bootloaderUnlocked = false;
    detector.checkBootloader(report);
    return static_cast<jboolean>(
        (report.flags & DETECT_BOOTLOADER_UNLOCKED) != 0);
}

} // extern "C"
