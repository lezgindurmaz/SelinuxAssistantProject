#include <jni.h>
#include "behavioral_analyzer.h"
#include <string>
#include <thread>
#include <memory>
#include <android/log.h>

#define LOG_TAG "AV_BehJNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)

using namespace AntiVirus;

// ══════════════════════════════════════════════════════════════════
//  Kotlin arayüzü: com.selinuxassistant.guardx.engine.BehavioralAnalyzer
//
//  Kotlin:
//    external fun analyzeProcess(pid: Int, durationMs: Int,
//                                deepMode: Boolean): String
//    external fun scanAllProcesses(durationMs: Int): String
//    external fun stopMonitoring()
//    external fun setCallback(cb: BehaviorCallback)
// ══════════════════════════════════════════════════════════════════

// Global analyzer (singleton — tek anda bir tarama)
static std::unique_ptr<BehavioralAnalyzer> g_analyzer;
static std::thread                          g_thread;

extern "C" {

// ──────────────────────────────────────────────────────────────────
//  Tek süreci izle  → JSON rapor döndür
// ──────────────────────────────────────────────────────────────────
JNIEXPORT jstring JNICALL
Java_com_selinuxassistant_guardx_engine_NativeEngine_analyzeProcess(
        JNIEnv* env, jobject /*thiz*/,
        jint    pid,
        jint    durationMs,
        jboolean deepMode)
{
    BehaviorConfig cfg;
    cfg.durationMs  = static_cast<uint32_t>(durationMs);
    cfg.method      = deepMode
                    ? MonitorMethod::METHOD_PTRACE_ATTACH
                    : MonitorMethod::METHOD_PROC_POLL;

    g_analyzer = std::make_unique<BehavioralAnalyzer>(cfg);
    auto report = g_analyzer->analyzeProcess(static_cast<pid_t>(pid));
    return env->NewStringUTF(report.toJSON().c_str());
}

// ──────────────────────────────────────────────────────────────────
//  Sistem geneli tarama  → JSON rapor döndür
// ──────────────────────────────────────────────────────────────────
JNIEXPORT jstring JNICALL
Java_com_selinuxassistant_guardx_engine_NativeEngine_scanAllProcesses(
        JNIEnv* env, jobject /*thiz*/,
        jint durationMs)
{
    BehaviorConfig cfg;
    cfg.durationMs   = static_cast<uint32_t>(durationMs);
    cfg.method       = MonitorMethod::METHOD_PROC_POLL;
    cfg.pollIntervalUs = 5000;  // 5ms polling

    g_analyzer = std::make_unique<BehavioralAnalyzer>(cfg);

    // Kotlin'i bloklamayalım: arka planda çalıştır
    // (Kotlin coroutine ile zaten suspend olarak çağrılmalı)
    auto report = g_analyzer->scanAllProcesses();
    return env->NewStringUTF(report.toJSON().c_str());
}

// ──────────────────────────────────────────────────────────────────
//  İzlemeyi durdur (Kotlin thread'den)
// ──────────────────────────────────────────────────────────────────
JNIEXPORT void JNICALL
Java_com_selinuxassistant_guardx_engine_NativeEngine_stopMonitoring(
        JNIEnv* /*env*/, jobject /*thiz*/)
{
    if (g_analyzer) {
        g_analyzer->stop();
        LOGI("İzleme durduruldu.");
    }
}

// ──────────────────────────────────────────────────────────────────
//  Tek bir syscall'ın risk skorunu sorgula
// ──────────────────────────────────────────────────────────────────
JNIEXPORT jint JNICALL
Java_com_selinuxassistant_guardx_engine_NativeEngine_getSyscallRisk(
        JNIEnv* /*env*/, jobject /*thiz*/,
        jint syscallNr)
{
    return static_cast<jint>(
        syscallRiskScore(static_cast<uint32_t>(syscallNr), isArm64()));
}

// ──────────────────────────────────────────────────────────────────
//  Syscall numarasından isim al
// ──────────────────────────────────────────────────────────────────
JNIEXPORT jstring JNICALL
Java_com_selinuxassistant_guardx_engine_NativeEngine_getSyscallName(
        JNIEnv* env, jobject /*thiz*/,
        jint syscallNr)
{
    return env->NewStringUTF(
        syscallName(static_cast<uint32_t>(syscallNr), isArm64()));
}

// ──────────────────────────────────────────────────────────────────
//  Callback'li gerçek zamanlı izleme
//  Kotlin: interface BehaviorCallback { fun onAlert(json: String) }
// ──────────────────────────────────────────────────────────────────
JNIEXPORT void JNICALL
Java_com_selinuxassistant_guardx_engine_NativeEngine_startRealtimeMonitor(
        JNIEnv* env, jobject thiz,
        jint    pid,
        jint    durationMs,
        jobject callback)
{
    // Global referans al (thread içinde kullanacağız)
    JavaVM* jvm;
    env->GetJavaVM(&jvm);
    jobject cbRef    = env->NewGlobalRef(callback);
    jobject thizRef  = env->NewGlobalRef(thiz);

    jclass   cbClass   = env->GetObjectClass(callback);
    jmethodID onAlert  = env->GetMethodID(cbClass, "onAlert",
                                          "(Ljava/lang/String;)V");

    BehaviorConfig cfg;
    cfg.durationMs = static_cast<uint32_t>(durationMs);
    cfg.method     = MonitorMethod::METHOD_PROC_POLL;

    g_analyzer = std::make_unique<BehavioralAnalyzer>(cfg);

    // Alert callback
    g_analyzer->setCallback(
        [jvm, cbRef, onAlert]
        (const SyscallEvent& ev, const ProcessProfile& p, BehaviorFlag flag) {
            JNIEnv* tenv = nullptr;
            if (jvm->AttachCurrentThread(&tenv, nullptr) != 0) return;

            // Mini JSON alert oluştur
            std::string alertJson =
                "{\"pid\":"       + std::to_string(p.pid) +
                ",\"comm\":\""    + std::string(p.comm) + "\"" +
                ",\"flag\":"      + std::to_string(static_cast<uint64_t>(flag)) +
                ",\"syscall\":"   + std::to_string(ev.syscallNr) +
                ",\"riskScore\":" + std::to_string(p.riskScore) + "}";

            jstring jAlert = tenv->NewStringUTF(alertJson.c_str());
            tenv->CallVoidMethod(cbRef, onAlert, jAlert);
            tenv->DeleteLocalRef(jAlert);
        }
    );

    // Arka planda çalıştır
    if (g_thread.joinable()) g_thread.join();
    g_thread = std::thread([pid, durationMs]() {
        g_analyzer->analyzeProcess(static_cast<pid_t>(pid));
    });

    // Thread'i detach et (Kotlin tarafı stopMonitoring ile durdurur)
    g_thread.detach();
}

} // extern "C"
