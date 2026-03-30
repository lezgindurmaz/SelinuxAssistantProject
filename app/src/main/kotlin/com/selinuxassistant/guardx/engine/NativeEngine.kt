package com.selinuxassistant.guardx.engine

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

// ══════════════════════════════════════════════════════════════════
//  NativeEngine  —  C++ katmanına tek giriş noktası
//  Tüm native çağrılar bu object üzerinden yapılır.
// ══════════════════════════════════════════════════════════════════
object NativeEngine {

    init {
        System.loadLibrary("guardx_engine")
    }

    val isLoaded: Boolean get() = runCatching { hashFile("/proc/self/exe") != null }.getOrDefault(false)

    // ── Hash Engine ────────────────────────────────────────────────
    external fun hashFile(path: String): String           // JSON: {sha256, md5}

    // ── File Scanner ───────────────────────────────────────────────
    external fun scanFile(path: String): String           // JSON: ScanResult
    external fun scanDirectory(path: String, cb: ScanCallback): String  // JSON: stats+threats
    external fun cancelScan()

    // ── Root Detector ──────────────────────────────────────────────
    external fun rootFullScan(deepKernel: Boolean, tolerateDev: Boolean): String
    external fun rootQuickScan(): String
    external fun isRooted(): Boolean
    external fun isBootloaderUnlocked(): Boolean

    // ── Behavioral Analyzer ────────────────────────────────────────
    external fun analyzeProcess(pid: Int, durationMs: Int, deepMode: Boolean): String
    external fun scanAllProcesses(durationMs: Int): String
    external fun stopMonitoring()
    external fun getSyscallRisk(syscallNr: Int): Int
    external fun getSyscallName(syscallNr: Int): String
    external fun startRealtimeMonitor(pid: Int, durationMs: Int, cb: BehaviorCallback)

    // ── APK Analyzer ───────────────────────────────────────────────
    external fun analyzeApk(path: String): String
    external fun analyzeInstalledApp(packageName: String): String

    // ── İmza veritabanı yönetimi ──────────────────────────────────
    external fun dbInit(assetManager: android.content.res.AssetManager,
                        filesDir: String): Boolean
    external fun dbGetVersion(): String
    external fun dbGetCount(): Long
    external fun dbApplyDelta(deltaPath: String): Int

    // ── Coroutine wrapper'lar ──────────────────────────────────────
    suspend fun hashFileSuspend(path: String)  = withContext(Dispatchers.IO) { hashFile(path) }
    suspend fun scanFileSuspend(path: String)  = withContext(Dispatchers.IO) { scanFile(path) }
    suspend fun analyzeApkSuspend(path: String)= withContext(Dispatchers.IO) { analyzeApk(path) }
    suspend fun rootScanSuspend(deep: Boolean) = withContext(Dispatchers.IO) {
        rootFullScan(deepKernel = deep, tolerateDev = false)
    }
}

// ── Callback arayüzleri ────────────────────────────────────────────
interface ScanCallback {
    fun onProgress(scanned: Int, total: Int, currentFile: String)
}

interface BehaviorCallback {
    fun onAlert(json: String)
}
