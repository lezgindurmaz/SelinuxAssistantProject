package com.selinuxassistant.guardx.service

import android.content.Context
import android.content.pm.PackageManager
import com.selinuxassistant.guardx.engine.NativeEngine
import com.selinuxassistant.guardx.engine.ScanCallback
import com.selinuxassistant.guardx.model.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.io.File

class ScanRepository(private val context: Context) {

    // ── Dosya / Dizin Tarama ──────────────────────────────────────
    suspend fun scanFile(path: String): ScanResult = withContext(Dispatchers.IO) {
        val json = NativeEngine.scanFile(path)
        ScanResult.fromJson(json)
    }

    fun scanDirectory(
        path: String,
        onProgress: (scanned: Int, total: Int, file: String) -> Unit
    ): Flow<ScanStats> = flow {
        val json = NativeEngine.scanDirectory(path, object : ScanCallback {
            override fun onProgress(scanned: Int, total: Int, currentFile: String) {
                onProgress(scanned, total, currentFile)
            }
        })
        emit(ScanStats.fromJson(json))
    }.flowOn(Dispatchers.IO)

    // ── Yüklü Uygulama Taraması ───────────────────────────────────
    fun scanInstalledApps(
        onProgress: (done: Int, total: Int, pkg: String) -> Unit
    ): Flow<List<ApkReport>> = flow {
        val pm = context.packageManager
        // Sadece kullanıcı uygulamalarını veya şüpheli sistem uygulamalarını filtreleyebiliriz ama ister tüm uygulamalar.
        val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
        val results = mutableListOf<ApkReport>()
        apps.forEachIndexed { i, app ->
            val label = app.loadLabel(pm).toString()
            onProgress(i + 1, apps.size, label)

            val json = runCatching {
                // analyzeApk doğrudan dosya yolunu (sourceDir) kullanarak daha güvenilir analiz yapar
                NativeEngine.analyzeApk(app.sourceDir)
            }.getOrElse { "{\"verdict\":\"ERROR\", \"apkPath\":\"${app.sourceDir}\"}" }

            runCatching {
                val report = ApkReport.fromJson(json).copy(appName = label)
                results.add(report)
            }
        }
        emit(results)
    }.flowOn(Dispatchers.IO)

    suspend fun analyzeApk(path: String): ApkReport = withContext(Dispatchers.IO) {
        ApkReport.fromJson(NativeEngine.analyzeApk(path))
    }

    suspend fun analyzeInstalledApp(pkg: String): ApkReport = withContext(Dispatchers.IO) {
        ApkReport.fromJson(NativeEngine.analyzeInstalledApp(pkg))
    }

    // ── Root Tespiti ──────────────────────────────────────────────
    suspend fun rootQuickScan(): RootReport = withContext(Dispatchers.IO) {
        RootReport.fromJson(NativeEngine.rootQuickScan())
    }

    suspend fun rootFullScan(deep: Boolean = false): RootReport = withContext(Dispatchers.IO) {
        RootReport.fromJson(NativeEngine.rootFullScan(deep, false))
    }

    // ── Davranışsal Analiz ────────────────────────────────────────
    suspend fun scanProcesses(durationMs: Int = 5000): BehaviorReport =
        withContext(Dispatchers.IO) {
            BehaviorReport.fromJson(NativeEngine.scanAllProcesses(durationMs))
        }

    // ── Hash ──────────────────────────────────────────────────────
    suspend fun hashFile(path: String): Pair<String, String> = withContext(Dispatchers.IO) {
        val json = org.json.JSONObject(NativeEngine.hashFile(path))
        json.optString("sha256") to json.optString("md5")
    }

    // ── Depolama alanlarını keşfet ────────────────────────────────
    fun storagePaths(): List<String> {
        val paths = mutableListOf<String>()
        context.getExternalFilesDirs(null).forEach { dir ->
            dir?.let {
                // /Android/data/.../files → kök depolama
                val root = it.absolutePath
                    .substringBefore("/Android/data")
                if (root.isNotEmpty()) paths.add(root)
            }
        }
        if (paths.isEmpty()) paths.add("/sdcard")
        return paths
    }

    fun cancelScan() = NativeEngine.cancelScan()
}
