package com.selinuxassistant.guardx

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import android.util.Log
import com.selinuxassistant.guardx.engine.NativeEngine
import com.selinuxassistant.guardx.service.ScanRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class GuardXApp : Application() {

    val repository: ScanRepository by lazy { ScanRepository(this) }

    /** Uygulama geneli coroutine scope — servis ve init işleri için */
    val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    override fun onCreate() {
        super.onCreate()
        instance = this
        createNotificationChannels()
        initSignatureDatabase()
    }

    // ── İmza veritabanını assets'ten kopyala ve aç ──────────────────
    private fun initSignatureDatabase() {
        appScope.launch {
            try {
                val ok = NativeEngine.dbInit(assets, filesDir.absolutePath)
                val count = NativeEngine.dbGetCount()
                Log.i(TAG, "İmza DB: $ok, $count imza yüklendi")
            } catch (e: Exception) {
                Log.e(TAG, "DB init hatası: ${e.message}")
            }
        }
    }

    // ── Bildirim kanalları ──────────────────────────────────────────
    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = getSystemService(NotificationManager::class.java)

        nm.createNotificationChannel(NotificationChannel(
            CHANNEL_SCAN, getString(R.string.channel_scan),
            NotificationManager.IMPORTANCE_LOW
        ).apply { description = "Arka plan tarama bildirimleri" })

        nm.createNotificationChannel(NotificationChannel(
            CHANNEL_THREAT, getString(R.string.channel_threat),
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = "Tehdit tespit uyarıları"
            enableVibration(true)
        })
    }

    companion object {
        private const val TAG          = "GuardXApp"
        const val CHANNEL_SCAN         = "guardx_scan"
        const val CHANNEL_THREAT       = "guardx_threat"

        @Volatile private var _instance: GuardXApp? = null
        var instance: GuardXApp
            get()  = _instance ?: error("GuardXApp başlatılmadı")
            set(v) { _instance = v }
    }
}
