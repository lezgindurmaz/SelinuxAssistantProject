package com.selinuxassistant.guardx.service

import android.app.*
import android.content.Context
import android.content.Intent
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.selinuxassistant.guardx.GuardXApp
import com.selinuxassistant.guardx.MainActivity
import com.selinuxassistant.guardx.R
import com.selinuxassistant.guardx.engine.NativeEngine
import com.selinuxassistant.guardx.engine.ScanCallback
import kotlinx.coroutines.*

class ScanService : Service() {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START_SCAN -> {
                val path = intent.getStringExtra(EXTRA_PATH) ?: "/sdcard"
                startForeground(NOTIF_ID, buildNotification("Tarama başlatılıyor…", 0))
                scope.launch { runScan(path) }
            }
            ACTION_STOP_SCAN -> {
                NativeEngine.cancelScan()
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    private suspend fun runScan(path: String) {
        var scanned = 0
        val json = NativeEngine.scanDirectory(path, object : ScanCallback {
            override fun onProgress(s: Int, total: Int, currentFile: String) {
                scanned = s
                val pct = if (total > 0) (s * 100 / total) else 0
                updateNotification("$s / $total dosya tarandı", pct)
            }
        })
        // Tehdit varsa bildirim
        val threats = runCatching {
            org.json.JSONObject(json).optInt("malwareFiles", 0) +
            org.json.JSONObject(json).optInt("criticalFiles", 0)
        }.getOrDefault(0)

        if (threats > 0) sendThreatNotification(threats)
        stopSelf()
    }

    private fun buildNotification(text: String, progress: Int): Notification {
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        val stopIntent = PendingIntent.getService(
            this, 1,
            Intent(this, ScanService::class.java).apply { action = ACTION_STOP_SCAN },
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, GuardXApp.CHANNEL_SCAN)
            .setContentTitle("GuardX — Taranıyor")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_menu_search)
            .setContentIntent(pi)
            .addAction(android.R.drawable.ic_delete, "Durdur", stopIntent)
            .apply {
                if (progress in 1..99)
                    setProgress(100, progress, false)
                else
                    setProgress(100, 0, true)
            }
            .build()
    }

    private fun updateNotification(text: String, progress: Int) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIF_ID, buildNotification(text, progress))
    }

    private fun sendThreatNotification(count: Int) {
        val pi = PendingIntent.getActivity(
            this, 2,
            Intent(this, MainActivity::class.java).apply {
                putExtra("nav_target", "scan_results")
            },
            PendingIntent.FLAG_IMMUTABLE
        )
        val n = NotificationCompat.Builder(this, GuardXApp.CHANNEL_THREAT)
            .setContentTitle("⚠️ Tehdit Tespit Edildi!")
            .setContentText("$count zararlı dosya bulundu. Hemen inceleyin.")
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentIntent(pi)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()
        getSystemService(NotificationManager::class.java).notify(NOTIF_THREAT_ID, n)
    }

    override fun onDestroy() { scope.cancel(); super.onDestroy() }

    companion object {
        const val ACTION_START_SCAN = "com.selinuxassistant.guardx.START_SCAN"
        const val ACTION_STOP_SCAN  = "com.selinuxassistant.guardx.STOP_SCAN"
        const val EXTRA_PATH        = "scan_path"
        const val NOTIF_ID          = 1001
        const val NOTIF_THREAT_ID   = 1002

        fun start(ctx: Context, path: String) {
            val i = Intent(ctx, ScanService::class.java).apply {
                action = ACTION_START_SCAN
                putExtra(EXTRA_PATH, path)
            }
            ctx.startForegroundService(i)
        }
    }
}
