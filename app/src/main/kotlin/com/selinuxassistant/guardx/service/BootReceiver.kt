package com.selinuxassistant.guardx.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.work.*
import java.util.concurrent.TimeUnit

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED ||
            intent.action == Intent.ACTION_MY_PACKAGE_REPLACED) {
            schedulePeriodic(context)
        }
    }

    companion object {
        fun schedulePeriodic(context: Context) {
            val req = PeriodicWorkRequestBuilder<BackgroundScanWorker>(6, TimeUnit.HOURS)
                .setConstraints(Constraints.Builder()
                    .setRequiresBatteryNotLow(true)
                    .build())
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                "guardx_periodic_scan",
                ExistingPeriodicWorkPolicy.KEEP,
                req
            )
        }
    }
}

class BackgroundScanWorker(ctx: Context, params: WorkerParameters) :
    CoroutineWorker(ctx, params) {
    override suspend fun doWork(): Result {
        return runCatching {
            ScanService.start(applicationContext, "/sdcard")
            Result.success()
        }.getOrElse { Result.retry() }
    }
}
