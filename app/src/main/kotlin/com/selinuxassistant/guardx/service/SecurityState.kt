package com.selinuxassistant.guardx.service

import com.selinuxassistant.guardx.model.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * SecurityState
 *
 * Uygulamanin tum tarama sonuclarini merkezi olarak tutan Singleton.
 * ViewModels bu veriyi gozlemler (Flow). Navigasyon sirasinda verinin
 * kaybolmasini onler ve birlesik bir "Guvenlik Skoru" hesaplar.
 */
object SecurityState {

    // --- Veri Kaynaklari (StateFlow) ---
    private val _rootReport = MutableStateFlow<RootReport?>(null)
    val rootReport: StateFlow<RootReport?> = _rootReport.asStateFlow()

    private val _lastApkReports = MutableStateFlow<List<ApkReport>>(emptyList())
    val lastApkReports: StateFlow<List<ApkReport>> = _lastApkReports.asStateFlow()

    private val _lastBehaviorReport = MutableStateFlow<BehaviorReport?>(null)
    val lastBehaviorReport: StateFlow<BehaviorReport?> = _lastBehaviorReport.asStateFlow()

    // --- Guncelleme Metotlari ---
    fun updateRoot(report: RootReport) {
        _rootReport.value = report
    }

    fun updateApks(reports: List<ApkReport>) {
        _lastApkReports.value = reports
    }

    fun updateBehavior(report: BehaviorReport) {
        _lastBehaviorReport.value = report
    }

    // --- Birlesik Skor Hesaplama ---
    /**
     * Genel Guvenlik Skoru (0-100)
     *
     * Formül:
     * - Root tespiti: %50 agirlik (Root varsa skor max 50 olur)
     * - Zararli APK: %30 agirlik (Her yuksek riskli APK skoru dusurur)
     * - Supheli Davranis: %20 agirlik
     */
    fun calculateOverallScore(): Int {
        var baseScore = 100

        // 1. Root Kontrolü (%50)
        _rootReport.value?.let { r ->
            if (r.isRooted) baseScore -= 40
            if (r.isHooked) baseScore -= 30
            if (r.bootloaderUnlocked) baseScore -= 10
        } ?: run { baseScore -= 5 } // Henuz taranmadiysa hafif dusur

        // 2. APK Kontrolü (%30)
        val highRiskApks = _lastApkReports.value.count { it.overallScore > 60 }
        baseScore -= (highRiskApks * 15).coerceAtMost(30)

        // 3. Davranis Kontrolü (%20)
        _lastBehaviorReport.value?.let { b ->
            if (b.highestRisk > 70) baseScore -= 20
            else if (b.highestRisk > 30) baseScore -= 10
        }

        return baseScore.coerceIn(0, 100)
    }
}
