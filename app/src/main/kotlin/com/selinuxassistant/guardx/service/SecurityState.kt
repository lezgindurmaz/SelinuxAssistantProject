package com.selinuxassistant.guardx.service

import com.selinuxassistant.guardx.model.RootReport
import com.selinuxassistant.guardx.model.ApkReport
import com.selinuxassistant.guardx.model.BehaviorReport
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

object SecurityState {
    private val _rootReport = MutableStateFlow<RootReport?>(null)
    val rootReport: StateFlow<RootReport?> = _rootReport.asStateFlow()

    private val _lastApkReports = MutableStateFlow<List<ApkReport>>(emptyList())
    val lastApkReports: StateFlow<List<ApkReport>> = _lastApkReports.asStateFlow()

    private val _lastBehaviorReport = MutableStateFlow<BehaviorReport?>(null)
    val lastBehaviorReport: StateFlow<BehaviorReport?> = _lastBehaviorReport.asStateFlow()

    fun updateRoot(report: RootReport) { _rootReport.value = report }
    fun updateApks(reports: List<ApkReport>) { _lastApkReports.value = reports }
    fun updateBehavior(report: BehaviorReport) { _lastBehaviorReport.value = report }

    fun calculateOverallScore(): Int {
        var score = 100

        // Root impact (up to -95)
        _rootReport.value?.let { r ->
            score -= when (r.riskLevel) {
                1 -> 15; 2 -> 35; 3 -> 70; 4 -> 95; else -> 0
            }
        } ?: run { score -= 10 } // Penalize for no scan

        // APK impact (up to -40)
        val malwareCount = _lastApkReports.value.count { it.verdict == "MALWARE" }
        val suspiciousCount = _lastApkReports.value.count { it.verdict == "SUSPICIOUS" }
        score -= (malwareCount * 20).coerceAtMost(40)
        score -= (suspiciousCount * 5).coerceAtMost(20)

        // Behavior impact (up to -30)
        _lastBehaviorReport.value?.let { b ->
            val highRiskCount = b.profiles.count { it.riskScore >= 40 }
            score -= (highRiskCount * 10).coerceAtMost(30)
        }

        return score.coerceIn(0, 100)
    }
}
