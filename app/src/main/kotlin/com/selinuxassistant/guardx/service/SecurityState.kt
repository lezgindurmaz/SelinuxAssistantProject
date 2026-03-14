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
        val root = _rootReport.value
        val apks = _lastApkReports.value
        val behavior = _lastBehaviorReport.value

        // Initial state: low score to encourage scanning
        if (root == null && apks.isEmpty() && behavior == null) return 0

        var score = 100

        // Root impact (High Weight)
        if (root != null) {
            score -= when (root.riskLevel) {
                1 -> 15; 2 -> 35; 3 -> 70; 4 -> 95; else -> 0
            }
        } else {
            score -= 30 // High penalty for no root scan
        }

        // APK impact (Medium Weight)
        if (apks.isNotEmpty()) {
            val malwareCount = apks.count { it.verdict == "MALWARE" }
            val suspiciousCount = apks.count { it.verdict == "SUSPICIOUS" }
            score -= (malwareCount * 25).coerceAtMost(50)
            score -= (suspiciousCount * 10).coerceAtMost(25)
        } else {
            score -= 25 // Penalty for no app scan
        }

        // Behavior impact (Medium Weight)
        if (behavior != null) {
            val highRiskCount = behavior.profiles.count { it.riskScore >= 40 }
            score -= (highRiskCount * 15).coerceAtMost(30)
        } else {
            score -= 15 // Penalty for no behavior monitor
        }

        return score.coerceIn(5, 100) // Minimum 5 as per user request for "second scan"
    }
}
