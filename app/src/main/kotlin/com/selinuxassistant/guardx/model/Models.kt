package com.selinuxassistant.guardx.model

import org.json.JSONObject
import org.json.JSONArray

// ══════════════════════════════════════════════════════════════════
//  Temel veri modelleri  —  C++ JSON çıktısından parse edilir
// ══════════════════════════════════════════════════════════════════

enum class ThreatLevel(val label: String, val colorHex: String) {
    CLEAN      ("Temiz",     "#22C55E"),
    SUSPICIOUS ("Şüpheli",   "#F59E0B"),
    MALWARE    ("Zararlı",   "#EF4444"),
    CRITICAL   ("Kritik",    "#7C3AED");

    companion object {
        fun from(level: Int) = when (level) {
            0 -> CLEAN; 1 -> SUSPICIOUS; 2 -> MALWARE; else -> CRITICAL
        }
    }
}

// ── Dosya tarama sonucu ───────────────────────────────────────────
data class ScanResult(
    val filePath:    String,
    val sha256:      String,
    val md5:         String,
    val threatLevel: ThreatLevel,
    val threatName:  String,
    val source:      String,   // "local_db" | "cloud" | "clean"
    val scanTimeMs:  Double,
    val success:     Boolean
) {
    companion object {
        fun fromJson(json: String): ScanResult {
            val j = JSONObject(json)
            return ScanResult(
                filePath    = j.optString("path", ""),
                sha256      = j.optString("sha256", ""),
                md5         = j.optString("md5", ""),
                threatLevel = ThreatLevel.from(j.optInt("threatLevel", 0)),
                threatName  = j.optString("threatName", ""),
                source      = j.optString("source", ""),
                scanTimeMs  = j.optDouble("scanTimeMs", 0.0),
                success     = j.optBoolean("success", false)
            )
        }
    }
}

// ── Tarama istatistikleri ─────────────────────────────────────────
data class ScanStats(
    val totalFiles:     Int,
    val cleanFiles:     Int,
    val malwareFiles:   Int,
    val criticalFiles:  Int,
    val suspiciousFiles:Int,
    val totalTimeMs:    Double,
    val threats:        List<ScanResult>
) {
    val threatCount get() = malwareFiles + criticalFiles + suspiciousFiles

    companion object {
        fun fromJson(json: String): ScanStats {
            val j = JSONObject(json)
            val threatsArr = j.optJSONArray("threats") ?: JSONArray()
            val threats = (0 until threatsArr.length()).map { i ->
                val t = threatsArr.getJSONObject(i)
                ScanResult(
                    filePath    = t.optString("path"),
                    sha256      = t.optString("sha256"),
                    md5         = "",
                    threatLevel = ThreatLevel.from(t.optInt("level", 2)),
                    threatName  = t.optString("name"),
                    source      = "local_db",
                    scanTimeMs  = 0.0,
                    success     = true
                )
            }
            return ScanStats(
                totalFiles      = j.optInt("totalFiles"),
                cleanFiles      = j.optInt("cleanFiles"),
                malwareFiles    = j.optInt("malwareFiles"),
                criticalFiles   = j.optInt("criticalFiles"),
                suspiciousFiles = j.optInt("suspiciousFiles"),
                totalTimeMs     = j.optDouble("totalTimeMs"),
                threats         = threats
            )
        }
    }
}

// ── Root tespit raporu ────────────────────────────────────────────
data class RootReport(
    val isRooted:            Boolean,
    val isHooked:            Boolean,
    val bootloaderUnlocked:  Boolean,
    val riskLevel:           Int,      // 0=SAFE 1=LOW 2=MED 3=HIGH 4=CRITICAL
    val flags:               Long,
    val scanTimeMs:          Double,
    val evidences:           List<Evidence>
) {
    val riskLabel get() = when (riskLevel) {
        0 -> "Güvenli"; 1 -> "Düşük Risk"; 2 -> "Orta Risk"
        3 -> "Yüksek Risk"; else -> "Kritik"
    }
    val riskColorHex get() = when (riskLevel) {
        0 -> "#22C55E"; 1 -> "#84CC16"; 2 -> "#F59E0B"
        3 -> "#EF4444"; else -> "#7C3AED"
    }

    companion object {
        fun fromJson(json: String): RootReport {
            val j = JSONObject(json)
            val evArr = j.optJSONArray("evidences") ?: JSONArray()
            val evidences = (0 until evArr.length()).map { i ->
                val e = evArr.getJSONObject(i)
                Evidence(
                    flag   = e.optInt("flag"),
                    weight = e.optInt("weight"),
                    detail = e.optString("detail")
                )
            }
            return RootReport(
                isRooted           = j.optBoolean("isRooted"),
                isHooked           = j.optBoolean("isHooked"),
                bootloaderUnlocked = j.optBoolean("bootloaderUnlocked"),
                riskLevel          = j.optInt("riskLevel"),
                flags              = j.optLong("flags"),
                scanTimeMs         = j.optDouble("scanTimeMs"),
                evidences          = evidences
            )
        }
    }
}

data class Evidence(val flag: Int, val weight: Int, val detail: String)

// ── APK raporu ────────────────────────────────────────────────────
data class ApkReport(
    val apkPath:        String,
    val packageName:    String,
    val versionName:    String,
    val sha256:         String,
    val verdict:        String,   // CLEAN | SUSPICIOUS | MALWARE
    val overallScore:   Int,
    val permScore:      Int,
    val behaviorScore:  Int,
    val sigScore:       Int,
    val criticalPerms:  Int,
    val highPerms:      Int,
    val isSigned:       Boolean,
    val isDebugCert:    Boolean,
    val debuggable:     Boolean,
    val cleartext:      Boolean,
    val permissions:    List<Permission>,
    val dexFindings:    List<DexFinding>,
    val suspiciousActions: List<String>,
    val exportedNoPermComponents: Int,
    val analysisDurationMs: Double
) {
    val threatLevel get() = when (verdict) {
        "MALWARE"    -> ThreatLevel.MALWARE
        "SUSPICIOUS" -> ThreatLevel.SUSPICIOUS
        else         -> ThreatLevel.CLEAN
    }
    companion object {
        fun fromJson(json: String): ApkReport {
            val j  = JSONObject(json)
            val m  = j.optJSONObject("manifest") ?: JSONObject()
            val sig= j.optJSONObject("signature") ?: JSONObject()

            val permsArr = m.optJSONArray("permissions") ?: JSONArray()
            val perms = (0 until permsArr.length()).map { i ->
                val p = permsArr.getJSONObject(i)
                Permission(p.optString("name"), p.optInt("risk"),
                           p.optString("cat"),  p.optString("desc"))
            }

            val dexArr = j.optJSONArray("dexFindings") ?: JSONArray()
            val dex = (0 until dexArr.length()).map { i ->
                val d = dexArr.getJSONObject(i)
                DexFinding(d.optInt("threat"), d.optString("dex"),
                           d.optInt("severity"), d.optString("desc"))
            }

            val actArr = m.optJSONArray("suspiciousActions") ?: JSONArray()
            val actions = (0 until actArr.length()).map { i -> actArr.getString(i) }

            return ApkReport(
                apkPath       = j.optString("apkPath"),
                packageName   = m.optString("package"),
                versionName   = m.optString("versionName"),
                sha256        = j.optString("sha256"),
                verdict       = j.optString("verdict", "CLEAN"),
                overallScore  = j.optInt("overallScore"),
                permScore     = j.optInt("permScore"),
                behaviorScore = j.optInt("behaviorScore"),
                sigScore      = j.optInt("sigScore"),
                criticalPerms = m.optInt("criticalPerm"),
                highPerms     = m.optInt("highPerm"),
                isSigned      = sig.optBoolean("signed"),
                isDebugCert   = sig.optBoolean("debugCert"),
                debuggable    = m.optBoolean("debuggable"),
                cleartext     = m.optBoolean("cleartext"),
                permissions   = perms,
                dexFindings   = dex,
                suspiciousActions = actions,
                exportedNoPermComponents = m.optInt("exportedNoPermComp"),
                analysisDurationMs = j.optDouble("analysisDurationMs")
            )
        }
    }
}

data class Permission(val name: String, val risk: Int,
                      val category: String, val description: String)
data class DexFinding(val threat: Int, val dexFile: String,
                      val severity: Int, val description: String)

// ── Davranışsal analiz ────────────────────────────────────────────
data class BehaviorReport(
    val targetPid:    Int,
    val durationMs:   Int,
    val totalEvents:  Long,
    val flagged:      Long,
    val highestRisk:  Int,
    val profiles:     List<ProcessProfile>
) {
    companion object {
        fun fromJson(json: String): BehaviorReport {
            val j = JSONObject(json)
            val profArr = j.optJSONArray("profiles") ?: JSONArray()
            val profiles = (0 until profArr.length()).map { i ->
                val p = profArr.getJSONObject(i)
                val findArr = p.optJSONArray("findings") ?: JSONArray()
                ProcessProfile(
                    pid          = p.optInt("pid"),
                    comm         = p.optString("comm"),
                    riskScore    = p.optInt("riskScore"),
                    isCompromised= p.optBoolean("isCompromised"),
                    behaviorFlags= p.optLong("behaviorFlags"),
                    totalSyscalls= p.optLong("totalSyscalls"),
                    syscallRate  = p.optInt("syscallRatePerSec"),
                    bytesSent    = p.optLong("bytesSent"),
                    findings     = (0 until findArr.length()).map { fi -> findArr.getString(fi) }
                )
            }
            return BehaviorReport(
                targetPid   = j.optInt("targetPid"),
                durationMs  = j.optInt("durationMs"),
                totalEvents = j.optLong("totalEvents"),
                flagged     = j.optLong("flagged"),
                highestRisk = j.optInt("highestRisk"),
                profiles    = profiles
            )
        }
    }
}

data class ProcessProfile(
    val pid:          Int,
    val comm:         String,
    val riskScore:    Int,
    val isCompromised:Boolean,
    val behaviorFlags:Long,
    val totalSyscalls:Long,
    val syscallRate:  Int,
    val bytesSent:    Long,
    val findings:     List<String>
)
