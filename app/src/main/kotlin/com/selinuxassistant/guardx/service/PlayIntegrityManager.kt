package com.selinuxassistant.guardx.service

import android.content.Context
import android.util.Base64
import android.util.Log
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.tasks.await
import org.json.JSONObject
import java.security.SecureRandom

// ══════════════════════════════════════════════════════════════════
//  PlayIntegrityManager
//
//  Google Play Integrity API entegrasyonu.
//
//  Akış:
//    1. Rastgele nonce üret (≥16 bayt, URL-safe Base64)
//    2. IntegrityManager.requestIntegrityToken() çağır
//    3. Google imzalı JWS (JSON Web Signature) token al
//    4. Token'ın payload bölümünü (ortadaki bölüm) decode et
//    5. deviceIntegrity, appIntegrity, accountDetails ayrıştır
//
//  NOT: Üretim ortamında token doğrulaması BACKEND tarafında
//  yapılmalıdır (Google'ın DecryptIntegrityToken API'si ile).
//  Bu implementasyon token payload'ını CLIENT tarafında okur —
//  güvenlik için yeterli değil ama hızlı sonuç göstermek için
//  kullanışlıdır. İleride backend eklendiğinde doğrulama oraya taşınır.
//
//  Verdictler:
//    MEETS_DEVICE_INTEGRITY   → Gerçek Android donanımı, bootloader kilitli
//    MEETS_BASIC_INTEGRITY    → Uygulama değiştirilmemiş, imza geçerli
//    MEETS_STRONG_INTEGRITY   → Donanım destekli güçlü doğrulama (eski: MEETS_STRONG_DEVICE_INTEGRITY)
//    MEETS_VIRTUAL_INTEGRITY  → Özellik doğrulama ortamı (emülatör/CI için)
// ══════════════════════════════════════════════════════════════════
class PlayIntegrityManager(private val context: Context) {

    companion object {
        private const val TAG = "PlayIntegrity"

        // Google Cloud Project numarası (değiştirilmeli — production)
        // Şimdilik sıfır bırakıldı: token yine de alınır ama
        // backend doğrulaması için kendi proje numaranızı kullanın
        private const val CLOUD_PROJECT_NUMBER = 0L

        // Beklenen uygulama paketi
        private const val EXPECTED_PACKAGE = "com.selinuxassistant.guardx"
    }

    // ── İstekte gönderilecek nonce ──────────────────────────────
    private fun generateNonce(): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return Base64.encodeToString(bytes,
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    // ── Ana fonksiyon: integrity token al ve ayrıştır ──────────
    suspend fun requestIntegrityVerdict(): IntegrityResult {
        return try {
            val manager = IntegrityManagerFactory.create(context)
            val nonce   = generateNonce()

            val builder = IntegrityTokenRequest.builder().setNonce(nonce)
            // Cloud Project Number varsa ekle (doğruluk için önerilen)
            if (CLOUD_PROJECT_NUMBER != 0L)
                builder.setCloudProjectNumber(CLOUD_PROJECT_NUMBER)

            val tokenResponse = manager.requestIntegrityToken(builder.build()).await()
            val token = tokenResponse.token()

            Log.i(TAG, "Token alındı (${token.length} karakter)")

            // JWS formatı: header.payload.signature
            // Payload = ortadaki bölüm, Base64URL
            val parts = token.split(".")
            if (parts.size < 2) {
                return IntegrityResult.Error("Geçersiz token formatı")
            }

            val payloadJson = try {
                val decoded = Base64.decode(
                    parts[1].padEnd(
                        parts[1].length + (4 - parts[1].length % 4) % 4, '='
                    ),
                    Base64.URL_SAFE
                )
                String(decoded, Charsets.UTF_8)
            } catch (e: Exception) {
                return IntegrityResult.Error("Token decode hatası: ${e.message}")
            }

            parsePayload(payloadJson)

        } catch (e: Exception) {
            Log.e(TAG, "Integrity hatası: ${e.message}")
            // Hata türünü kullanıcıya anlamlı göster
            val userMsg = when {
                e.message?.contains("10") == true  -> "Play Store yok / güncel değil"
                e.message?.contains("-3") == true  -> "İnternet bağlantısı yok"
                e.message?.contains("-8") == true  -> "Play hizmetleri güncelleme gerektirir"
                e.message?.contains("403") == true -> "API erişim yetkisi yok (proje numarası?)"
                else -> "Hata: ${e.message}"
            }
            IntegrityResult.Error(userMsg)
        }
    }

    // ── Payload JSON'unu IntegrityVerdict'e dönüştür ────────────
    private fun parsePayload(json: String): IntegrityResult {
        return try {
            val root = JSONObject(json)
            Log.d(TAG, "Payload: $json")

            // ── requestDetails ───────────────────────────────────
            val req = root.optJSONObject("requestDetails")
            val requestPackage = req?.optString("requestPackageName") ?: ""
            val nonce          = req?.optString("nonce")              ?: ""

            // ── appIntegrity ─────────────────────────────────────
            val app           = root.optJSONObject("appIntegrity")
            val appRecog      = app?.optString("appRecognitionVerdict") ?: ""
            val appPkg        = app?.optString("packageName")           ?: ""
            val certDigests   = buildList {
                app?.optJSONArray("certificateSha256Digest")?.let { arr ->
                    repeat(arr.length()) { add(arr.getString(it)) }
                }
            }
            val versionCode   = app?.optLong("versionCode") ?: 0L

            // ── deviceIntegrity ──────────────────────────────────
            val dev           = root.optJSONObject("deviceIntegrity")
            val deviceLabels  = buildList {
                dev?.optJSONArray("deviceRecognitionVerdict")?.let { arr ->
                    repeat(arr.length()) { add(arr.getString(it)) }
                }
            }

            // ── accountDetails ───────────────────────────────────
            val acc           = root.optJSONObject("accountDetails")
            val licenseVerdict = acc?.optString("appLicensingVerdict") ?: ""

            // ── environmentDetails (yeni API) ─────────────────────
            val env           = root.optJSONObject("environmentDetails")
            val envVerdict    = env?.optString("environmentVerdict")    ?: ""

            // ── Güvenlik puanı hesapla ────────────────────────────
            val verdict = IntegrityVerdict(
                // Cihaz
                meetsDeviceIntegrity  = deviceLabels.contains("MEETS_DEVICE_INTEGRITY"),
                meetsStrongIntegrity  = deviceLabels.contains("MEETS_STRONG_INTEGRITY"),
                meetsVirtualIntegrity = deviceLabels.contains("MEETS_VIRTUAL_INTEGRITY"),
                deviceLabels          = deviceLabels,

                // Uygulama
                appRecognized         = appRecog == "PLAY_RECOGNIZED",
                appUnrecognized       = appRecog == "UNRECOGNIZED_VERSION",
                appPackageName        = appPkg,
                certDigests           = certDigests,
                versionCode           = versionCode,

                // Hesap
                licensingVerdict      = licenseVerdict,

                // Ortam
                environmentVerdict    = envVerdict,

                // Meta
                requestPackage        = requestPackage,
                rawPayload            = json
            )

            IntegrityResult.Success(verdict)

        } catch (e: Exception) {
            IntegrityResult.Error("JSON ayrıştırma hatası: ${e.message}")
        }
    }
}

// ══════════════════════════════════════════════════════════════════
//  Veri modelleri
// ══════════════════════════════════════════════════════════════════

data class IntegrityVerdict(
    // ── Cihaz ────────────────────────────────────────────────────
    /** Gerçek Android donanımı, TrustZone, bootloader kilitli */
    val meetsDeviceIntegrity:  Boolean,
    /** Donanım destekli güçlü kanıt (Play Protect sertifikalı) */
    val meetsStrongIntegrity:  Boolean,
    /** Özellik doğrulama/emülatör ortamı */
    val meetsVirtualIntegrity: Boolean,
    val deviceLabels:          List<String>,

    // ── Uygulama ─────────────────────────────────────────────────
    /** Play Store'da kayıtlı, orijinal imza */
    val appRecognized:    Boolean,
    /** Bilinmeyen sürüm / değiştirilmiş */
    val appUnrecognized:  Boolean,
    val appPackageName:   String,
    val certDigests:      List<String>,
    val versionCode:      Long,

    // ── Hesap lisanslama ─────────────────────────────────────────
    /** LICENSED | UNLICENSED | UNEVALUATED */
    val licensingVerdict: String,

    // ── Ortam ────────────────────────────────────────────────────
    val environmentVerdict: String,

    // ── Meta ─────────────────────────────────────────────────────
    val requestPackage: String,
    val rawPayload:     String
) {
    /** 0–100 arası genel güven skoru */
    val trustScore: Int get() {
        var score = 0
        if (meetsDeviceIntegrity)  score += 40
        if (meetsStrongIntegrity)  score += 30
        if (appRecognized)         score += 20
        if (licensingVerdict == "LICENSED") score += 10
        return score.coerceIn(0, 100)
    }

    /** İnsan okunabilir özet */
    val summary: String get() = buildString {
        if (meetsStrongIntegrity)       append("Güçlü donanım doğrulaması ✓\n")
        else if (meetsDeviceIntegrity)  append("Cihaz bütünlüğü ✓\n")
        else                            append("⚠ Cihaz bütünlüğü doğrulanamadı\n")
        if (appRecognized) append("Uygulama Play Store'da tanındı ✓\n")
        else               append("⚠ Uygulama tanınmadı (değiştirilmiş?)\n")
        if (meetsVirtualIntegrity) append("⚠ Sanal/emülatör ortamı tespit edildi\n")
    }.trimEnd()
}

sealed class IntegrityResult {
    data class Success(val verdict: IntegrityVerdict) : IntegrityResult()
    data class Error  (val message: String)           : IntegrityResult()
}
