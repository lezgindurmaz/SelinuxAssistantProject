package com.selinuxassistant.guardx.service

import android.content.Context
import android.util.Base64
import android.util.Log
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.security.SecureRandom
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Google Play Integrity API  — v1.0.1 (cloud project numarası gerektirmez)
 *
 * Önceki sürümdeki hatalar:
 *   1. .await() extension kullanıyordu. Bu,
 *      play-services-tasks bağımlılığını (veya play:core-ktx) gerektiriyor.
 *      Bağımlılık listede yoktu → NoSuchMethodError / ClassNotFoundException.
 *
 *   2. Google Task<T> → coroutine köprüsü elle yazılmadıkça çalışmıyor.
 *
 * Çözüm: suspendCancellableCoroutine + addOnSuccessListener/addOnFailureListener
 *   ile Google Task API'si native olarak bekleniyor.
 *   Dış bağımlılık gerektirmez.
 *
 * Play Integrity Error Codes:
 *   -1  API_NOT_AVAILABLE     : Play Services güncel değil / kurulu değil
 *   -2  PLAY_STORE_NOT_FOUND  : Play Store yok veya devre dışı
 *   -3  NETWORK_ERROR         : İnternet bağlantısı yok
 *   -4  PLAY_STORE_VERSION_OUTDATED
 *   -6  CANNOT_BIND_TO_SERVICE
 *   -7  NONCE_TOO_SHORT       : Nonce < 16 bytes
 *   -8  NONCE_TOO_LONG        : Nonce > 500 bytes
 *   -9  GOOGLE_SERVER_UNAVAILABLE
 *   -10 PLAY_INTEGRITY_API_NOT_AVAILABLE
 *   -16 CLOUD_PROJECT_NUMBER_IS_INVALID (v1.3.0+)
 *   -100 TOO_MANY_REQUESTS
 */
class PlayIntegrityManager(private val context: Context) {

    companion object {
        private const val TAG = "PlayIntegrity"
    }

    data class IntegrityVerdict(
        val meetsDeviceIntegrity  : Boolean,
        val meetsStrongIntegrity  : Boolean,
        val meetsVirtualIntegrity : Boolean,
        val deviceLabels          : List<String>,
        val appRecognized         : Boolean,
        val appPackageName        : String,
        val certDigestShort       : String,
        val versionCode           : Long,
        val licensingVerdict      : String   // LICENSED | UNLICENSED | UNEVALUATED
    ) {
        /** 0–100 arası Play Integrity güven skoru */
        val integrityScore: Int get() {
            var s = 0
            if (meetsDeviceIntegrity)  s += 40
            if (meetsStrongIntegrity)  s += 30   // zaten DeviceIntegrity'yi kapsıyor
            if (appRecognized)         s += 20
            if (licensingVerdict == "LICENSED") s += 10
            return s.coerceIn(0, 100)
        }
    }

    sealed class IntegrityResult {
        data class Success(val verdict: IntegrityVerdict) : IntegrityResult()
        data class Error  (val message: String)           : IntegrityResult()
    }

    // ─────────────────────────────────────────────────────────────
    suspend fun requestVerdict(): IntegrityResult = withContext(Dispatchers.IO) {
        try {
            val manager = IntegrityManagerFactory.create(context)
            val nonce   = generateNonce()

            // v1.0.1: sadece setNonce() — setCloudProjectNumber() YOK
            val request = IntegrityTokenRequest.builder()
                .setNonce(nonce)
                .build()

            // Google Task → suspendCancellableCoroutine köprüsü
            val token = awaitTask<com.google.android.play.core.integrity.IntegrityTokenResponse> { cb ->
                manager.requestIntegrityToken(request)
                    .addOnSuccessListener { cb.resume(it) }
                    .addOnFailureListener { cb.resumeWithException(it) }
            }.token()

            Log.i(TAG, "Token alındı (${token.length} karakter)")
            parseToken(token)

        } catch (e: Exception) {
            Log.e(TAG, "Play Integrity hatası: ${e.javaClass.simpleName}: ${e.message}")
            IntegrityResult.Error(humanizeError(e.message ?: "Bilinmeyen hata"))
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Google Task<T> → suspend coroutine köprüsü
    // ─────────────────────────────────────────────────────────────
    private suspend fun <T> awaitTask(
        block: (kotlin.coroutines.Continuation<T>) -> Unit
    ): T = suspendCancellableCoroutine { cont ->
        block(cont)
    }

    // ─────────────────────────────────────────────────────────────
    // Nonce üretimi
    // Gereksinim: URL-safe Base64, 16–500 karakter (byte değil karakter)
    // ─────────────────────────────────────────────────────────────
    private fun generateNonce(): String {
        val raw = ByteArray(32)
        SecureRandom().nextBytes(raw)
        // URL_SAFE + NO_WRAP + NO_PADDING → padding olmayan URL-safe Base64
        // 32 byte → 43 karakter (16–500 arasında ✓)
        return Base64.encodeToString(raw, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    // ─────────────────────────────────────────────────────────────
    // JWS token parse et
    // Format: base64url(header) . base64url(payload) . base64url(signature)
    // ─────────────────────────────────────────────────────────────
    private fun parseToken(token: String): IntegrityResult {
        return try {
            val parts = token.split(".")
            if (parts.size < 2)
                return IntegrityResult.Error("Geçersiz JWS token formatı (${parts.size} parça)")

            // Base64URL padding ekle ve decode et
            val payload = parts[1].let { raw ->
                val padded = raw + "=".repeat((4 - raw.length % 4) % 4)
                String(Base64.decode(padded, Base64.URL_SAFE), Charsets.UTF_8)
            }
            Log.d(TAG, "Payload parse ediliyor")

            val root = JSONObject(payload)

            // deviceIntegrity
            val dev    = root.optJSONObject("deviceIntegrity")
            val labels = buildList {
                dev?.optJSONArray("deviceRecognitionVerdict")?.let { arr ->
                    repeat(arr.length()) { add(arr.getString(it)) }
                }
            }

            // appIntegrity
            val app      = root.optJSONObject("appIntegrity")
            val appRecog = app?.optString("appRecognitionVerdict") ?: ""
            val appPkg   = app?.optString("packageName") ?: ""
            val certDig  = buildList {
                app?.optJSONArray("certificateSha256Digest")?.let { arr ->
                    repeat(arr.length()) { add(arr.getString(it)) }
                }
            }
            val vCode = app?.optLong("versionCode") ?: 0L

            // accountDetails
            val acc      = root.optJSONObject("accountDetails")
            val licensing = acc?.optString("appLicensingVerdict") ?: "UNEVALUATED"

            Log.i(TAG, "DeviceLabels: $labels, AppRecog: $appRecog, Licensing: $licensing")

            IntegrityResult.Success(
                IntegrityVerdict(
                    meetsDeviceIntegrity  = "MEETS_DEVICE_INTEGRITY"  in labels,
                    meetsStrongIntegrity  = "MEETS_STRONG_INTEGRITY"  in labels,
                    meetsVirtualIntegrity = "MEETS_VIRTUAL_INTEGRITY" in labels,
                    deviceLabels          = labels,
                    appRecognized         = appRecog == "PLAY_RECOGNIZED",
                    appPackageName        = appPkg,
                    certDigestShort       = certDig.firstOrNull()?.take(16) ?: "",
                    versionCode           = vCode,
                    licensingVerdict      = licensing
                )
            )
        } catch (e: Exception) {
            Log.e(TAG, "Token parse hatası: ${e.message}")
            IntegrityResult.Error("Token ayrıştırılamadı: ${e.message}")
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Hata kodunu kullanıcı dostu mesaja çevir
    // ─────────────────────────────────────────────────────────────
    private fun humanizeError(msg: String): String = when {
        msg.contains("-1")  || msg.contains("API_NOT_AVAILABLE")         ->
            "Play Services güncel değil veya kurulu değil"
        msg.contains("-2")  || msg.contains("PLAY_STORE_NOT_FOUND")      ->
            "Play Store bulunamadı veya devre dışı bırakılmış"
        msg.contains("-3")  || msg.contains("NETWORK_ERROR")             ->
            "İnternet bağlantısı yok"
        msg.contains("-4")  || msg.contains("PLAY_STORE_VERSION_OUTDATED") ->
            "Play Store sürümü güncel değil, lütfen güncelleyin"
        msg.contains("-6")  || msg.contains("CANNOT_BIND")               ->
            "Play Services'e bağlanılamadı"
        msg.contains("-7")  || msg.contains("NONCE_TOO_SHORT")           ->
            "İç hata: nonce çok kısa (rapor edin)"
        msg.contains("-8")  || msg.contains("NONCE_TOO_LONG")            ->
            "İç hata: nonce çok uzun (rapor edin)"
        msg.contains("-9")  || msg.contains("GOOGLE_SERVER_UNAVAILABLE") ->
            "Google sunucuları geçici olarak kullanılamıyor"
        msg.contains("-10") || msg.contains("PLAY_INTEGRITY_API_NOT_AVAILABLE") ->
            "Play Integrity API bu cihazda desteklenmiyor"
        msg.contains("-16") || msg.contains("CLOUD_PROJECT_NUMBER")      ->
            "API yapılandırma hatası (geliştirici hatası)"
        msg.contains("-100") || msg.contains("TOO_MANY_REQUESTS")        ->
            "Çok fazla istek gönderildi, lütfen bekleyin"
        msg.contains("NoSuchMethod") || msg.contains("ClassNotFound")    ->
            "Kütüphane uyumsuzluğu (derleme hatası)"
        else -> "Play Integrity: $msg"
    }
}
