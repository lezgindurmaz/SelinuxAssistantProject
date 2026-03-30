package com.selinuxassistant.guardx.service

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

/**
 * TeeAttestationManager
 *
 * AndroidKeyStore donanim kanitlamasi.
 *
 * deviceLocked ve verifiedBootState BIRINCIL olarak sistem ozelliklerinden
 * (ro.boot.*) okunur. Bu ozellikler bootloader tarafindan cekirdek
 * baslangicinda ayarlanir; uygulama katmanindan degistirilemez.
 *
 * AndroidKeyStore anahtar uretimi donanim guvenlik seviyesini (SOFTWARE /
 * TEE / STRONGBOX) belirlemek icin kullanilir.
 */
class TeeAttestationManager(private val context: Context) {

    companion object {
        private const val TAG       = "TeeAttest"
        private const val KEY_ALIAS = "guardx_attest_tmp"
        private const val PROVIDER  = "AndroidKeyStore"
        private const val ATTEST_OID = "1.3.6.1.4.1.11129.2.1.17"
    }

    enum class SecurityLevel(val label: String, val score: Int) {
        STRONG_BOX("StrongBox (Ayrik Guvenlik Cipi)", 100),
        TEE       ("TEE (Guvenli Yurutme Ortami)",    75),
        SOFTWARE  ("Yazilim (Donanim destegi yok)",   20),
        UNKNOWN   ("Belirlenemedi",                     0)
    }

    enum class VerifiedBootState(val label: String, val isClean: Boolean) {
        VERIFIED   ("Dogrulandi",                true),
        SELF_SIGNED("Oz-Imzali (Custom ROM)",    false),
        UNVERIFIED ("Dogrulanmadi (BL acik)",    false),
        FAILED     ("HATA: Onyukleme bozuk",     false),
        UNKNOWN    ("Belirlenemedi",              false)
    }

    data class AttestationData(
        val securityLevel     : SecurityLevel,
        val verifiedBootState : VerifiedBootState,
        val deviceLocked      : Boolean,
        val isHardwareBacked  : Boolean,
        val certChainLength   : Int,
        val challengeVerified : Boolean,
        val bootStateSource   : String
    ) {
        val trustScore: Int get() {
            var s = 0
            s += securityLevel.score / 2
            if (verifiedBootState.isClean) s += 30
            if (deviceLocked)              s += 15
            if (isHardwareBacked)          s +=  5
            return s.coerceIn(0, 100)
        }
    }

    sealed class TeeResult {
        data class Success(val data: AttestationData) : TeeResult()
        data class Error  (val message: String)       : TeeResult()
    }

    // ==============================================================
    //  Ana fonksiyon
    // ==============================================================
    suspend fun performAttestation(): TeeResult = withContext(Dispatchers.IO) {

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return@withContext TeeResult.Error("Android 8.0+ gerekli")
        }

        // 1. Bootloader durumunu DOGRUDAN sistem ozelliklerinden oku
        val (deviceLocked, bootState, bootSource) = readBootState()

        // 2. Attest anahtari olustur
        val ks = KeyStore.getInstance(PROVIDER).also { it.load(null) }
        ks.deleteEntry(KEY_ALIAS)

        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }

        val (keyGenOk, usedStrongBox) = tryGenerateAttestationKey(ks, challenge)

        if (!keyGenOk) {
            // Anahtar olusturulamadi ama boot state okundu — kismi sonuc
            return@withContext TeeResult.Success(
                AttestationData(
                    securityLevel     = SecurityLevel.UNKNOWN,
                    verifiedBootState = bootState,
                    deviceLocked      = deviceLocked,
                    isHardwareBacked  = false,
                    certChainLength   = 0,
                    challengeVerified = false,
                    bootStateSource   = bootSource
                )
            )
        }

        return@withContext try {
            // 3. KeyInfo ile donanim destegini dogrula
            val privateKey    = ks.getKey(KEY_ALIAS, null)
            val isHwBacked    = queryKeyInfo(privateKey)
            val secLevel      = when {
                usedStrongBox -> SecurityLevel.STRONG_BOX
                isHwBacked    -> SecurityLevel.TEE
                else          -> SecurityLevel.SOFTWARE
            }

            // 4. Sertifika zincirini al
            val certChain = ks.getCertificateChain(KEY_ALIAS)
                ?.filterIsInstance<X509Certificate>()
                ?: emptyList()

            // 5. Challenge dogrulamasi
            val challengeOk = certChain.firstOrNull()
                ?.let { verifyChallengeInCert(it, challenge) }
                ?: false

            ks.deleteEntry(KEY_ALIAS)

            TeeResult.Success(
                AttestationData(
                    securityLevel     = secLevel,
                    verifiedBootState = bootState,
                    deviceLocked      = deviceLocked,
                    isHardwareBacked  = isHwBacked,
                    certChainLength   = certChain.size,
                    challengeVerified = challengeOk,
                    bootStateSource   = bootSource
                )
            )
        } catch (e: Exception) {
            ks.deleteEntry(KEY_ALIAS)
            Log.e(TAG, "Kanitlama hatasi: ${e.message}")
            TeeResult.Error("TEE hatasi: ${e.message}")
        }
    }

    // ==============================================================
    //  Bootloader durumunu oku
    //
    //  Kaynak onceligi:
    //    1. ro.boot.flash.locked         -- OEM'lerin cogu bunu ayarlar
    //    2. ro.boot.vbmeta.device_state  -- Android Verified Boot 2.0
    //    3. ro.boot.verifiedbootstate    -- AVB: green/yellow=kilitli, orange=acik
    //    4. /proc/cmdline                -- kernel parametreleri
    //
    //  BIR kaynak "locked" diyorsa sonuc LOCKED'dir.
    //  Hicbiri bulunamazsa UNLOCKED sayilir (guvenli taraf hatasi).
    // ==============================================================
    private fun readBootState(): Triple<Boolean, VerifiedBootState, String> {

        // Yansima ile android.os.SystemProperties okuma
        val getPropMethod = runCatching {
            Class.forName("android.os.SystemProperties")
                .getMethod("get", String::class.java, String::class.java)
        }.getOrNull()

        fun sysProp(key: String, default: String = ""): String =
            getPropMethod?.invoke(null, key, default) as? String ?: default

        // -- Kaynak 1: ro.boot.flash.locked ---------------------------
        val flashLocked = sysProp("ro.boot.flash.locked")
        when (flashLocked) {
            "1"  -> {
                Log.i(TAG, "Boot: LOCKED via ro.boot.flash.locked=1")
                return Triple(true, VerifiedBootState.VERIFIED, "ro.boot.flash.locked")
            }
            "0"  -> {
                Log.i(TAG, "Boot: UNLOCKED via ro.boot.flash.locked=0")
                return Triple(false, VerifiedBootState.UNVERIFIED, "ro.boot.flash.locked")
            }
        }

        // -- Kaynak 2: ro.boot.vbmeta.device_state --------------------
        val vbmeta = sysProp("ro.boot.vbmeta.device_state")
        if (vbmeta.isNotEmpty()) {
            val locked = vbmeta == "locked"
            val state  = if (locked) VerifiedBootState.VERIFIED else VerifiedBootState.UNVERIFIED
            Log.i(TAG, "Boot: vbmeta=$vbmeta locked=$locked")
            return Triple(locked, state, "ro.boot.vbmeta.device_state")
        }

        // -- Kaynak 3: ro.boot.verifiedbootstate ----------------------
        val vbs = sysProp("ro.boot.verifiedbootstate")
        if (vbs.isNotEmpty()) {
            val (locked, state) = when (vbs) {
                "green"  -> true  to VerifiedBootState.VERIFIED
                "yellow" -> true  to VerifiedBootState.SELF_SIGNED
                "orange" -> false to VerifiedBootState.UNVERIFIED
                "red"    -> false to VerifiedBootState.FAILED
                else     -> false to VerifiedBootState.UNKNOWN
            }
            Log.i(TAG, "Boot: verifiedbootstate=$vbs locked=$locked")
            return Triple(locked, state, "ro.boot.verifiedbootstate")
        }

        // -- Kaynak 4: /proc/cmdline ----------------------------------
        val cmdline = runCatching {
            java.io.File("/proc/cmdline").readText(Charsets.UTF_8).take(4096)
        }.getOrElse { "" }

        when {
            cmdline.contains("verifiedbootstate=green")  ->
                return Triple(true,  VerifiedBootState.VERIFIED,    "/proc/cmdline")
            cmdline.contains("verifiedbootstate=yellow") ->
                return Triple(true,  VerifiedBootState.SELF_SIGNED,  "/proc/cmdline")
            cmdline.contains("verifiedbootstate=orange") ->
                return Triple(false, VerifiedBootState.UNVERIFIED,   "/proc/cmdline")
            cmdline.contains("bootloader=unlocked")      ->
                return Triple(false, VerifiedBootState.UNVERIFIED,   "/proc/cmdline")
            cmdline.contains("androidboot.unlocked=1")   ->
                return Triple(false, VerifiedBootState.UNVERIFIED,   "/proc/cmdline")
        }

        // Hicbiri bulunamadi
        Log.w(TAG, "Boot durumu belirlenemedi — tum kaynaklar bos")
        return Triple(false, VerifiedBootState.UNKNOWN, "belirlenemedi")
    }

    // ==============================================================
    //  Attest anahtari olustur
    //  Once StrongBox dener, yoksa standart TEE/SW ile devam eder.
    //  (basarili, strongbox_kullanildi_mi)
    // ==============================================================
    private fun tryGenerateAttestationKey(
        ks       : KeyStore,
        challenge: ByteArray
    ): Pair<Boolean, Boolean> {

        // StrongBox denemesi (API 28+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            runCatching {
                val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
                kpg.initialize(
                    KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setAttestationChallenge(challenge)
                        .setIsStrongBoxBacked(true)
                        .build()
                )
                kpg.generateKeyPair()
                return true to true
            }.onFailure { e ->
                Log.i(TAG, "StrongBox basarisiz: ${e.javaClass.simpleName}")
            }
        }

        // Standart TEE / yazilim
        return runCatching {
            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
            kpg.initialize(
                KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                    .build()
            )
            kpg.generateKeyPair()
            true to false
        }.getOrElse { e ->
            Log.e(TAG, "Anahtar olusturulamadi: ${e.message}")
            false to false
        }
    }

    // ==============================================================
    //  KeyInfo ile donanim destegini sorgula
    // ==============================================================
    private fun queryKeyInfo(privateKey: java.security.Key?): Boolean {
        if (privateKey == null) return false
        return runCatching {
            val factory  = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
            val keyInfo  = factory.getKeySpec(privateKey, KeyInfo::class.java)
            if (Build.VERSION.SDK_INT >= 31) {
                keyInfo.securityLevel >= 2   // 0=SW, 1=SW-safe, 2=TEE, 3=StrongBox
            } else {
                @Suppress("DEPRECATION")
                keyInfo.isInsideSecureHardware
            }
        }.getOrElse { false }
    }

    // ==============================================================
    //  Challenge dogrulamasi
    //
    //  Key Attestation uzantisindaki attestationChallenge alani, anahtar
    //  olusturulurken verilen nonce ile eslesmelidir.
    //
    //  Parse: OCTET STRING kapsayicisi -> KeyDescription SEQUENCE
    //  -> [0]attVersion, [1]attSecLevel, [2]kmVersion, [3]kmSecLevel,
    //     [4]attestationChallenge <- istedigimiz alan
    // ==============================================================
    private fun verifyChallengeInCert(cert: X509Certificate, expected: ByteArray): Boolean {
        return runCatching {
            val extBytes = cert.getExtensionValue(ATTEST_OID) ?: return false
            val inner    = unwrapOctetString(extBytes)        ?: return false
            val r        = DerReader(inner)

            if (!r.expect(0x30)) return false  // SEQUENCE
            r.skipLength()

            // [0] attestationVersion INTEGER
            if (!r.expect(0x02)) return false
            r.skip(r.readLength())
            // [1] attestationSecurityLevel ENUMERATED
            if (!r.expect(0x0A)) return false
            r.skip(r.readLength())
            // [2] keymasterVersion INTEGER
            if (!r.expect(0x02)) return false
            r.skip(r.readLength())
            // [3] keymasterSecurityLevel ENUMERATED
            if (!r.expect(0x0A)) return false
            r.skip(r.readLength())
            // [4] attestationChallenge OCTET STRING
            if (!r.expect(0x04)) return false
            val len   = r.readLength()
            val bytes = r.readBytes(len)

            bytes.contentEquals(expected)
        }.getOrElse { false }
    }

    // -- DER yardimseverleri -----------------------------------------

    private fun unwrapOctetString(encoded: ByteArray): ByteArray? {
        if (encoded.isEmpty() || encoded[0].toInt() and 0xFF != 0x04) return null
        val (len, lb) = derLen(encoded, 1)
        val start = 1 + lb
        if (start + len > encoded.size) return null
        return encoded.copyOfRange(start, start + len)
    }

    private fun derLen(b: ByteArray, at: Int): Pair<Int, Int> {
        if (at >= b.size) return 0 to 1
        val f = b[at].toInt() and 0xFF
        return when {
            f < 0x80  -> f to 1
            f == 0x81 -> if (at + 1 < b.size) (b[at+1].toInt() and 0xFF) to 2 else 0 to 2
            f == 0x82 -> if (at + 2 < b.size)
                (((b[at+1].toInt() and 0xFF) shl 8) or (b[at+2].toInt() and 0xFF)) to 3
                else 0 to 3
            else -> 0 to 1
        }
    }

    private inner class DerReader(private val data: ByteArray, private var pos: Int = 0) {
        fun expect(tag: Int): Boolean {
            if (pos >= data.size) return false
            return if ((data[pos].toInt() and 0xFF) == tag) { pos++; true } else false
        }
        fun readLength(): Int {
            val (len, lb) = derLen(data, pos); pos += lb; return len
        }
        fun skipLength() { val (len, lb) = derLen(data, pos); pos += lb + len }
        fun skip(n: Int) { pos = (pos + n).coerceAtMost(data.size) }
        fun readBytes(n: Int): ByteArray {
            val r = data.copyOfRange(pos, (pos + n).coerceAtMost(data.size)); pos += n; return r
        }
    }
}
