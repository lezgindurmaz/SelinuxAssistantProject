#include "apk_analyzer.h"
#include <cstring>
#include <algorithm>
#include <android/log.h>

#define LOG_TAG "AV_Dex"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)

namespace AntiVirus {

// ══════════════════════════════════════════════════════════════════
//  DEX magic kontrolü
//  "dex\n035\0" veya "dex\n036\0" veya "dex\n039\0"
// ══════════════════════════════════════════════════════════════════
bool DexAnalyzer::isDexValid(const uint8_t* data, size_t len) {
    if (len < sizeof(DexHeader)) return false;
    // İlk 3 byte "dex"
    return data[0] == 'd' && data[1] == 'e' && data[2] == 'x' && data[3] == '\n';
}

// ══════════════════════════════════════════════════════════════════
//  String tablosunu çıkar
//  DEX string format: ULEB128 length, then UTF-16 data (or MUTF-8)
// ══════════════════════════════════════════════════════════════════
static uint32_t readULEB128(const uint8_t* data, size_t len, size_t& pos) {
    uint32_t result = 0, shift = 0;
    while (pos < len) {
        uint8_t b = data[pos++];
        result |= (uint32_t)(b & 0x7F) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
        if (shift >= 35) break;
    }
    return result;
}

std::vector<std::string> DexAnalyzer::extractStrings(const uint8_t* data,
                                                       size_t len,
                                                       const DexHeader& hdr) {
    std::vector<std::string> strings;
    strings.reserve(hdr.stringIdsSize);

    // String ID tablosu: her giriş 4-byte offset (string verisi başlangıcı)
    if ((uint64_t)hdr.stringIdsOff + hdr.stringIdsSize * 4 > len) return strings;

    const uint32_t* ids = reinterpret_cast<const uint32_t*>(data + hdr.stringIdsOff);

    for (uint32_t i = 0; i < hdr.stringIdsSize; ++i) {
        uint32_t strDataOff = ids[i];
        if (strDataOff >= len) { strings.push_back(""); continue; }

        // MUTF-8: ULEB128 UTF-16 char sayısı, sonra MUTF-8 baytları
        size_t pos = strDataOff;
        uint32_t charLen = readULEB128(data, len, pos);

        if (charLen > 65535 || pos + charLen > len) {
            strings.push_back(""); continue;
        }

        // Null byte'a kadar oku (charLen bytes'tan fazlasını okuma)
        std::string s;
        s.reserve(charLen);
        while (pos < len && data[pos] != 0 && s.size() < charLen) {
            char c = static_cast<char>(data[pos++]);
            s += c;
        }
        strings.push_back(std::move(s));
    }
    return strings;
}

// ══════════════════════════════════════════════════════════════════
//  Type isimlerini çıkar  (type_ids → string_ids referansları)
// ══════════════════════════════════════════════════════════════════
std::vector<std::string> DexAnalyzer::extractTypeNames(const uint8_t* data,
                                                         size_t len,
                                                         const DexHeader& hdr) {
    std::vector<std::string> types;
    if ((uint64_t)hdr.typeIdsOff + hdr.typeIdsSize * 4 > len) return types;

    const uint32_t* typeIds = reinterpret_cast<const uint32_t*>(data + hdr.typeIdsOff);

    // Önce tüm stringleri çıkar
    auto allStrings = extractStrings(data, len, hdr);

    types.reserve(hdr.typeIdsSize);
    for (uint32_t i = 0; i < hdr.typeIdsSize; ++i) {
        uint32_t strIdx = typeIds[i];
        if (strIdx < allStrings.size())
            types.push_back(allStrings[strIdx]);
        else
            types.push_back("");
    }
    return types;
}

// ══════════════════════════════════════════════════════════════════
//  String tabanlı tehdit tespiti
//  Hardcoded string'ler, URL'ler, komutlar vb.
// ══════════════════════════════════════════════════════════════════
struct StringPattern {
    const char*  needle;
    DexThreat    threat;
    uint8_t      severity;
    const char*  description;
};

static const StringPattern STRING_PATTERNS[] = {
    // Dinamik kod yükleme
    { "DexClassLoader",         DexThreat::REFLECTION_CLASSLOAD, 8,
      "Çalışma zamanında DEX/JAR yükleme" },
    { "PathClassLoader",        DexThreat::REFLECTION_CLASSLOAD, 6,
      "Dinamik sınıf yükleme" },
    { "InMemoryDexClassLoader", DexThreat::REFLECTION_CLASSLOAD, 9,
      "Bellek içi DEX yükleme — fileless ❗" },
    { "loadDex",                DexThreat::REFLECTION_CLASSLOAD, 7,
      "DEX yükleme metodu" },
    { "dalvik.system.DexFile",  DexThreat::REFLECTION_CLASSLOAD, 7,
      "Doğrudan DexFile API" },

    // Native kod / exec
    { "System.loadLibrary",     DexThreat::NATIVE_CODE, 5,
      "Native kütüphane yükleme" },
    { "Runtime.exec",           DexThreat::PROCESS_EXEC, 8,
      "Sistem komutu çalıştırma ❗" },
    { "ProcessBuilder",         DexThreat::PROCESS_EXEC, 7,
      "ProcessBuilder ile komut çalıştırma" },
    { "/bin/sh",                DexThreat::SHELL_CMD, 9,
      "Shell komutu çalıştırma ❗" },
    { "/system/bin/sh",         DexThreat::SHELL_CMD, 9,
      "Android shell çalıştırma ❗" },
    { "su\0",                   DexThreat::SHELL_CMD, 8,
      "su komutu çağrısı — root girişimi ❗" },

    // SMS kötüye kullanımı
    { "SmsManager",             DexThreat::SMS_ABUSE, 7,
      "SMS gönderme API'si" },
    { "sendTextMessage",        DexThreat::SMS_ABUSE, 8,
      "SMS gönderme metodu" },
    { "sendMultipartTextMessage",DexThreat::SMS_ABUSE,8,
      "Çok parçalı SMS gönderme" },

    // Telefon kötüye kullanımı
    { "ACTION_CALL",            DexThreat::CALL_ABUSE, 7,
      "Arama başlatma intent'i" },
    { "TelephonyManager",       DexThreat::CALL_ABUSE, 5,
      "Telefon servisi erişimi" },

    // Cihaz yöneticisi
    { "DevicePolicyManager",    DexThreat::DEVICE_ADMIN, 8,
      "Cihaz politikası yönetimi ❗" },
    { "wipeData",               DexThreat::DEVICE_ADMIN, 10,
      "Cihaz silme metodu — fidye yazılımı ❗❗" },
    { "lockNow",                DexThreat::DEVICE_ADMIN, 9,
      "Cihazı kilitleme metodu" },
    { "resetPassword",          DexThreat::DEVICE_ADMIN, 9,
      "Parola sıfırlama ❗" },

    // Erişilebilirlik kötüye kullanımı
    { "AccessibilityService",   DexThreat::ACCESSIBILITY_ABUSE, 7,
      "Erişilebilirlik servisi" },
    { "performGlobalAction",    DexThreat::ACCESSIBILITY_ABUSE, 8,
      "Global eylem gerçekleştirme" },
    { "findFocusedViewInWindow",DexThreat::ACCESSIBILITY_ABUSE, 8,
      "Odaklanmış görünümü okuma — keylogger şüphesi" },

    // Overlay saldırısı
    { "TYPE_APPLICATION_OVERLAY",DexThreat::OVERLAY_ATTACK, 9,
      "Uygulama üzerine overlay ❗" },
    { "TYPE_SYSTEM_ALERT",      DexThreat::OVERLAY_ATTACK, 8,
      "Sistem uyarı penceresi" },

    // Gizli kayıt
    { "MediaRecorder",          DexThreat::CAMERA_MICROPHONE, 6,
      "Medya kaydı" },
    { "AudioRecord",            DexThreat::CAMERA_MICROPHONE, 7,
      "Ham ses kaydı" },

    // Pano izleme
    { "ClipboardManager",       DexThreat::CLIPBOARD_MONITOR, 6,
      "Pano erişimi" },
    { "OnPrimaryClipChangedListener",DexThreat::CLIPBOARD_MONITOR,7,
      "Pano değişiklik dinleyicisi" },

    // Hesap çalma
    { "AccountManager",         DexThreat::ACCOUNT_STEAL, 7,
      "Hesap yöneticisi erişimi" },
    { "getAuthToken",           DexThreat::ACCOUNT_STEAL, 9,
      "Kimlik doğrulama token'ı alma ❗" },
    { "invalidateAuthToken",    DexThreat::ACCOUNT_STEAL, 8,
      "Token geçersizleştirme — tekrar istemek için" },

    // Programatik yükleme
    { "PackageInstaller",       DexThreat::PACKAGE_INSTALLER, 8,
      "APK yükleme API'si ❗" },
    { "installPackage",         DexThreat::PACKAGE_INSTALLER, 9,
      "Programatik paket yükleme ❗" },

    // Zayıf kriptografi
    { "MD5",                    DexThreat::CRYPTO_WEAK, 5,
      "MD5 kullanımı — güvensiz hash" },
    { "DES",                    DexThreat::CRYPTO_WEAK, 7,
      "DES şifreleme — kırılabilir" },
    { "DESede",                 DexThreat::CRYPTO_WEAK, 5,
      "3DES — zayıf" },
    { "RC4",                    DexThreat::CRYPTO_WEAK, 7,
      "RC4 — güvensiz stream cipher" },
    { "ECB",                    DexThreat::CRYPTO_WEAK, 6,
      "ECB modu — şifreli metinde desen kalır" },

    // Sentinel
    { nullptr, DexThreat::REFLECTION_CLASSLOAD, 0, nullptr }
};

void DexAnalyzer::scanStrings(const std::vector<std::string>& strings,
                               const std::string& dexName,
                               std::vector<DexFinding>& out) {
    // Zaten raporlanan tehdit tiplerini tekrar ekleme
    std::unordered_set<int> reported;

    for (const auto& s : strings) {
        if (s.empty() || s.size() > 512) continue;

        for (const auto* pat = STRING_PATTERNS; pat->needle != nullptr; ++pat) {
            if (reported.count(static_cast<int>(pat->threat))) continue;
            if (s.find(pat->needle) != std::string::npos) {
                DexFinding f;
                f.threat      = pat->threat;
                f.dexFile     = dexName;
                f.methodOrStr = s.substr(0, 80);
                f.severity    = pat->severity;
                f.description = pat->description;
                out.push_back(f);
                reported.insert(static_cast<int>(pat->threat));
                LOGW("DEX tehdit [%s]: %s — %s",
                     dexName.c_str(), pat->needle, pat->description);
                break;
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════════
//  Type (sınıf) isimleri üzerinden analiz
//  DEX descriptor formatı: "Lcom/example/MyClass;" şeklinde
// ══════════════════════════════════════════════════════════════════
struct TypePattern {
    const char*  needle;
    DexThreat    threat;
    uint8_t      severity;
    const char*  description;
};

static const TypePattern TYPE_PATTERNS[] = {
    { "Ldalvik/system/DexClassLoader;", DexThreat::REFLECTION_CLASSLOAD, 8,
      "DexClassLoader sınıfı mevcut" },
    { "Ljava/lang/reflect/",            DexThreat::REFLECTION_CLASSLOAD, 5,
      "Reflection API kullanımı" },
    { "Landroid/app/admin/DevicePolicyManager;", DexThreat::DEVICE_ADMIN, 9,
      "DevicePolicyManager sınıfı" },
    { "Landroid/accessibilityservice/",  DexThreat::ACCESSIBILITY_ABUSE, 7,
      "AccessibilityService sınıfı" },
    { "Landroid/telephony/SmsManager;",  DexThreat::SMS_ABUSE, 7,
      "SmsManager sınıfı" },
    { "Landroid/accounts/AccountManager;",DexThreat::ACCOUNT_STEAL, 7,
      "AccountManager sınıfı" },
    { "Landroid/content/pm/PackageInstaller;",DexThreat::PACKAGE_INSTALLER,8,
      "PackageInstaller sınıfı" },
    { nullptr, DexThreat::REFLECTION_CLASSLOAD, 0, nullptr }
};

void DexAnalyzer::scanTypeNames(const std::vector<std::string>& types,
                                 const std::string& dexName,
                                 std::vector<DexFinding>& out) {
    std::unordered_set<int> reported;

    for (const auto& t : types) {
        for (const auto* pat = TYPE_PATTERNS; pat->needle != nullptr; ++pat) {
            if (reported.count(static_cast<int>(pat->threat))) continue;
            if (t.find(pat->needle) != std::string::npos) {
                DexFinding f;
                f.threat      = pat->threat;
                f.dexFile     = dexName;
                f.className   = t;
                f.severity    = pat->severity;
                f.description = pat->description;
                out.push_back(f);
                reported.insert(static_cast<int>(pat->threat));
                break;
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════════
//  Obfuscation tespiti
//  Kötü yazılımlar genellikle çok kısa (1-2 karakter) sınıf ve
//  metot isimleri kullanır. Normal uygulama oranı < %20
// ══════════════════════════════════════════════════════════════════
void DexAnalyzer::checkObfuscation(const std::vector<std::string>& types,
                                    const std::string& dexName,
                                    std::vector<DexFinding>& out) {
    if (types.size() < 50) return;  // Çok az sınıf → değerlendirme anlamsız

    int shortNames = 0, total = 0;
    for (const auto& t : types) {
        if (t.empty() || t[0] != 'L') continue;
        ++total;
        // Sınıf adının son bölümünü al: "Lcom/a/b;" → "b"
        size_t lastSlash = t.rfind('/');
        size_t lastDot   = t.rfind(';');
        if (lastSlash == std::string::npos || lastDot == std::string::npos) continue;
        size_t nameLen = lastDot - lastSlash - 1;
        if (nameLen <= 2) ++shortNames;  // 1-2 karakter sınıf ismi
    }

    if (total == 0) return;
    double ratio = static_cast<double>(shortNames) / total;

    if (ratio > 0.40) {  // %40'tan fazla kısa isim → yüksek obfuscation
        DexFinding f;
        f.threat      = DexThreat::OBFUSCATION;
        f.dexFile     = dexName;
        f.severity    = (ratio > 0.70) ? 8 : 6;
        f.description = "Yüksek obfuscation: %" +
                        std::to_string(static_cast<int>(ratio * 100)) +
                        " kısa sınıf ismi (" +
                        std::to_string(shortNames) + "/" +
                        std::to_string(total) + ")";
        out.push_back(f);
        LOGW("Obfuscation tespit edildi [%s]: %.0f%%", dexName.c_str(), ratio*100);
    }
}

// ══════════════════════════════════════════════════════════════════
//  Ana DEX analiz fonksiyonu
// ══════════════════════════════════════════════════════════════════
std::vector<DexFinding> DexAnalyzer::analyze(const uint8_t* dexData,
                                               size_t          dexLen,
                                               const std::string& dexName) {
    std::vector<DexFinding> findings;

    if (!isDexValid(dexData, dexLen)) {
        LOGW("Geçersiz DEX: %s", dexName.c_str());
        return findings;
    }

    const DexHeader& hdr = *reinterpret_cast<const DexHeader*>(dexData);

    // Temel sınır kontrolleri
    if (hdr.fileSize > dexLen ||
        hdr.headerSize < sizeof(DexHeader)) {
        LOGW("DEX header tutarsız: %s", dexName.c_str());
        return findings;
    }

    LOGI("DEX analiz: %s (strings=%u, types=%u, methods=%u)",
         dexName.c_str(), hdr.stringIdsSize, hdr.typeIdsSize, hdr.methodIdsSize);

    // 1. String analizi
    auto strings = extractStrings(dexData, dexLen, hdr);
    scanStrings(strings, dexName, findings);

    // 2. Type ismi analizi
    auto types = extractTypeNames(dexData, dexLen, hdr);
    scanTypeNames(types, dexName, findings);

    // 3. Obfuscation kontrolü
    checkObfuscation(types, dexName, findings);

    return findings;
}

} // namespace AntiVirus
