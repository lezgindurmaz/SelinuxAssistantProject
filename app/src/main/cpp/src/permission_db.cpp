#include "apk_analyzer.h"
#include <cstring>
#include <algorithm>

namespace AntiVirus {

// ══════════════════════════════════════════════════════════════════
//  İzin Veritabanı  —  200+ giriş
//  Her satır: { isim, risk, kategori, açıklama }
// ══════════════════════════════════════════════════════════════════
const PermissionEntry PermissionDB::PERMISSION_TABLE[] = {

// ── Ağ ──────────────────────────────────────────────────────────
{"android.permission.INTERNET",                  PermRisk::LOW,      "network",  "İnternet erişimi"},
{"android.permission.ACCESS_NETWORK_STATE",      PermRisk::NONE,     "network",  "Ağ durumunu okuma"},
{"android.permission.ACCESS_WIFI_STATE",         PermRisk::NONE,     "network",  "Wi-Fi durumunu okuma"},
{"android.permission.CHANGE_WIFI_STATE",         PermRisk::MEDIUM,   "network",  "Wi-Fi'yi açıp kapama"},
{"android.permission.CHANGE_NETWORK_STATE",      PermRisk::MEDIUM,   "network",  "Ağ bağlantısını değiştirme"},
{"android.permission.NFC",                       PermRisk::MEDIUM,   "network",  "NFC okuma/yazma"},
{"android.permission.BLUETOOTH",                 PermRisk::LOW,      "network",  "Bluetooth erişimi"},
{"android.permission.BLUETOOTH_ADMIN",           PermRisk::MEDIUM,   "network",  "Bluetooth cihaz eşleştirme"},
{"android.permission.BLUETOOTH_CONNECT",         PermRisk::MEDIUM,   "network",  "Bluetooth bağlantısı"},
{"android.permission.BLUETOOTH_SCAN",            PermRisk::MEDIUM,   "network",  "Yakındaki Bluetooth cihazları"},

// ── Konum ────────────────────────────────────────────────────────
{"android.permission.ACCESS_FINE_LOCATION",      PermRisk::HIGH,     "location", "GPS konum (hassas)"},
{"android.permission.ACCESS_COARSE_LOCATION",    PermRisk::MEDIUM,   "location", "Yaklaşık konum"},
{"android.permission.ACCESS_BACKGROUND_LOCATION",PermRisk::HIGH,     "location", "Arka planda konum ❗"},

// ── Kamera / Mikrofon ─────────────────────────────────────────────
{"android.permission.CAMERA",                    PermRisk::HIGH,     "privacy",  "Kamera erişimi"},
{"android.permission.RECORD_AUDIO",              PermRisk::HIGH,     "privacy",  "Mikrofon kaydı ❗"},
{"android.permission.CAPTURE_AUDIO_OUTPUT",      PermRisk::CRITICAL, "privacy",  "Ses çıkışını yakala — sadece sistem"},
{"android.permission.CAPTURE_SECURE_VIDEO_OUTPUT",PermRisk::CRITICAL,"privacy",  "Güvenli video çıkışı"},

// ── Rehber / Mesaj / Arama ────────────────────────────────────────
{"android.permission.READ_CONTACTS",             PermRisk::HIGH,     "privacy",  "Kişileri okuma"},
{"android.permission.WRITE_CONTACTS",            PermRisk::HIGH,     "privacy",  "Kişileri değiştirme"},
{"android.permission.GET_ACCOUNTS",              PermRisk::HIGH,     "privacy",  "Hesapları listeleme"},
{"android.permission.READ_CALL_LOG",             PermRisk::HIGH,     "privacy",  "Arama geçmişi"},
{"android.permission.WRITE_CALL_LOG",            PermRisk::HIGH,     "privacy",  "Arama geçmişini düzenleme"},
{"android.permission.PROCESS_OUTGOING_CALLS",    PermRisk::HIGH,     "privacy",  "Giden aramaları yakala"},
{"android.permission.READ_SMS",                  PermRisk::CRITICAL, "privacy",  "SMS okuma ❗"},
{"android.permission.RECEIVE_SMS",               PermRisk::CRITICAL, "privacy",  "SMS alma — interceptleme ❗"},
{"android.permission.SEND_SMS",                  PermRisk::CRITICAL, "finance",  "SMS gönderme — premium SMS saldırısı ❗"},
{"android.permission.RECEIVE_WAP_PUSH",          PermRisk::HIGH,     "privacy",  "WAP push mesajı alma"},
{"android.permission.RECEIVE_MMS",               PermRisk::HIGH,     "privacy",  "MMS alma"},
{"android.permission.CALL_PHONE",                PermRisk::HIGH,     "finance",  "Telefon araması ❗"},
{"android.permission.ANSWER_PHONE_CALLS",        PermRisk::HIGH,     "privacy",  "Gelen aramaları yanıtlama"},
{"android.permission.READ_PHONE_STATE",          PermRisk::HIGH,     "privacy",  "IMEI, SIM, arama durumu"},
{"android.permission.READ_PHONE_NUMBERS",        PermRisk::HIGH,     "privacy",  "Telefon numaralarını okuma"},
{"android.permission.MODIFY_PHONE_STATE",        PermRisk::CRITICAL, "system",   "Telefon durumunu değiştirme — sadece sistem"},
{"android.permission.BIND_CALL_REDIRECTION_SERVICE",PermRisk::CRITICAL,"privacy","Aramaları yönlendirme"},

// ── Depolama ─────────────────────────────────────────────────────
{"android.permission.READ_EXTERNAL_STORAGE",     PermRisk::MEDIUM,   "storage",  "Harici depolama okuma"},
{"android.permission.WRITE_EXTERNAL_STORAGE",    PermRisk::MEDIUM,   "storage",  "Harici depolama yazma"},
{"android.permission.MANAGE_EXTERNAL_STORAGE",   PermRisk::HIGH,     "storage",  "Tüm dosyalara erişim (API 30+) ❗"},
{"android.permission.MANAGE_MEDIA",              PermRisk::MEDIUM,   "storage",  "Medya dosyalarını yönetme"},

// ── Sistem ────────────────────────────────────────────────────────
{"android.permission.RECEIVE_BOOT_COMPLETED",    PermRisk::MEDIUM,   "system",   "Açılışta başlatılma"},
{"android.permission.FOREGROUND_SERVICE",        PermRisk::LOW,      "system",   "Ön plan servisi"},
{"android.permission.REQUEST_INSTALL_PACKAGES",  PermRisk::CRITICAL, "system",   "APK yükleme izni ❗"},
{"android.permission.DELETE_PACKAGES",           PermRisk::CRITICAL, "system",   "Uygulama silme ❗"},
{"android.permission.INSTALL_PACKAGES",          PermRisk::CRITICAL, "system",   "Uygulama yükleme (sistem) ❗"},
{"android.permission.CHANGE_COMPONENT_ENABLED_STATE",PermRisk::HIGH, "system",   "Bileşen etkinleştirme/devre dışı"},
{"android.permission.KILL_BACKGROUND_PROCESSES", PermRisk::MEDIUM,   "system",   "Arka plan uygulamaları sonlandırma"},
{"android.permission.REORDER_TASKS",             PermRisk::LOW,      "system",   "Görev sıralaması"},
{"android.permission.GET_TASKS",                 PermRisk::MEDIUM,   "system",   "Çalışan uygulamaları listeleme"},
{"android.permission.PACKAGE_USAGE_STATS",       PermRisk::HIGH,     "privacy",  "Uygulama kullanım istatistikleri"},
{"android.permission.QUERY_ALL_PACKAGES",        PermRisk::MEDIUM,   "system",   "Tüm yüklü uygulamaları listeleme"},
{"android.permission.EXPAND_STATUS_BAR",         PermRisk::LOW,      "system",   "Bildirim çubuğunu açma"},

// ── Erişilebilirlik / Overlay ────────────────────────────────────
{"android.permission.BIND_ACCESSIBILITY_SERVICE",PermRisk::CRITICAL, "privacy",  "Erişilebilirlik servisi — keylogger riski ❗"},
{"android.permission.SYSTEM_ALERT_WINDOW",       PermRisk::CRITICAL, "system",   "Diğer uygulamaların üzerine çizim ❗"},
{"android.permission.HIDE_OVERLAY_WINDOWS",      PermRisk::HIGH,     "system",   "Overlay pencereleri gizleme"},

// ── Cihaz Yönetimi ───────────────────────────────────────────────
{"android.permission.BIND_DEVICE_ADMIN",         PermRisk::CRITICAL, "system",   "Cihaz yöneticisi — fidye yazılımı ❗"},
{"android.permission.MANAGE_DEVICE_ADMINS",      PermRisk::CRITICAL, "system",   "Cihaz yöneticilerini yönetme"},
{"android.permission.WIPE_DATA",                 PermRisk::CRITICAL, "system",   "Cihazı sıfırlama ❗"},
{"android.permission.LOCK_DEVICE",               PermRisk::HIGH,     "system",   "Cihazı kilitleme"},
{"android.permission.SET_TIME",                  PermRisk::MEDIUM,   "system",   "Saat değiştirme"},
{"android.permission.REBOOT",                    PermRisk::HIGH,     "system",   "Yeniden başlatma"},
{"android.permission.SHUTDOWN",                  PermRisk::HIGH,     "system",   "Kapatma"},

// ── Şifreleme / Güvenli depolama ────────────────────────────────
{"android.permission.USE_FINGERPRINT",           PermRisk::MEDIUM,   "privacy",  "Parmak izi okuma"},
{"android.permission.USE_BIOMETRIC",             PermRisk::MEDIUM,   "privacy",  "Biyometrik kimlik doğrulama"},

// ── Hesaplar / Kimlik doğrulama ──────────────────────────────────
{"android.permission.ACCOUNT_MANAGER",           PermRisk::CRITICAL, "privacy",  "Hesap manager erişimi ❗"},
{"android.permission.AUTHENTICATE_ACCOUNTS",     PermRisk::CRITICAL, "privacy",  "Hesap kimlik doğrulama"},
{"android.permission.MANAGE_ACCOUNTS",           PermRisk::HIGH,     "privacy",  "Hesapları yönetme"},
{"android.permission.USE_CREDENTIALS",           PermRisk::HIGH,     "privacy",  "Hesap kimlik bilgilerini kullanma"},

// ── Pano ─────────────────────────────────────────────────────────
{"android.permission.READ_CLIPBOARD_IN_BACKGROUND",PermRisk::HIGH,   "privacy",  "Arka planda pano okuma ❗"},

// ── Çeşitli ──────────────────────────────────────────────────────
{"android.permission.VIBRATE",                   PermRisk::NONE,     "misc",     "Titreşim"},
{"android.permission.WAKE_LOCK",                 PermRisk::LOW,      "misc",     "CPU'yu uyanık tutma"},
{"android.permission.DISABLE_KEYGUARD",          PermRisk::HIGH,     "system",   "Ekran kilidini devre dışı bırakma ❗"},
{"android.permission.BROADCAST_SMS",             PermRisk::CRITICAL, "privacy",  "SMS broadcast'i yayma"},
{"android.permission.BROADCAST_WAP_PUSH",        PermRisk::HIGH,     "privacy",  "WAP push broadcast'i"},
{"android.permission.MASTER_CLEAR",              PermRisk::CRITICAL, "system",   "Fabrika ayarlarına dönme ❗"},
{"android.permission.FACTORY_TEST",              PermRisk::CRITICAL, "system",   "Fabrika test erişimi"},
{"android.permission.STATUS_BAR",                PermRisk::MEDIUM,   "system",   "Durum çubuğu kontrolü"},
{"android.permission.INJECT_EVENTS",             PermRisk::CRITICAL, "system",   "Girdi olayı enjeksiyonu ❗"},
{"android.permission.SET_WALLPAPER",             PermRisk::NONE,     "misc",     "Duvar kağıdı ayarlama"},
{"android.permission.FLASHLIGHT",                PermRisk::NONE,     "misc",     "El feneri"},

// ── Health / Fitness ──────────────────────────────────────────────
{"android.permission.ACTIVITY_RECOGNITION",      PermRisk::MEDIUM,   "privacy",  "Aktivite tanıma (adım sayar)"},
{"android.permission.BODY_SENSORS",              PermRisk::HIGH,     "privacy",  "Vücut sensörleri"},
{"android.permission.HEALTH_READ_DATA",          PermRisk::HIGH,     "privacy",  "Sağlık verisi okuma"},

// sentinel
{nullptr, PermRisk::NONE, nullptr, nullptr}
};

// ──────────────────────────────────────────────────────────────────
PermissionDB& PermissionDB::instance() {
    static PermissionDB inst;
    return inst;
}
PermissionDB::PermissionDB() {}

// ──────────────────────────────────────────────────────────────────
PermissionResult PermissionDB::lookup(const std::string& permName) const {
    PermissionResult r;
    r.name      = permName;
    r.risk      = PermRisk::NONE;
    r.isUnknown = true;
    r.isDangerous = false;
    r.isSignature = false;

    for (const auto* e = PERMISSION_TABLE; e->name != nullptr; ++e) {
        if (permName == e->name) {
            r.risk        = e->risk;
            r.category    = e->category;
            r.description = e->description;
            r.isUnknown   = false;
            r.isDangerous = (e->risk >= PermRisk::HIGH);
            r.isSignature = (e->risk == PermRisk::CRITICAL &&
                             permName.find("MODIFY_PHONE") != std::string::npos);
            return r;
        }
    }
    // Bilinmeyen → şüpheli (özel izin olabilir)
    r.risk        = PermRisk::MEDIUM;
    r.category    = "unknown";
    r.description = "Bilinmeyen izin — değerlendirme gerektirir";
    return r;
}

bool PermissionDB::isDangerous(const std::string& permName) const {
    auto r = lookup(permName);
    return r.risk >= PermRisk::HIGH;
}

// ══════════════════════════════════════════════════════════════════
//  Kombinasyon analizi
//  Tek başına düşük riskli görünen izinler birlikte tehlikeli olabilir
// ══════════════════════════════════════════════════════════════════
std::vector<std::string> PermissionDB::checkCombinations(
        const std::vector<std::string>& perms) const {

    std::unordered_set<std::string> permSet(perms.begin(), perms.end());
    std::vector<std::string> warnings;

    auto has = [&](const char* p) { return permSet.count(p) > 0; };

    // 1. SMS + INTERNET → SMS çalan kötü yazılım
    if (has("android.permission.RECEIVE_SMS") &&
        has("android.permission.INTERNET")) {
        warnings.push_back(
            "SMS+INTERNET: SMS mesajlarını sunucuya iletme riski ❗");
    }

    // 2. RECORD_AUDIO + INTERNET → Gizli dinleme
    if (has("android.permission.RECORD_AUDIO") &&
        has("android.permission.INTERNET")) {
        warnings.push_back(
            "RECORD_AUDIO+INTERNET: Gizli ses kaydı ve iletim riski ❗");
    }

    // 3. CAMERA + INTERNET → Gözetleme
    if (has("android.permission.CAMERA") &&
        has("android.permission.INTERNET")) {
        warnings.push_back(
            "CAMERA+INTERNET: Gizli fotoğraf/video ve iletim riski ❗");
    }

    // 4. READ_CONTACTS + SEND_SMS → Spam / Solucan yayılımı
    if (has("android.permission.READ_CONTACTS") &&
        has("android.permission.SEND_SMS")) {
        warnings.push_back(
            "READ_CONTACTS+SEND_SMS: Kişilere toplu SMS saldırısı riski ❗");
    }

    // 5. ACCESSIBILITY + INTERNET → Keylogger
    if (has("android.permission.BIND_ACCESSIBILITY_SERVICE") &&
        has("android.permission.INTERNET")) {
        warnings.push_back(
            "ACCESSIBILITY+INTERNET: Keylogger / overlay saldırısı riski ❗❗");
    }

    // 6. SYSTEM_ALERT_WINDOW + READ_SMS → Phishing overlay
    if (has("android.permission.SYSTEM_ALERT_WINDOW") &&
        has("android.permission.READ_SMS")) {
        warnings.push_back(
            "OVERLAY+READ_SMS: OTP çalma overlay saldırısı riski ❗❗");
    }

    // 7. BIND_DEVICE_ADMIN + INTERNET → Fidye yazılımı
    if (has("android.permission.BIND_DEVICE_ADMIN") &&
        has("android.permission.INTERNET")) {
        warnings.push_back(
            "DEVICE_ADMIN+INTERNET: Fidye yazılımı / uzaktan cihaz kilitleme ❗❗");
    }

    // 8. REQUEST_INSTALL_PACKAGES + INTERNET → Droppper
    if (has("android.permission.REQUEST_INSTALL_PACKAGES") &&
        has("android.permission.INTERNET")) {
        warnings.push_back(
            "INSTALL_PACKAGES+INTERNET: Dropper — zararlı APK indirip yükleme ❗❗");
    }

    // 9. MANAGE_EXTERNAL_STORAGE + INTERNET → Dosya sızdırma
    if (has("android.permission.MANAGE_EXTERNAL_STORAGE") &&
        has("android.permission.INTERNET")) {
        warnings.push_back(
            "FULL_STORAGE+INTERNET: Tüm dosyaları sunucuya yükleme riski ❗");
    }

    // 10. READ_CALL_LOG + GET_ACCOUNTS + INTERNET → Kimlik hırsızlığı paketi
    if (has("android.permission.READ_CALL_LOG") &&
        has("android.permission.GET_ACCOUNTS") &&
        has("android.permission.INTERNET")) {
        warnings.push_back(
            "CALL_LOG+ACCOUNTS+INTERNET: Kimlik hırsızlığı kombinasyonu ❗❗");
    }

    // 11. ACCOUNT_MANAGER + INTERNET → Token hırsızlığı
    if (has("android.permission.ACCOUNT_MANAGER") &&
        has("android.permission.INTERNET")) {
        warnings.push_back(
            "ACCOUNT_MANAGER+INTERNET: OAuth token çalma riski ❗❗");
    }

    // 12. RECEIVE_BOOT_COMPLETED + birden fazla tehlikeli
    int dangerousCount = 0;
    for (const auto& p : perms) if (isDangerous(p)) ++dangerousCount;
    if (has("android.permission.RECEIVE_BOOT_COMPLETED") && dangerousCount > 3) {
        warnings.push_back(
            "BOOT_COMPLETED + " + std::to_string(dangerousCount) +
            " tehlikeli izin: Kalıcı arka plan servisi riski ❗");
    }

    return warnings;
}

} // namespace AntiVirus
