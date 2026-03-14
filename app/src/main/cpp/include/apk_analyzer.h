#pragma once
#ifndef APK_ANALYZER_H
#define APK_ANALYZER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>

namespace AntiVirus {

// ══════════════════════════════════════════════════════════════════
//  İzin risk kategorileri
// ══════════════════════════════════════════════════════════════════
enum class PermRisk {
    NONE        = 0,  // Sistem izni, zararsız
    LOW         = 1,  // Düşük risk (internet gibi çok yaygın)
    MEDIUM      = 2,  // Orta risk — dikkat gerektirir
    HIGH        = 3,  // Yüksek risk — çoğu uygulamanın ihtiyacı yok
    CRITICAL    = 4,  // Kritik — olağan dışı; genellikle kötü niyetli
};

// ══════════════════════════════════════════════════════════════════
//  İzin kaydı (veritabanı satırı)
// ══════════════════════════════════════════════════════════════════
struct PermissionEntry {
    const char* name;        // "android.permission.READ_CONTACTS"
    PermRisk    risk;
    const char* category;    // "privacy", "finance", "system", "network" vb.
    const char* description; // İnsan okunabilir açıklama
};

// ══════════════════════════════════════════════════════════════════
//  Tek izin analiz sonucu
// ══════════════════════════════════════════════════════════════════
struct PermissionResult {
    std::string name;
    PermRisk    risk;
    std::string category;
    std::string description;
    bool        isDangerous;    // Android "dangerous" protection level
    bool        isSignature;    // Sistem/signature izni
    bool        isUnknown;      // DB'de yok
};

// ══════════════════════════════════════════════════════════════════
//  Manifest bileşen bilgileri
// ══════════════════════════════════════════════════════════════════
struct ComponentInfo {
    std::string name;         // Sınıf adı
    std::string type;         // "activity", "service", "receiver", "provider"
    bool        exported;     // android:exported="true"
    bool        hasIntentFilter; // Intent filter var mı?
    std::vector<std::string> actions;    // Intent action'ları
    std::vector<std::string> categories;
    std::string permission;   // Bileşen düzeyinde izin
};

// ══════════════════════════════════════════════════════════════════
//  AndroidManifest.xml analiz sonucu
// ══════════════════════════════════════════════════════════════════
struct ManifestInfo {
    std::string packageName;
    std::string versionName;
    uint32_t    versionCode;
    uint32_t    minSdkVersion;
    uint32_t    targetSdkVersion;

    // İzinler
    std::vector<PermissionResult> requestedPermissions;
    std::vector<std::string>      customPermissions;     // Uygulamanın tanımladıkları

    // Bileşenler
    std::vector<ComponentInfo> components;

    // Özellikler
    bool debuggable;            // android:debuggable="true" ❗
    bool allowBackup;           // android:allowBackup="true"
    bool usesCleartextTraffic;  // http://... ❗
    bool requestLegacyStorage;
    bool networkSecurityConfig;

    // Şüpheli intent filter'lar
    std::vector<std::string> suspiciousActions;
};

// ══════════════════════════════════════════════════════════════════
//  DEX içi tehlikeli API kullanımı
// ══════════════════════════════════════════════════════════════════
enum class DexThreat {
    REFLECTION_CLASSLOAD,   // DexClassLoader / PathClassLoader dinamik yükleme
    NATIVE_CODE,            // System.loadLibrary / Runtime.exec
    CRYPTO_WEAK,            // MD5/DES/ECB kullanımı
    OBFUSCATION,            // Anormal kısa sınıf/metot isimleri oranı
    SMS_ABUSE,              // SmsManager.sendTextMessage
    CALL_ABUSE,             // TelephonyManager.call
    DEVICE_ADMIN,           // DevicePolicyManager kullanımı ❗
    ACCESSIBILITY_ABUSE,    // AccessibilityService
    OVERLAY_ATTACK,         // TYPE_APPLICATION_OVERLAY
    CAMERA_MICROPHONE,      // MediaRecorder gizli kayıt
    CLIPBOARD_MONITOR,      // ClipboardManager sürekli izleme
    KEYLOGGER_PATTERN,      // KeyEvent dinleyici + ağ gönderimi
    ACCOUNT_STEAL,          // AccountManager.getAuthToken
    PACKAGE_INSTALLER,      // PackageInstaller programatik yükleme
    PROCESS_EXEC,           // Runtime.getRuntime().exec()
    SHELL_CMD,              // ProcessBuilder + /bin/sh
};

struct DexFinding {
    DexThreat   threat;
    std::string dexFile;       // "classes.dex", "classes2.dex" vb.
    std::string className;     // Bulunan sınıf
    std::string methodOrStr;   // Hangi metot veya string
    uint8_t     severity;      // 1–10
    std::string description;
};

// ══════════════════════════════════════════════════════════════════
//  APK imza bilgisi
// ══════════════════════════════════════════════════════════════════
struct SignatureInfo {
    bool        isSigned;
    std::string sigScheme;    // "v1", "v2", "v3", "v4"
    std::string issuer;
    std::string subject;
    bool        isDebugCert;  // CN=Android Debug → şüpheli
    bool        isExpired;
    std::string sha256Fingerprint;
    int         keySize;      // RSA bit genişliği
};

// ══════════════════════════════════════════════════════════════════
//  Tam APK analiz raporu
// ══════════════════════════════════════════════════════════════════
struct ApkReport {
    std::string apkPath;
    std::string sha256;
    std::string md5;
    uint64_t    fileSize;

    ManifestInfo manifest;
    SignatureInfo signature;
    std::vector<DexFinding> dexFindings;

    // Tehdit skorları (0–100)
    uint32_t permissionScore;   // İzin riski
    uint32_t behaviorScore;     // DEX davranış riski
    uint32_t signatureScore;    // İmza riski
    uint32_t overallScore;      // Genel risk skoru

    // Özet
    uint32_t criticalPermCount;
    uint32_t highPermCount;
    uint32_t exportedComponentCount;
    uint32_t exportedWithoutPermCount;  // İzinsiz dışa açık bileşen ❗

    bool     hasKnownMalwareSignature;  // Hash DB'de bulundu
    bool     isRepackaged;             // Orijinal imza değiştirilmiş
    std::string verdict;               // "CLEAN" | "SUSPICIOUS" | "MALWARE"

    double   analysisDurationMs;
    std::string toJSON() const;
};

// ══════════════════════════════════════════════════════════════════
//  AXML (Android Binary XML) Parser
// ══════════════════════════════════════════════════════════════════
class AXMLParser {
public:
    // Ham AXML baytlarından manifest bilgilerini çıkar
    bool parse(const uint8_t* data, size_t length, ManifestInfo& out);

private:
    const uint8_t* m_data   = nullptr;
    size_t         m_length = 0;
    size_t         m_pos    = 0;

    // String pool
    std::vector<std::string> m_strings;

    // Chunk türleri
    static constexpr uint16_t CHUNK_NULL         = 0x0000;
    static constexpr uint16_t CHUNK_STRING_POOL  = 0x0001;
    static constexpr uint16_t CHUNK_TABLE        = 0x0002;
    static constexpr uint16_t CHUNK_XML          = 0x0003;
    static constexpr uint16_t CHUNK_XML_START_NS = 0x0100;
    static constexpr uint16_t CHUNK_XML_END_NS   = 0x0101;
    static constexpr uint16_t CHUNK_XML_START_EL = 0x0102;
    static constexpr uint16_t CHUNK_XML_END_EL   = 0x0103;
    static constexpr uint16_t CHUNK_XML_CDATA    = 0x0104;
    static constexpr uint16_t CHUNK_XML_RES_MAP  = 0x0180;

    // Değer tipleri
    static constexpr uint8_t TYPE_NULL       = 0x00;
    static constexpr uint8_t TYPE_REFERENCE  = 0x01;
    static constexpr uint8_t TYPE_STRING     = 0x03;
    static constexpr uint8_t TYPE_INT_DEC    = 0x10;
    static constexpr uint8_t TYPE_INT_HEX    = 0x11;
    static constexpr uint8_t TYPE_INT_BOOL   = 0x12;

    bool     parseStringPool();
    bool     parseXmlChunks(ManifestInfo& out);
    bool     parseStartElement(ManifestInfo& out,
                                ComponentInfo* curComp,
                                std::string& curTag);

    uint8_t  readU8 ();
    uint16_t readU16();
    uint32_t readU32();
    bool     canRead(size_t n) const;

    std::string getString(uint32_t idx) const;
    std::string resolveAttrValue(uint8_t type, uint32_t data) const;
};

// ══════════════════════════════════════════════════════════════════
//  ZIP okuyucu (minizip bağımlılığı olmadan — lightweight)
// ══════════════════════════════════════════════════════════════════
struct ZipEntry {
    std::string  name;
    uint32_t     compressedSize;
    uint32_t     uncompressedSize;
    uint32_t     compression;   // 0=store, 8=deflate
    uint32_t     localOffset;
};

class ZipReader {
public:
    explicit ZipReader(const std::string& path);
    ~ZipReader();

    bool open();
    void close();

    std::vector<ZipEntry>  listEntries() const;
    std::vector<uint8_t>   extract(const std::string& entryName) const;

private:
    std::string m_path;
    int         m_fd = -1;
    uint64_t    m_fileSize = 0;

    std::vector<ZipEntry> m_entries;

    bool   findEndOfCentralDir(uint32_t& eocdOffset);
    bool   parseCentralDir(uint32_t eocdOffset);
    bool   inflate(const uint8_t* src, size_t srcLen,
                   std::vector<uint8_t>& dst, size_t dstLen) const;
};

// ══════════════════════════════════════════════════════════════════
//  DEX Dosya Analizörü
// ══════════════════════════════════════════════════════════════════
class DexAnalyzer {
public:
    // DEX baytlarından tehlikeli API + string kalıplarını tara
    std::vector<DexFinding> analyze(const uint8_t* dexData,
                                     size_t          dexLen,
                                     const std::string& dexName);

private:
    struct DexHeader {
        uint8_t  magic[8];
        uint8_t  checksum[4];
        uint8_t  sha1[20];
        uint32_t fileSize;
        uint32_t headerSize;
        uint32_t endianTag;
        uint32_t linkSize;
        uint32_t linkOff;
        uint32_t mapOff;
        uint32_t stringIdsSize;
        uint32_t stringIdsOff;
        uint32_t typeIdsSize;
        uint32_t typeIdsOff;
        uint32_t protoIdsSize;
        uint32_t protoIdsOff;
        uint32_t fieldIdsSize;
        uint32_t fieldIdsOff;
        uint32_t methodIdsSize;
        uint32_t methodIdsOff;
        uint32_t classDefsSize;
        uint32_t classDefsOff;
        uint32_t dataSize;
        uint32_t dataOff;
    };

    std::vector<std::string> extractStrings (const uint8_t* data, size_t len,
                                              const DexHeader& hdr);
    std::vector<std::string> extractTypeNames(const uint8_t* data, size_t len,
                                              const DexHeader& hdr);
    void scanStrings  (const std::vector<std::string>& strings,
                       const std::string& dexName,
                       std::vector<DexFinding>& out);
    void scanTypeNames(const std::vector<std::string>& types,
                       const std::string& dexName,
                       std::vector<DexFinding>& out);
    void checkObfuscation(const std::vector<std::string>& types,
                          const std::string& dexName,
                          std::vector<DexFinding>& out);

    static bool isDexValid(const uint8_t* data, size_t len);
};

// ══════════════════════════════════════════════════════════════════
//  İzin Veritabanı
// ══════════════════════════════════════════════════════════════════
class PermissionDB {
public:
    static PermissionDB& instance();

    PermissionResult lookup(const std::string& permName) const;
    bool             isDangerous(const std::string& permName) const;

    // Kombinasyon analizi: birlikte kullanıldığında tehlikeli izin grupları
    std::vector<std::string> checkCombinations(
        const std::vector<std::string>& perms) const;

private:
    PermissionDB();
    static const PermissionEntry PERMISSION_TABLE[];
};

// ══════════════════════════════════════════════════════════════════
//  Ana APK Analizörü
// ══════════════════════════════════════════════════════════════════
class ApkAnalyzer {
public:
    ApkReport analyze(const std::string& apkPath);

private:
    void analyzeManifest (ZipReader& zip, ApkReport& report);
    void analyzeSignature(const std::string& apkPath, ApkReport& report);
    void analyzeDex      (ZipReader& zip, ApkReport& report);
    void computeScores   (ApkReport& report);
    void assessExportedComponents(ApkReport& report);
    void detectRepackaging(const std::string& apkPath, ApkReport& report);

    uint32_t scorePermissions(const ManifestInfo& manifest);
    uint32_t scoreDexFindings(const std::vector<DexFinding>& findings);
};

} // namespace AntiVirus

#endif // APK_ANALYZER_H
