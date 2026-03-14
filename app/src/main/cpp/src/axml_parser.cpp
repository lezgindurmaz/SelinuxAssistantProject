#include "apk_analyzer.h"
#include <cstring>
#include <android/log.h>

#define LOG_TAG "AV_AXML"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ══════════════════════════════════════════════════════════════════
//  AXML (Android Binary XML) Format
//
//  Tüm yapı little-endian.
//
//  ┌──────────────────────────────────────────────────────────────┐
//  │  ResXMLTree_header   (magic=0x0003, headerSize, fileSize)    │
//  │  ─────────────────────────────────────────────────────────── │
//  │  StringPool Chunk    (tüm string'ler burada)                 │
//  │  ─────────────────────────────────────────────────────────── │
//  │  ResID Map Chunk     (opsiyonel, attribute resource IDs)     │
//  │  ─────────────────────────────────────────────────────────── │
//  │  XML Node Chunk'ları (START_NS, START_EL, END_EL, END_NS...) │
//  └──────────────────────────────────────────────────────────────┘
//
//  Her chunk başında: { uint16_t type, uint16_t headerSize,
//                       uint32_t chunkSize }
// ══════════════════════════════════════════════════════════════════

namespace AntiVirus {

// ──────────────────────────────────────────────────────────────────
//  Düşük seviyeli okuma yardımcıları
// ──────────────────────────────────────────────────────────────────
bool AXMLParser::canRead(size_t n) const {
    return (m_pos + n) <= m_length;
}
uint8_t  AXMLParser::readU8()  { return m_data[m_pos++]; }
uint16_t AXMLParser::readU16() {
    uint16_t v = (uint16_t)m_data[m_pos] | ((uint16_t)m_data[m_pos+1] << 8);
    m_pos += 2; return v;
}
uint32_t AXMLParser::readU32() {
    uint32_t v = (uint32_t)m_data[m_pos]
               | ((uint32_t)m_data[m_pos+1] <<  8)
               | ((uint32_t)m_data[m_pos+2] << 16)
               | ((uint32_t)m_data[m_pos+3] << 24);
    m_pos += 4; return v;
}

// String pool'dan string al
std::string AXMLParser::getString(uint32_t idx) const {
    if (idx >= m_strings.size() || idx == 0xFFFFFFFF) return "";
    return m_strings[idx];
}

// Attribute değerini çöz
std::string AXMLParser::resolveAttrValue(uint8_t type, uint32_t data) const {
    switch (type) {
        case TYPE_STRING:   return getString(data);
        case TYPE_INT_DEC:  return std::to_string(static_cast<int32_t>(data));
        case TYPE_INT_HEX:  { char buf[12]; snprintf(buf,sizeof(buf),"0x%x",data); return buf; }
        case TYPE_INT_BOOL: return data ? "true" : "false";
        case TYPE_REFERENCE:{ char buf[16]; snprintf(buf,sizeof(buf),"@0x%x",data); return buf; }
        default:            return "";
    }
}

// ══════════════════════════════════════════════════════════════════
//  String Pool Chunk Parser
//
//  ResStringPool_header layout:
//    chunkType(2) headerSize(2) chunkSize(4)
//    stringCount(4) styleCount(4) flags(4)
//    stringsStart(4) stylesStart(4)
//    [stringOffsets × stringCount]
//    [styleOffsets  × styleCount ]
//    [string data (UTF-16 veya UTF-8)]
// ══════════════════════════════════════════════════════════════════
bool AXMLParser::parseStringPool() {
    size_t chunkStart = m_pos - 2;  // type zaten okunmuştu, geri git
    m_pos = chunkStart;

    if (!canRead(28)) return false;

    uint16_t chunkType  = readU16();
    uint16_t headerSize = readU16();
    uint32_t chunkSize  = readU32();
    uint32_t stringCount = readU32();
    uint32_t styleCount  = readU32();
    uint32_t flags       = readU32();
    uint32_t stringsStart = readU32();
    uint32_t stylesStart  = readU32();

    bool isUtf8 = (flags & (1u << 8)) != 0;

    if (stringCount == 0 || chunkSize > m_length) return false;

    // Offset tablosunu oku
    std::vector<uint32_t> offsets(stringCount);
    for (uint32_t i = 0; i < stringCount; ++i) {
        if (!canRead(4)) return false;
        offsets[i] = readU32();
    }

    // Style offsetlerini atla
    m_pos += styleCount * 4;

    // String verilerinin başlangıcı
    size_t dataBase = chunkStart + stringsStart;

    m_strings.clear();
    m_strings.reserve(stringCount);

    for (uint32_t i = 0; i < stringCount; ++i) {
        size_t strOff = dataBase + offsets[i];
        if (strOff >= m_length) { m_strings.push_back(""); continue; }

        std::string result;
        if (isUtf8) {
            // UTF-8: uint8_t charCount, uint8_t byteCount, data...
            // (Android'in özel UTF-8 length encoding'i: 1 veya 2 byte)
            size_t p = strOff;
            auto readLen = [&]() -> uint16_t {
                uint8_t b = m_data[p++];
                if (b & 0x80) return (uint16_t)((b & 0x7F) << 8 | m_data[p++]);
                return b;
            };
            if (p >= m_length) { m_strings.push_back(""); continue; }
            /*uint16_t charLen =*/ readLen();   // UTF-16 char sayısı (kullanmıyoruz)
            if (p >= m_length) { m_strings.push_back(""); continue; }
            uint16_t byteLen = readLen();
            if (p + byteLen > m_length) { m_strings.push_back(""); continue; }
            result.assign(reinterpret_cast<const char*>(m_data + p), byteLen);
        } else {
            // UTF-16LE: uint16_t charCount, [uint16_t chars], uint16_t null
            size_t p = strOff;
            if (p + 2 > m_length) { m_strings.push_back(""); continue; }
            uint16_t charLen = m_data[p] | (m_data[p+1] << 8);
            p += 2;
            for (uint16_t c = 0; c < charLen && p + 1 < m_length; ++c, p += 2) {
                uint16_t ch = m_data[p] | (m_data[p+1] << 8);
                // Basit ASCII dışı karakterler için '?' koy
                if (ch < 0x80) result += static_cast<char>(ch);
                else if (ch < 0x800) {
                    result += static_cast<char>(0xC0 | (ch >> 6));
                    result += static_cast<char>(0x80 | (ch & 0x3F));
                } else {
                    result += '?';
                }
            }
        }
        m_strings.push_back(result);
    }

    // Chunk'ın sonuna atla
    m_pos = chunkStart + chunkSize;
    LOGI("String pool: %zu string yüklendi (%s)",
         m_strings.size(), isUtf8 ? "UTF-8" : "UTF-16");
    return true;
}

// ══════════════════════════════════════════════════════════════════
//  Start Element Parser
//  Layout sonrası (type+headerSize+chunkSize okunmuş):
//    lineNumber(4) comment(4) ns(4) name(4)
//    attrStart(2) attrSize(2) attrCount(2) idIndex(2)
//    classIndex(2) styleIndex(2)
//    [attributes × attrCount]:
//      ns(4) name(4) rawVal(4) size(2) res0(1) dataType(1) data(4)
// ══════════════════════════════════════════════════════════════════
bool AXMLParser::parseStartElement(ManifestInfo& out,
                                    ComponentInfo* curComp,
                                    std::string& curTag) {
    if (!canRead(24)) return false;

    /*uint32_t lineNum =*/ readU32();
    /*uint32_t comment =*/ readU32();
    /*uint32_t ns      =*/ readU32();
    uint32_t nameIdx  =    readU32();

    uint16_t attrStart = readU16();
    uint16_t attrSize  = readU16();
    uint16_t attrCount = readU16();
    /*uint16_t idIdx   =*/ readU16();
    /*uint16_t classIdx=*/ readU16();
    /*uint16_t styleIdx=*/ readU16();

    curTag = getString(nameIdx);

    // Attribute'ları oku
    // Her attribute: ns(4) name(4) rawVal(4) size(2) res0(1) type(1) data(4) = 20 byte
    std::unordered_map<std::string, std::string> attrs;
    for (uint16_t i = 0; i < attrCount; ++i) {
        if (!canRead(20)) break;
        /*uint32_t attrNs  =*/ readU32();
        uint32_t attrName = readU32();
        uint32_t rawVal   = readU32();
        /*uint16_t sz      =*/ readU16();
        /*uint8_t  res0    =*/ readU8();
        uint8_t  dataType =    readU8();
        uint32_t data     =    readU32();

        std::string key = getString(attrName);
        std::string val;
        if (dataType == TYPE_STRING) {
            val = getString(rawVal != 0xFFFFFFFF ? rawVal : data);
        } else {
            val = resolveAttrValue(dataType, data);
        }
        if (!key.empty()) attrs[key] = val;
    }

    // ── Tag'a göre işle ─────────────────────────────────
    if (curTag == "manifest") {
        if (attrs.count("package"))     out.packageName    = attrs["package"];
        if (attrs.count("versionName")) out.versionName    = attrs["versionName"];
        if (attrs.count("versionCode")) {
            try { out.versionCode = std::stoul(attrs["versionCode"]); } catch(...) {}
        }
    }
    else if (curTag == "uses-sdk") {
        if (attrs.count("minSdkVersion")) {
            try { out.minSdkVersion = std::stoul(attrs["minSdkVersion"]); } catch(...) {}
        }
        if (attrs.count("targetSdkVersion")) {
            try { out.targetSdkVersion = std::stoul(attrs["targetSdkVersion"]); } catch(...) {}
        }
    }
    else if (curTag == "uses-permission") {
        if (attrs.count("name") && !attrs["name"].empty()) {
            // Ham ismi sakla; PermissionDB lookup üst katmanda yapılacak
            PermissionResult pr;
            pr.name       = attrs["name"];
            pr.isUnknown  = true;
            out.requestedPermissions.push_back(pr);
        }
    }
    else if (curTag == "permission") {
        // Uygulamanın kendi tanımladığı izin
        if (attrs.count("name")) out.customPermissions.push_back(attrs["name"]);
    }
    else if (curTag == "application") {
        out.debuggable            = (attrs["debuggable"]          == "true");
        out.allowBackup           = (attrs["allowBackup"]         != "false");
        out.usesCleartextTraffic  = (attrs["usesCleartextTraffic"]== "true");
        out.requestLegacyStorage  = (attrs["requestLegacyStorage"]== "true");
        out.networkSecurityConfig = attrs.count("networkSecurityConfig") > 0;
    }
    else if (curTag == "activity"  || curTag == "service" ||
             curTag == "receiver"  || curTag == "provider") {
        ComponentInfo comp;
        comp.type       = curTag;
        comp.name       = attrs.count("name")       ? attrs["name"]       : "";
        comp.permission = attrs.count("permission") ? attrs["permission"] : "";

        // exported varsayılan:
        // activity/service/receiver → intent-filter varsa true, yoksa false
        // provider → API<17'de true; false bırakıyoruz, intent-filter'da güncellenir
        if (attrs.count("exported")) {
            comp.exported = (attrs["exported"] == "true");
        } else {
            comp.exported = false;  // intent-filter bulununca true yapılacak
        }
        out.components.push_back(comp);
    }
    else if (curTag == "intent-filter") {
        // Son eklenen bileşene intent-filter var
        if (!out.components.empty()) {
            out.components.back().hasIntentFilter = true;
            // exported belirtilmemişse ve intent-filter varsa → exported=true
            if (!attrs.count("exported"))
                out.components.back().exported = true;
        }
    }
    else if (curTag == "action") {
        if (!out.components.empty() && attrs.count("name")) {
            std::string action = attrs["name"];
            out.components.back().actions.push_back(action);
            // Şüpheli action'ları işaretle
            static const char* SUSPICIOUS_ACTIONS[] = {
                "android.intent.action.BOOT_COMPLETED",
                "android.intent.action.PACKAGE_ADDED",
                "android.intent.action.PACKAGE_REPLACED",
                "android.intent.action.MY_PACKAGE_REPLACED",
                "android.provider.Telephony.SMS_RECEIVED",
                "android.provider.Telephony.WAP_PUSH_RECEIVED",
                "android.intent.action.SEND_MULTIPLE",
                "android.app.action.DEVICE_ADMIN_ENABLED",
                nullptr
            };
            for (int i = 0; SUSPICIOUS_ACTIONS[i]; ++i) {
                if (action == SUSPICIOUS_ACTIONS[i])
                    out.suspiciousActions.push_back(action);
            }
        }
    }

    return true;
}

// ══════════════════════════════════════════════════════════════════
//  XML Chunk Döngüsü
// ══════════════════════════════════════════════════════════════════
bool AXMLParser::parseXmlChunks(ManifestInfo& out) {
    ComponentInfo* curComp = nullptr;
    std::string    curTag;

    while (m_pos + 8 <= m_length) {
        size_t chunkStart = m_pos;
        uint16_t chunkType   = readU16();
        uint16_t headerSize  = readU16();
        uint32_t chunkSize   = readU32();

        if (chunkSize == 0 || chunkSize > m_length - chunkStart) break;

        switch (chunkType) {
            case CHUNK_STRING_POOL:
                m_pos = chunkStart;   // parseStringPool kendi başından okur
                parseStringPool();
                // parseStringPool zaten m_pos'u chunk sonuna taşıdı
                break;

            case CHUNK_XML_RES_MAP:
                // Resource ID map — atlıyoruz (attr isimlerini zaten string pool'dan alıyoruz)
                m_pos = chunkStart + chunkSize;
                break;

            case CHUNK_XML_START_NS:
            case CHUNK_XML_END_NS:
                // Namespace tanımı — atlıyoruz
                m_pos = chunkStart + chunkSize;
                break;

            case CHUNK_XML_START_EL:
                m_pos = chunkStart + 8;  // header'ı zaten okuduk
                parseStartElement(out, curComp, curTag);
                // parseStartElement m_pos'u tüketmedi ise chunk sonuna atla
                m_pos = chunkStart + chunkSize;
                break;

            case CHUNK_XML_END_EL:
                // lineNum(4) comment(4) ns(4) name(4)
                m_pos = chunkStart + chunkSize;
                break;

            case CHUNK_XML_CDATA:
                m_pos = chunkStart + chunkSize;
                break;

            default:
                // Bilinmeyen chunk → atla
                m_pos = chunkStart + chunkSize;
                break;
        }
    }
    return true;
}

// ══════════════════════════════════════════════════════════════════
//  Ana parse fonksiyonu
// ══════════════════════════════════════════════════════════════════
bool AXMLParser::parse(const uint8_t* data, size_t length, ManifestInfo& out) {
    m_data   = data;
    m_length = length;
    m_pos    = 0;
    m_strings.clear();

    if (length < 8) { LOGE("AXML çok kısa"); return false; }

    // AXML magic kontrolü: file başı chunk type = 0x0003
    uint16_t magic = readU16();
    if (magic != CHUNK_XML) {
        LOGE("AXML magic yanlış: 0x%04x (beklenen 0x0003)", magic);
        return false;
    }
    /*uint16_t hdrSize =*/ readU16();
    /*uint32_t fileSize=*/ readU32();

    // Chunk'ları işle
    return parseXmlChunks(out);
}

} // namespace AntiVirus
