// ══════════════════════════════════════════════════════════════════
//  LocalDB — Sıfır harici bağımlılık imza veritabanı
//
//  Dosya formatı (signatures.bin):
//    Başlık : "GXSIG001"  (8 bayt magic)
//             uint32_t version
//             uint32_t record_count
//    Her kayıt:
//             uint8_t  severity         (0-3)
//             char[65] sha256_hex + null
//             char[33] md5_hex   + null
//             uint16_t name_len
//             char[name_len] threat_name (null terminated)
//             uint16_t family_len
//             char[family_len] family    (null terminated)
// ══════════════════════════════════════════════════════════════════
#include "local_db.h"
#include <cstring>
#include <cstdio>
#include <sys/stat.h>
#include <android/log.h>
#include <memory>

#define LOG_TAG "GX_DB"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static constexpr char   MAGIC[]   = "GXSIG001";
static constexpr size_t MAGIC_LEN = 8;

namespace AntiVirus {

static std::unique_ptr<LocalDB> g_globalDB = nullptr;

LocalDB* LocalDB::getGlobalInstance() {
    return g_globalDB.get();
}

void LocalDB::setGlobalInstance(std::unique_ptr<LocalDB> db) {
    g_globalDB = std::move(db);
}

LocalDB::LocalDB(const std::string& dbPath) : m_dbPath(dbPath) {}

bool LocalDB::initializeSchema() {
    // Dosya yoksa boş bir DB oluştur
    struct stat st;
    if (stat(m_dbPath.c_str(), &st) == 0) return true;  // Zaten var

    FILE* f = fopen(m_dbPath.c_str(), "wb");
    if (!f) { LOGE("DB oluşturulamadı: %s", m_dbPath.c_str()); return false; }

    fwrite(MAGIC, 1, MAGIC_LEN, f);
    uint32_t ver = 1, cnt = 0;
    fwrite(&ver, 4, 1, f);
    fwrite(&cnt, 4, 1, f);
    fclose(f);
    LOGI("Boş imza DB oluşturuldu: %s", m_dbPath.c_str());
    return true;
}

bool LocalDB::open() {
    std::lock_guard<std::mutex> lk(m_mutex);
    m_sha256Map.clear();
    m_md5Map.clear();

    initializeSchema();

    if (!loadFromDisk()) {
        LOGI("DB yüklenemedi veya boş, devam ediliyor");
    }
    m_open = true;
    LOGI("LocalDB açıldı: %zu imza", m_sha256Map.size());
    return true;
}

void LocalDB::close() {
    std::lock_guard<std::mutex> lk(m_mutex);
    m_sha256Map.clear();
    m_md5Map.clear();
    m_open = false;
}

bool LocalDB::loadFromDisk() {
    FILE* f = fopen(m_dbPath.c_str(), "rb");
    if (!f) return false;

    // Magic kontrol
    char magic[MAGIC_LEN];
    if (fread(magic, 1, MAGIC_LEN, f) != MAGIC_LEN ||
        memcmp(magic, MAGIC, MAGIC_LEN) != 0) {
        fclose(f); return false;
    }

    uint32_t ver = 0, cnt = 0;
    fread(&ver, 4, 1, f);
    fread(&cnt, 4, 1, f);

    char sha256buf[65], md5buf[33], namebuf[256], familybuf[64];

    for (uint32_t i = 0; i < cnt; ++i) {
        uint8_t sev = 0;
        if (fread(&sev, 1, 1, f) != 1) break;

        if (fread(sha256buf, 1, 65, f) != 65) break;
        if (fread(md5buf,    1, 33, f) != 33) break;

        uint16_t nameLen = 0;
        fread(&nameLen, 2, 1, f);
        if (nameLen >= sizeof(namebuf)) { fclose(f); return false; }
        fread(namebuf, 1, nameLen, f);
        namebuf[nameLen] = '\0';

        uint16_t famLen = 0;
        fread(&famLen, 2, 1, f);
        if (famLen >= sizeof(familybuf)) { fclose(f); return false; }
        fread(familybuf, 1, famLen, f);
        familybuf[famLen] = '\0';

        Entry e;
        e.level      = static_cast<ThreatLevel>(sev > 3 ? 2 : sev);
        e.threatName = namebuf;
        e.family     = familybuf;
        e.sha256     = sha256buf;
        e.md5        = md5buf;

        m_sha256Map[e.sha256] = e;
        if (!e.md5.empty()) m_md5Map[e.md5] = e;
    }
    fclose(f);
    return true;
}

std::optional<DBRecord> LocalDB::lookupBySHA256(const std::string& sha256) {
    std::lock_guard<std::mutex> lk(m_mutex);
    auto it = m_sha256Map.find(sha256);
    if (it == m_sha256Map.end()) return std::nullopt;
    const auto& e = it->second;
    return DBRecord{sha256, e.md5, e.threatName, e.level, e.family, ""};
}

std::optional<DBRecord> LocalDB::lookupByMD5(const std::string& md5) {
    std::lock_guard<std::mutex> lk(m_mutex);
    auto it = m_md5Map.find(md5);
    if (it == m_md5Map.end()) return std::nullopt;
    const auto& e = it->second;
    return DBRecord{e.sha256, md5, e.threatName, e.level, e.family, ""};
}

// ── Basit JSON satır parser (her imza tek satır) ──────────────────
// Beklenen format: {"sha256":"...","md5":"...","name":"...","level":2,"family":"..."}
bool LocalDB::parseJsonEntry(const std::string& line, DBRecord& out) const {
    auto extract = [&](const std::string& key) -> std::string {
        std::string search = "\"" + key + "\":\"";
        size_t pos = line.find(search);
        if (pos == std::string::npos) return "";
        pos += search.size();
        size_t end = line.find('"', pos);
        if (end == std::string::npos) return "";
        return line.substr(pos, end - pos);
    };
    auto extractInt = [&](const std::string& key) -> int {
        std::string search = "\"" + key + "\":";
        size_t pos = line.find(search);
        if (pos == std::string::npos) return 0;
        pos += search.size();
        return atoi(line.c_str() + pos);
    };

    out.sha256      = extract("sha256");
    out.md5         = extract("md5");
    out.threatName  = extract("name");
    out.family      = extract("family");
    out.threatLevel = static_cast<ThreatLevel>(extractInt("level"));
    return !out.sha256.empty() && !out.threatName.empty();
}

bool LocalDB::importSignatures(const std::string& jsonPath) {
    FILE* f = fopen(jsonPath.c_str(), "r");
    if (!f) { LOGE("Delta JSON açılamadı: %s", jsonPath.c_str()); return false; }

    char line[1024];
    int  added = 0;

    std::lock_guard<std::mutex> lk(m_mutex);

    while (fgets(line, sizeof(line), f)) {
        std::string s(line);
        if (s.size() < 10) continue;

        DBRecord rec;
        if (!parseJsonEntry(s, rec)) continue;

        Entry e;
        e.level      = rec.threatLevel;
        e.threatName = rec.threatName;
        e.family     = rec.family;
        e.sha256     = rec.sha256;
        e.md5        = rec.md5;

        m_sha256Map[e.sha256] = e;
        if (!e.md5.empty()) m_md5Map[e.md5] = e;
        ++added;
    }
    fclose(f);
    LOGI("Delta import: %d imza eklendi, toplam %zu", added, m_sha256Map.size());
    return true;
}

} // namespace AntiVirus
