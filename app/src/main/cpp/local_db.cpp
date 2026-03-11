#include "local_db.h"
#include <android/log.h>
#include <cstring>

#define LOG_TAG "AV_LocalDB"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace AntiVirus {

// ══════════════════════════════════════════════════════
//  Constructor / Destructor
// ══════════════════════════════════════════════════════
LocalDB::LocalDB(const std::string& dbPath) : m_dbPath(dbPath) {}

LocalDB::~LocalDB() { close(); }

// ══════════════════════════════════════════════════════
//  open
// ══════════════════════════════════════════════════════
bool LocalDB::open() {
    int rc = sqlite3_open_v2(
        m_dbPath.c_str(),
        &m_db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
        nullptr
    );
    if (rc != SQLITE_OK) {
        LOGE("DB açılamadı: %s", sqlite3_errmsg(m_db));
        m_db = nullptr;
        return false;
    }

    // WAL modu → eş zamanlı okuma için optimize
    sqlite3_exec(m_db, "PRAGMA journal_mode=WAL;",  nullptr, nullptr, nullptr);
    sqlite3_exec(m_db, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(m_db, "PRAGMA cache_size=4096;",    nullptr, nullptr, nullptr);

    initializeSchema();
    return prepareStatements();
}

// ══════════════════════════════════════════════════════
//  close
// ══════════════════════════════════════════════════════
void LocalDB::close() {
    finalizeStatements();
    if (m_db) {
        sqlite3_close(m_db);
        m_db = nullptr;
    }
}

// ══════════════════════════════════════════════════════
//  initializeSchema
// ══════════════════════════════════════════════════════
bool LocalDB::initializeSchema() {
    const char* sql =
        "CREATE TABLE IF NOT EXISTS signatures ("
        "  sha256       TEXT PRIMARY KEY,"
        "  md5          TEXT,"
        "  threat_name  TEXT NOT NULL,"
        "  threat_level INTEGER NOT NULL DEFAULT 2,"
        "  family       TEXT,"
        "  added_date   TEXT"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_md5 ON signatures(md5);"
        "CREATE TABLE IF NOT EXISTS db_meta ("
        "  key   TEXT PRIMARY KEY,"
        "  value TEXT"
        ");";

    char* errMsg = nullptr;
    int rc = sqlite3_exec(m_db, sql, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        LOGE("Şema oluşturulamadı: %s", errMsg);
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

// ══════════════════════════════════════════════════════
//  prepareStatements  (önceden hazırla → hız)
// ══════════════════════════════════════════════════════
bool LocalDB::prepareStatements() {
    const char* sqlSHA256 =
        "SELECT sha256, md5, threat_name, threat_level, family, added_date "
        "FROM signatures WHERE sha256 = ? LIMIT 1;";

    const char* sqlMD5 =
        "SELECT sha256, md5, threat_name, threat_level, family, added_date "
        "FROM signatures WHERE md5 = ? LIMIT 1;";

    if (sqlite3_prepare_v2(m_db, sqlSHA256, -1, &m_stmtLookupSHA256, nullptr) != SQLITE_OK) {
        LOGE("SHA256 statement hazırlanamadı: %s", sqlite3_errmsg(m_db));
        return false;
    }
    if (sqlite3_prepare_v2(m_db, sqlMD5, -1, &m_stmtLookupMD5, nullptr) != SQLITE_OK) {
        LOGE("MD5 statement hazırlanamadı: %s", sqlite3_errmsg(m_db));
        return false;
    }
    return true;
}

// ══════════════════════════════════════════════════════
//  finalizeStatements
// ══════════════════════════════════════════════════════
void LocalDB::finalizeStatements() {
    if (m_stmtLookupSHA256) { sqlite3_finalize(m_stmtLookupSHA256); m_stmtLookupSHA256 = nullptr; }
    if (m_stmtLookupMD5)    { sqlite3_finalize(m_stmtLookupMD5);    m_stmtLookupMD5    = nullptr; }
}

// ══════════════════════════════════════════════════════
//  Yardımcı: row → DBRecord
// ══════════════════════════════════════════════════════
static DBRecord rowToRecord(sqlite3_stmt* stmt) {
    DBRecord rec;
    auto col = [&](int idx) -> std::string {
        const char* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, idx));
        return text ? text : "";
    };
    rec.sha256      = col(0);
    rec.md5         = col(1);
    rec.threatName  = col(2);
    rec.threatLevel = static_cast<ThreatLevel>(sqlite3_column_int(stmt, 3));
    rec.family      = col(4);
    rec.addedDate   = col(5);
    return rec;
}

// ══════════════════════════════════════════════════════
//  lookupBySHA256
// ══════════════════════════════════════════════════════
std::optional<DBRecord> LocalDB::lookupBySHA256(const std::string& sha256) {
    if (!m_stmtLookupSHA256) return std::nullopt;

    sqlite3_reset(m_stmtLookupSHA256);
    sqlite3_bind_text(m_stmtLookupSHA256, 1, sha256.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(m_stmtLookupSHA256) == SQLITE_ROW) {
        return rowToRecord(m_stmtLookupSHA256);
    }
    return std::nullopt;
}

// ══════════════════════════════════════════════════════
//  lookupByMD5
// ══════════════════════════════════════════════════════
std::optional<DBRecord> LocalDB::lookupByMD5(const std::string& md5) {
    if (!m_stmtLookupMD5) return std::nullopt;

    sqlite3_reset(m_stmtLookupMD5);
    sqlite3_bind_text(m_stmtLookupMD5, 1, md5.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(m_stmtLookupMD5) == SQLITE_ROW) {
        return rowToRecord(m_stmtLookupMD5);
    }
    return std::nullopt;
}

// ══════════════════════════════════════════════════════
//  getSignatureCount
// ══════════════════════════════════════════════════════
uint64_t LocalDB::getSignatureCount() {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(m_db, "SELECT COUNT(*) FROM signatures;", -1, &stmt, nullptr);
    uint64_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = static_cast<uint64_t>(sqlite3_column_int64(stmt, 0));
    sqlite3_finalize(stmt);
    return count;
}

// ══════════════════════════════════════════════════════
//  getDBVersion
// ══════════════════════════════════════════════════════
std::string LocalDB::getDBVersion() {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(m_db,
        "SELECT value FROM db_meta WHERE key='version' LIMIT 1;",
        -1, &stmt, nullptr);
    std::string version = "unknown";
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* v = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (v) version = v;
    }
    sqlite3_finalize(stmt);
    return version;
}

// ══════════════════════════════════════════════════════
//  importSignatures  (cloud'dan gelen JSON delta)
//
//  Beklenen JSON formatı:
//  {
//    "version": "2024.03.11",
//    "signatures": [
//      { "sha256":"...", "md5":"...", "name":"...", "level":2, "family":"..." },
//      ...
//    ]
//  }
// ══════════════════════════════════════════════════════
bool LocalDB::importSignatures(const std::string& jsonPath) {
    // Basit bir JSON parser bu kapsam dışı;
    // production'da nlohmann/json veya cJSON kullanın.
    //
    // İskelet akış:
    //   1. JSON dosyasını oku
    //   2. "signatures" dizisini parse et
    //   3. BEGIN TRANSACTION;
    //   4. INSERT OR REPLACE INTO signatures (...) VALUES (...);  (her kayıt)
    //   5. UPDATE db_meta SET value=? WHERE key='version';
    //   6. COMMIT;
    //
    LOGI("İmza güncelleme başlatıldı: %s", jsonPath.c_str());

    sqlite3_exec(m_db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

    // TODO: JSON parse + INSERT döngüsü buraya

    sqlite3_exec(m_db, "COMMIT;", nullptr, nullptr, nullptr);
    LOGI("İmza güncellemesi tamamlandı. Toplam: %llu", (unsigned long long)getSignatureCount());
    return true;
}

} // namespace AntiVirus
