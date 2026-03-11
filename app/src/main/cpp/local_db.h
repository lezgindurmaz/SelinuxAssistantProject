#pragma once
#ifndef LOCAL_DB_H
#define LOCAL_DB_H

#include "scanner.h"
#include <string>
#include <optional>
#include "mock_external.h"

namespace AntiVirus {

// ─────────────────────────────────────────────
//  Veritabanı kayıt yapısı
// ─────────────────────────────────────────────
struct DBRecord {
    std::string sha256;
    std::string md5;
    std::string threatName;
    ThreatLevel threatLevel;
    std::string family;       // ör: "Trojan", "Ransomware", "Spyware"
    std::string addedDate;
};

// ─────────────────────────────────────────────
//  LocalDB: SQLite tabanlı imza veritabanı
//
//  Tablo şeması:
//  CREATE TABLE signatures (
//      sha256      TEXT PRIMARY KEY,
//      md5         TEXT,
//      threat_name TEXT NOT NULL,
//      threat_level INTEGER NOT NULL,  -- 0=clean,1=suspicious,2=malware,3=critical
//      family      TEXT,
//      added_date  TEXT
//  );
//  CREATE INDEX idx_md5 ON signatures(md5);
// ─────────────────────────────────────────────
class LocalDB {
public:
    explicit LocalDB(const std::string& dbPath);
    ~LocalDB();

    // Bağlantı aç/kapat
    bool open();
    void close();
    bool isOpen() const { return m_db != nullptr; }

    // SHA256 ile sorgula (öncelikli)
    std::optional<DBRecord> lookupBySHA256(const std::string& sha256);

    // MD5 ile sorgula (ikincil / eski imzalar için)
    std::optional<DBRecord> lookupByMD5(const std::string& md5);

    // Toplu imza güncelleme (cloud'dan indirilen delta dosyası)
    bool importSignatures(const std::string& jsonPath);

    // İstatistik
    uint64_t getSignatureCount();
    std::string getDBVersion();

    // Veritabanını oluştur (ilk kurulum)
    bool initializeSchema();

private:
    std::string m_dbPath;
    sqlite3*    m_db = nullptr;
    sqlite3_stmt* m_stmtLookupSHA256 = nullptr;
    sqlite3_stmt* m_stmtLookupMD5    = nullptr;

    // Prepared statement'ları hazırla (performans için)
    bool prepareStatements();
    void finalizeStatements();

    // SQLite hata loglama
    void logError(const std::string& context);
};

} // namespace AntiVirus

#endif // LOCAL_DB_H
