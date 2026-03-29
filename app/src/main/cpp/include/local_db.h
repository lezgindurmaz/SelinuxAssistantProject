#pragma once
#ifndef LOCAL_DB_H
#define LOCAL_DB_H

#include "scanner.h"
#include <string>
#include <optional>
#include <unordered_map>
#include <mutex>
#include <vector>

namespace AntiVirus {

struct DBRecord {
    std::string sha256;
    std::string md5;
    std::string threatName;
    ThreatLevel threatLevel;
    std::string family;
    std::string addedDate;
};

// Harici bağımlılık yok — saf C++17 + Android NDK
// Depolama: ikili imza dosyası, açılışta unordered_map'e yüklenir → O(1) arama
class LocalDB {
public:
    static LocalDB* getGlobalInstance();
    static void setGlobalInstance(std::unique_ptr<LocalDB> db);
public:
    explicit LocalDB(const std::string& dbPath);
    ~LocalDB() = default;

    bool open();
    void close();
    bool isOpen() const { return m_open; }

    std::optional<DBRecord> lookupBySHA256(const std::string& sha256);
    std::optional<DBRecord> lookupByMD5   (const std::string& md5);
    bool        importSignatures(const std::string& jsonPath);
    uint64_t    getSignatureCount() const { return m_sha256Map.size(); }
    std::string getDBVersion()      const { return m_version; }
    bool        initializeSchema();

private:
    struct Entry {
        ThreatLevel level;
        std::string threatName;
        std::string family;
        std::string md5;
        std::string sha256;
    };

    std::string m_dbPath;
    bool        m_open = false;
    std::string m_version = "1.0.0";
    std::mutex  m_mutex;
    std::unordered_map<std::string, Entry> m_sha256Map;
    std::unordered_map<std::string, Entry> m_md5Map;

    bool loadFromDisk();
    bool parseJsonEntry(const std::string& line, DBRecord& out) const;
};

} // namespace AntiVirus
#endif // LOCAL_DB_H
