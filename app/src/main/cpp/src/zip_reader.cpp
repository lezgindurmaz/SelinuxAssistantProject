#include "apk_analyzer.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <zlib.h>        // NDK zlib — deflate decompress
#include <android/log.h>

#define LOG_TAG "AV_Zip"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace AntiVirus {

// ══════════════════════════════════════════════════════════════════
//  ZIP format sabitleri (PKZIP spesifikasyonu)
// ══════════════════════════════════════════════════════════════════
static constexpr uint32_t ZIP_LOCAL_MAGIC   = 0x04034b50;  // "PK\x03\x04"
static constexpr uint32_t ZIP_CENTRAL_MAGIC = 0x02014b50;  // "PK\x01\x02"
static constexpr uint32_t ZIP_EOCD_MAGIC    = 0x06054b50;  // "PK\x05\x06"

#pragma pack(push, 1)
struct ZipLocalHeader {
    uint32_t signature;
    uint16_t versionNeeded;
    uint16_t flags;
    uint16_t compression;
    uint16_t modTime;
    uint16_t modDate;
    uint32_t crc32;
    uint32_t compressedSize;
    uint32_t uncompressedSize;
    uint16_t fileNameLen;
    uint16_t extraLen;
};

struct ZipCentralDir {
    uint32_t signature;
    uint16_t versionMadeBy;
    uint16_t versionNeeded;
    uint16_t flags;
    uint16_t compression;
    uint16_t modTime;
    uint16_t modDate;
    uint32_t crc32;
    uint32_t compressedSize;
    uint32_t uncompressedSize;
    uint16_t fileNameLen;
    uint16_t extraLen;
    uint16_t commentLen;
    uint16_t diskStart;
    uint16_t internalAttr;
    uint32_t externalAttr;
    uint32_t localOffset;
};

struct ZipEOCD {
    uint32_t signature;
    uint16_t diskNum;
    uint16_t startDisk;
    uint16_t diskEntries;
    uint16_t totalEntries;
    uint32_t centralDirSize;
    uint32_t centralDirOffset;
    uint16_t commentLen;
};
#pragma pack(pop)

// ──────────────────────────────────────────────────────────────────
ZipReader::ZipReader(const std::string& path) : m_path(path) {}
ZipReader::~ZipReader() { close(); }

// ──────────────────────────────────────────────────────────────────
bool ZipReader::open() {
    m_fd = ::open(m_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (m_fd < 0) {
        LOGE("APK açılamadı: %s", m_path.c_str());
        return false;
    }
    struct stat st;
    if (fstat(m_fd, &st) != 0) { ::close(m_fd); m_fd = -1; return false; }
    m_fileSize = static_cast<uint64_t>(st.st_size);

    if (m_fileSize < sizeof(ZipEOCD)) {
        LOGE("APK çok küçük: %llu byte", (unsigned long long)m_fileSize);
        ::close(m_fd); m_fd = -1; return false;
    }

    uint32_t eocdOffset = 0;
    if (!findEndOfCentralDir(eocdOffset)) return false;
    return parseCentralDir(eocdOffset);
}

void ZipReader::close() {
    if (m_fd >= 0) { ::close(m_fd); m_fd = -1; }
}

// ──────────────────────────────────────────────────────────────────
//  End of Central Directory bul
//  Sonda arama: ZIP arşivi sona EOCD imzasıyla biter
// ──────────────────────────────────────────────────────────────────
bool ZipReader::findEndOfCentralDir(uint32_t& eocdOffset) {
    // Maksimum yorum uzunluğu = 65535 byte
    // EOCD bu aralıkta bir yerde olmalı
    const size_t maxSearch = std::min((uint64_t)65536 + sizeof(ZipEOCD),
                                       m_fileSize);
    std::vector<uint8_t> tail(maxSearch);
    uint64_t tailStart = m_fileSize - maxSearch;

    if (lseek(m_fd, static_cast<off_t>(tailStart), SEEK_SET) < 0) return false;
    ssize_t n = read(m_fd, tail.data(), maxSearch);
    if (n < static_cast<ssize_t>(sizeof(ZipEOCD))) return false;

    // Geriden arama
    for (ssize_t i = n - static_cast<ssize_t>(sizeof(ZipEOCD)); i >= 0; --i) {
        uint32_t sig = *reinterpret_cast<const uint32_t*>(tail.data() + i);
        if (sig == ZIP_EOCD_MAGIC) {
            eocdOffset = static_cast<uint32_t>(tailStart + i);
            return true;
        }
    }
    LOGE("EOCD imzası bulunamadı — geçerli APK değil.");
    return false;
}

// ──────────────────────────────────────────────────────────────────
//  Central Directory'yi parse et → m_entries'e doldur
// ──────────────────────────────────────────────────────────────────
bool ZipReader::parseCentralDir(uint32_t eocdOffset) {
    ZipEOCD eocd{};
    if (lseek(m_fd, eocdOffset, SEEK_SET) < 0) return false;
    if (read(m_fd, &eocd, sizeof(eocd)) < static_cast<ssize_t>(sizeof(eocd)))
        return false;
    if (eocd.signature != ZIP_EOCD_MAGIC) return false;

    // Güvenlik: central dir offset ve boyutu sınır içinde mi?
    if ((uint64_t)eocd.centralDirOffset + eocd.centralDirSize > m_fileSize) {
        LOGE("Central dir sınır dışı.");
        return false;
    }

    if (lseek(m_fd, eocd.centralDirOffset, SEEK_SET) < 0) return false;

    m_entries.clear();
    m_entries.reserve(eocd.totalEntries);

    for (uint16_t i = 0; i < eocd.totalEntries; ++i) {
        ZipCentralDir cd{};
        if (read(m_fd, &cd, sizeof(cd)) < static_cast<ssize_t>(sizeof(cd))) break;
        if (cd.signature != ZIP_CENTRAL_MAGIC) break;

        // Dosya adını oku
        std::string fname(cd.fileNameLen, '\0');
        if (read(m_fd, &fname[0], cd.fileNameLen) < cd.fileNameLen) break;

        // Extra + comment atla
        lseek(m_fd, cd.extraLen + cd.commentLen, SEEK_CUR);

        ZipEntry entry;
        entry.name             = fname;
        entry.compressedSize   = cd.compressedSize;
        entry.uncompressedSize = cd.uncompressedSize;
        entry.compression      = cd.compression;
        entry.localOffset      = cd.localOffset;
        m_entries.push_back(std::move(entry));
    }
    LOGI("APK içeriği: %zu dosya", m_entries.size());
    return !m_entries.empty();
}

// ──────────────────────────────────────────────────────────────────
//  Girdi listesi
// ──────────────────────────────────────────────────────────────────
std::vector<ZipEntry> ZipReader::listEntries() const {
    return m_entries;
}

// ──────────────────────────────────────────────────────────────────
//  Belirli bir dosyayı belleğe çıkar
// ──────────────────────────────────────────────────────────────────
std::vector<uint8_t> ZipReader::extract(const std::string& entryName) const {
    // Giriş bul
    const ZipEntry* found = nullptr;
    for (const auto& e : m_entries) {
        if (e.name == entryName) { found = &e; break; }
    }
    if (!found) return {};

    // Local header'a git ve doğrula
    if (lseek(m_fd, found->localOffset, SEEK_SET) < 0) return {};
    ZipLocalHeader lh{};
    if (read(m_fd, &lh, sizeof(lh)) < static_cast<ssize_t>(sizeof(lh))) return {};
    if (lh.signature != ZIP_LOCAL_MAGIC) return {};

    // Local extra + filename atla
    lseek(m_fd, lh.fileNameLen + lh.extraLen, SEEK_CUR);

    // Boyut güvenlik kontrolü (100 MB sınırı)
    if (found->uncompressedSize > 100 * 1024 * 1024) {
        LOGE("Girdi çok büyük: %s (%u byte)", entryName.c_str(),
             found->uncompressedSize);
        return {};
    }

    // Sıkıştırılmış veriyi oku
    std::vector<uint8_t> compressed(found->compressedSize);
    if (read(m_fd, compressed.data(), found->compressedSize)
            < static_cast<ssize_t>(found->compressedSize))
        return {};

    if (found->compression == 0) {
        // Store (sıkıştırılmamış)
        return compressed;
    } else if (found->compression == 8) {
        // Deflate
        std::vector<uint8_t> output;
        if (!inflate(compressed.data(), found->compressedSize,
                     output, found->uncompressedSize))
            return {};
        return output;
    }

    LOGE("Desteklenmeyen sıkıştırma: %u", found->compression);
    return {};
}

// ──────────────────────────────────────────────────────────────────
//  zlib ile deflate decompress
// ──────────────────────────────────────────────────────────────────
bool ZipReader::inflate(const uint8_t* src, size_t srcLen,
                         std::vector<uint8_t>& dst, size_t dstLen) const {
    dst.resize(dstLen);
    z_stream zs{};
    zs.next_in   = const_cast<uint8_t*>(src);
    zs.avail_in  = static_cast<uInt>(srcLen);
    zs.next_out  = dst.data();
    zs.avail_out = static_cast<uInt>(dstLen);

    // -15: raw deflate (ZIP inner stream, no zlib header)
    if (inflateInit2(&zs, -15) != Z_OK) return false;
    int ret = ::inflate(&zs, Z_FINISH);
    inflateEnd(&zs);
    return ret == Z_STREAM_END;
}

} // namespace AntiVirus
