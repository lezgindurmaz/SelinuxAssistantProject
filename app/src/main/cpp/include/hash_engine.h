#pragma once
#ifndef HASH_ENGINE_H
#define HASH_ENGINE_H

#include <stdint.h>
#include <stddef.h>
#include <string>
#include <vector>

namespace AntiVirus {

// ─────────────────────────────────────────────
//  Hash türleri
// ─────────────────────────────────────────────
enum class HashType {
    MD5,
    SHA256,
    BOTH
};

// ─────────────────────────────────────────────
//  Hash sonucu
// ─────────────────────────────────────────────
struct HashResult {
    std::string md5;       // 32 hex karakter
    std::string sha256;    // 64 hex karakter
    bool        valid;
    std::string error;
};

// ─────────────────────────────────────────────
//  MD5 Context (RFC 1321)
// ─────────────────────────────────────────────
struct MD5Context {
    uint32_t state[4];
    uint32_t count[2];
    uint8_t  buffer[64];
};

// ─────────────────────────────────────────────
//  SHA-256 Context (FIPS 180-4)
// ─────────────────────────────────────────────
struct SHA256Context {
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t  buffer[64];
};

// ─────────────────────────────────────────────
//  Ana Hash Engine sınıfı
// ─────────────────────────────────────────────
class HashEngine {
public:
    HashEngine();
    ~HashEngine() = default;

    // Dosya hash'i hesapla (büyük dosyalar için chunk-by-chunk okur)
    HashResult  hashFile(const std::string& filePath, HashType type = HashType::BOTH);

    // Bellek buffer'ından hash hesapla
    HashResult  hashBuffer(const uint8_t* data, size_t length, HashType type = HashType::BOTH);

    // Yardımcı: hex string → binary
    static std::vector<uint8_t> hexToBytes(const std::string& hex);

    // Yardımcı: binary → hex string
    static std::string bytesToHex(const uint8_t* data, size_t length);

private:
    static constexpr size_t CHUNK_SIZE = 65536; // 64 KB chunk okuma

    // MD5 internal
    void md5Init   (MD5Context& ctx);
    void md5Update (MD5Context& ctx, const uint8_t* data, size_t length);
    void md5Final  (MD5Context& ctx, uint8_t digest[16]);
    void md5Transform(uint32_t state[4], const uint8_t block[64]);

    // SHA256 internal
    void sha256Init   (SHA256Context& ctx);
    void sha256Update (SHA256Context& ctx, const uint8_t* data, size_t length);
    void sha256Final  (SHA256Context& ctx, uint8_t digest[32]);
    void sha256Transform(SHA256Context& ctx, const uint8_t block[64]);
};

} // namespace AntiVirus

#endif // HASH_ENGINE_H
