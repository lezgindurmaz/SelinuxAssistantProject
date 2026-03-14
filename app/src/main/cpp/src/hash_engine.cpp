#include "hash_engine.h"

#include <fstream>
#include <cstring>
#include <stdexcept>
#include <chrono>

namespace AntiVirus {

// ══════════════════════════════════════════════════════
//  SHA-256 Sabitleri (FIPS 180-4)
// ══════════════════════════════════════════════════════
static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// ══════════════════════════════════════════════════════
//  Bit işlem makroları
// ══════════════════════════════════════════════════════
#define ROTR32(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)   (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)        (ROTR32(x, 2)  ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define EP1(x)        (ROTR32(x, 6)  ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SIG0(x)       (ROTR32(x, 7)  ^ ROTR32(x, 18) ^ ((x) >> 3))
#define SIG1(x)       (ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))

// MD5 makroları
#define MD5_F(x,y,z)  ((x & y) | (~x & z))
#define MD5_G(x,y,z)  ((x & z) | (y & ~z))
#define MD5_H(x,y,z)  (x ^ y ^ z)
#define MD5_I(x,y,z)  (y ^ (x | ~z))
#define ROTL32(x,n)   (((x) << (n)) | ((x) >> (32-(n))))
#define MD5_STEP(f,a,b,c,d,x,t,s) \
    a = b + ROTL32(a + f(b,c,d) + x + t, s)

// MD5 T sabitleri (precomputed sine)
static const uint32_t MD5_T[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

// ══════════════════════════════════════════════════════
//  Constructor
// ══════════════════════════════════════════════════════
HashEngine::HashEngine() {}

// ══════════════════════════════════════════════════════
//  bytesToHex
// ══════════════════════════════════════════════════════
std::string HashEngine::bytesToHex(const uint8_t* data, size_t length) {
    static const char HEX[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(length * 2);
    for (size_t i = 0; i < length; ++i) {
        hex.push_back(HEX[(data[i] >> 4) & 0xF]);
        hex.push_back(HEX[ data[i]       & 0xF]);
    }
    return hex;
}

// ══════════════════════════════════════════════════════
//  hexToBytes
// ══════════════════════════════════════════════════════
std::vector<uint8_t> HashEngine::hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        auto h = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        bytes.push_back((h(hex[i]) << 4) | h(hex[i+1]));
    }
    return bytes;
}

// ══════════════════════════════════════════════════════
//  hashBuffer
// ══════════════════════════════════════════════════════
HashResult HashEngine::hashBuffer(const uint8_t* data, size_t length, HashType type) {
    HashResult result;
    result.valid = true;

    if (type == HashType::MD5 || type == HashType::BOTH) {
        MD5Context ctx;
        uint8_t digest[16];
        md5Init(ctx);
        md5Update(ctx, data, length);
        md5Final(ctx, digest);
        result.md5 = bytesToHex(digest, 16);
    }

    if (type == HashType::SHA256 || type == HashType::BOTH) {
        SHA256Context ctx;
        uint8_t digest[32];
        sha256Init(ctx);
        sha256Update(ctx, data, length);
        sha256Final(ctx, digest);
        result.sha256 = bytesToHex(digest, 32);
    }

    return result;
}

// ══════════════════════════════════════════════════════
//  hashFile  — chunk-by-chunk okuma (büyük dosya desteği)
// ══════════════════════════════════════════════════════
HashResult HashEngine::hashFile(const std::string& filePath, HashType type) {
    HashResult result;

    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        result.valid = false;
        result.error = "Dosya açılamadı: " + filePath;
        return result;
    }

    MD5Context    md5ctx;
    SHA256Context sha256ctx;
    uint8_t       chunk[CHUNK_SIZE];

    if (type == HashType::MD5 || type == HashType::BOTH)
        md5Init(md5ctx);
    if (type == HashType::SHA256 || type == HashType::BOTH)
        sha256Init(sha256ctx);

    while (file.read(reinterpret_cast<char*>(chunk), CHUNK_SIZE) || file.gcount() > 0) {
        size_t bytesRead = static_cast<size_t>(file.gcount());
        if (type == HashType::MD5    || type == HashType::BOTH)
            md5Update(md5ctx, chunk, bytesRead);
        if (type == HashType::SHA256 || type == HashType::BOTH)
            sha256Update(sha256ctx, chunk, bytesRead);
    }

    if (type == HashType::MD5 || type == HashType::BOTH) {
        uint8_t digest[16];
        md5Final(md5ctx, digest);
        result.md5 = bytesToHex(digest, 16);
    }

    if (type == HashType::SHA256 || type == HashType::BOTH) {
        uint8_t digest[32];
        sha256Final(sha256ctx, digest);
        result.sha256 = bytesToHex(digest, 32);
    }

    result.valid = true;
    return result;
}

// ══════════════════════════════════════════════════════
//  SHA-256 Implementasyonu
// ══════════════════════════════════════════════════════
void HashEngine::sha256Init(SHA256Context& ctx) {
    ctx.state[0] = 0x6a09e667;
    ctx.state[1] = 0xbb67ae85;
    ctx.state[2] = 0x3c6ef372;
    ctx.state[3] = 0xa54ff53a;
    ctx.state[4] = 0x510e527f;
    ctx.state[5] = 0x9b05688c;
    ctx.state[6] = 0x1f83d9ab;
    ctx.state[7] = 0x5be0cd19;
    ctx.bitcount = 0;
    memset(ctx.buffer, 0, 64);
}

void HashEngine::sha256Transform(SHA256Context& ctx, const uint8_t block[64]) {
    uint32_t w[64], a, b, c, d, e, f, g, h;

    // Mesaj çizelgesi
    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)block[i*4  ] << 24) |
               ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] <<  8) |
               ((uint32_t)block[i*4+3]);
    }
    for (int i = 16; i < 64; ++i)
        w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];

    a = ctx.state[0]; b = ctx.state[1];
    c = ctx.state[2]; d = ctx.state[3];
    e = ctx.state[4]; f = ctx.state[5];
    g = ctx.state[6]; h = ctx.state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h + EP1(e) + CH(e,f,g) + SHA256_K[i] + w[i];
        uint32_t t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx.state[0] += a; ctx.state[1] += b;
    ctx.state[2] += c; ctx.state[3] += d;
    ctx.state[4] += e; ctx.state[5] += f;
    ctx.state[6] += g; ctx.state[7] += h;
}

void HashEngine::sha256Update(SHA256Context& ctx, const uint8_t* data, size_t length) {
    size_t bufLen = (ctx.bitcount / 8) % 64;
    ctx.bitcount += (uint64_t)length * 8;

    size_t i = 0;
    if (bufLen > 0) {
        size_t fill = 64 - bufLen;
        if (length < fill) {
            memcpy(ctx.buffer + bufLen, data, length);
            return;
        }
        memcpy(ctx.buffer + bufLen, data, fill);
        sha256Transform(ctx, ctx.buffer);
        i = fill;
    }

    for (; i + 63 < length; i += 64)
        sha256Transform(ctx, data + i);

    memcpy(ctx.buffer, data + i, length - i);
}

void HashEngine::sha256Final(SHA256Context& ctx, uint8_t digest[32]) {
    uint8_t pad[64] = {};
    uint64_t bitcount = ctx.bitcount;
    size_t bufLen = (bitcount / 8) % 64;

    pad[0] = 0x80;
    size_t padLen = (bufLen < 56) ? (56 - bufLen) : (120 - bufLen);
    sha256Update(ctx, pad, padLen);

    // Big-endian bit sayısı
    uint8_t len[8];
    for (int i = 7; i >= 0; --i) { len[i] = bitcount & 0xFF; bitcount >>= 8; }
    sha256Update(ctx, len, 8);

    for (int i = 0; i < 8; ++i) {
        digest[i*4  ] = (ctx.state[i] >> 24) & 0xFF;
        digest[i*4+1] = (ctx.state[i] >> 16) & 0xFF;
        digest[i*4+2] = (ctx.state[i] >>  8) & 0xFF;
        digest[i*4+3] =  ctx.state[i]        & 0xFF;
    }
}

// ══════════════════════════════════════════════════════
//  MD5 Implementasyonu (RFC 1321)
// ══════════════════════════════════════════════════════
void HashEngine::md5Init(MD5Context& ctx) {
    ctx.state[0] = 0x67452301;
    ctx.state[1] = 0xefcdab89;
    ctx.state[2] = 0x98badcfe;
    ctx.state[3] = 0x10325476;
    ctx.count[0] = ctx.count[1] = 0;
    memset(ctx.buffer, 0, 64);
}

void HashEngine::md5Transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t x[16];

    for (int i = 0; i < 16; ++i)
        x[i] = ((uint32_t)block[i*4  ])       |
               ((uint32_t)block[i*4+1] <<  8)  |
               ((uint32_t)block[i*4+2] << 16)  |
               ((uint32_t)block[i*4+3] << 24);

    // Round 1
    MD5_STEP(MD5_F, a,b,c,d, x[ 0], MD5_T[ 0],  7);
    MD5_STEP(MD5_F, d,a,b,c, x[ 1], MD5_T[ 1], 12);
    MD5_STEP(MD5_F, c,d,a,b, x[ 2], MD5_T[ 2], 17);
    MD5_STEP(MD5_F, b,c,d,a, x[ 3], MD5_T[ 3], 22);
    MD5_STEP(MD5_F, a,b,c,d, x[ 4], MD5_T[ 4],  7);
    MD5_STEP(MD5_F, d,a,b,c, x[ 5], MD5_T[ 5], 12);
    MD5_STEP(MD5_F, c,d,a,b, x[ 6], MD5_T[ 6], 17);
    MD5_STEP(MD5_F, b,c,d,a, x[ 7], MD5_T[ 7], 22);
    MD5_STEP(MD5_F, a,b,c,d, x[ 8], MD5_T[ 8],  7);
    MD5_STEP(MD5_F, d,a,b,c, x[ 9], MD5_T[ 9], 12);
    MD5_STEP(MD5_F, c,d,a,b, x[10], MD5_T[10], 17);
    MD5_STEP(MD5_F, b,c,d,a, x[11], MD5_T[11], 22);
    MD5_STEP(MD5_F, a,b,c,d, x[12], MD5_T[12],  7);
    MD5_STEP(MD5_F, d,a,b,c, x[13], MD5_T[13], 12);
    MD5_STEP(MD5_F, c,d,a,b, x[14], MD5_T[14], 17);
    MD5_STEP(MD5_F, b,c,d,a, x[15], MD5_T[15], 22);
    // Round 2
    MD5_STEP(MD5_G, a,b,c,d, x[ 1], MD5_T[16],  5);
    MD5_STEP(MD5_G, d,a,b,c, x[ 6], MD5_T[17],  9);
    MD5_STEP(MD5_G, c,d,a,b, x[11], MD5_T[18], 14);
    MD5_STEP(MD5_G, b,c,d,a, x[ 0], MD5_T[19], 20);
    MD5_STEP(MD5_G, a,b,c,d, x[ 5], MD5_T[20],  5);
    MD5_STEP(MD5_G, d,a,b,c, x[10], MD5_T[21],  9);
    MD5_STEP(MD5_G, c,d,a,b, x[15], MD5_T[22], 14);
    MD5_STEP(MD5_G, b,c,d,a, x[ 4], MD5_T[23], 20);
    MD5_STEP(MD5_G, a,b,c,d, x[ 9], MD5_T[24],  5);
    MD5_STEP(MD5_G, d,a,b,c, x[14], MD5_T[25],  9);
    MD5_STEP(MD5_G, c,d,a,b, x[ 3], MD5_T[26], 14);
    MD5_STEP(MD5_G, b,c,d,a, x[ 8], MD5_T[27], 20);
    MD5_STEP(MD5_G, a,b,c,d, x[13], MD5_T[28],  5);
    MD5_STEP(MD5_G, d,a,b,c, x[ 2], MD5_T[29],  9);
    MD5_STEP(MD5_G, c,d,a,b, x[ 7], MD5_T[30], 14);
    MD5_STEP(MD5_G, b,c,d,a, x[12], MD5_T[31], 20);
    // Round 3
    MD5_STEP(MD5_H, a,b,c,d, x[ 5], MD5_T[32],  4);
    MD5_STEP(MD5_H, d,a,b,c, x[ 8], MD5_T[33], 11);
    MD5_STEP(MD5_H, c,d,a,b, x[11], MD5_T[34], 16);
    MD5_STEP(MD5_H, b,c,d,a, x[14], MD5_T[35], 23);
    MD5_STEP(MD5_H, a,b,c,d, x[ 1], MD5_T[36],  4);
    MD5_STEP(MD5_H, d,a,b,c, x[ 4], MD5_T[37], 11);
    MD5_STEP(MD5_H, c,d,a,b, x[ 7], MD5_T[38], 16);
    MD5_STEP(MD5_H, b,c,d,a, x[10], MD5_T[39], 23);
    MD5_STEP(MD5_H, a,b,c,d, x[13], MD5_T[40],  4);
    MD5_STEP(MD5_H, d,a,b,c, x[ 0], MD5_T[41], 11);
    MD5_STEP(MD5_H, c,d,a,b, x[ 3], MD5_T[42], 16);
    MD5_STEP(MD5_H, b,c,d,a, x[ 6], MD5_T[43], 23);
    MD5_STEP(MD5_H, a,b,c,d, x[ 9], MD5_T[44],  4);
    MD5_STEP(MD5_H, d,a,b,c, x[12], MD5_T[45], 11);
    MD5_STEP(MD5_H, c,d,a,b, x[15], MD5_T[46], 16);
    MD5_STEP(MD5_H, b,c,d,a, x[ 2], MD5_T[47], 23);
    // Round 4
    MD5_STEP(MD5_I, a,b,c,d, x[ 0], MD5_T[48],  6);
    MD5_STEP(MD5_I, d,a,b,c, x[ 7], MD5_T[49], 10);
    MD5_STEP(MD5_I, c,d,a,b, x[14], MD5_T[50], 15);
    MD5_STEP(MD5_I, b,c,d,a, x[ 5], MD5_T[51], 21);
    MD5_STEP(MD5_I, a,b,c,d, x[12], MD5_T[52],  6);
    MD5_STEP(MD5_I, d,a,b,c, x[ 3], MD5_T[53], 10);
    MD5_STEP(MD5_I, c,d,a,b, x[10], MD5_T[54], 15);
    MD5_STEP(MD5_I, b,c,d,a, x[ 1], MD5_T[55], 21);
    MD5_STEP(MD5_I, a,b,c,d, x[ 8], MD5_T[56],  6);
    MD5_STEP(MD5_I, d,a,b,c, x[15], MD5_T[57], 10);
    MD5_STEP(MD5_I, c,d,a,b, x[ 6], MD5_T[58], 15);
    MD5_STEP(MD5_I, b,c,d,a, x[13], MD5_T[59], 21);
    MD5_STEP(MD5_I, a,b,c,d, x[ 4], MD5_T[60],  6);
    MD5_STEP(MD5_I, d,a,b,c, x[11], MD5_T[61], 10);
    MD5_STEP(MD5_I, c,d,a,b, x[ 2], MD5_T[62], 15);
    MD5_STEP(MD5_I, b,c,d,a, x[ 9], MD5_T[63], 21);

    state[0] += a; state[1] += b;
    state[2] += c; state[3] += d;
}

void HashEngine::md5Update(MD5Context& ctx, const uint8_t* data, size_t length) {
    uint32_t index = (ctx.count[0] >> 3) & 0x3F;
    if ((ctx.count[0] += (uint32_t)(length << 3)) < (uint32_t)(length << 3))
        ctx.count[1]++;
    ctx.count[1] += (uint32_t)(length >> 29);

    size_t partLen = 64 - index;
    size_t i = 0;
    if (length >= partLen) {
        memcpy(ctx.buffer + index, data, partLen);
        md5Transform(ctx.state, ctx.buffer);
        for (i = partLen; i + 63 < length; i += 64)
            md5Transform(ctx.state, data + i);
        index = 0;
    }
    memcpy(ctx.buffer + index, data + i, length - i);
}

void HashEngine::md5Final(MD5Context& ctx, uint8_t digest[16]) {
    static const uint8_t PAD[64] = { 0x80 };
    uint8_t bits[8];
    for (int i = 0; i < 4; ++i) {
        bits[i  ] = (ctx.count[0] >> (i * 8)) & 0xFF;
        bits[i+4] = (ctx.count[1] >> (i * 8)) & 0xFF;
    }
    uint32_t index = (ctx.count[0] >> 3) & 0x3F;
    uint32_t padLen = (index < 56) ? (56 - index) : (120 - index);
    md5Update(ctx, PAD, padLen);
    md5Update(ctx, bits, 8);

    for (int i = 0; i < 4; ++i) {
        digest[i*4  ] = (ctx.state[i]      ) & 0xFF;
        digest[i*4+1] = (ctx.state[i] >>  8) & 0xFF;
        digest[i*4+2] = (ctx.state[i] >> 16) & 0xFF;
        digest[i*4+3] = (ctx.state[i] >> 24) & 0xFF;
    }
}

} // namespace AntiVirus
