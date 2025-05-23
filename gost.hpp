#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <iostream>
#define GOST_DEBUG
// ======= Debugging Macros =======
#ifdef GOST_DEBUG
#define GOST_DEBUG_LOG(msg) \
    std::cerr << "[GOST-DEBUG] " << __FILE__ << ":" << __LINE__ << " (" << __FUNCTION__ << ") - " << msg << std::endl
#define GOST_DEBUG_DUMP(label, data) \
    do { \
        std::cerr << "[GOST-DEBUG] " << label << ": "; \
        for (size_t _i = 0; _i < (data).size(); ++_i) \
            std::cerr << std::hex << ((unsigned int)(uint8_t)(data)[_i]) << " "; \
        std::cerr << std::dec << "(len=" << (data).size() << ")" << std::endl; \
    } while (0)
#else
#define GOST_DEBUG_LOG(msg) ((void)0)
#define GOST_DEBUG_DUMP(label, data) ((void)0)
#endif

// ========== Attribute Macros ==========
#if defined(__GNUC__) || defined(__clang__)
#define __attr_nodiscard __attribute__((warn_unused_result))
#define __attr_malloc __attribute__((malloc))
#define __attr_hot __attribute__((hot))
#define __attr_cold __attribute__((cold))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define __attr_nodiscard
#define __attr_malloc
#define __attr_hot
#define __attr_cold
#define likely(x) (x)
#define unlikely(x) (x)
#endif

#ifdef __cplusplus
#define __restrict__ __restrict
#define __noexcept noexcept
#define __const_noexcept noexcept
#else
#define __restrict__ restrict
#define __noexcept
#define __const_noexcept
#endif

/**
 * @brief Enum for supported key sizes (in bytes).
 */
enum class GOST_KEY_SIZE : size_t
{
    BITS_256 = 32
};

/** @brief Block cipher modes. */
struct GOST_ECB_Mode {};
struct GOST_CBC_Mode {};
struct GOST_CFB_Mode {};
struct GOST_OFB_Mode {};
struct GOST_CTR_Mode {};

// ===================== Internal error handling =====================
namespace gost_detail
{
[[noreturn]] __attr_cold inline void fail(const char *msg)
{
    GOST_DEBUG_LOG(std::string("Exception: ") + msg);
    throw std::runtime_error(msg);
}
} // namespace gost_detail

// ========== Utility namespace for hex, base64, binary ==========
namespace gost_util
{
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char b64_pad = '=';

inline std::string toHex(const std::string &data)
{
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (uint8_t b : data)
    {
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0xF]);
    }
    return out;
}

inline std::string fromHex(const std::string &hexStr)
{
    std::string out;
    if (hexStr.size() % 2 != 0)
        gost_detail::fail("Odd length hex string");
    out.reserve(hexStr.size() / 2);
    for (size_t i = 0; i < hexStr.size(); i += 2)
    {
        uint8_t hi = static_cast<uint8_t>(std::stoi(hexStr.substr(i, 1), nullptr, 16));
        uint8_t lo = static_cast<uint8_t>(std::stoi(hexStr.substr(i + 1, 1), nullptr, 16));
        out.push_back((hi << 4) | lo);
    }
    return out;
}

inline std::string toBase64(const std::string &data)
{
    std::string out;
    int val = 0, valb = -6;
    for (uint8_t c : data)
    {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0)
        {
            out.push_back(b64_table[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
        out.push_back(b64_table[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4)
        out.push_back(b64_pad);
    return out;
}

inline std::string fromBase64(const std::string &b64)
{
    int val = 0, valb = -8;
    std::string out;
    for (uint8_t c : b64)
    {
        if (c == b64_pad)
            break;
        const char *p = std::find(b64_table, b64_table + 64, c);
        if (p == b64_table + 64)
            break;
        val = (val << 6) + (p - b64_table);
        valb += 6;
        if (valb >= 0)
        {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}
} // namespace gost_util

/**
 * @class GOSTKeyIVGenerator
 * @brief Utility class for securely generating random keys and IVs.
 */
class GOSTKeyIVGenerator
{
public:
    static std::string generateKey(GOST_KEY_SIZE keySize = GOST_KEY_SIZE::BITS_256)
    {
        size_t size = static_cast<size_t>(keySize);
        std::string key(size, '\0');
        randomFill(reinterpret_cast<uint8_t *>(&key[0]), size);
        GOST_DEBUG_DUMP("Generated Key", key);
        return key;
    }
    static std::string generateIV(size_t ivSize = 8)
    {
        std::string iv(ivSize, '\0');
        randomFill(reinterpret_cast<uint8_t *>(&iv[0]), ivSize);
        GOST_DEBUG_DUMP("Generated IV", iv);
        return iv;
    }

private:
    static void randomFill(uint8_t *buf, size_t n)
    {
        std::random_device rd;
        for (size_t i = 0; i < n; ++i)
        {
            buf[i] = static_cast<uint8_t>(rd());
        }
    }
};

/**
 * @class GOSTResult
 * @brief Wrapper for encrypted/decrypted results supporting method chaining and conversion utilities.
 */
class GOSTResult
{
    std::string data_;

public:
    GOSTResult(const std::string &data) : data_(data) {}
    GOSTResult toHex() const { return GOSTResult(gost_util::toHex(data_)); }
    GOSTResult fromHex() const { return GOSTResult(gost_util::fromHex(data_)); }
    GOSTResult toBase64() const { return GOSTResult(gost_util::toBase64(data_)); }
    GOSTResult fromBase64() const { return GOSTResult(gost_util::fromBase64(data_)); }
    std::string asString() const { return data_; }
    operator std::string() const { return data_; }
};

/**
 * @class GOST
 * @brief Flexible, template-based implementation of the GOST 28147-89 block cipher.
 * @tparam KEY_SZ The key size (default 256 bits).
 */
template <GOST_KEY_SIZE KEY_SZ = GOST_KEY_SIZE::BITS_256>
class GOST
{
public:
    using uint = uint32_t;
    using uchar = uint8_t;
    static constexpr size_t BlockSize = 8;
    static constexpr size_t KeySize = static_cast<size_t>(KEY_SZ);

    // Mode structs
    struct ECB
    {
        static GOSTResult Encrypt(const std::string &plaintext, const std::string &key)
        {
            GOST cipher;
            return GOSTResult(cipher.encryptECB(plaintext, key));
        }
        static GOSTResult Decrypt(const std::string &ciphertext, const std::string &key)
        {
            GOST cipher;
            return GOSTResult(cipher.decryptECB(ciphertext, key));
        }
    };
    struct CBC
    {
        static GOSTResult Encrypt(const std::string &plaintext, const std::string &key, const std::string &iv)
        {
            GOST cipher;
            return GOSTResult(cipher.encryptCBC(plaintext, key, iv));
        }
        static GOSTResult Decrypt(const std::string &ciphertext, const std::string &key, const std::string &iv)
        {
            GOST cipher;
            return GOSTResult(cipher.decryptCBC(ciphertext, key, iv));
        }
    };
    struct CFB
    {
        static GOSTResult Encrypt(const std::string &plaintext, const std::string &key, const std::string &iv)
        {
            GOST cipher;
            return GOSTResult(cipher.encryptCFB(plaintext, key, iv));
        }
        static GOSTResult Decrypt(const std::string &ciphertext, const std::string &key, const std::string &iv)
        {
            GOST cipher;
            return GOSTResult(cipher.decryptCFB(ciphertext, key, iv));
        }
    };
    struct OFB
    {
        static GOSTResult Encrypt(const std::string &plaintext, const std::string &key, const std::string &iv)
        {
            GOST cipher;
            return GOSTResult(cipher.encryptOFB(plaintext, key, iv));
        }
        static GOSTResult Decrypt(const std::string &ciphertext, const std::string &key, const std::string &iv)
        {
            GOST cipher;
            return GOSTResult(cipher.decryptOFB(ciphertext, key, iv));
        }
    };
    struct CTR
    {
        static GOSTResult Encrypt(const std::string &plaintext, const std::string &key, const std::string &nonce)
        {
            GOST cipher;
            return GOSTResult(cipher.encryptCTR(plaintext, key, nonce));
        }
        static GOSTResult Decrypt(const std::string &ciphertext, const std::string &key, const std::string &nonce)
        {
            GOST cipher;
            return GOSTResult(cipher.decryptCTR(ciphertext, key, nonce));
        }
    };

private:
    static constexpr size_t NumRounds = 32;
    static constexpr size_t SubkeyCount = 8;

    // Standard S-box (test S-box from RFC 5830)
    static constexpr uint8_t SBOX[8][16] = {
        {4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3},
        {14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9},
        {5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11},
        {7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3},
        {6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2},
        {4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14},
        {13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12},
        {1, 15, 13, 0, 5, 10, 3, 14, 9, 7, 6, 8, 2, 11, 4, 12}
    };

    // PKCS7 Padding
    std::string pkcs7Pad(const std::string &data) const __noexcept
    {
        size_t padLen = BlockSize - (data.size() % BlockSize);
        if (padLen == 0) padLen = BlockSize;
        std::string padded = data;
        padded.append(padLen, static_cast<char>(padLen));
        GOST_DEBUG_LOG("Padding applied");
        GOST_DEBUG_LOG("padLen = " + std::to_string(padLen));
        GOST_DEBUG_DUMP("Padded data", padded);
        return padded;
    }
    std::string pkcs7Unpad(const std::string &data) const
    {
        GOST_DEBUG_LOG("Entering pkcs7Unpad");
        GOST_DEBUG_DUMP("Data to unpad", data);
        if (unlikely(data.empty() || data.size() % BlockSize != 0))
        {
            GOST_DEBUG_LOG("Invalid padding size: data.size() = " + std::to_string(data.size()));
            gost_detail::fail("GOST: pkcs7Unpad: Invalid padding size.");
        }
        uchar padLen = static_cast<uchar>(data.back());
        GOST_DEBUG_LOG("padLen from data.back() = " + std::to_string(padLen));
        if (unlikely(padLen == 0 || padLen > BlockSize))
        {
            GOST_DEBUG_LOG("Invalid padding value: " + std::to_string(padLen));
            gost_detail::fail("GOST: pkcs7Unpad: Invalid padding value.");
        }
        for (size_t i = data.size() - padLen; i < data.size(); ++i)
        {
            if (unlikely(static_cast<uchar>(data[i]) != padLen))
            {
                GOST_DEBUG_LOG("Invalid padding content at offset " + std::to_string(i) +
                    " (expected " + std::to_string(padLen) +
                    ", got " + std::to_string(static_cast<uchar>(data[i])) + ")");
                gost_detail::fail("GOST: pkcs7Unpad: Invalid padding content.");
            }
        }
        std::string result = data.substr(0, data.size() - padLen);
        GOST_DEBUG_LOG("Unpadding successful");
        GOST_DEBUG_DUMP("Unpadded data", result);
        return result;
    }

    static std::string xorStrings(const std::string &a, const std::string &b) __noexcept
    {
        if (unlikely(a.size() != b.size()))
        {
            GOST_DEBUG_LOG("xorStrings: size mismatch: a.size() = " + std::to_string(a.size()) + ", b.size() = " + std::to_string(b.size()));
            gost_detail::fail("GOST: xorStrings: Inputs must have equal size.");
        }
        std::string out(a.size(), '\0');
        for (size_t i = 0; i < a.size(); ++i)
            out[i] = a[i] ^ b[i];
        GOST_DEBUG_DUMP("xorStrings result", out);
        return out;
    }

    static void incrementCounter(std::string &counter) __noexcept
    {
        GOST_DEBUG_DUMP("Counter before increment", counter);
        for (int i = BlockSize - 1; i >= 0; --i)
        {
            uint8_t &b = reinterpret_cast<uint8_t &>(counter[i]);
            if (++b != 0)
                break;
        }
        GOST_DEBUG_DUMP("Counter after increment", counter);
    }

    static uint32_t f(uint32_t data, const uint32_t *k)
    {
        uint32_t x = data + *k;
        uint32_t y = 0;
        // Apply S-Box
        for (int i = 0; i < 8; ++i)
            y |= SBOX[i][(x >> (4 * i)) & 0xF] << (4 * i);
        // 11-bit left rotation
        return (y << 11) | (y >> (32 - 11));
    }

    void encryptBlock(const uchar *in, uchar *out, const uint32_t *key) const
{
    uint32_t n1 = get32le(in);
    uint32_t n2 = get32le(in + 4);

    // 24 rounds: K1..K8 repeated 3 times
    for (int i = 0; i < 24; ++i)
    {
        uint32_t tmp = n1;
        n1 = n2 ^ f(n1, &key[i % 8]);
        n2 = tmp;
    }
    // 8 rounds: K8..K1
    for (int i = 0; i < 8; ++i)
    {
        uint32_t tmp = n1;
        n1 = n2 ^ f(n1, &key[7 - (i % 8)]);
        n2 = tmp;
    }
    put32le(out, n1);
    put32le(out + 4, n2);
}

void decryptBlock(const uchar *in, uchar *out, const uint32_t *key) const
{
    uint32_t n1 = get32le(in);
    uint32_t n2 = get32le(in + 4);
    // 8 rounds: K1..K8
    for (int i = 0; i < 8; ++i) {
        uint32_t tmp = n1;
        n1 = n2 ^ f(n1, &key[i % 8]);
        n2 = tmp;
    }
    // 24 rounds: K8..K1, repeated 3 times
    for (int i = 0; i < 24; ++i) {
        uint32_t tmp = n1;
        n1 = n2 ^ f(n1, &key[7 - (i % 8)]);
        n2 = tmp;
    }
    put32le(out, n1);
    put32le(out + 4, n2);
}
    // Utilities for 32-bit LE encoding/decoding
    static uint32_t get32le(const uchar *p)
    {
        return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
    }
    static void put32le(uchar *p, uint32_t v)
    {
        p[0] = v & 0xFF;
        p[1] = (v >> 8) & 0xFF;
        p[2] = (v >> 16) & 0xFF;
        p[3] = (v >> 24) & 0xFF;
    }

    void keySchedule(std::array<uint32_t, SubkeyCount> &key, const std::string &userKey) const
    {
        GOST_DEBUG_LOG("keySchedule: userKey.size() = " + std::to_string(userKey.size()));
        GOST_DEBUG_DUMP("keySchedule: userKey", userKey);
        if (userKey.size() != KeySize)
            gost_detail::fail("GOST: keySchedule: Key must be 32 bytes.");
        for (size_t i = 0; i < SubkeyCount; ++i)
            key[i] = get32le(reinterpret_cast<const uchar *>(&userKey[i * 4]));
        GOST_DEBUG_LOG("keySchedule: key loaded");
    }

    std::string encryptECB(const std::string &plaintext, const std::string &keystr) const __const_noexcept
    {
        GOST_DEBUG_LOG("encryptECB: plaintext.size() = " + std::to_string(plaintext.size()));
        GOST_DEBUG_DUMP("encryptECB: plaintext", plaintext);
        GOST_DEBUG_DUMP("encryptECB: key", keystr);
        auto padded = pkcs7Pad(plaintext);
        std::string ciphertext;
        ciphertext.resize(padded.size());
        std::array<uint32_t, SubkeyCount> key;
        keySchedule(key, keystr);

        for (size_t i = 0; i < padded.size(); i += BlockSize)
            encryptBlock(reinterpret_cast<const uchar *>(&padded[i]), reinterpret_cast<uchar *>(&ciphertext[i]), key.data());
        GOST_DEBUG_DUMP("encryptECB: ciphertext", ciphertext);
        return ciphertext;
    }

    std::string decryptECB(const std::string &ciphertext, const std::string &keystr) const __const_noexcept
    {
        GOST_DEBUG_LOG("decryptECB: ciphertext.size() = " + std::to_string(ciphertext.size()));
        GOST_DEBUG_DUMP("decryptECB: ciphertext", ciphertext);
        GOST_DEBUG_DUMP("decryptECB: key", keystr);
        if (unlikely(ciphertext.empty() || (ciphertext.size() % BlockSize) != 0))
            gost_detail::fail("GOST: decryptECB: Ciphertext size must be a positive multiple of 8 bytes.");
        std::string padded;
        padded.resize(ciphertext.size());
        std::array<uint32_t, SubkeyCount> key;
        keySchedule(key, keystr);

        for (size_t i = 0; i < ciphertext.size(); i += BlockSize)
            decryptBlock(reinterpret_cast<const uchar *>(&ciphertext[i]), reinterpret_cast<uchar *>(&padded[i]), key.data());
        GOST_DEBUG_DUMP("decryptECB: decrypted padded", padded);
        std::string result = pkcs7Unpad(padded);
        GOST_DEBUG_DUMP("decryptECB: result", result);
        return result;
    }

    std::string encryptCBC(const std::string &plaintext, const std::string &keystr, const std::string &iv) const __const_noexcept
    {
        GOST_DEBUG_LOG("encryptCBC: plaintext.size() = " + std::to_string(plaintext.size()));
        GOST_DEBUG_DUMP("encryptCBC: plaintext", plaintext);
        GOST_DEBUG_DUMP("encryptCBC: key", keystr);
        GOST_DEBUG_DUMP("encryptCBC: iv", iv);
        if (unlikely(iv.size() != BlockSize))
            gost_detail::fail("GOST: encryptCBC: IV must be 8 bytes.");
        auto padded = pkcs7Pad(plaintext);
        std::string ciphertext;
        ciphertext.resize(padded.size());
        std::array<uint32_t, SubkeyCount> key;
        keySchedule(key, keystr);

        std::string prev = iv;
        for (size_t i = 0; i < padded.size(); i += BlockSize)
        {
            std::string block = xorStrings(padded.substr(i, BlockSize), prev);
            encryptBlock(reinterpret_cast<const uchar *>(block.data()), reinterpret_cast<uchar *>(&ciphertext[i]), key.data());
            prev = ciphertext.substr(i, BlockSize);
        }
        GOST_DEBUG_DUMP("encryptCBC: ciphertext", ciphertext);
        return ciphertext;
    }

    std::string decryptCBC(const std::string &ciphertext, const std::string &keystr, const std::string &iv) const __const_noexcept
    {
        GOST_DEBUG_LOG("decryptCBC: ciphertext.size() = " + std::to_string(ciphertext.size()));
        GOST_DEBUG_DUMP("decryptCBC: ciphertext", ciphertext);
        GOST_DEBUG_DUMP("decryptCBC: key", keystr);
        GOST_DEBUG_DUMP("decryptCBC: iv", iv);
        if (unlikely(iv.size() != BlockSize))
            gost_detail::fail("GOST: decryptCBC: IV must be 8 bytes.");
        if (unlikely(ciphertext.empty() || (ciphertext.size() % BlockSize) != 0))
            gost_detail::fail("GOST: decryptCBC: Ciphertext size must be a positive multiple of 8 bytes.");
        std::string padded;
        padded.resize(ciphertext.size());
        std::array<uint32_t, SubkeyCount> key;
        keySchedule(key, keystr);

        std::string prev = iv;
        for (size_t i = 0; i < ciphertext.size(); i += BlockSize)
        {
            decryptBlock(reinterpret_cast<const uchar *>(&ciphertext[i]), reinterpret_cast<uchar *>(&padded[i]), key.data());
            for (size_t j = 0; j < BlockSize; ++j)
                padded[i + j] ^= prev[j];
            prev = ciphertext.substr(i, BlockSize);
        }
        GOST_DEBUG_DUMP("decryptCBC: decrypted padded", padded);
        std::string result = pkcs7Unpad(padded);
        GOST_DEBUG_DUMP("decryptCBC: result", result);
        return result;
    }

    std::string encryptCFB(const std::string &plaintext, const std::string &keystr, const std::string &iv) const __const_noexcept
    {
        GOST_DEBUG_LOG("encryptCFB: plaintext.size() = " + std::to_string(plaintext.size()));
        GOST_DEBUG_DUMP("encryptCFB: plaintext", plaintext);
        GOST_DEBUG_DUMP("encryptCFB: key", keystr);
        GOST_DEBUG_DUMP("encryptCFB: iv", iv);
        if (unlikely(iv.size() != BlockSize))
            gost_detail::fail("GOST: encryptCFB: IV must be 8 bytes.");
        std::string ciphertext;
        ciphertext.resize(plaintext.size());
        std::array<uint32_t, SubkeyCount> key;
        keySchedule(key, keystr);

        std::string prev = iv;
        for (size_t i = 0; i < plaintext.size(); i += BlockSize)
        {
            uchar enc[BlockSize];
            encryptBlock(reinterpret_cast<const uchar *>(prev.data()), enc, key.data());
            size_t chunk = std::min(BlockSize, plaintext.size() - i);
            for (size_t j = 0; j < chunk; ++j)
                ciphertext[i + j] = plaintext[i + j] ^ enc[j];
            prev = ciphertext.substr(i, chunk) + prev.substr(chunk, BlockSize - chunk);
        }
        GOST_DEBUG_DUMP("encryptCFB: ciphertext", ciphertext);
        return ciphertext;
    }

    std::string decryptCFB(const std::string &ciphertext, const std::string &keystr, const std::string &iv) const __const_noexcept
    {
        GOST_DEBUG_LOG("decryptCFB: ciphertext.size() = " + std::to_string(ciphertext.size()));
        GOST_DEBUG_DUMP("decryptCFB: ciphertext", ciphertext);
        GOST_DEBUG_DUMP("decryptCFB: key", keystr);
        GOST_DEBUG_DUMP("decryptCFB: iv", iv);
        if (unlikely(iv.size() != BlockSize))
            gost_detail::fail("GOST: decryptCFB: IV must be 8 bytes.");
        std::string plaintext;
        plaintext.resize(ciphertext.size());
        std::array<uint32_t, SubkeyCount> key;
        keySchedule(key, keystr);

        std::string prev = iv;
        for (size_t i = 0; i < ciphertext.size(); i += BlockSize)
        {
            uchar enc[BlockSize];
            encryptBlock(reinterpret_cast<const uchar *>(prev.data()), enc, key.data());
            size_t chunk = std::min(BlockSize, ciphertext.size() - i);
            for (size_t j = 0; j < chunk; ++j)
                plaintext[i + j] = ciphertext[i + j] ^ enc[j];
            prev = ciphertext.substr(i, chunk) + prev.substr(chunk, BlockSize - chunk);
        }
        GOST_DEBUG_DUMP("decryptCFB: plaintext", plaintext);
        return plaintext;
    }

    std::string encryptOFB(const std::string &plaintext, const std::string &keystr, const std::string &iv) const __const_noexcept
    {
        GOST_DEBUG_LOG("encryptOFB: plaintext.size() = " + std::to_string(plaintext.size()));
        GOST_DEBUG_DUMP("encryptOFB: plaintext", plaintext);
        GOST_DEBUG_DUMP("encryptOFB: key", keystr);
        GOST_DEBUG_DUMP("encryptOFB: iv", iv);
        if (unlikely(iv.size() != BlockSize))
            gost_detail::fail("GOST: encryptOFB: IV must be 8 bytes.");
        std::string ciphertext;
        ciphertext.resize(plaintext.size());
        std::array<uint32_t, SubkeyCount> key;
        keySchedule(key, keystr);

        std::string ofb = iv;
        for (size_t i = 0; i < plaintext.size(); i += BlockSize)
        {
            uchar outblock[BlockSize];
            encryptBlock(reinterpret_cast<const uchar *>(ofb.data()), outblock, key.data());
            size_t chunk = std::min(BlockSize, plaintext.size() - i);
            for (size_t j = 0; j < chunk; ++j)
                ciphertext[i + j] = plaintext[i + j] ^ outblock[j];
            ofb.assign(reinterpret_cast<const char *>(outblock), BlockSize);
        }
        GOST_DEBUG_DUMP("encryptOFB: ciphertext", ciphertext);
        return ciphertext;
    }

    std::string decryptOFB(const std::string &ciphertext, const std::string &keystr, const std::string &iv) const __const_noexcept
    {
        return encryptOFB(ciphertext, keystr, iv);
    }

    std::string encryptCTR(const std::string &plaintext, const std::string &keystr, const std::string &nonce) const __const_noexcept
    {
        GOST_DEBUG_LOG("encryptCTR: plaintext.size() = " + std::to_string(plaintext.size()));
        GOST_DEBUG_DUMP("encryptCTR: plaintext", plaintext);
        GOST_DEBUG_DUMP("encryptCTR: key", keystr);
        GOST_DEBUG_DUMP("encryptCTR: nonce", nonce);
        if (unlikely(nonce.size() != BlockSize))
            gost_detail::fail("GOST: encryptCTR: Nonce must be 8 bytes.");
        std::string ciphertext;
        ciphertext.resize(plaintext.size());
        std::array<uint32_t, SubkeyCount> key;
        keySchedule(key, keystr);

        std::string counter = nonce;
        for (size_t i = 0; i < plaintext.size(); i += BlockSize)
        {
            uchar keystream[BlockSize];
            encryptBlock(reinterpret_cast<const uchar *>(counter.data()), keystream, key.data());
            size_t chunk = std::min(BlockSize, plaintext.size() - i);
            for (size_t j = 0; j < chunk; ++j)
                ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
            incrementCounter(counter);
        }
        GOST_DEBUG_DUMP("encryptCTR: ciphertext", ciphertext);
        return ciphertext;
    }

    std::string decryptCTR(const std::string &ciphertext, const std::string &keystr, const std::string &nonce) const __const_noexcept
    {
        return encryptCTR(ciphertext, keystr, nonce);
    }
};
