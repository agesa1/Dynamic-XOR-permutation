#ifndef MEMORYENC_H
#define MEMORYENC_H

#include <cstdint>
#include <cstring>
#include <random>

class MemoryEncryption {
private:
    uint64_t k1, k2, k3;
    std::mt19937_64 gen;

    inline uint64_t rotl(uint64_t x, int r) {
        return (x << r) | (x >> (64 - r));
    }

    inline uint64_t rotr(uint64_t x, int r) {
        return (x >> r) | (x << (64 - r));
    }

    inline uint8_t rotl8(uint8_t x, int r) {
        r = r & 7;
        return (x << r) | (x >> (8 - r));
    }

    inline uint8_t rotr8(uint8_t x, int r) {
        r = r & 7;
        return (x >> r) | (x << (8 - r));
    }

    uint64_t mix(uint64_t v, uint64_t s) {
        v ^= s;
        v *= 0x9e3779b97f4a7c15ULL;
        v = rotl(v, 31);
        v *= 0xbf58476d1ce4e5b9ULL;
        return v;
    }

    void expandKey(uint64_t seed, size_t len) {
        gen.seed(seed);
        k1 = gen();
        k2 = gen();
        k3 = gen();

        for (size_t i = 0; i < (len & 0xFF); i++) {
            k1 = mix(k1, k2);
            k2 = mix(k2, k3);
            k3 = mix(k3, k1);
        }
    }

    uint8_t getKeyByte(size_t idx) {
        uint64_t pos = idx;
        uint64_t h = k1;

        h ^= mix(pos, k2);
        h = rotl(h, 13);
        h ^= mix(pos * k3, k1);
        h = rotr(h, 7);
        h ^= k3;

        return static_cast<uint8_t>((h ^ (h >> 32)) & 0xFF);
    }

    void transform(uint8_t* data, size_t size, uint32_t salt, bool encrypt) {
        for (size_t i = 0; i < size; i++) {
            uint8_t kb = getKeyByte(i + salt);

            if (encrypt) {
                data[i] ^= kb;
                data[i] = rotl8(data[i], (kb & 7));
                data[i] ^= getKeyByte(size - i - 1 + salt);
            }
            else {
                data[i] ^= getKeyByte(size - i - 1 + salt);
                data[i] = rotr8(data[i], (kb & 7));
                data[i] ^= kb;
            }
        }
    }

    uint64_t seed;
    uint32_t salt;

public:
    MemoryEncryption() {
        std::random_device rd;
        seed = (static_cast<uint64_t>(rd()) << 32) | rd();
        salt = rd();
        expandKey(seed, 256);
    }

    template<typename T>
    void encryptValue(T& value) {
        expandKey(seed, sizeof(T) + salt);
        uint8_t* ptr = reinterpret_cast<uint8_t*>(&value);
        transform(ptr, sizeof(T), salt, true);
    }

    template<typename T>
    void decryptValue(T& value) {
        expandKey(seed, sizeof(T) + salt);
        uint8_t* ptr = reinterpret_cast<uint8_t*>(&value);
        transform(ptr, sizeof(T), salt, false);
    }

    void encryptMemory(void* ptr, size_t size) {
        expandKey(seed, size + salt);
        transform(static_cast<uint8_t*>(ptr), size, salt, true);
    }

    void decryptMemory(void* ptr, size_t size) {
        expandKey(seed, size + salt);
        transform(static_cast<uint8_t*>(ptr), size, salt, false);
    }
};

template<typename T>
class SecureValue {
private:
    T encrypted;
    MemoryEncryption enc;

public:
    SecureValue() : encrypted(T()) {
        enc.encryptValue(encrypted);
    }

    SecureValue(const T& val) : encrypted(val) {
        enc.encryptValue(encrypted);
    }

    T get() {
        T temp = encrypted;
        enc.decryptValue(temp);
        return temp;
    }

    void set(const T& val) {
        encrypted = val;
        enc.encryptValue(encrypted);
    }

    operator T() {
        return get();
    }

    SecureValue& operator=(const T& val) {
        set(val);
        return *this;
    }
};

#endif
