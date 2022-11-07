#include <iostream>

#include <include/repl/siphash.h>

#define PREAMBLE(len)                                                               \
    uint64_t v0 = SIPHASH_CONST_0;                                                  \
    uint64_t v1 = SIPHASH_CONST_1;                                                  \
    uint64_t v2 = SIPHASH_CONST_2;                                                  \
    uint64_t v3 = SIPHASH_CONST_3;                                                  \
    uint64_t b = ((u64)(len)) << 56;                                                \
    v3 ^= key->key[1];                                                              \
    v2 ^= key->key[0];                                                              \
    v1 ^= key->key[1];                                                              \
    v0 ^= key->key[0];                                                              \

#define ROL64(x, b) ((x << (b & 63)) | (x >> ((-b) & 63)))

#define U8TO64_LE(p)                                                                \
    (((uint64_t)((p)[0])) | ((uint64_t)((p)[1]) << 8) |                             \
     ((uint64_t)((p)[2]) << 16) | ((uint64_t)((p)[3]) << 24) |                      \
     ((uint64_t)((p)[4]) << 32) | ((uint64_t)((p)[5]) << 40) |                      \
     ((uint64_t)((p)[6]) << 48) | ((uint64_t)((p)[7]) << 56))

#define SIPROUND(v0, v1, v2, v3)                                                    \
    (v0) += (v1);                                                                   \
    (v1) = ROL64((v1), 13);                                                         \ 
    (v1) ^= (v0);                                                                   \
    (v0) = ROL64((v0), 32);                                                         \
    (v2) += (v3);                                                                   \
    (v3) = ROL64((v3), 16);                                                         \
    (v3) ^= (v2);                                                                   \
    (v0) += (v3);                                                                   \
    (v3) = ROL64((v3), 21);                                                         \
    (v3) ^= (v0);                                                                   \
    (v2) += (v1);                                                                   \
    (v1) = ROL64((v1), 17);                                                         \
    (v1) ^= (v2);                                                                   \
    (v2) = ROL64((v2), 32);

#define POSTAMBLE                                                                   \
    v3 ^= b;                                                                        \
    SIPROUND;                                                                       \
    SIPROUND;                                                                       \
    v0 ^= b;                                                                        \
    v2 ^= 0xff;                                                                     \
    SIPROUND;                                                                       \
    SIPROUND;                                                                       \
    SIPROUND;                                                                       \
    SIPROUND;                                                                       \
    return (v0 ^ v1) ^ (v2 ^ v3);                                                   

uint64_t siphash(char *data, size_t len, const siphash_key key) {
    const uint8_t *end = data + len - (len % sizeof(uint64_t));
    const uint8_t left = len & (sizeof(uint64_t) - 1);
    uint64_t m;
    PREAMBLE(len);
    for (; data != end; data += sizeof(uint64_t)) {
        m = U8TO64_LE(data);
        v3 ^= m;
        SIPROUND;
        SIPROUND;
        v0 ^= m;
    }

    switch (left) {
        case 7: 
            b |= ((uint64_t)end[6]) << 48; 
        case 6: 
            b |= ((uint64_t)end[5]) << 40;
        case 5:
            b |= ((uint64_t)end[4]) << 32;
        case 4:
            b |= ((uint64_t)end[3]) << 24;
        case 3:
            b |= ((uint64_t)end[2]) << 16;
        case 2:
            b |= ((uint64_t)end[1]) << 8;
        case 1:
            b |= ((uint64_t)end[0]);
            break;
        case 0:
            break;
    }
    POSTAMBLE
}

uint64_t siphash_3u32(const uint32_t first, const uint32_t second, const uint32_t third, 
        const siphash_key key) {
    uint64_t combined = (uint64_t)second << 32 | first;
    PREAMBLE(12);
    v3 ^= combined;
    SIPROUND;
    SIPROUND;
    v0 ^= combined;
    b |= third;
    POSTAMBLE
}
