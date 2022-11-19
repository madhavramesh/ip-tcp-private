#pragma once 

#include <cstdint>

constexpr unsigned int_hash(uint32_t key) {
    key += ~(key << 15);
    key ^= (key >> 10);
    key += (key << 3);
    key ^= (key >> 6);
    key += ~(key << 11);
    key ^= (key >> 16);
    return key;
}

constexpr unsigned pair_int_hash(uint32_t key1, uint32_t key2) {
    return int_hash((int_hash(key1) * 209) ^ (int_hash(key2 * 413)));
}
