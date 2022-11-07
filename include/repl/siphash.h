/* Modified from the LINUX source code
 *
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
 * Copyright (C) 2016-2022 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * SipHash: a fast short-input PRF
 * https://131002.net/siphash/
 *
 * This implementation is specifically for SipHash2-4 for a secure PRF
 * and HalfSipHash1-3/SipHash1-3 for an insecure PRF only suitable for
 * hashtables.
 */

# pragma once

#include <iostream>

struct siphash_key {
    uint64_t key[2];
};

uint64_t siphash(char *data, size_t len, const siphash_key key);

uint64_t siphash_3u32(const uint32_t first, const uint32_t second, const uint32_t third, 
                      const siphash_key key);

const unsigned long long SIPHASH_CONST_0 = 0x736f6d6570736575ULL;
const unsigned long long SIPHASH_CONST_1 = 0x646f72616e646f6dULL;
const unsigned long long SIPHASH_CONST_2 = 0x6c7967656e657261ULL;
const unsigned long long SIPHASH_CONST_3 = 0x7465646279746573ULL;
