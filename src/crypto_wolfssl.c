/*
 * crypto_wolfssl.c - Provide simplevpn client service
 *
 * Copyright (C) 2018, hxdyxd <hxdyxd@gmail.com>
 *
 * This file is part of the simplevpn.
 *
 * simplevpn is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * simplevpn is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with simplevpn; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "crypto.h"
#include "netclock.h"
#include "blake2.h"

#define CRYPTO_KEY_LEN    CHACHA20_POLY1305_AEAD_KEYSIZE
#define CRYPTO_NOICE_LEN  CHACHA20_POLY1305_AEAD_IV_SIZE

static uint8_t key[CRYPTO_KEY_LEN];
static uint8_t nonce[CRYPTO_NOICE_LEN];
static uint8_t has_crypto = 0;
static WC_RNG rng;

static void nonce_increment(uint8_t *n, size_t len)
{
    uint32_t c = 1;
    for (size_t i = 0; i < len; i++) {
        c += n[i];
        n[i] = (uint8_t)c;
        c >>= 8;
    }
}

char * crypto_version(void)
{
    return "wolfSSL";
}

int crypto_init(void)
{
    if (wc_InitRng(&rng) != 0) {
        return -1;
    }
    if (wc_RNG_GenerateBlock(&rng, nonce, CRYPTO_NOICE_LEN) != 0) {
        return -1;
    }
    return 0;
}

int crypto_set_password(const char *p, int plen)
{
    has_crypto = 1;
    return blake2b(key, sizeof(key), (uint8_t *)p, plen, NULL, 0);
}

int crypto_is_enabled(void)
{
    return has_crypto;
}

int crypto_encrypt(uint8_t *out_buf, uint8_t *in_buf, int in_len)
{
    int ret;

    if (in_len == 0) {
        return -1;
    }

    memcpy(out_buf, nonce, CRYPTO_NOICE_LEN);
    nonce_increment(nonce, CRYPTO_NOICE_LEN);

    ret = wc_ChaCha20Poly1305_Encrypt(key, out_buf, NULL, 0,
         in_buf, in_len,
         out_buf + CRYPTO_NOICE_LEN,
         out_buf + CRYPTO_NOICE_LEN + in_len);

    if (ret != 0) {
        return -1;
    }

    return in_len + CRYPTO_NOICE_LEN + CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;
}

int crypto_decrypt(uint8_t *out_buf, uint8_t *in_buf, int in_len)
{
    int ret;

    if (in_len <= CRYPTO_NOICE_LEN + CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE) {
        return -1;
    }

    ret = wc_ChaCha20Poly1305_Decrypt(key, in_buf, NULL, 0,
     in_buf + CRYPTO_NOICE_LEN, in_len - CRYPTO_NOICE_LEN - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE,
     in_buf + in_len - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE, out_buf);

    if (ret == MAC_CMP_FAILED_E) {
        printf("MAC_CMP_FAILED_E\n");
        return -1;
    } else if (ret != 0) {
        return -1;
    }
    return in_len - CRYPTO_NOICE_LEN - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;
}

void crypto_gen_rand(uint8_t *out_buf, int len)
{
    wc_RNG_GenerateBlock(&rng, out_buf, len);
}

void crypto_cleanup(void)
{
    wc_FreeRng(&rng);
}
