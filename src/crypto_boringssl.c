/*
 * crypto_boringssl.c - Provide simplevpn client service
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
#include <openssl/aead.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "crypto.h"
#include "netclock.h"
#include "blake2.h"

#define CRYPTO_KEY_LEN    32  // ChaCha20-Poly1305 key size
#define CRYPTO_NOICE_LEN  12  // ChaCha20-Poly1305 nonce size
#define CRYPTO_TAG_LEN    16  // ChaCha20-Poly1305 authentication tag size

static uint8_t key[CRYPTO_KEY_LEN];
static uint8_t nonce[CRYPTO_NOICE_LEN];
static uint8_t has_crypto = 0;
static EVP_AEAD_CTX encrypt_ctx;
static EVP_AEAD_CTX decrypt_ctx;
static int ctx_initialized = 0;

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
#ifdef OPENSSL_VERSION_TEXT
    return (char *)OPENSSL_VERSION_TEXT;
#else
    return (char *)OPENSSL_VERSION_NUMBER;
#endif
}

int crypto_init(void)
{
    if (!RAND_bytes(nonce, CRYPTO_NOICE_LEN)) {
        return -1;
    }
    
    const EVP_AEAD *aead = EVP_aead_chacha20_poly1305();
    if (!EVP_AEAD_CTX_init(&encrypt_ctx, aead, key, CRYPTO_KEY_LEN, CRYPTO_TAG_LEN, NULL) ||
        !EVP_AEAD_CTX_init(&decrypt_ctx, aead, key, CRYPTO_KEY_LEN, CRYPTO_TAG_LEN, NULL)) {
        return -1;
    }
    
    ctx_initialized = 1;
    return 0;
}

int crypto_set_password(const char *p, int plen)
{
    has_crypto = 1;
    int ret = blake2b(key, sizeof(key), (uint8_t *)p, plen, NULL, 0);

    if (ctx_initialized) {
        EVP_AEAD_CTX_cleanup(&encrypt_ctx);
        EVP_AEAD_CTX_cleanup(&decrypt_ctx);
        
        const EVP_AEAD *aead = EVP_aead_chacha20_poly1305();
        if (!EVP_AEAD_CTX_init(&encrypt_ctx, aead, key, CRYPTO_KEY_LEN, CRYPTO_TAG_LEN, NULL) ||
            !EVP_AEAD_CTX_init(&decrypt_ctx, aead, key, CRYPTO_KEY_LEN, CRYPTO_TAG_LEN, NULL)) {
            ctx_initialized = 0;
            return -1;
        }
    }
    
    return ret;
}

int crypto_is_enabled(void)
{
    return has_crypto;
}

int crypto_encrypt(uint8_t *out_buf, uint8_t *in_buf, int in_len)
{
    size_t out_len;

    if (in_len == 0) {
        return -1;
    }

    memcpy(out_buf, nonce, CRYPTO_NOICE_LEN);
    nonce_increment(nonce, CRYPTO_NOICE_LEN);

    if (!EVP_AEAD_CTX_seal(&encrypt_ctx, 
                          out_buf + CRYPTO_NOICE_LEN, &out_len,
                          in_len + CRYPTO_TAG_LEN,
                          out_buf, CRYPTO_NOICE_LEN,
                          in_buf, in_len,
                          NULL, 0)) {
        return -1;
    }

    return in_len + CRYPTO_NOICE_LEN + CRYPTO_TAG_LEN;
}

int crypto_decrypt(uint8_t *out_buf, uint8_t *in_buf, int in_len)
{
    size_t out_len;

    if (in_len <= CRYPTO_NOICE_LEN + CRYPTO_TAG_LEN) {
        return -1;
    }

    if (!EVP_AEAD_CTX_open(&decrypt_ctx,
                          out_buf, &out_len,
                          in_len - CRYPTO_NOICE_LEN - CRYPTO_TAG_LEN,
                          in_buf, CRYPTO_NOICE_LEN,
                          in_buf + CRYPTO_NOICE_LEN, 
                          in_len - CRYPTO_NOICE_LEN,
                          NULL, 0)) {
        return -1;
    }

    return (int)out_len;
}

void crypto_gen_rand(uint8_t *out_buf, int len)
{
    RAND_bytes(out_buf, len);
}

void crypto_cleanup(void)
{
    if (ctx_initialized) {
        EVP_AEAD_CTX_cleanup(&encrypt_ctx);
        EVP_AEAD_CTX_cleanup(&decrypt_ctx);
        ctx_initialized = 0;
    }
}
