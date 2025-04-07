/*
 * crypto.c - Provide simplevpn client service
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

#include <sodium.h>
#include <stdint.h>
#include <string.h>
#include "crypto.h"
#include "netclock.h"

#define CRYPTO_KEY_LEN    crypto_aead_chacha20poly1305_IETF_KEYBYTES
#define CRYPTO_NOICE_LEN  crypto_aead_chacha20poly1305_IETF_NPUBBYTES

// will not copy key any more
static uint8_t key[CRYPTO_KEY_LEN];
static uint8_t nonce[CRYPTO_NOICE_LEN];
static uint8_t has_crypto = 0;

int crypto_init(void)
{
    randombytes_set_implementation(&randombytes_salsa20_implementation);
    if (-1 == sodium_init())
        return -1;
    randombytes_buf(nonce, CRYPTO_NOICE_LEN);
    return 0;
}

int crypto_set_password(const char *p, int plen)
{
    has_crypto = 1;
    return crypto_generichash(key, sizeof(key), (uint8_t *)p, plen, NULL, 0);
}

int crypto_is_enabled(void)
{
    return has_crypto;
}

//message
//ciphertext
int crypto_encrypt(uint8_t *out_buf, uint8_t *in_buf, int in_len)
{
    unsigned long long out_len = 0;
    if(in_len == 0) {
        return -1;
    }
    //randombytes_buf(out_buf, CRYPTO_NOICE_LEN);
    memcpy(out_buf, nonce, CRYPTO_NOICE_LEN);
    sodium_increment(nonce, CRYPTO_NOICE_LEN);
    int err = crypto_aead_chacha20poly1305_ietf_encrypt(out_buf + CRYPTO_NOICE_LEN, &out_len,
                                                    in_buf, (unsigned long long)in_len,
                                                     NULL, 0, NULL, out_buf, key);
    if (err != 0) {
        return -1;
    }
    return (uint32_t)out_len + CRYPTO_NOICE_LEN;
}

int crypto_decrypt(uint8_t *out_buf, uint8_t *in_buf, int in_len)
{
    unsigned long long out_len = 0;
    if(in_len <= CRYPTO_NOICE_LEN) {
        return -1;
    }
    int err = crypto_aead_chacha20poly1305_ietf_decrypt(out_buf, &out_len, NULL,
                                                     in_buf + CRYPTO_NOICE_LEN,
                                                     (unsigned long long)in_len - CRYPTO_NOICE_LEN,
                                                    NULL, 0, in_buf, key);
    if (err != 0) {
        return -1;
    }
    return (uint32_t)out_len;
}

void crypto_gen_rand(uint8_t *out_buf, int in_len)
{
    randombytes_buf(out_buf, in_len);
}

int crypto_speed_test(int test_len)
{
    uint32_t et;
    uint32_t st;
    uint32_t count;
    char *test_key = "testkey";
    uint8_t inbuff[2048];
    uint8_t outbuff[2048];
    int test_time = 3000;
    int dec_len;
    int r;

    if (test_len < 1 || test_len > 2000) {
        test_len = 1400;
    }

    crypto_init();
    crypto_set_password(test_key, strlen(test_key));
    randombytes_buf(inbuff, sizeof(inbuff));

    r = 0;
    st = get_time_ms();
    et = st;
    for (count = 0; count < 0xffffffff; count++) {
        r |= crypto_encrypt(outbuff, inbuff, test_len);
        if (count % 10000 == 0) {
            et = get_time_ms() - st;
            if (et >= test_time)
                break;
        }
    }
    if (r < 0) {
        printf("encrypt fail = %d\n", r);
        return r;
    }
    printf("encrypt block=%u cost= %ums, speed = %.1fMB/s\n", test_len, et, count / et / 1000.0 * test_len);

    dec_len = r;
    r = 0;
    st = get_time_ms();
    et = st;
    for (count = 0; count < 0xffffffff; count++) {
        r |= crypto_decrypt(inbuff, outbuff, dec_len);
        if (count % 10000 == 0) {
            et = get_time_ms() - st;
            if (et >= test_time)
                break;
        }
    }
    if (r < 0) {
        printf("decrypt fail = %d\n", r);
        return r;
    }
    printf("decrypt block=%u cost= %ums, speed = %.1fMB/s\n", dec_len, et, count / et / 1000.0 * test_len);
    return 0;
}
