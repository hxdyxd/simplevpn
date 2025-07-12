/*
 * utils.c - Provide simplevpn client service
 *
 * Copyright (C) 2024, hxdyxd <hxdyxd@gmail.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "crypto.h"
#include "app_debug.h"
#include "netclock.h"


void msg_dump(void *buf, int len)
{
    int i, j;
    unsigned char *ch = buf;
    for (i = 0; i < len; i = j) {
        for (j = i; j < i + 16; j++) {
            if (j < len) {
                PRINTF("%02x ", ch[j]);
            } else {
                PRINTF("   ");
            }
        }
        PRINTF("  ");
        for (j = i; j < len && j < i + 16; j++) {
            if ('0' <= ch[j] && ch[j] <= 'z') {
                PRINTF("%c", ch[j]);
            } else {
                PRINTF(".");
            }
        }

        PRINTF("\n");
    }
}

// Interent checksum
uint16_t switch_in_cksum(const uint16_t *buf, int bufsz)
{
    uint32_t sum = 0;

    while (bufsz > 1)
    {
        sum += *buf;
        buf++;
        bufsz -= 2;
    }

    if (bufsz == 1)
        sum += *(uint8_t *)buf;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += sum >> 16;
    return ~sum;
}

#ifdef USE_CRYPTO
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
    memset(inbuff, 0, sizeof(inbuff));
    memset(outbuff, 0, sizeof(outbuff));

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
    printf("encrypt block=%u/%u cost= %ums, speed = %.1fMB/s\n", test_len, r, et, count / et / 1000.0 * test_len);

    dec_len = r;
    r = 0;
    st = get_time_ms();
    et = st;
    for (count = 0; count < 0xffffffff; count++) {
        r |= crypto_decrypt(inbuff, outbuff, dec_len);
        if (r <= 0)
            break;
        if (count % 10000 == 0) {
            et = get_time_ms() - st;
            if (et >= test_time)
                break;
        }
    }
    if (r < 1) {
        printf("decrypt fail = %d\n", r);
        return r;
    }
    printf("decrypt block=%u/%u cost= %ums, speed = %.1fMB/s\n", dec_len, r, et, count / et / 1000.0 * test_len);
    return 0;
}
#endif
