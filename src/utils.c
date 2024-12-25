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

#include <stdint.h>
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

