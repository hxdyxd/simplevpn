/*
 * utils.h - Provide simplevpn service
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
#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdint.h>

//utils
void msg_dump(void *buf, int len);
uint16_t switch_in_cksum(const uint16_t *buf, int bufsz);

#ifdef USE_CRYPTO
int crypto_speed_test(int test_len);
#endif

#endif
