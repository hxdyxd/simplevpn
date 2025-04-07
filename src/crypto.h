/*
 * crypto.h - Provide simplevpn client service
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

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdint.h>

/* call once after start */
int crypto_init(void);

// TODO use a struct to hold context instead
/* call when password changed */
int crypto_set_password(const char *p, int plen);

int crypto_encrypt(uint8_t *out_buf, uint8_t *in_buf, int in_len);

int crypto_decrypt(uint8_t *out_buf, uint8_t *in_buf, int in_len);

int crypto_is_enabled(void);

void crypto_gen_rand(uint8_t *out_buf, int in_len);

int crypto_speed_test(int test_len);

#endif
