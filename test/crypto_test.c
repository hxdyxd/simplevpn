/*
 * crypto_test.c - Provide simplevpn client service
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

#include <crypto.h>
#include <stdio.h>
#include <string.h>


#define MESSAGE  "hello world\n"
#define PASSWORD  "12345678"

uint8_t buf[1024];
uint8_t ciphertext[1024];

int main()
{
	if(crypto_init() < 0) {
		printf("crypto_init error\n");
		return -1;
	}
	if(crypto_set_password(PASSWORD, strlen(PASSWORD)) < 0) {
		printf("crypto_set_password error\n");
		return -1;
	}
	int len = crypto_encrypt(buf, MESSAGE, strlen(MESSAGE));
	if(len == -1) {
		printf("crypto_encrypt error\n");
		return -1;
	}
	printf("[%d] encrypted\n", len);
	for(int i=0;i<len;i++) {
		printf("%02x", buf[i]);
	}
	printf("\n");

	len = crypto_decrypt(ciphertext, buf, len);
	if(len == -1) {
		printf("crypto_decrypt error\n");
		return -1;
	}	
	printf("[%d] %s\n", len, ciphertext);

	return 0;
}
