/*
 * switch.c - Provide simplevpn switch service
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

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <sys/select.h> 
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <sys/time.h>
#include "app_debug.h"
#include "crypto.h"
#include "cache_table.h"

#define DEBUG_INFO     1
#define TIME_DEBUG    15

#define BUF_SIZE                   2000

typedef struct {
	int sock;
	void *buf;
	int len;
	char type;
	struct sockaddr_storage *src_addr;
}UDP_CTX;

int vpn_udp_alloc(int, const char *, int, struct sockaddr_storage *, socklen_t*);

void send_to_target(struct cache_table_t *table, void *p)
{
	uint8_t addr_buf[100];
	if(table == NULL || p == NULL) {
		APP_ERROR("ptr error\n");
		return;
	}
	UDP_CTX *ctx_p = (UDP_CTX *)p;
	socklen_t sin_size;
	const char *ip;
	uint16_t port;
	if(table->addr.ss_family == AF_INET) {
		sin_size = sizeof(struct sockaddr_in);
		struct sockaddr_in *addr_v4 = (struct sockaddr_in *)&table->addr;
		port = ntohs(addr_v4->sin_port);
		ip = inet_ntop(table->addr.ss_family, &addr_v4->sin_addr, addr_buf, sin_size);
	} else if(table->addr.ss_family == AF_INET6) {
		sin_size = sizeof(struct sockaddr_in6);
		struct sockaddr_in6 *addr_v6 = (struct sockaddr_in6 *)&table->addr;
		port = ntohs(addr_v6->sin6_port);
		ip = inet_ntop(table->addr.ss_family, &addr_v6->sin6_addr, addr_buf, sin_size);
	} else {
		APP_ERROR("Unknown AF\n");
		return;
	}

	if(table->addr.ss_family == ctx_p->src_addr->ss_family &&
		 memcmp(&table->addr, ctx_p->src_addr, sin_size) == 0) {
		return;
	}
#if DEBUG_INFO 
	if(ctx_p->type != 'n')
		APP_DEBUG("[%c] target=%s:%d len=%d\n", ctx_p->type, ip, port, ctx_p->len);
#endif
	int r = sendto(ctx_p->sock, ctx_p->buf, ctx_p->len, 0, (struct sockaddr *)&table->addr, sin_size);
	if (r < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			// do nothing
		} else if (errno == ENETUNREACH || errno == ENETDOWN ||
				 errno == EPERM || errno == EINTR || errno == EMSGSIZE) {
			// just log, do nothing
			APP_WARN("sendto\n");
		} else {
			APP_ERROR("sendto\n");
			// TODO rebuild socket
		}
	}
}

int switch_run(const char *server_host, const int server_port, const char *password)
{
	unsigned char in_buffer[BUF_SIZE];
	unsigned char out_buffer[BUF_SIZE];
	struct cache_table_t *cache_all = NULL;
	struct timeval cache_tv;
	uint64_t lasttimer;

	if(crypto_init() < 0) {
		APP_ERROR("crypto_init error\n");
		return -1;
	}

	if(crypto_set_password(password, strlen(password)) < 0) {
		APP_ERROR("crypto_set_password error\n");
		return -1;
	}

	struct sockaddr_storage addr;
	socklen_t sin_size;

	int sock = vpn_udp_alloc(1, server_host, server_port, &addr, &sin_size);
	if(sock < 0) {
		APP_ERROR("Failed to create udp socket\n");
		return -1;
	}

	while (1) {
		fd_set readset;
		FD_ZERO(&readset);

		int maxsock = 0;
		FD_SET(sock, &readset);
		if(sock > maxsock) {
			maxsock = sock;
		}

		if (-1 == select(maxsock + 1, &readset, NULL, NULL, NULL)) {
			if (errno == EINTR)
				continue;
			APP_ERROR("select error\n");
			break;
		}

		if (FD_ISSET(sock, &readset)) {
			//note: struct sockaddr
			int len = recvfrom(sock, in_buffer, BUF_SIZE, 0, (struct sockaddr *)&addr, &sin_size);
			if (len == -1) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					// do nothing
					continue;
				} else if (errno == ENETUNREACH || errno == ENETDOWN ||
						errno == EPERM || errno == EINTR) {
					// just log, do nothing
					APP_WARN("recvfrom\n");
					continue;
				} else {
					APP_ERROR("recvfrom\n");
					// TODO rebuild socket
					break;
				}
			}

			int dlen = crypto_decrypt(out_buffer, in_buffer, len);
			if(dlen < 0) {
				APP_WARN("decrypt error\n");
				continue;
			}

			if(dlen < 14) {
				APP_WARN("ethernet pack error\n");
				continue;
			}

			uint8_t *ether_dst = &out_buffer[0];
			uint8_t *ether_src = &out_buffer[6];
			//APP_DEBUG("!new pack : \n");
			if(gettimeofday(&cache_tv, NULL) < 0) {
				cache_tv.tv_sec = 0;
			}
			cache_table_add(&cache_all, ether_src, (uint64_t)cache_tv.tv_sec, &addr);
			//APP_DEBUG("!add cache : \n");

			UDP_CTX ctx;
			ctx.sock = sock;
			ctx.buf = in_buffer;
			ctx.len = len;
			ctx.src_addr = &addr;
			if(memcmp(ether_dst, "\xff\xff\xff\xff\xff\xff", HWADDR_LEN) == 0 ||
			   memcmp(ether_dst, "\x33\x33", 2) == 0 ) {
				//广播包
				APP_DEBUG("!Broadcast : \n");
				ctx.type = 'b';
				cache_table_iter_once(&cache_all, send_to_target, &ctx);
				continue;
			}

			struct cache_table_t *target = cache_table_find(&cache_all, ether_dst);
			if(target == NULL) {
				//目标硬件地址未找到，泛洪包
				APP_DEBUG("!Flood : \n");
				ctx.type = 'f';
				cache_table_iter_once(&cache_all, send_to_target, &ctx);
				//printf("fl\n");
				continue;
			} else {
				//转发包
				//APP_DEBUG("!Normal : \n");
				ctx.type = 'n';
				send_to_target(target, &ctx);
			}
		}

		if(cache_tv.tv_sec - lasttimer > TIME_DEBUG) {
			lasttimer = cache_tv.tv_sec;
			printf("Active Count: %d\n", cache_table_count(&cache_all));
			cache_table_print(&cache_all);
		}
	}
	close(sock);
	cache_table_delete_all(&cache_all);
	return -1;
}
