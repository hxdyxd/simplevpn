/*
 * udp_alloc.c - Provide simplevpn client service
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

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include "app_debug.h"

int vpn_udp_alloc(int if_bind, const char *host, int port,
				  struct sockaddr_storage *addr, socklen_t* addrlen)
{
	struct addrinfo hints;
	struct addrinfo *res;
	int sock, r, flags;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	if (0 != (r = getaddrinfo(host, NULL, &hints, &res))) {
		APP_ERROR("getaddrinfo: %s\n", gai_strerror(r));
		return -1;
	}

	if (res->ai_family == AF_INET)
		((struct sockaddr_in *)res->ai_addr)->sin_port = htons(port);
	else if (res->ai_family == AF_INET6)
		((struct sockaddr_in6 *)res->ai_addr)->sin6_port = htons(port);
	else {
		APP_ERROR("unknown ai_family %d\n", res->ai_family);
		freeaddrinfo(res);
		return -1;
	}
	memcpy(addr, res->ai_addr, res->ai_addrlen);
	*addrlen = res->ai_addrlen;

	if (-1 == (sock = socket(res->ai_family, SOCK_DGRAM, IPPROTO_UDP))) {
		APP_ERROR("can not create socket\n");
		freeaddrinfo(res);
		return -1;
	}

	if (if_bind) {
		if (0 != bind(sock, res->ai_addr, res->ai_addrlen)) {
			APP_ERROR("can not bind %s:%d\n", host, port);
			close(sock);
			freeaddrinfo(res);
			return -1;
		}
	}
	freeaddrinfo(res);

	flags = fcntl(sock, F_GETFL, 0);
	if (flags != -1) {
		if (-1 != fcntl(sock, F_SETFL, flags | O_NONBLOCK))
			return sock;
	}
	APP_ERROR("fcntl error\n");

	close(sock);
	return -1;
}
