/*
 * tap_client.c - Provide simplevpn client service
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
#include <sys/ioctl.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <linux/if_tun.h>
#include "app_debug.h"
#include "crypto.h"

#define VERSION "0.1.1"


#define BUF_SIZE 2000
#define DEFAULT_SERVER_HOST  "127.0.0.1"
#define DEFAULT_SERVER_PORT        2020
#define DEFAULT_PASSWORD     "12345678"


int tun_alloc(int flags)
{
	struct ifreq ifr;
	int fd, err;
	char *clonedev = "/dev/net/tun";

	if ((fd = open(clonedev, O_RDWR)) < 0) {
		return fd;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = flags;

	if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
		close(fd);
		return err;
	}

	APP_DEBUG("Open tun/tap device: %s for reading...\n", ifr.ifr_name);

	return fd;
}

int vpn_udp_alloc(int if_bind, const char *host, int port,
				  struct sockaddr_storage *addr, socklen_t* addrlen) {
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

int tap_client_run(const char *server_host, const int server_port, const char *password)
{
	unsigned char in_buffer[BUF_SIZE];
	unsigned char out_buffer[BUF_SIZE];

	if(crypto_init() < 0) {
		APP_ERROR("crypto_init error\n");
		return -1;
	}

	if(crypto_set_password(password, strlen(password)) < 0) {
		APP_ERROR("crypto_set_password error\n");
		return -1;
	}

	/* Flags: IFF_TUN   - TUN device (no Ethernet headers)
	 *        IFF_TAP   - TAP device
	 *        IFF_NO_PI - Do not provide packet information
	 */
	int tun_fd = tun_alloc(IFF_TAP | IFF_NO_PI);
	if (tun_fd < 0) {
		APP_ERROR("Failed to allocating tun/tap interface\n");
		return -1;
	}

	struct sockaddr_storage addr;
	socklen_t sin_size;

	int sock = vpn_udp_alloc(0, server_host, server_port, &addr, &sin_size);
	if(sock < 0) {
		APP_ERROR("Failed to create udp socket\n");
		return -1;
	}

	while (1) {
		fd_set readset;
		FD_ZERO(&readset);

		int maxsock = 0;
		FD_SET(tun_fd, &readset);
		if(tun_fd > maxsock) {
			maxsock = tun_fd;
		}

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

		if (FD_ISSET(tun_fd, &readset)) {
			int len = read(tun_fd, in_buffer, BUF_SIZE);
			if (len < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					// do nothing
					continue;
				} else if (errno == EPERM || errno == EINTR) {
					// just log, do nothing
					APP_WARN("read from tun\n");
					continue;
				} else {
					APP_ERROR("read from tun\n");
					break;
				}
			}

			len = crypto_encrypt(out_buffer, in_buffer, len);
			if(len < 0) {
				continue;
			}

			int r = sendto(sock, out_buffer, len, 0, (struct sockaddr *)&addr, sin_size);
			if (r < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					// do nothing
					continue;
				} else if (errno == ENETUNREACH || errno == ENETDOWN ||
						 errno == EPERM || errno == EINTR || errno == EMSGSIZE) {
					// just log, do nothing
					APP_WARN("sendto\n");
					continue;
				} else {
					APP_ERROR("sendto\n");
					// TODO rebuild socket
					break;
				}
			}
		}

		if (FD_ISSET(sock, &readset)) {
			int len = recvfrom(sock, in_buffer, BUF_SIZE, 0, NULL, NULL);
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

			len = crypto_decrypt(out_buffer, in_buffer, len);
			if(len < 0) {
				continue;
			}

			int r = write(tun_fd, out_buffer, len);
			if(r < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					// do nothing
					continue;
				} else if (errno == EPERM || errno == EINTR || errno == EINVAL) {
					// just log, do nothing
					APP_WARN("write to tun\n");
					continue;
				} else {
					APP_ERROR("write to tun\n");
					break;
				}
			}
		}
	}
	close(tun_fd);
	close(sock);
	return 0;
}

void usage(void)
{
	PRINTF("\n");
	PRINTF("simplevpn %s\n\n", VERSION);
	PRINTF("  usage:\n\n");
	PRINTF("    simplevpn-client\n");
	PRINTF("\n");
	PRINTF(
		"       -s <server_host>           Host name or IP address of your remote server.\n");
	PRINTF(
		"       -p <server_port>           Port number of your remote server.\n");
	PRINTF(
		"       -k <password>              Password of your remote server.\n");
	PRINTF("\n");
	PRINTF(
		"       [-v]                       Verbose mode.\n");
	PRINTF(
		"       [-h, --help]               Print this message.\n");
	PRINTF("\n");
}

int main(int argc, char **argv)
{
	char *server_host = DEFAULT_SERVER_HOST;
	int server_port = DEFAULT_SERVER_PORT;
	char *password = DEFAULT_PASSWORD;
	int ch;

	while((ch = getopt(argc, argv, "s:p:k:hv")) != -1) {
		switch(ch) {
		case 's':
			server_host = optarg;
			break;
		case 'p':
			server_port = atoi(optarg);
			break;
		case 'k':
			password = optarg;
			break;
		case 'v':
		case 'h':
			usage();
			exit(EXIT_SUCCESS);
		case '?': // 输入未定义的选项, 都会将该选项的值变为 ?
			APP_ERROR("unknown option \n");
			usage();
			exit(EXIT_FAILURE);
		}
	}

	APP_DEBUG("remote server address: %s:%d\n", server_host, server_port);
	if(strcmp(password, DEFAULT_PASSWORD) == 0) {
		APP_WARN("use default password: %s\n", password);
	}
	
	return tap_client_run(server_host, server_port, password);
}
