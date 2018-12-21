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
#include "app_debug.h"

#ifndef DISABLE_CLIENT

#include <linux/if_tun.h>
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
#include "crypto.h"

#define BUF_SIZE 2000

int vpn_udp_alloc(int, const char *, int, struct sockaddr_storage *, socklen_t*);

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

#else

int tap_client_run(const char *server_host, const int server_port, const char *password)
{
	APP_WARN("client mode unsupport\n");
	return 0;
}

#endif
