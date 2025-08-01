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
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include "udp_alloc.h"
#include "app_debug.h"

int vpn_udp_alloc(int if_bind, const char *host, const char *port, const char *ifname,
                  struct sockaddr_storage *addr, socklen_t* addrlen)
{
    struct addrinfo hints;
    struct addrinfo *res;
    int sock, r, flags;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    if (0 != (r = getaddrinfo(host, port, &hints, &res))) {
        if (EAI_SYSTEM == r) {
            APP_ERROR("getaddrinfo: %s\n", strerror(errno));
        }
        APP_ERROR("getaddrinfo: %s\n", gai_strerror(r));
        return -1;
    }

    memcpy(addr, res->ai_addr, res->ai_addrlen);
    *addrlen = res->ai_addrlen;

    if (-1 == (sock = socket(res->ai_family, SOCK_DGRAM, IPPROTO_UDP))) {
        APP_ERROR("can not create socket: %s\n", strerror(errno));
        freeaddrinfo(res);
        return -1;
    }

    if (0 != strlen(ifname)) {
        r = vpn_sock_bind_interface(sock, ifname);
        if (r < 0) {
            close(sock);
            freeaddrinfo(res);
            return -1;
        }
    }

    if (if_bind) {
        r = bind(sock, res->ai_addr, res->ai_addrlen);
        if (r < 0) {
            APP_ERROR("fail to bind %s:%s %s\n", host, port, strerror(errno));
            close(sock);
            freeaddrinfo(res);
            return -1;
        }
    } else {
        r = connect(sock, res->ai_addr, res->ai_addrlen);
        if (r < 0) {
            APP_ERROR("connect(fd = %d, %s:%s): %s\n", sock, host, port, strerror(errno));
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

int vpn_tcp_alloc(int if_bind, const char *host, const char *port, const char *ifname,
                  struct sockaddr_storage *addr, socklen_t* addrlen)
{
    struct addrinfo hints;
    struct addrinfo *res;
    int sock, r;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if (0 != (r = getaddrinfo(host, port, &hints, &res))) {
        if (EAI_SYSTEM == r) {
            APP_ERROR("getaddrinfo: %s\n", strerror(errno));
        }
        APP_ERROR("getaddrinfo: %s\n", gai_strerror(r));
        return -1;
    }

    memcpy(addr, res->ai_addr, res->ai_addrlen);
    *addrlen = res->ai_addrlen;

    if (-1 == (sock = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP))) {
        APP_ERROR("can not create socket: %s\n", strerror(errno));
        freeaddrinfo(res);
        return -1;
    }

    if (0 != strlen(ifname)) {
        r = vpn_sock_bind_interface(sock, ifname);
        if (r < 0) {
            close(sock);
            freeaddrinfo(res);
            return -1;
        }
    }

    r = vpn_sock_set_blocking(sock, 0);
    if (r < 0) {
        APP_WARN("sock_set_blocking(fd = %d): %s\n", sock, strerror(errno));
        close(sock);
        freeaddrinfo(res);
        return -1;
    }

    if (if_bind) {
#ifdef SO_REUSEPORT
        int opt = 1;
        r = setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
        if (r < 0) {
            APP_WARN("setsockopt(SO_REUSEPORT): %s\n", strerror(errno));
        }
#endif

        r = bind(sock, res->ai_addr, res->ai_addrlen);
        if (r < 0) {
            APP_ERROR("bind %s:%s %s\n", host, port, strerror(errno));
            close(sock);
            freeaddrinfo(res);
            return -1;
        }

        r = listen(sock, 512);
        if (r < 0) {
            APP_ERROR("listen(fd = %d, %s:%s): %s\n", sock, host, port, strerror(errno));
            close(sock);
            freeaddrinfo(res);
            return -1;
        }
    } else {
        r = vpn_sock_tcp_nodelay(sock, VPN_TCP_NODELAY);
        if (r < 0) {
            APP_ERROR("sock_tcp_nodelay(fd = %d, %s:%s): %s\n", sock, host, port, strerror(errno));
            close(sock);
            freeaddrinfo(res);
            return -1;
        }

        r = connect(sock, res->ai_addr, res->ai_addrlen);
        if (r < 0 && errno != EINPROGRESS) {
            APP_ERROR("connect(fd = %d, %s:%s): %s\n", sock, host, port, strerror(errno));
            close(sock);
            freeaddrinfo(res);
            return -1;
        }
    }
    freeaddrinfo(res);
    return sock;
}

int vpn_get_sockaddr(const char *host, const char *port,
                  struct sockaddr_storage *addr, socklen_t* addrlen)
{
    struct addrinfo hints;
    struct addrinfo *res;
    int r;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    if (0 != (r = getaddrinfo(host, port, &hints, &res))) {
        if (EAI_SYSTEM == r) {
            APP_ERROR("getaddrinfo: %s\n", strerror(errno));
        }
        APP_ERROR("getaddrinfo: %s\n", gai_strerror(r));
        return -1;
    }

    memcpy(addr, res->ai_addr, res->ai_addrlen);
    *addrlen = res->ai_addrlen;

    freeaddrinfo(res);
    return 0;
}


int vpn_udp_sinsize(struct sockaddr_storage *src_addr)
{
    if (src_addr->ss_family == AF_INET) {
        return sizeof(struct sockaddr_in);
    } else if(src_addr->ss_family == AF_INET6) {
        return sizeof(struct sockaddr_in6);
    } else {
        APP_ERROR("Unknown AF\n");
        return -1;
    }
}

int vpn_udp_ntop(struct sockaddr_storage *src_addr, char *addr_buf, int len, const char **host, uint16_t *port)
{
    if (!src_addr || !host || !port) {
        return -1;
    }
    if(src_addr->ss_family == AF_INET) {
        struct sockaddr_in *addr_v4 = (struct sockaddr_in *)src_addr;
        *port = ntohs(addr_v4->sin_port);
        *host = inet_ntop(src_addr->ss_family, &addr_v4->sin_addr, addr_buf, len);
    } else if(src_addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *addr_v6 = (struct sockaddr_in6 *)src_addr;
        *port = ntohs(addr_v6->sin6_port);
        *host = inet_ntop(src_addr->ss_family, &addr_v6->sin6_addr, addr_buf, len);
        if (*host && strncmp(*host, "::ffff:", strlen("::ffff:")) == 0) {
            *host += strlen("::ffff:");
        }
    } else {
        return -1;
    }

    return 0;
}

void vpn_convert_ipv6_to_sockaddr(struct sockaddr_storage *storage, const uint8_t *dest_v6, uint16_t port)
{
    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)storage;
    memset(storage, 0, sizeof(struct sockaddr_storage));

    addr6->sin6_family = AF_INET6;
    addr6->sin6_port = htons(port);
    memcpy(&addr6->sin6_addr, dest_v6, sizeof(addr6->sin6_addr));
}

int vpn_sock_set_blocking(int sock, int if_block)
{
    int flags, r;

    flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        APP_ERROR("fcntl: %s\n", strerror(errno));
        return -1;
    }

    if (if_block)
        flags &= ~O_NONBLOCK;
    else
        flags |= O_NONBLOCK;

    r = fcntl(sock, F_SETFL, flags);
    if (r < 0) {
        APP_ERROR("fcntl: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

int vpn_sock_set_keepalive(int sock, int enable, int time, int intvl, int probes)
{
    int ret;
    int keepalive = enable;

    ret = setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
    if (ret < 0) {
        APP_ERROR("setsockopt(SO_KEEPALIVE) failed: %s\n", strerror(errno));
        return -1;
    }

    if (!enable) {
        return 0;
    }

    ret = setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &time, sizeof(time));
    if (ret < 0) {
        APP_ERROR("setsockopt(TCP_KEEPIDLE) failed: %s\n", strerror(errno));
        return -1;
    }

    ret = setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
    if (ret < 0) {
        APP_ERROR("setsockopt(TCP_KEEPINTVL) failed: %s\n", strerror(errno));
        return -1;
    }

    ret = setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &probes, sizeof(probes));
    if (ret < 0) {
        APP_ERROR("setsockopt(TCP_KEEPCNT) failed: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int vpn_sock_bind_interface(int sock, const char *ifname)
{
    int ret;
    ret = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));
    if (ret < 0) {
        APP_ERROR("setsockopt(SO_BINDTODEVICE) failed: %s\n", strerror(errno));
        return -1;
    }
    APP_INFO("bind sock=%d to interface: %s\n", sock, ifname);
    return ret;
}

int vpn_sock_tcp_nodelay(int sock, int enable)
{
    int ret;
    int flag = enable;
    ret = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    if (ret < 0) {
        APP_ERROR("setsockopt(TCP_NODELAY) failed: %s\n", strerror(errno));
        return -1;
    }
    return ret;
}
