/*
 * simplevpn.h - Provide simplevpn client service
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
#ifndef _UDP_ALLOC_H_
#define _UDP_ALLOC_H_

#include <stdint.h>
#include <sys/socket.h>

#ifndef VPN_TCP_NODELAY
#define VPN_TCP_NODELAY        (1)
#endif

int vpn_udp_alloc(int if_bind, const char *host, const char *port, const char *ifname,
                  struct sockaddr_storage *addr, socklen_t* addrlen);
int vpn_tcp_alloc(int if_bind, const char *host, const char *port, const char *ifname,
                  struct sockaddr_storage *addr, socklen_t* addrlen);
int vpn_get_sockaddr(const char *host, const char *port,
                  struct sockaddr_storage *addr, socklen_t* addrlen);
int vpn_udp_ntop(struct sockaddr_storage *src_addr, char *addr_buf, int len, const char **host, uint16_t *port);
void vpn_convert_ipv6_to_sockaddr(struct sockaddr_storage *storage, const uint8_t *dest_v6, uint16_t port);
int vpn_udp_sinsize(struct sockaddr_storage *src_addr);
int vpn_sock_set_blocking(int sock, int if_block);
int vpn_sock_set_keepalive(int sock, int enable, int time, int intvl, int probes);
int vpn_sock_bind_interface(int sock, const char *ifname);
int vpn_sock_tcp_nodelay(int sock, int enable);

#endif
