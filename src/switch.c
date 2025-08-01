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
//#define _LINUX_IN6_H
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h> 
#include <sys/ioctl.h>
#include <sys/time.h>
#include <fcntl.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include "app_debug.h"
#include "netclock.h"
#include "simplevpn.h"
#include "cache_table.h"
#include "udp_alloc.h"
#include "rip.h"
#include "utils.h"
#ifdef USE_CRYPTO
#include "crypto.h"
#endif

#define DEBUG_INFO     (log_level == log_debug)
#define TRACE_INFO     (log_level == log_trace)
#define TIME_DEBUG      (15000)

#define BUF_SIZE                   2000

struct switch_pack_t {
    uint8_t hop_limit;
    uint8_t recv[3];
    uint32_t daddr;
    uint32_t saddr;
};

int switch_read_encode(uint8_t *out, uint8_t *in, int rlen)
{
    int dlen = -1;

#ifdef USE_CRYPTO
    if (crypto_is_enabled()) {
        dlen = crypto_encrypt(out, in, rlen);
        if(dlen < 0) {
            return dlen;
        }
    } else
#endif
    {
        memcpy(out, in, rlen);
        dlen = rlen;
    }

    return dlen;
}

int switch_read_decode(uint8_t *out, uint8_t *in, int rlen)
{
    int dlen = -1;
    if (rlen <= 0) {
        return -1;
    }

#ifdef USE_CRYPTO
    if (crypto_is_enabled()) {
        dlen = crypto_decrypt(out, in, rlen);
        if(dlen < 0) {
            return dlen;
        }
    } else
#endif
    {
        memcpy(out, in, rlen);
        dlen = rlen;
    }

    return dlen;
}

static int switch_write(struct switch_ctx_t *psctx, UDP_CTX *ctx_p)
{
    int wlen = -1;
    if (SWITCH_UDP == psctx->type) {
        struct sockaddr *target_addr = (struct sockaddr *)&psctx->udp.addr;
        socklen_t sin_size = sizeof(struct sockaddr_in6);

        wlen = sendto(psctx->udp.sock, ctx_p->cbuf, ctx_p->clen, 0, target_addr, sin_size);
        if (wlen < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // do nothing
            } else if (errno == ENETUNREACH || errno == ENETDOWN ||
                     errno == EPERM || errno == EINTR || errno == EMSGSIZE) {
                // just log, do nothing
                APP_WARN("sendto: %s\n", strerror(errno));
            } else {
                APP_ERROR("sendto: %s\n", strerror(errno));
                // TODO rebuild socket
            }
        }
    } else if (SWITCH_TCP == psctx->type) {

        if (!psctx->tcp.if_bind && psctx->tcp.sock < 0) {
            wlen = switch_reconnect_tcp(psctx);
            if (wlen < 0) {
                APP_WARN("switch_reconnect_tcp: %s\n", strerror(errno));
                return wlen;
            }
        }

        if (psctx->tcp.write_size) {
            ;//lost packet
        } else {
            uint16_t write_size = ctx_p->clen;

            if (psctx->tcp.write_buffer_size < 2 + write_size) {
                psctx->tcp.write_buffer = realloc(psctx->tcp.write_buffer, 2 + write_size);
                if (!psctx->tcp.write_buffer) {
                    APP_WARN("fail to realloc %d\n", 2 + write_size);
                    return -1;
                }
                psctx->tcp.write_buffer_size = 2 + write_size;
                APP_DEBUG("realloc write_buffer to %d\n", psctx->tcp.write_buffer_size);
            }

            psctx->tcp.write_buffer[0] = (write_size >> 8) & 0xff;
            psctx->tcp.write_buffer[1] = write_size & 0xff;
            memcpy(&psctx->tcp.write_buffer[2], ctx_p->cbuf, write_size);
            psctx->tcp.write_pos = 0;
            psctx->tcp.write_size = 2 + write_size;
        }

        wlen = send(psctx->tcp.sock, &psctx->tcp.write_buffer[psctx->tcp.write_pos], psctx->tcp.write_size, 0);
        if (wlen < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // do nothing
                return 0;
            } else if (errno == ENETUNREACH || errno == ENETDOWN ||
                     errno == EPERM || errno == EINTR || errno == EMSGSIZE) {
                // just log, do nothing
                APP_WARN("send %d: %s\n", psctx->tcp.sock, strerror(errno));
            } else {
                APP_ERROR("send %d: %s\n", psctx->tcp.sock, strerror(errno));
                // TODO rebuild socket
            }
            return 0;
        }
        psctx->tcp.write_pos += wlen;
        psctx->tcp.write_size -= wlen;

    } else if (SWITCH_TAP == psctx->type) {
        wlen = write(psctx->tap.fd, ctx_p->pbuf, ctx_p->plen);
        if (wlen < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // do nothing
            } else if (errno == EPERM || errno == EINTR || errno == EINVAL) {
                // just log, do nothing
                APP_WARN("write to tun %s\n", strerror(errno));
            } else {
                APP_ERROR("write to tun %s\n", strerror(errno));
            }
        }
    }
    return wlen;
}

int switch_write_both(struct switch_ctx_t *ctx, UDP_CTX *ctx_p)
{
    int dlen = 0;
    uint8_t encbuff[4096];

    if (SWITCH_UDP == ctx->type || SWITCH_TCP == ctx->type) {
        dlen = switch_read_encode(encbuff, ctx_p->cbuf, ctx_p->clen);
        if(dlen < 0) {
            APP_WARN("encode error\n");
            return dlen;
        }
        memcpy(ctx_p->cbuf, encbuff, dlen);
        ctx_p->clen = dlen;
    }

    return switch_write(ctx, ctx_p);
}

int send_to_self(UDP_CTX *ctx_p)
{
    if (DEBUG_INFO) {
        switch_dump_send_router(ctx_p->src_pctx, NULL, "[self]");
    }

    return switch_write_both(ctx_p->src_pctx, ctx_p);
}

static int send_icmp_packet(UDP_CTX *ctx, struct switch_main_t *psmb, uint8_t type, uint8_t code)
{
    struct icmphdr *icmph = (struct icmphdr *)((uint8_t *)ctx->pbuf - sizeof(struct icmphdr));
    struct iphdr *iph = (struct iphdr *)((uint8_t *)icmph - sizeof(struct iphdr));
    uint16_t ip_len;

    ip_len = ctx->plen + sizeof(struct icmphdr) + sizeof(struct iphdr);
    memset(iph, 0, sizeof(struct iphdr));
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0xc0;
    iph->tot_len = htons(ip_len);
    iph->ttl = 0x40;
    iph->daddr = htonl(ctx->saddr);
    iph->saddr = htonl(psmb->param.router_mac);
    iph->protocol = 1;
    iph->check = switch_in_cksum((uint16_t *)iph, iph->ihl * 4); //-O3 Abnormal

    memset(icmph, 0, sizeof(struct icmphdr));
    icmph->type = type;
    icmph->code = code;
    icmph->checksum = 0;
    icmph->checksum = switch_in_cksum((uint16_t *)icmph, ctx->plen + sizeof(struct icmphdr)); //-O3 Abnormal

    ctx->type = 'i';
    ctx->pbuf = iph;
    ctx->plen = ip_len;
    ctx->cbuf = ctx->cbuf;
    ctx->clen = switch_add_header(ctx->cbuf, iph, ip_len, psmb);
    if (ctx->clen < 0) {
        APP_WARN("[heart] add header error\n");
        return ctx->clen;
    }
    send_to_self(ctx);
    APP_DEBUG("write icmp %d %d = %d\n", type, code, ip_len);
    return 0;
}

static int send_to_target_router(const struct cache_router_t *rt, struct cache_router_t *s, void *p)
{
    UDP_CTX *ctx_p = (UDP_CTX *)p;

    if (TRACE_INFO) {
        switch_dump_send_router(ctx_p->src_pctx, s, "[forward]");
    }

    int r = switch_write_both(s->ctx, ctx_p);
    if (r < 0) {
        return r;
    }
    s->tx_bytes += ctx_p->clen;
    s->tx_pks++;
    return r;
}

static void send_to_router_item(const struct cache_router_t *rt, struct cache_router_t *target, void *p)
{
    UDP_CTX *ctx_p = (UDP_CTX *)p;
    if ('b' != ctx_p->type) {
        APP_WARN("[%c]send type fail %08x!\n", ctx_p->type, target->dest_router);
        return;
    }

    //APP_WARN("[%c]send to %08x!\n", ctx_p->type, target->dest_router);
    //send_to_target_router(rt, target, p);
}

static int send_to_router(UDP_CTX *ctx_p, struct switch_main_t *smb)
{
    struct switch_pack_t *head = (struct switch_pack_t *)ctx_p->cbuf;
    ctx_p->daddr = ntohl(head->daddr);
    ctx_p->saddr = ntohl(head->saddr);

    if (0xffffffff == ctx_p->daddr) {
        ctx_p->type = 'b';
        cache_route_iter(&smb->param, send_to_router_item, ctx_p);
        return 0;
    }

    struct cache_router_t *target = cache_router_search(&smb->param, ctx_p->daddr);
    if (!target && ctx_p->saddr == smb->param.router_mac) {
        if (smb->default_mac) {
            ctx_p->daddr = smb->default_mac;
        }
        target = cache_router_search(&smb->param, ctx_p->daddr);
        if (target) {
            head->daddr = htonl(ctx_p->daddr);
        }
    }
    if (!target || target->metric >= CACHE_ROUTE_METRIC_MAX) {
        APP_DEBUG("[%c]can't found target %08x\n", ctx_p->type, ctx_p->daddr);
        send_icmp_packet(ctx_p, smb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
        return -1;
    }
    if (!target->ctx || !target->ctx->type) {
        APP_WARN("[%c]can't found target device  %08x\n", ctx_p->type, ctx_p->daddr);
        send_icmp_packet(ctx_p, smb, ICMP_DEST_UNREACH, ICMP_PROT_UNREACH);
        return -1;
    }

    if (ctx_p->daddr != smb->param.router_mac && head->hop_limit == 0) {
        APP_WARN("[%c]ttl is zero %08x -> %08x\n", ctx_p->type, ctx_p->saddr, ctx_p->daddr);
        send_icmp_packet(ctx_p, smb, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
        return -1;
    }

    if (ctx_p->saddr == target->dest_router) {
        APP_WARN("[%c]send to self %08x!\n", ctx_p->type, target->dest_router);
        return -1;
    }

    return send_to_target_router(&smb->param, target, ctx_p);
}

int switch_rebind_udp(struct switch_ctx_t *ctx)
{
    int sock;
    socklen_t sin_size;
    struct switch_addr_t *addr = &ctx->udp.local_addr;

    if (SWITCH_UDP != ctx->type) {
        APP_ERROR("Failed to rebind udp\n");
        return -1;
    }

    APP_INFO("udp rebind %s:%s [%s]\n", addr->host, addr->port, addr->ifname);

    sock = vpn_udp_alloc(0, addr->host, addr->port, addr->ifname, &ctx->udp.addr, &sin_size);
    if (sock < 0) {
        APP_ERROR("Failed to create udp socket\n");
        return -1;
    }

    if (ctx->udp.sock >= 0)
        close(ctx->udp.sock);
    ctx->msg_time = get_time_ms();
    ctx->udp.sock = sock;
    return sock;
}

struct switch_ctx_t *switch_add_udp(struct switch_main_t *smb, int if_bind, struct switch_addr_t *addr)
{
    int sock;
    socklen_t sin_size;

    struct switch_ctx_t *psctx = malloc(sizeof(struct switch_ctx_t));
    if (!psctx) {
        APP_ERROR("Failed to alloc memory\n");
        return NULL;
    }
    memset(psctx, 0, sizeof(struct switch_ctx_t));

    APP_DEBUG("add udp %s:%s [%s]\n", addr->host, addr->port, addr->ifname);
    if (if_bind) {
        sock = vpn_udp_alloc(if_bind, addr->host, addr->port, addr->ifname, &psctx->udp.localaddr, &sin_size);
    } else {
        sock = vpn_udp_alloc(if_bind, addr->host, addr->port, addr->ifname, &psctx->udp.addr, &sin_size);
    }
    if (sock < 0) {
        APP_ERROR("Failed to create udp socket\n");
        free(psctx);
        return NULL;
    }

    psctx->type = SWITCH_UDP;
    psctx->events = SWITCH_POLLIN;
    psctx->udp.sock = sock;
    psctx->udp.if_bind = if_bind;
    psctx->udp.if_local = 1;
    memcpy(&psctx->udp.local_addr, addr, sizeof(struct switch_addr_t));
    list_add(&psctx->list, &smb->head.list);
    return psctx;
}

int switch_disconnect_tcp(struct switch_ctx_t *ctx)
{
    if (SWITCH_TCP != ctx->type) {
        APP_ERROR("Failed to disconnect tcp\n");
        return -1;
    }

    APP_WARN("tcp connect disconnect sock=%d\n", ctx->tcp.sock);
    if (ctx->tcp.write_buffer)
        free(ctx->tcp.write_buffer);
    if (ctx->tcp.read_buffer)
        free(ctx->tcp.read_buffer);
    if (ctx->tcp.sock >= 0)
        close(ctx->tcp.sock);
    ctx->tcp.write_buffer = NULL;
    ctx->tcp.read_buffer = NULL;
    ctx->tcp.sock = -1;
    ctx->events = 0;
    ctx->msg_time = 0;
    return 0;
}

int switch_connected_tcp(struct switch_ctx_t *ctx)
{
    int error = 0;
    socklen_t len = sizeof(error);

    if (SWITCH_TCP != ctx->type) {
        APP_ERROR("Failed to connected tcp %d\n", ctx->tcp.sock);
        return -1;
    }

    getsockopt(ctx->tcp.sock, SOL_SOCKET, SO_ERROR, &error, &len);
    if (error != 0) {
        APP_WARN("tcp connected fail sock=%d %s:%s %s\n", ctx->tcp.sock, ctx->tcp.local_addr.host, ctx->tcp.local_addr.port, strerror(error));
        return switch_disconnect_tcp(ctx);
    }

    APP_INFO("tcp connected success sock=%d %s:%s\n", ctx->tcp.sock, ctx->tcp.local_addr.host, ctx->tcp.local_addr.port);

    ctx->events &= ~SWITCH_POLLOUT;
    ctx->events |= SWITCH_POLLIN;
    return 0;
}

int switch_reconnect_tcp(struct switch_ctx_t *ctx)
{
    int sock;
    socklen_t sin_size;
    struct switch_addr_t *addr = &ctx->tcp.local_addr;

    if (SWITCH_TCP != ctx->type || ctx->tcp.if_bind) {
        APP_ERROR("Failed to reconnect tcp\n");
        return -1;
    }

    if (ctx->tcp.sock >= 0) {
        switch_disconnect_tcp(ctx);
    }

    APP_INFO("tcp reconnect %s:%s [%s]\n", addr->host, addr->port, addr->ifname);

    sock = vpn_tcp_alloc(0, addr->host, addr->port, addr->ifname, &ctx->tcp.addr, &sin_size);
    if (sock < 0) {
        APP_ERROR("Failed to create tcp socket\n");
        return sock;
    }

    if (ctx->tcp.write_buffer)
        free(ctx->tcp.write_buffer);
    if (ctx->tcp.read_buffer)
        free(ctx->tcp.read_buffer);
    if (ctx->tcp.sock >= 0)
        close(ctx->tcp.sock);

    ctx->msg_time = 0;
    ctx->events = SWITCH_POLLOUT;
    ctx->tcp.sock = sock;
    ctx->tcp.write_buffer = NULL;
    ctx->tcp.write_buffer_size = 0;
    ctx->tcp.write_pos = 0;
    ctx->tcp.write_size = 0;
    ctx->tcp.read_buffer = NULL;
    ctx->tcp.read_buffer_size = 0;
    ctx->tcp.read_pos = 0;
    ctx->tcp.read_size = 0;
    return sock;
}

struct switch_ctx_t *switch_add_tcp(struct switch_main_t *smb, int if_bind, struct switch_addr_t *addr)
{
    int sock;
    socklen_t sin_size;

    struct switch_ctx_t *psctx = malloc(sizeof(struct switch_ctx_t));
    if (!psctx) {
        APP_ERROR("Failed to alloc memory\n");
        return NULL;
    }
    memset(psctx, 0, sizeof(struct switch_ctx_t));

    APP_DEBUG("add tcp %s:%s [%s]\n", addr->host, addr->port, addr->ifname);
    if (if_bind) {
        sock = vpn_tcp_alloc(if_bind, addr->host, addr->port, addr->ifname, &psctx->tcp.localaddr, &sin_size);
        if (sock < 0) {
            APP_ERROR("Failed to create tcp socket\n");
            free(psctx);
            return NULL;
        }
    } else {
        //sock = vpn_tcp_alloc(if_bind, addr->host, addr->port, addr->ifname, &psctx->tcp.addr, &sin_size);
        sock = -1;
    }

    psctx->type = SWITCH_TCP;
    if (if_bind)
        psctx->events = SWITCH_POLLIN;
    else
        psctx->events = SWITCH_POLLOUT;
    psctx->tcp.sock = sock;
    psctx->tcp.if_bind = if_bind;
    psctx->tcp.if_local = 1;
    psctx->tcp.write_buffer = NULL;
    psctx->tcp.write_buffer_size = 0;
    psctx->tcp.write_pos = 0;
    psctx->tcp.write_size = 0;
    psctx->tcp.read_buffer = NULL;
    psctx->tcp.read_buffer_size = 0;
    psctx->tcp.read_pos = 0;
    psctx->tcp.read_size = 0;
    memcpy(&psctx->tcp.local_addr, addr, sizeof(struct switch_addr_t));
    list_add(&psctx->list, &smb->head.list);
    return psctx;
}

struct switch_ctx_t *switch_add_accepted_tcp(struct switch_main_t *smb, struct switch_ctx_t *ctx)
{
    int r;
    int sock;
    socklen_t sin_size = sizeof(struct sockaddr_storage);
    char addr_buf[INET6_ADDRSTRLEN];
    const char *ip = "";
    uint16_t port = 0;

    if (!ctx->tcp.if_bind || !ctx->tcp.if_local) {
        APP_ERROR("Failed to accept tcp\n");
        return NULL;
    }

    struct switch_ctx_t *psctx = malloc(sizeof(struct switch_ctx_t));
    if (!psctx) {
        APP_ERROR("Failed to alloc memory\n");
        return NULL;
    }
    memset(psctx, 0, sizeof(struct switch_ctx_t));

    sock  = accept(ctx->tcp.sock, (struct sockaddr *)&psctx->tcp.addr, &sin_size);
    if (sock < 0) {
        APP_WARN("accept(fd = %d) %s\n", ctx->tcp.sock, strerror(errno));
        free(psctx);
        return NULL;
    }

    r = vpn_sock_set_blocking(sock, 0);
    if (r < 0) {
        APP_ERROR("sock_setblocking(fd = %d)\n", sock);
        close(sock);
        free(psctx);
        return NULL;
    }

    r = vpn_sock_set_keepalive(sock, 1, TCP_KEEPALIVE_TIME, TCP_KEEPALIVE_INTVL, TCP_KEEPALIVE_CNT);
    if (r < 0) {
        APP_ERROR("sock_set_keepalive(fd = %d)\n", sock);
        close(sock);
        free(psctx);
        return NULL;
    }

    r = vpn_sock_tcp_nodelay(sock, VPN_TCP_NODELAY);
    if (r < 0) {
        APP_ERROR("sock_tcp_nodelay(fd = %d)\n", sock);
        close(sock);
        free(psctx);
        return NULL;
    }

    vpn_udp_ntop(&psctx->tcp.addr, addr_buf, sizeof(addr_buf), &ip, &port);
    APP_INFO("accept tcp sock=%d from %s:%u\n", sock, ip, port);
    psctx->type = SWITCH_TCP;
    psctx->events = SWITCH_POLLIN;
    psctx->tcp.sock = sock;
    psctx->tcp.if_bind = 1;
    psctx->tcp.if_local = 0;
    psctx->tcp.write_buffer = NULL;
    psctx->tcp.write_buffer_size = 0;
    psctx->tcp.write_pos = 0;
    psctx->tcp.write_size = 0;
    psctx->tcp.read_buffer = NULL;
    psctx->tcp.read_buffer_size = 0;
    psctx->tcp.read_pos = 0;
    psctx->tcp.read_size = 0;
    list_add(&psctx->list, &smb->head.list);
    return psctx;
}

struct switch_ctx_t *switch_add_tap(struct switch_main_t *smb, int flags, const char *ifname, uint16_t mtu)
{
    struct ifreq ifr;
    int fd, err;
    char *tundev1 = "/dev/net/tun";
    char *tundev2 = "/dev/tun";

    struct switch_ctx_t *psctx = malloc(sizeof(struct switch_ctx_t));
    if (!psctx) {
        APP_ERROR("Failed to alloc memory\n");
        return NULL;
    }
    memset(psctx, 0, sizeof(struct switch_ctx_t));

    if ((fd = open(tundev1, O_RDWR)) < 0) {
        if ((fd = open(tundev2, O_RDWR)) < 0) {
            free(psctx);
            return NULL;
        }
    }

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    ifr.ifr_flags = flags;

    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        close(fd);
        free(psctx);
        APP_ERROR("ioctl(%d, TUNSETIFF, 0x%x) = %s\n", fd, flags, strerror(errno));
        return NULL;
    }

    err = vpn_sock_set_blocking(fd, 0);
    if (err < 0) {
        APP_ERROR("sock_setblocking(fd = %d)\n", fd);
        close(fd);
        free(psctx);
        return NULL;
    }

    APP_INFO("Open tun/tap device: %s for reading...\n", ifr.ifr_name);

    char sys_cmd[256];
    err = snprintf(sys_cmd, sizeof(sys_cmd), "ip link set mtu %u dev %s up", mtu, ifr.ifr_name);
    if (err < 0) {
        close(fd);
        free(psctx);
        return NULL;
    }
    err = system(sys_cmd);
    if (err < 0) {
        close(fd);
        free(psctx);
        return NULL;
    }
    APP_INFO(" %s\n", sys_cmd);

    psctx->type = SWITCH_TAP;
    psctx->events = SWITCH_POLLIN;
    psctx->tap.fd = fd;
    psctx->tap.if_native = 1;
    strncpy(psctx->tap.ifname, ifr.ifr_name, sizeof(psctx->tap.ifname));
    list_add(&psctx->list, &smb->head.list);
    return psctx;
}

struct switch_ctx_t *switch_add_tun_native(struct switch_main_t *smb, int tun_fd, char *name)
{
    int err;
    struct switch_ctx_t *psctx = malloc(sizeof(struct switch_ctx_t));
    if (!psctx) {
        APP_ERROR("Failed to alloc memory\n");
        return NULL;
    }

    err = vpn_sock_set_blocking(tun_fd, 0);
    if (err < 0) {
        APP_ERROR("sock_setblocking(fd = %d)\n", tun_fd);
        free(psctx);
        return NULL;
    }

    psctx->type = SWITCH_TAP;
    psctx->events = SWITCH_POLLIN;
    psctx->tap.fd = tun_fd;
    psctx->tap.if_native = 0;
    strcpy(psctx->tap.ifname, name);
    list_add(&psctx->list, &smb->head.list);
    return psctx;
}

int switch_add_router(struct cache_router_t *rt, int is_add)
{
    char sys_cmd[256];
    int err = -1;
    struct switch_ctx_t *self_ctx = rt->router_data;
    char *str_dest = NULL;
    struct in_addr ipaddr;
    const char *str_add = NULL;
    uint8_t prefix_length = 0;

    if (SWITCH_TAP != self_ctx->type) {
        APP_WARN("add router fail\n");
        return -1;
    }

    if (rt->metric >= CACHE_ROUTE_METRIC_MAX) {
        is_add = 0;
    }

    str_add = is_add ? "add" : "del";
    if (rt->dest_router == rt->router_mac) {
        ipaddr.s_addr = htonl(rt->dest_router);
        err = snprintf(sys_cmd, sizeof(sys_cmd), "ip addr %s %s dev %s", str_add, inet_ntoa(ipaddr), self_ctx->tap.ifname);
        if (err < 0) {
            goto exit;
        }
    } else if (!rt->metric) {
        ipaddr.s_addr = htonl(rt->dest_router);
        APP_INFO("export %s/%u\n", inet_ntoa(ipaddr), rt->prefix_length);
        goto exit;
    } else {
        ipaddr.s_addr = htonl(rt->dest_router);
        str_dest = strdup(inet_ntoa(ipaddr));
        prefix_length = rt->prefix_length;
        ipaddr.s_addr = htonl(rt->next_hop_router);
        if (!str_dest) {
            goto exit;
        }

        if (!prefix_length) {
            prefix_length = 32;
            APP_WARN("unsupport prefix length = 0\n");
        }

        err = snprintf(sys_cmd, sizeof(sys_cmd), "ip route %s %s/%u dev %s metric %u", str_add, str_dest, prefix_length, self_ctx->tap.ifname, DEFAULT_METRIC);
        if (err < 0) {
            goto exit;
        }
    }
    err = system(sys_cmd);
    if (err < 0) {
        goto exit;
    }
    APP_INFO(" %s\n", sys_cmd);

exit:
    free(str_dest);
    return err;
}

int switch_get_fd(struct switch_ctx_t *psctx)
{
    if (SWITCH_UDP == psctx->type) {
        if (psctx->udp.if_local)
            return psctx->udp.sock;
        else
            return -1;
    } else if (SWITCH_TCP == psctx->type) {
        return psctx->tcp.sock;
    } else if (SWITCH_TAP == psctx->type) {
        return psctx->tap.fd;
    } else {
        APP_ERROR("unsupported %d\n", psctx->type);
        return -1;
    }
}

int switch_get_type(struct switch_ctx_t *psctx)
{
    return psctx->type;
}

int switch_read(struct switch_ctx_t *psctx, void *buff, int len, struct switch_main_t *psmb)
{
    int rlen = -1;

    if (SWITCH_UDP == psctx->type) {
        socklen_t sin_size = sizeof(psctx->udp.addr);

        //note: struct sockaddr
        if (psctx->udp.if_local) {
            rlen = recvfrom(psctx->udp.sock, buff, len, 0, (struct sockaddr *)&psctx->udp.addr, &sin_size);
        } else {
            rlen = -1;
        }

        if (rlen < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // do nothing
                return rlen;
            } else if (errno == ENETUNREACH || errno == ENETDOWN ||
                    errno == EPERM || errno == EINTR) {
                // just log, do nothing
                APP_WARN("recvfrom %s\n", strerror(errno));
                return rlen;
            } else {
                APP_ERROR("recvfrom %s\n", strerror(errno));
                // TODO rebuild socket
                return rlen;
            }
        }
    } else if (SWITCH_TCP == psctx->type) {
        if (psctx->tcp.if_bind && psctx->tcp.if_local) {
            switch_add_accepted_tcp(psmb, psctx);
            return 0;
        } else {
            
            if (psctx->tcp.read_pos < 2) {
                int read_size = 2 - psctx->tcp.read_pos;

                if (psctx->tcp.read_buffer_size < psctx->tcp.read_pos + read_size) {
                    psctx->tcp.read_buffer = realloc(psctx->tcp.read_buffer, psctx->tcp.read_pos + read_size);
                    if (!psctx->tcp.read_buffer) {
                        APP_WARN("fail to realloc %d\n", psctx->tcp.read_pos + read_size);
                        return -1;
                    }
                    psctx->tcp.read_buffer_size = psctx->tcp.read_pos + read_size;
                    APP_DEBUG("realloc read_buffer to %d\n", psctx->tcp.read_buffer_size);
                }
                rlen = recv(psctx->tcp.sock, &psctx->tcp.read_buffer[psctx->tcp.read_pos], read_size, 0);
                if (rlen < 0) {
                    goto fail_reconnect;
                }
                psctx->tcp.read_pos += rlen;
            } else {
                int packet_size = (psctx->tcp.read_buffer[0] << 8) + psctx->tcp.read_buffer[1];
                int read_size = 2 + packet_size - psctx->tcp.read_pos;

                if (psctx->tcp.read_buffer_size < psctx->tcp.read_pos + read_size) {
                    psctx->tcp.read_buffer = realloc(psctx->tcp.read_buffer, psctx->tcp.read_pos + read_size);
                    if (!psctx->tcp.read_buffer) {
                        APP_WARN("fail to realloc %d\n", psctx->tcp.read_pos + read_size);
                        return -1;
                    }
                    psctx->tcp.read_buffer_size = psctx->tcp.read_pos + read_size;
                    APP_DEBUG("realloc read_buffer to %d\n", psctx->tcp.read_buffer_size);
                }
                rlen = recv(psctx->tcp.sock, &psctx->tcp.read_buffer[psctx->tcp.read_pos], read_size, 0);
                if (rlen < 0) {
                    goto fail_reconnect;
                }
                psctx->tcp.read_pos += rlen;
                if (psctx->tcp.read_pos >= packet_size + 2) {
                    int mlen = (packet_size <= len) ? packet_size : len;
                    if (packet_size != mlen) {
                        APP_WARN("truncated incoming packet (original: %d bytes, stored: %d bytes)\n", packet_size, mlen);
                    }

                    memcpy(buff, &psctx->tcp.read_buffer[2], mlen);

                    psctx->tcp.read_pos -= (packet_size + 2);
                    memmove(&psctx->tcp.read_buffer[0], &psctx->tcp.read_buffer[packet_size + 2], psctx->tcp.read_pos);
                    return mlen;
                }
            }

fail_reconnect:
            if (rlen == 0) {
                switch_disconnect_tcp(psctx);
                if (psctx->tcp.if_bind && !psctx->tcp.if_local) {

                    struct cache_router_t *s, *tmp;
                    cache_router_iter(&(psmb->param),s,tmp) {
                        if (s->ctx == psctx) {
                            s->ctx = NULL;
                            APP_DEBUG("del accepted ctx\n");
                        }
                    }
                    list_del(&psctx->list);
                    free(psctx);
                }
                
                return 0;
            } else if (rlen < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // do nothing
                    return rlen;
                } else if (errno == ENETUNREACH || errno == ENETDOWN ||
                        errno == EPERM || errno == EINTR) {
                    // just log, do nothing
                    APP_WARN("recv %d: %s\n", psctx->tcp.sock, strerror(errno));
                    return rlen;
                } else {
                    APP_ERROR("recv %d: %s\n", psctx->tcp.sock, strerror(errno));
                    // TODO rebuild socket
                    return rlen;
                }
            }
            return 0;
        }
    } else if (SWITCH_TAP == psctx->type) {
        rlen = read(psctx->tap.fd, buff, len);
        if (rlen < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // do nothing
                return rlen;
            } else if (errno == EPERM || errno == EINTR) {
                // just log, do nothing
                APP_WARN("read from tun %s\n", strerror(errno));
                return rlen;
            } else {
                APP_ERROR("read from tun %s\n", strerror(errno));
                return rlen;
            }
        }
    } else {
        APP_ERROR("unsupported %d\n", psctx->type);
        return -1;
    }
    return rlen;
}

int switch_address_cmp(struct switch_ctx_t *ctxa, struct switch_ctx_t *ctxb)
{
    if (SWITCH_UDP == ctxa->type && SWITCH_UDP == ctxb->type && ctxa->sock == ctxb->sock)
        return memcmp(&ctxa->udp.addr, &ctxb->udp.addr, sizeof(struct sockaddr_storage));
    if (SWITCH_TCP == ctxa->type && SWITCH_TCP == ctxb->type && ctxa->sock == ctxb->sock)
        return memcmp(&ctxa->tcp.addr, &ctxb->tcp.addr, sizeof(struct sockaddr_storage));

    return -1;
}

int switch_update_header(void *outbuff, void *inbuff, int len, struct switch_main_t *psmb)
{
    struct switch_pack_t *head = (struct switch_pack_t *)inbuff;
    struct iphdr *iph = (struct iphdr *)((uint8_t *)inbuff + sizeof(struct switch_pack_t));
    struct ipv6hdr *ip6h = (struct ipv6hdr *)((uint8_t *)inbuff + sizeof(struct switch_pack_t));
    struct cache_v6_t v6rt;

    if (4 == iph->version) {
        if (!iph->ttl) {
            APP_WARN("ttl is zero\n");
            return -1;
        }
        head->hop_limit = iph->ttl - 1;
        uint32_t check = iph->check;
        check += htons((iph->ttl - head->hop_limit) << 8);
        iph->check = (uint16_t)(check + (check >= 0xFFFF));
        iph->ttl = head->hop_limit;
    } else if (6 == ip6h->version) {
        if (!ip6h->hop_limit) {
            APP_WARN("hop_limit is zero\n");
            return -1;
        }
        head->hop_limit = ip6h->hop_limit - 1;
        ip6h->hop_limit = head->hop_limit;

        v6rt.time = psmb->current_time;
        v6rt.table = &psmb->v6table;
        cache_v6_add(&v6rt, ip6h->saddr.s6_addr, ntohl(head->saddr));
    } else {
        APP_WARN("invalid packet type - expected ipv4 or ipv6, received type %u\n", iph->version);
        return -1;
    }

    memcpy(outbuff, (uint8_t *)inbuff + sizeof(struct switch_pack_t), len - sizeof(struct switch_pack_t));
    return len - sizeof(struct switch_pack_t);
}

int switch_add_header(void *outbuff, void *inbuff, int len, struct switch_main_t *psmb)
{
    struct switch_pack_t *head = (struct switch_pack_t *)outbuff;
    struct iphdr *iph = (struct iphdr *)inbuff;
    struct ipv6hdr *ip6h = (struct ipv6hdr *)inbuff;
    struct cache_v6_t *v6target = NULL;
    struct cache_v6_t v6rt;

    memset(head, 0, sizeof(struct switch_pack_t));
    if (4 == iph->version) {
        if (!iph->ttl) {
            APP_WARN("ttl is zero\n");
            return -1;
        }
        head->hop_limit = iph->ttl;
        head->daddr = iph->daddr;
        head->saddr = htonl(psmb->param.router_mac);
    } else if (6 == ip6h->version) {
        if (!ip6h->hop_limit) {
            APP_WARN("hop_limit is zero\n");
            return -1;
        }
        head->hop_limit = ip6h->hop_limit;
        head->daddr = htonl(psmb->default_mac);
        head->saddr = htonl(psmb->param.router_mac);

        v6rt.time = psmb->current_time;
        v6rt.table = &psmb->v6table;
        if (0xff == ip6h->daddr.s6_addr[0] && 0x02 == ip6h->daddr.s6_addr[1]) {
            struct sockaddr_storage v6addr;
            char addr_buff[INET6_ADDRSTRLEN];
            const char *ip = "";
            uint16_t port = 0;

            vpn_convert_ipv6_to_sockaddr(&v6addr, ip6h->daddr.s6_addr, 0);
            vpn_udp_ntop(&v6addr, addr_buff, sizeof(addr_buff), &ip, &port);
            APP_WARN("send v6 to %s\n", ip);

            //head->daddr = htonl(0xffffffff);
        } else {
            v6target = cache_v6_find(&v6rt, ip6h->daddr.s6_addr);
            if (v6target) {
                head->daddr = htonl(v6target->dest);
            }
        }

        cache_v6_add(&v6rt, ip6h->saddr.s6_addr, psmb->param.router_mac);
    } else {
        APP_WARN("invalid packet type - expected ipv4 or ipv6, received type %u\n", iph->version);
        return -1;
    }

    memcpy((uint8_t *)outbuff + sizeof(struct switch_pack_t), inbuff, len);
    return len + sizeof(struct switch_pack_t);
}

int switch_read_both(UDP_CTX *ctx, void *buff1, void *buff2, int len, struct switch_main_t *psmb)
{
    int dlen = -1;
    int rlen = switch_read(ctx->src_pctx, buff1, len, psmb);
    if (rlen <= 0) {
        return rlen;
    }

    if (SWITCH_UDP == ctx->src_pctx->type || SWITCH_TCP == ctx->src_pctx->type) {
        dlen = switch_read_decode(buff2, buff1, rlen);
        if(dlen < 0) {
            APP_WARN("invalid packet detected (socket: %d, len: %d)\n", ctx->src_pctx->sock, rlen);
            return dlen;
        }
        ctx->cbuf = buff2;
        ctx->clen = dlen;
        ctx->pbuf = buff1;
        ctx->plen = switch_update_header(buff1, buff2, dlen, psmb);
        if (ctx->clen < 0) {
            return -1;
        }
    } else if (SWITCH_TAP == ctx->src_pctx->type) {
        ctx->pbuf = buff1;
        ctx->plen = rlen;
        ctx->cbuf = buff2;
        ctx->clen = switch_add_header(buff2, buff1, rlen, psmb);
        if (ctx->clen < 0) {
            return -1;
        }
    } else {
        return -1;
    }

    return ctx->plen;
}

int switch_forward(struct switch_main_t *psmb, struct switch_ctx_t *sctx)
{
    unsigned char in_buffer[BUF_SIZE * 2];
    unsigned char out_buffer[BUF_SIZE * 2];
    int rlen, wlen;
    int packet_cnt = 0;

    while (1) {
        UDP_CTX ctx;
        ctx.src_pctx = sctx;

        rlen = switch_read_both(&ctx, &in_buffer[BUF_SIZE], &out_buffer[BUF_SIZE], BUF_SIZE, psmb);
        if (rlen <= 0) {
            break;
        }

        if(rlen < 20) {
            APP_WARN("invalid packet size - received %d bytes (minimum threshold: %d)\n", rlen, 20);
            continue;
        }

        /* switch or client todo... */
        struct iphdr *iph = (struct iphdr *)ctx.pbuf;
        uint32_t daddr = ntohl(iph->daddr);
        uint8_t version = iph->version;

        if (version == 4) {
            if (switch_in_cksum((uint16_t *)iph, iph->ihl * 4)) {
                APP_WARN("checksum validation failed\n");
                continue;
            }

            if (0xffffffff == daddr && 0xff == iph->protocol) {
                switch_process_heart(&ctx, &in_buffer[BUF_SIZE], &out_buffer[BUF_SIZE], BUF_SIZE, psmb);
                continue;
            }
        }

        ctx.type = 'n';
        wlen = send_to_router(&ctx, psmb);
        if (wlen <= 0) {
            break;
        }
        packet_cnt++;
    }
    return packet_cnt;
}

int switch_send_heart_timer(struct switch_main_t *psmb)
{
    unsigned char in_buffer[BUF_SIZE * 2];
    unsigned char out_buffer[BUF_SIZE * 2];
    struct switch_ctx_t *sctx, *stmp;
    uint32_t cache_time = get_time_ms();

    list_for_each_entry_safe(sctx, stmp, &psmb->head.list, list) {
        UDP_CTX ctx;
        ctx.src_pctx = sctx;
        if (SWITCH_TAP == ctx.src_pctx->type)
            continue;
        if (SWITCH_UDP == ctx.src_pctx->type && ctx.src_pctx->udp.if_bind)
            continue;
        if (SWITCH_TCP == ctx.src_pctx->type && ctx.src_pctx->tcp.if_bind)
            continue;

        struct cache_router_t *rt = NULL;
        struct cache_router_t *s, *tmp;
        cache_router_iter(&psmb->param,s,tmp) {
            if (!s->ctx)
                continue;
            if (!switch_address_cmp(ctx.src_pctx, s->ctx)) {
                rt = s;
                break;
            }
        }

        if (rt) {
            ctx.src_pctx = rt->ctx;
            APP_DEBUG("[heart] send neigh probe heart -> %08x\n", rt->next_hop_router);
        } else {
            APP_INFO("[heart] send probe heart\n");

            //check tcp
            if (ctx.src_pctx->msg_time && (cache_time - ctx.src_pctx->msg_time) > (3 * CACHE_ROUTE_UPDATE_TIME)) {
                if (SWITCH_TCP == ctx.src_pctx->type && ctx.src_pctx->tcp.sock >= 0) {
                    APP_WARN("[heart] lost heart, close tcp %d\n", ctx.src_pctx->tcp.sock);
                    switch_disconnect_tcp(ctx.src_pctx);
                }
            }

            //check udp
            if (ctx.src_pctx->msg_time && (cache_time - ctx.src_pctx->msg_time) > (6 * CACHE_ROUTE_UPDATE_TIME)) {
                if (SWITCH_UDP == ctx.src_pctx->type) {
                    APP_WARN("[heart] lost heart, rebind udp %d\n", ctx.src_pctx->tcp.sock);
                    switch_rebind_udp(ctx.src_pctx);
                }
            }
        }

        switch_send_heart(&ctx, &in_buffer[BUF_SIZE], &out_buffer[BUF_SIZE], BUF_SIZE, psmb);
    }
    return 0;
}

int switch_run(struct switch_args_t *args)
{
    uint32_t last_heart_time = 0, last_route_time = 0;
    int sctx_count = 0;
    int ret = -1;
    struct cache_router_t *router_all = NULL;
    struct cache_v6_t v6rt;
    struct switch_main_t smb;
    struct switch_ctx_t *sctx, *stmp;

    INIT_LIST_HEAD(&smb.head.list);
    memset(&smb.param, 0, sizeof(struct cache_router_t));
    smb.v6table = NULL;

    if (args->running) {
        APP_WARN("vpn is running\n");
        return -1;
    }

    args->running = 1;

#ifdef USE_CRYPTO
    ret = crypto_init();
    if(ret < 0) {
        APP_ERROR("crypto_init error\n");
        goto exit;
    }

    if (strcmp(args->password, DEFAULT_PASSWORD) != 0) {
        ret = crypto_set_password(args->password, strlen(args->password));
        if(ret < 0) {
            APP_ERROR("crypto_set_password error\n");
            goto exit;
        }
    }
#endif

    if (args->if_default_network) {
        struct in_addr ipaddr;
        ret = inet_aton(args->default_network, &ipaddr);
        if (ret < 0) {
            APP_ERROR("inet_aton error\n");
            goto exit;
        }
        smb.default_mac = ntohl(ipaddr.s_addr);
    }

    if (args->if_local_network) {
        struct in_addr ipaddr;
        ret = inet_aton(args->local_network, &ipaddr);
        if (ret < 0) {
            APP_ERROR("inet_aton error\n");
            goto exit;
        }
        smb.param.router_mac = ntohl(ipaddr.s_addr);
    } else {
#ifdef USE_CRYPTO
        crypto_gen_rand((void *)&smb.param.router_mac, sizeof(smb.param.router_mac));
#else
        smb.param.router_mac = rand();
#endif
        smb.param.router_mac &= ~(0xff << 24);
        smb.param.router_mac |= (0xa << 24);
    }
    smb.param.dest_router = smb.param.router_mac;
    smb.param.prefix_length = 32;
    smb.param.next_hop_router = smb.param.router_mac;
    smb.param.metric = 0;
    smb.param.time = 0;
    smb.param.ctx = NULL;
    smb.param.table = &router_all;
    cache_router_add(&smb.param);

    APP_DEBUG("router_mac = 0x%08x\n", smb.param.router_mac);
    APP_DEBUG("header = %d\n", sizeof(struct switch_pack_t));

    for (int i = 0; i < args->local_count; i++) {
        struct switch_ctx_t *rctx = NULL;
        if (args->local_addr[i].if_tcp) {
            rctx = switch_add_tcp(&smb, 1, &args->local_addr[i]);
        } else {
            rctx = switch_add_udp(&smb, 1, &args->local_addr[i]);
        }
        if (!rctx) {
            APP_ERROR("Failed to create local socket\n");
            goto exit;
        }
        sctx_count++;
    }

    for (int i = 0; i < args->server_count; i++) {
        struct switch_ctx_t *rctx = NULL;
        if (args->server_addr[i].if_tcp) {
            rctx = switch_add_tcp(&smb, 0, &args->server_addr[i]);
        } else {
            rctx = switch_add_udp(&smb, 0, &args->server_addr[i]);
        }
        if (!rctx) {
            APP_ERROR("Failed to create remote socket\n");
            goto exit;
        }
        sctx_count++;
    }

    if (args->has_tap) {
        struct switch_ctx_t *rctx = NULL;
        if (args->has_tap == 2) {
            rctx = switch_add_tun_native(&smb, args->tun_fd, "vpn");
        } else {
            /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
             *        IFF_TAP   - TAP device
             *        IFF_NO_PI - Do not provide packet information
             */
            rctx = switch_add_tap(&smb, IFF_TUN | IFF_NO_PI, args->ifname, args->mtu);
            if (!rctx) {
                APP_ERROR("Failed to allocating tun/tap interface\n");
                goto exit;
            }

            smb.param.add_router = switch_add_router;
        }

        smb.param.router_data = rctx;
        smb.param.ctx = rctx;
        cache_router_add(&smb.param);
        sctx_count++;
    }

    for (int i = 0; i < args->prefix_count; i++) {
        struct in_addr ipaddr;
        ret = inet_aton(args->prefixs[i].prefix, &ipaddr);
        if (ret < 0) {
            APP_ERROR("inet_aton error\n");
            continue;
        }
        smb.param.prefix_length = args->prefixs[i].len;
        smb.param.dest_router = ntohl(ipaddr.s_addr);
        smb.param.dest_router &= (0xffffffff << (32 - smb.param.prefix_length));
        cache_router_add(&smb.param);
    }

    APP_INFO("vpn started\n");

    while (args->running) {
        int maxsock = 0;
        int sock_count = 0;
        fd_set readset, writeset;
        struct timeval timeout;

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        FD_ZERO(&readset);
        FD_ZERO(&writeset);
        list_for_each_entry_safe(sctx, stmp, &smb.head.list, list) {
            int cur_fd = switch_get_fd(sctx);
            if (cur_fd < 0) {
                continue;
            }

            if (sctx->events & SWITCH_POLLIN)
                FD_SET(cur_fd, &readset);
            if (sctx->events & SWITCH_POLLOUT)
                FD_SET(cur_fd, &writeset);
            if(cur_fd > maxsock) {
                maxsock = cur_fd;
            }
            sock_count++;
        }

        if (-1 == select(maxsock + 1, &readset, &writeset, NULL, &timeout)) {
            if (errno == EINTR)
                continue;
            APP_ERROR("select() = %s\n", strerror(errno));
            break;
        }

        smb.current_time = get_time_ms();
        smb.param.time = smb.current_time;

        list_for_each_entry_safe(sctx, stmp, &smb.head.list, list) {
            int cur_fd = switch_get_fd(sctx);
            if (cur_fd < 0) {
                continue;
            }

            if (FD_ISSET(cur_fd, &readset)) {
                switch_forward(&smb, sctx);
            }

            if (FD_ISSET(cur_fd, &writeset)) {
                switch_connected_tcp(sctx);
            }
        }

        if (smb.current_time - last_route_time > CACHE_ROUTE_UPDATE_TIME) {
            last_route_time = smb.current_time;

            v6rt.time = smb.current_time;
            v6rt.table = &smb.v6table;
            if (DEBUG_INFO) {
                APP_INFO("active count: sock = %d, router = %d, router_v6 = %d\n",
                         sock_count, cache_router_count(&smb.param), cache_v6_count(&v6rt));
                list_for_each_entry_safe(sctx, stmp, &smb.head.list, list) {
                    switch_dump_send_router(sctx, NULL, "sock_list:");
                }
            }
            cache_route_update(&smb.param);
            cache_v6_update(&v6rt);
        }

        if (smb.current_time - last_heart_time > CACHE_ROUTE_UPDATE_TIME) {
            last_heart_time = smb.current_time;
            switch_send_heart_timer(&smb);
        }
    }
exit:
    list_for_each_entry_safe(sctx, stmp, &smb.head.list, list) {
        int cur_fd = switch_get_fd(sctx);
        if (cur_fd < 0) {
            continue;
        }

        if (SWITCH_TAP == sctx->type && !sctx->tap.if_native) {
            continue;
        }
        close(cur_fd);
    }
    cache_router_delete_all(&smb.param);
    v6rt.time = smb.current_time;
    v6rt.table = &smb.v6table;
    cache_v6_delete_all(&v6rt);

    args->running = 0;
    return 0;
}
