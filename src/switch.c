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

#include "simplevpn.h"
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <sys/select.h> 
#include <sys/ioctl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include <sys/time.h>
#include "app_debug.h"
#include "netclock.h"
#include "cache_table.h"
#include "udp_alloc.h"
#ifdef USE_CRYPTO
#include "crypto.h"
#endif

#define DEBUG_INFO     (log_level == log_debug)
#define TRACE_INFO     (log_level == log_trace)
#define TIME_DEBUG      (15000)

#define BUF_SIZE                   2000

typedef struct {
    void *cbuf;
    void *pbuf;
    int clen;
    int plen;
    char type;
    uint32_t saddr;
    uint32_t daddr;
    uint32_t default_addr;
    struct switch_ctx_t *src_pctx;
} UDP_CTX;

struct switch_pack_t {
    uint8_t hop_limit;
    uint8_t recv[3];
};


#define RIP_ITEM_MAX    25
#define RIP_HEADER_LEN  8
#define RIP_TYPE_REQ    1
#define RIP_TYPE_REP    2

struct switch_rip_item_t {
    uint32_t next_hop_router;
    uint32_t dest_router;
    uint8_t prefix_length;
    uint8_t metric;
    uint8_t recv[2];
};

struct switch_rip_t {
    uint8_t type;
    uint8_t ver;
    uint16_t len;
    uint32_t router_mac;
    struct switch_rip_item_t info[RIP_ITEM_MAX];
};

int switch_read_encode(uint8_t *out, uint8_t *in, int rlen, struct cache_router_t *ppam);
static uint16_t switch_in_cksum(const uint16_t *buf, int bufsz);

void msg_dump(void *buf, int len)
{
    int i, j;
    unsigned char *ch = buf;
    for (i = 0; i < len; i = j) {
        for (j = i; j < i + 16; j++) {
            if (j < len) {
                PRINTF("%02x ", ch[j]);
            } else {
                PRINTF("   ");
            }
        }
        PRINTF("  ");
        for (j = i; j < len && j < i + 16; j++) {
            if ('0' <= ch[j] && ch[j] <= 'z') {
                PRINTF("%c", ch[j]);
            } else {
                PRINTF(".");
            }
        }

        PRINTF("\n");
    }
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
            APP_WARN("switch_write: write buffer is full, pos = %d, size = %d\n", psctx->tcp.write_pos, psctx->tcp.write_size);
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
                APP_WARN("send: %s\n", strerror(errno));
            } else {
                APP_ERROR("send: %s\n", strerror(errno));
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

static void send_to_self(UDP_CTX *ctx_p)
{
    if (DEBUG_INFO) {
        switch_dump_send_router(ctx_p->src_pctx, NULL, "[self]");
    }

    int r = switch_write(ctx_p->src_pctx, ctx_p);
    if (r < 0) {
        return;
    }
}

static void send_to_target_router(const struct cache_router_t *rt, struct cache_router_t *s, void *p)
{
    UDP_CTX *ctx_p = (UDP_CTX *)p;

    if (ctx_p->saddr == s->dest_router) {
        APP_DEBUG("[%c]send udp to self!\n", ctx_p->type);
        return;
    }

    if (TRACE_INFO) {
        switch_dump_send_router(ctx_p->src_pctx, s, "[forward]");
    }

    int r = switch_write(s->ctx, ctx_p);
    if (r < 0) {
        return;
    }
    s->tx_bytes += ctx_p->clen;
    s->tx_pks++;
}

static int send_icmp_packet(UDP_CTX *ctx, struct cache_router_t *ppam, uint8_t type, uint8_t code)
{
    struct icmphdr *icmph = (struct icmphdr *)((uint8_t *)ctx->pbuf - sizeof(struct icmphdr));
    struct iphdr *iph = (struct iphdr *)((uint8_t *)icmph - sizeof(struct iphdr));
    int dlen = 0;
    uint16_t ip_len;

    ip_len = ctx->plen + sizeof(struct icmphdr) + sizeof(struct iphdr);
    memset(iph, 0, sizeof(struct iphdr));
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0xc0;
    iph->tot_len = htons(ip_len);
    iph->ttl = 0x40;
    iph->daddr = htonl(ctx->saddr);
    iph->saddr = htonl(ppam->router_mac);
    iph->protocol = 1;
    iph->check = switch_in_cksum((uint16_t *)iph, iph->ihl * 4); //-O3 Abnormal

    memset(icmph, 0, sizeof(struct icmphdr));
    icmph->type = type;
    icmph->code = code;
    icmph->checksum = 0;
    icmph->checksum = switch_in_cksum((uint16_t *)icmph, ctx->plen + sizeof(struct icmphdr)); //-O3 Abnormal

    if (SWITCH_UDP == ctx->src_pctx->type || SWITCH_TCP == ctx->src_pctx->type) {
        dlen = switch_read_encode(ctx->cbuf, (void *)iph, ip_len, ppam);
        if(dlen < 0) {
            APP_WARN("encode error\n");
            return dlen;
        }
        ctx->pbuf = iph;
        ctx->cbuf = ctx->cbuf;
        ctx->plen = ip_len;
        ctx->clen = dlen;
    } else if (SWITCH_TAP == ctx->src_pctx->type) {
        ctx->clen = ctx->plen = ip_len;
        ctx->cbuf = ctx->pbuf = iph;
    } else {
        return -1;
    }

    ctx->type = 'i';
    send_to_self(ctx);
    APP_DEBUG("write icmp %d %d = %d\n", type, code, ip_len);
    return 0;
}

static void send_to_router(UDP_CTX *ctx_p, struct cache_router_t *ppam)
{
    struct cache_router_t src_rt;
    src_rt.dest_router = ppam->router_mac;
    src_rt.table = ppam->table;
    struct cache_router_t *target = NULL;
    target = cache_router_search(&src_rt, ctx_p->daddr);
    if (!target && ctx_p->default_addr) {
        target = cache_router_search(&src_rt, ctx_p->default_addr);
    }
    if (!target || target->metric >= CACHE_ROUTE_METRIC_MAX) {
        APP_DEBUG("can't found target %08x\n", ctx_p->daddr);
        send_icmp_packet(ctx_p, ppam, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
        return;
    }
    if (!target->ctx || !target->ctx->type) {
        APP_WARN("can't found target device  %08x\n", ctx_p->daddr);
        send_icmp_packet(ctx_p, ppam, ICMP_DEST_UNREACH, ICMP_PROT_UNREACH);
        return;
    }

    if (ctx_p->daddr != ppam->router_mac && ((uint8_t *)(ctx_p->cbuf))[0] == 0) {
        APP_WARN("ttl is zero\n");
        send_icmp_packet(ctx_p, ppam, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
        return;
    }

    send_to_target_router(&src_rt, target, ctx_p);
}

// Interent checksum
static uint16_t switch_in_cksum(const uint16_t *buf, int bufsz)
{
    uint32_t sum = 0;

    while (bufsz > 1)
    {
        sum += *buf;
        buf++;
        bufsz -= 2;
    }

    if (bufsz == 1)
        sum += *(uint8_t *)buf;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += sum >> 16;
    return ~sum;
}

struct switch_ctx_t *switch_add_udp(struct switch_main_t *smb, int if_bind, const char *host, const char *port)
{
    int sock;
    socklen_t sin_size;

    struct switch_ctx_t *psctx = malloc(sizeof(struct switch_ctx_t));
    if (!psctx) {
        APP_ERROR("Failed to alloc memory\n");
        return NULL;
    }

    APP_DEBUG("add udp %s:%s\n", host, port);
    if (if_bind) {
        sock = vpn_udp_alloc(if_bind, host, port, &psctx->udp.localaddr, &sin_size);
    } else {
        sock = vpn_udp_alloc(if_bind, host, port, &psctx->udp.addr, &sin_size);
    }
    if (sock < 0) {
        APP_ERROR("Failed to create udp socket\n");
        return NULL;
    }

    psctx->type = SWITCH_UDP;
    psctx->udp.sock = sock;
    psctx->udp.if_bind = if_bind;
    psctx->udp.if_local = 1;
    list_add(&psctx->list, &smb->head.list);
    return psctx;
}

int switch_reconnect_tcp(struct switch_ctx_t *ctx)
{
    int sock;
    socklen_t sin_size;

    if (SWITCH_TCP != ctx->type || ctx->tcp.if_bind) {
        APP_ERROR("Failed to reconnect tcp\n");
        return -1;
    }

    APP_DEBUG("reconnect tcp %s:%s\n", ctx->tcp.local_addr.host, ctx->tcp.local_addr.port);

    sock = vpn_tcp_alloc(0, ctx->tcp.local_addr.host, ctx->tcp.local_addr.port, &ctx->tcp.addr, &sin_size);
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

struct switch_ctx_t *switch_add_tcp(struct switch_main_t *smb, int if_bind, const char *host, const char *port)
{
    int sock;
    socklen_t sin_size;

    struct switch_ctx_t *psctx = malloc(sizeof(struct switch_ctx_t));
    if (!psctx) {
        APP_ERROR("Failed to alloc memory\n");
        return NULL;
    }

    APP_DEBUG("add tcp %s:%s\n", host, port);
    if (if_bind) {
        sock = vpn_tcp_alloc(if_bind, host, port, &psctx->tcp.localaddr, &sin_size);
    } else {
        sock = vpn_tcp_alloc(if_bind, host, port, &psctx->tcp.addr, &sin_size);
    }
    if (sock < 0) {
        APP_ERROR("Failed to create tcp socket\n");
        return NULL;
    }

    psctx->type = SWITCH_TCP;
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
    strcpy(psctx->tcp.local_addr.host, host);
    strcpy(psctx->tcp.local_addr.port, port);
    psctx->tcp.local_addr.if_tcp = 1;
    list_add(&psctx->list, &smb->head.list);
    return psctx;
}

struct switch_ctx_t *switch_add_accepted_tcp(struct switch_ctx_t *ctx)
{
    int sock;
    socklen_t sin_size = sizeof(struct sockaddr_storage);

    if (!ctx->tcp.if_bind || !ctx->tcp.if_local) {
        APP_ERROR("Failed to accept tcp\n");
        return NULL;
    }

    struct switch_ctx_t *psctx = malloc(sizeof(struct switch_ctx_t));
    if (!psctx) {
        APP_ERROR("Failed to alloc memory\n");
        return NULL;
    }

    sock  = accept(ctx->tcp.sock, (struct sockaddr *)&psctx->tcp.addr, &sin_size);
    if (sock < 0) {
        APP_WARN("accept(fd = %d) %s\n", ctx->tcp.sock, strerror(errno));
        return NULL;
    }

    APP_DEBUG("accept tcp %d\n", sock);
    psctx->type = SWITCH_TCP;
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
    list_add(&psctx->list, &ctx->list);
    return psctx;
}

struct switch_ctx_t *switch_add_tap(struct switch_main_t *smb, int flags, uint16_t mtu)
{
    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";

    struct switch_ctx_t *psctx = malloc(sizeof(struct switch_ctx_t));
    if (!psctx) {
        APP_ERROR("Failed to alloc memory\n");
        return NULL;
    }

    if ((fd = open(clonedev, O_RDWR)) < 0) {
        free(psctx);
        return NULL;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags;

    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        close(fd);
        free(psctx);
        APP_ERROR("ioctl(%d, TUNSETIFF, 0x%x) = %s\n", fd, flags, strerror(errno));
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
    psctx->tap.fd = fd;
    psctx->tap.if_native = 1;
    strncpy(psctx->tap.ifname, ifr.ifr_name, sizeof(psctx->tap.ifname));
    list_add(&psctx->list, &smb->head.list);
    return psctx;
}

struct switch_ctx_t *switch_add_tun_native(struct switch_main_t *smb, int tun_fd, char *name)
{
    struct switch_ctx_t *psctx = malloc(sizeof(struct switch_ctx_t));
    if (!psctx) {
        APP_ERROR("Failed to alloc memory\n");
        return NULL;
    }
    psctx->type = SWITCH_TAP;
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

int switch_read(struct switch_ctx_t *psctx, void *buff, int len, struct cache_router_t *ppam)
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
            switch_add_accepted_tcp(psctx);
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
                    memcpy(buff, &psctx->tcp.read_buffer[2], packet_size);

                    psctx->tcp.read_pos -= (packet_size + 2);
                    memmove(&psctx->tcp.read_buffer[0], &psctx->tcp.read_buffer[packet_size + 2], psctx->tcp.read_pos);
                    return packet_size;
                }
            }

fail_reconnect:
            if (rlen == 0) {
                APP_WARN("connect disconnect %d\n", psctx->tcp.sock);
                if (psctx->tcp.write_buffer)
                    free(psctx->tcp.write_buffer);
                if (psctx->tcp.read_buffer)
                    free(psctx->tcp.read_buffer);
                if (psctx->tcp.sock >= 0)
                    close(psctx->tcp.sock);
                psctx->tcp.write_buffer = NULL;
                psctx->tcp.read_buffer = NULL;
                psctx->tcp.sock = -1;

                if (psctx->tcp.if_bind && !psctx->tcp.if_local) {

                    struct cache_router_t *s, *tmp;
                    cache_router_iter(ppam,s,tmp) {
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
                    APP_WARN("recvfrom %s\n", strerror(errno));
                    return rlen;
                } else {
                    APP_ERROR("recvfrom %s\n", strerror(errno));
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

int switch_read_decode(uint8_t *out, uint8_t *in, int rlen, struct cache_router_t *ppam)
{
    int dlen = -1;
    struct switch_pack_t *head = (struct switch_pack_t *)in;
    in += sizeof(struct switch_pack_t);
    rlen -= sizeof(struct switch_pack_t);

#ifdef USE_CRYPTO
    if (crypto_is_enabled()) {
        dlen = crypto_decrypt(out, in, rlen);
        if(dlen < 0) {
            APP_WARN("decrypt error, len = %d\n", rlen);
            return dlen;
        }
    } else
#endif
    {
        memcpy(out, in, rlen);
        dlen = rlen;
    }

    struct iphdr *iph = (struct iphdr *)out;
    if (4 == iph->version) {
        if (head->hop_limit < iph->ttl) {
            iph->check += iph->ttl - head->hop_limit;
            iph->ttl = head->hop_limit;
        }
        if (!iph->ttl) {
            APP_WARN("ttl is zero\n");
            return -1;
        }
    }

    head->hop_limit--;

    return dlen;
}

int switch_read_encode(uint8_t *out, uint8_t *in, int rlen, struct cache_router_t *ppam)
{
    int dlen = -1;

    struct iphdr *iph = (struct iphdr *)in;
    struct switch_pack_t *head = (struct switch_pack_t *)out;
    out += sizeof(struct switch_pack_t);
    memset(head, 0, sizeof(struct switch_pack_t));
    if (4 == iph->version) {
        head->hop_limit = iph->ttl;
    }

#ifdef USE_CRYPTO
    if (crypto_is_enabled()) {
        dlen = crypto_encrypt(out, in, rlen);
        if(dlen < 0) {
            APP_WARN("encrypt error, len = %d\n", rlen);
            return dlen;
        }
    } else
#endif
    {
        memcpy(out, in, rlen);
        dlen = rlen;
    }
    return dlen + sizeof(struct switch_pack_t);
}

int switch_read_both(UDP_CTX *ctx, void *buff1, void *buff2, int len, struct cache_router_t *ppam)
{
    int dlen = -1;
    int rlen = switch_read(ctx->src_pctx, buff1, len, ppam);
    if (rlen <= 0) {
        return rlen;
    }

    if (SWITCH_UDP == ctx->src_pctx->type || SWITCH_TCP == ctx->src_pctx->type) {
        dlen = switch_read_decode(buff2, buff1, rlen, ppam);
        if(dlen < 0) {
            return dlen;
        }
        ctx->pbuf = buff2;
        ctx->cbuf = buff1;
        ctx->plen = dlen;
        ctx->clen = rlen;
    } else if (SWITCH_TAP == ctx->src_pctx->type) {
        dlen = switch_read_encode(buff2, buff1, rlen, ppam);
        if(dlen < 0) {
            return dlen;
        }
        ctx->pbuf = buff1;
        ctx->cbuf = buff2;
        ctx->plen = rlen;
        ctx->clen = dlen;
    } else {
        return -1;
    }

    return ctx->plen;
}

void switch_rip_add_item(const struct cache_router_t *src_rt, struct cache_router_t *rt, void *p)
{
    uint8_t rip_sum = 0;
    struct switch_rip_t *rip = (struct switch_rip_t *)p;
    if (!rip) {
        return;
    }

    rip_sum = rip->len / sizeof(struct switch_rip_item_t);
    if (rip_sum >= RIP_ITEM_MAX) {
        APP_WARN("[heart] rip_sum too large %u\n", rip_sum);
        return;
    }

    /* 排除请求者自己 */
    if (src_rt->dest_router == rt->dest_router)
        return;

    /* 排除下一跳是自己 */
    if (src_rt->dest_router == rt->next_hop_router)
        return;

    rt->rtt_send_time = get_time_ms();
    rip->info[rip_sum].next_hop_router = htonl(rt->next_hop_router);
    rip->info[rip_sum].prefix_length = rt->prefix_length;
    rip->info[rip_sum].dest_router = htonl(rt->dest_router);
    rip->info[rip_sum].metric = rt->metric;
    rip->len += sizeof(struct switch_rip_item_t);
    APP_DEBUG("[heart] send rip_id=%u dest=%08x/%u next=%08x metric=%u -> %08x\n",
             rip_sum, rt->dest_router, rt->prefix_length, rt->next_hop_router, rt->metric, src_rt->dest_router);
}

void switch_rip_add_resp_item(struct cache_router_t *rt, struct switch_rip_t *rip)
{
    uint8_t rip_id = 0;
    uint8_t rip_sum = 0;
    uint32_t src_router = rt->dest_router;

    rip_sum = rip->len / sizeof(struct switch_rip_item_t);
    if (rip_sum >= RIP_ITEM_MAX) {
        APP_WARN("[heart] rip_sum too large %u\n", rip_sum);
        return;
    }

    for (rip_id = 0; rip_id < rip_sum; rip_id++) {
        uint32_t dest_router = ntohl(rip->info[rip_id].dest_router);
        uint8_t prefix_length = rip->info[rip_id].prefix_length;
        uint32_t next_hop_router = ntohl(rip->router_mac);
        uint8_t metric = rip->info[rip_id].metric + 1;
        uint32_t peer_next_hop = ntohl(rip->info[rip_id].next_hop_router);

        if (peer_next_hop == rt->router_mac) {
            APP_WARN("[heart] S rip_id=%u dest=%08x next=%08x metric=%u <- %08x\n", rip_id, dest_router, next_hop_router, metric, src_router);
            continue;
        }

        struct cache_router_t *dest_rt = cache_router_find(rt, dest_router);
        if (!dest_rt) {
            rt->dest_router = dest_router;
            rt->prefix_length = prefix_length;
            rt->next_hop_router = next_hop_router;
            rt->metric = metric;
            cache_router_add(rt);
            APP_DEBUG("[heart] A rip_id=%u dest=%08x/%u next=%08x metric=%u <- %08x\n",
                 rip_id, dest_router, prefix_length, next_hop_router, metric, src_router);
        } else if (src_router == dest_rt->next_hop_router) {
            rt->dest_router = dest_router;
            rt->prefix_length = prefix_length;
            rt->next_hop_router = next_hop_router;
            rt->metric = metric;
            cache_router_add(rt);
            APP_DEBUG("[heart] U rip_id=%u dest=%08x/%u next=%08x metric=%u <- %08x\n",
                 rip_id, dest_router, prefix_length, next_hop_router, metric, src_router);
        } else if (metric < dest_rt->metric || (metric == dest_rt->metric && rt->time - dest_rt->time >= CACHE_ROUTE_TIME_OUT/2)) {
            rt->dest_router = dest_router;
            rt->prefix_length = prefix_length;
            rt->next_hop_router = next_hop_router;
            rt->metric = metric;
            cache_router_add(rt);
            APP_DEBUG("[heart] C rip_id=%u dest=%08x/%u next=%08x metric=%u <- %08x\n",
                 rip_id, dest_router, prefix_length, next_hop_router, metric, src_router);
        } else {
            APP_DEBUG("[heart] . rip_id=%u dest=%08x/%u next=%08x metric=%u <- %08x\n",
                 rip_id, dest_router, prefix_length, next_hop_router, metric, src_router);
        }
    }
}

int switch_send_heart(UDP_CTX *ctx, void *buff1, void *buff2, int len, struct cache_router_t *ppam)
{
    int dlen = -1;
    int new_len = 0;
    struct iphdr *iph = (struct iphdr *)buff1;
    struct switch_rip_t *new_rip = (struct switch_rip_t *)((uint8_t *)iph + sizeof(struct iphdr));

    memset(iph, 0, sizeof(struct iphdr));
    iph->version = 4;
    iph->ihl = 5;
    iph->ttl = 0x40;
    iph->daddr = 0xffffffff;
    iph->saddr = htonl(ppam->router_mac);
    iph->protocol = 0xff;
    iph->check = switch_in_cksum((uint16_t *)iph, iph->ihl * 4); //-O3 Abnormal

    memset(new_rip, 0, sizeof(struct switch_rip_t));
    new_rip->type = RIP_TYPE_REQ;
    new_rip->ver = 1;
    new_rip->len = 0;
    new_rip->router_mac = htonl(ppam->router_mac);

    struct cache_router_t src_rt;
    src_rt.dest_router = ctx->src_pctx->router_mac;
    src_rt.table = ppam->table;
    cache_route_iter(&src_rt, switch_rip_add_item, new_rip);

    new_len = sizeof(struct iphdr) + RIP_HEADER_LEN + new_rip->len;

    //Big Endian
    new_rip->len = htons(new_rip->len);

    if (SWITCH_UDP == ctx->src_pctx->type || SWITCH_TCP == ctx->src_pctx->type) {
        dlen = switch_read_encode(buff2, buff1, new_len, ppam);
        if(dlen < 0) {
            APP_WARN("[heart] encode error\n");
            return dlen;
        }
        ctx->pbuf = buff1;
        ctx->cbuf = buff2;
        ctx->plen = new_len;
        ctx->clen = dlen;
    } else if (SWITCH_TAP == ctx->src_pctx->type) {
        ctx->clen = ctx->plen = new_len;
        ctx->cbuf = ctx->pbuf = buff1;
    } else {
        return -1;
    }

    ctx->type = 'h';
    send_to_self(ctx);
    return ctx->plen;
}

int switch_process_heart(UDP_CTX *ctx, void *buff1, void *buff2, int len, struct cache_router_t *ppam)
{
    int dlen = -1;
    uint8_t *in_buff = ctx->pbuf;
    uint8_t *new_buff = ctx->cbuf;
    int new_len = 0;
    struct iphdr *iph = (struct iphdr *)in_buff;
    int rlen = ctx->plen - RIP_HEADER_LEN;
    struct switch_rip_t *rip = (struct switch_rip_t *)((uint8_t *)iph + sizeof(struct iphdr));
    if (rlen < 0) {
        APP_WARN("[heart] length error\n");
        return -1;
    }

    if (RIP_TYPE_REQ == rip->type) {
        struct iphdr *new_iph = (struct iphdr *)new_buff;
        struct switch_rip_t *new_rip = (struct switch_rip_t *)((uint8_t *)new_iph + sizeof(struct iphdr));
        memset(new_iph, 0, sizeof(struct iphdr));
        new_iph->version = 4;
        new_iph->ihl = 5;
        new_iph->ttl = 0x40;
        new_iph->daddr = 0xffffffff;
        new_iph->saddr = htonl(ppam->router_mac);
        new_iph->protocol = 0xff;
        new_iph->check = switch_in_cksum((uint16_t *)new_iph, iph->ihl * 4);

        //Little Endian
        rip->len = ntohs(rip->len);
        APP_DEBUG("[heart] new req info 0x%08x %u\n", ntohl(rip->router_mac), rip->len);
        ctx->src_pctx->router_mac = ntohl(rip->router_mac);
        struct cache_router_t rt, src_rt;
        memcpy(&rt, ppam, sizeof(struct cache_router_t));
        rt.router_mac = ppam->router_mac;
        rt.dest_router = ntohl(rip->router_mac);
        rt.prefix_length = 32;
        rt.next_hop_router = ntohl(rip->router_mac);
        rt.metric = 1;
        rt.time = ppam->time;
        rt.table = ppam->table;
        rt.ctx = ctx->src_pctx;
        //memcpy(&rt.ctx, ctx->src_pctx, sizeof(rt.ctx));
        memcpy(&src_rt, &rt, sizeof(src_rt));
        cache_router_add(&rt);
        switch_rip_add_resp_item(&rt, rip);

        memset(new_rip, 0, sizeof(struct switch_rip_t));
        new_rip->type = RIP_TYPE_REP;
        new_rip->ver = 1;
        new_rip->len = 0;
        new_rip->router_mac = htonl(ppam->router_mac);
        cache_route_iter(&src_rt, switch_rip_add_item, new_rip);

        new_len = sizeof(struct iphdr) + RIP_HEADER_LEN + new_rip->len;

        //Big Endian
        new_rip->len = htons(new_rip->len);

    } else if (RIP_TYPE_REP == rip->type) {
        //Little Endian
        rip->len = ntohs(rip->len);
        APP_DEBUG("[heart] new resp info 0x%08x %u\n", ntohl(rip->router_mac), rip->len);
        ctx->src_pctx->router_mac = ntohl(rip->router_mac);
        struct cache_router_t rt;
        memcpy(&rt, ppam, sizeof(struct cache_router_t));
        rt.router_mac = ppam->router_mac;
        rt.dest_router = ntohl(rip->router_mac);
        rt.prefix_length = 32;
        rt.next_hop_router = ntohl(rip->router_mac);
        rt.metric = 1;
        rt.time = ppam->time;
        rt.table = ppam->table;
        rt.ctx = ctx->src_pctx;
        //memcpy(&rt.ctx, ctx->src_pctx, sizeof(rt.ctx));
        cache_router_add(&rt);
        switch_rip_add_resp_item(&rt, rip);

        return 0;
    } else {
        APP_WARN("[heart] new err info 0x%08x\n", ntohl(rip->router_mac));
        return -1;
    }

    if (SWITCH_UDP == ctx->src_pctx->type || SWITCH_TCP == ctx->src_pctx->type) {
        dlen = switch_read_encode(in_buff, new_buff, new_len, ppam);
        if(dlen < 0) {
            APP_WARN("[heart] encode error\n");
            return dlen;
        }
        ctx->pbuf = new_buff;
        ctx->cbuf = in_buff;
        ctx->plen = new_len;
        ctx->clen = dlen;
    } else {
        return -1;
    }

    ctx->type = 'h';
    send_to_self(ctx);
    return 0;
}

int switch_run(struct switch_args_t *args)
{
    unsigned char in_buffer[BUF_SIZE * 2];
    unsigned char out_buffer[BUF_SIZE * 2];
    uint32_t cache_time = 0;
    uint32_t last_heart_time = 0, last_route_time = 0;
    int sctx_count = 0;
    int ret = -1;
    struct cache_router_t *router_all = NULL;
    struct cache_router_t param;
    uint32_t default_mac = 0;
    struct switch_main_t smb;
    struct switch_ctx_t *sctx, *stmp;

    INIT_LIST_HEAD(&smb.head.list);
    memset(&param, 0, sizeof(struct cache_router_t));

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
        default_mac = ntohl(ipaddr.s_addr);
    }

    if (args->if_local_network) {
        struct in_addr ipaddr;
        ret = inet_aton(args->local_network, &ipaddr);
        if (ret < 0) {
            APP_ERROR("inet_aton error\n");
            goto exit;
        }
        param.router_mac = ntohl(ipaddr.s_addr);
    } else {
#ifdef USE_CRYPTO
        crypto_gen_rand((void *)&param.router_mac, sizeof(param.router_mac));
#else
        param.router_mac = rand();
#endif
        param.router_mac &= ~(0xff << 24);
        param.router_mac |= (0xa << 24);
    }
    param.dest_router = param.router_mac;
    param.prefix_length = 32;
    param.next_hop_router = param.router_mac;
    param.metric = 0;
    param.time = 0;
    param.ctx = NULL;
    param.table = &router_all;
    cache_router_add(&param);

    APP_DEBUG("router_mac = 0x%08x\n", param.router_mac);
    APP_DEBUG("header = %d\n", sizeof(struct switch_pack_t));

    for (int i = 0; i < args->local_count; i++) {
        struct switch_ctx_t *rctx = NULL;
        if (args->local_addr[i].if_tcp) {
            rctx = switch_add_tcp(&smb, 1, args->local_addr[i].host, args->local_addr[i].port);
        } else {
            rctx = switch_add_udp(&smb, 1, args->local_addr[i].host, args->local_addr[i].port);
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
            rctx = switch_add_tcp(&smb, 0, args->server_addr[i].host, args->server_addr[i].port);
        } else {
            rctx = switch_add_udp(&smb, 0, args->server_addr[i].host, args->server_addr[i].port);
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
            rctx = switch_add_tap(&smb, IFF_TUN | IFF_NO_PI, args->mtu);
            if (!rctx) {
                APP_ERROR("Failed to allocating tun/tap interface\n");
                goto exit;
            }

            param.add_router = switch_add_router;
        }

        param.router_data = rctx;
        param.ctx = rctx;
        cache_router_add(&param);
        sctx_count++;
    }

    for (int i = 0; i < args->prefix_count; i++) {
        struct in_addr ipaddr;
        ret = inet_aton(args->prefixs[i].prefix, &ipaddr);
        if (ret < 0) {
            APP_ERROR("inet_aton error\n");
            continue;
        }
        param.dest_router = ntohl(ipaddr.s_addr);
        param.prefix_length = args->prefixs[i].len;
        cache_router_add(&param);
    }

    APP_INFO("vpn started\n");

    while (args->running) {
        int maxsock = 0;
        int sock_count = 0;
        fd_set readset;
        struct timeval timeout;

        timeout.tv_sec = 2;
        timeout.tv_usec = 0;

        FD_ZERO(&readset);
        list_for_each_entry_safe(sctx, stmp, &smb.head.list, list) {
            int cur_fd = switch_get_fd(sctx);
            if (cur_fd < 0) {
                continue;
            }

            FD_SET(cur_fd, &readset);
            if(cur_fd > maxsock) {
                maxsock = cur_fd;
            }
            sock_count++;
        }

        if (-1 == select(maxsock + 1, &readset, NULL, NULL, &timeout)) {
            if (errno == EINTR)
                continue;
            APP_ERROR("select() = %s\n", strerror(errno));
            break;
        }

        cache_time = get_time_ms();
        param.time = cache_time;

        list_for_each_entry_safe(sctx, stmp, &smb.head.list, list) {
            int cur_fd = switch_get_fd(sctx);
            if (cur_fd < 0) {
                continue;
            }

            if (FD_ISSET(cur_fd, &readset)) {
                UDP_CTX ctx;
                ctx.src_pctx = sctx;

                int rlen = switch_read_both(&ctx, &in_buffer[BUF_SIZE], &out_buffer[BUF_SIZE], BUF_SIZE, &param);
                if (rlen <= 0) {
                    continue;
                }

                if(rlen < 20) {
                    APP_WARN("recv length error\n");
                    continue;
                }

                /* switch or client todo... */
                struct iphdr *iph = (struct iphdr *)ctx.pbuf;
                uint32_t daddr = ntohl(iph->daddr);
                uint32_t saddr = ntohl(iph->saddr);
                uint8_t version = iph->version;

                if (version != 4) {
                    APP_WARN("verssion = %u error\n", version);
                    continue;
                }

                if (switch_in_cksum((uint16_t *)iph, iph->ihl * 4)) {
                    APP_WARN("recv cksum error\n");
                    continue;
                }

                if (daddr == 0xffffffff) {
                    switch_process_heart(&ctx, &in_buffer[BUF_SIZE], &out_buffer[BUF_SIZE], BUF_SIZE, &param);
                    continue;
                }

                ctx.type = 'n';
                ctx.saddr = saddr;
                ctx.daddr = daddr;
                ctx.default_addr = default_mac;
                send_to_router(&ctx, &param);
            }
        }

        if (cache_time - last_heart_time > CACHE_ROUTE_UPDATE_TIME) {
            last_heart_time = cache_time;

            list_for_each_entry_safe(sctx, stmp, &smb.head.list, list) {
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
                cache_router_iter(&param,s,tmp) {
                    if (!s->ctx)
                        continue;
                    if (SWITCH_TAP == s->ctx->type)
                        continue;
                    if (SWITCH_UDP == s->ctx->type 
                     && !memcmp(&ctx.src_pctx->udp.addr, &s->ctx->udp.addr, sizeof(struct sockaddr_storage))) {
                        rt = s;
                        break;
                    }
                    if (SWITCH_TCP == s->ctx->type 
                     && !memcmp(&ctx.src_pctx->tcp.addr, &s->ctx->tcp.addr, sizeof(struct sockaddr_storage))) {
                        rt = s;
                        break;
                    }
                }

                if (rt) {
                    ctx.src_pctx = rt->ctx;
                    APP_DEBUG("[heart] send neigh probe heart -> %08x\n", rt->next_hop_router);
                } else {
                    APP_DEBUG("[heart] send probe heart\n");
                }

                switch_send_heart(&ctx, &in_buffer[BUF_SIZE], &out_buffer[BUF_SIZE], BUF_SIZE, &param);
            }
        }

        if (cache_time - last_route_time > CACHE_ROUTE_UPDATE_TIME) {
            last_route_time = cache_time;
            APP_INFO("active count: router = %d, sock = %d\n", cache_router_count(&param), sock_count);
            cache_route_printall(&param);
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
    cache_router_delete_all(&param);

    args->running = 0;
    return 0;
}
