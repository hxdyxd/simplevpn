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

#include <linux/if_tun.h>
#include <linux/if_ether.h>
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
#include <net/if.h>
#include <fcntl.h>

#include <sys/time.h>
#include "app_debug.h"
#include "netclock.h"
#include "cache_table.h"
#include "udp_alloc.h"
#include "simplevpn.h"
#ifdef USE_CRYPTO
#include "crypto.h"
#endif

#define DEBUG_INFO     (log_level == log_debug)
#define TIME_DEBUG      (15000)
#define MAX_HEART_TIME  (CACHE_TIME_OUT / 10)

#define BUF_SIZE                   2000

typedef struct {
    void *cbuf;
    void *pbuf;
    int clen;
    int plen;
    char type;
    struct switch_ctx_t *src_pctx;
}UDP_CTX;

struct switch_pack_t {
    uint32_t router_mac;
    uint32_t reserved[3];
};

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
                APP_WARN("sendto\n");
            } else {
                APP_ERROR("sendto\n");
                // TODO rebuild socket
            }
        }
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

static void send_to_target(struct cache_table_t *table, void *p)
{
    if(table == NULL || p == NULL) {
        APP_ERROR("ptr error\n");
        return;
    }
    UDP_CTX *ctx_p = (UDP_CTX *)p;

    if (SWITCH_TAP == table->ctx.type) {
        if (table->ctx.type == ctx_p->src_pctx->type) {
            if (table->ctx.tap.fd == ctx_p->src_pctx->tap.fd) {
                APP_DEBUG("[%c]send tap to self!\n", ctx_p->type);
                return;
            }
        }
    } else if (SWITCH_UDP == table->ctx.type) {
        struct sockaddr_storage *target_addr = &table->ctx.udp.addr;
        char *tip = "";
        uint16_t tport = 0;
        char addr_buf[INET6_ADDRSTRLEN];
        vpn_udp_ntop(target_addr, addr_buf, sizeof(addr_buf), &tip, &tport);

        if (table->ctx.type == ctx_p->src_pctx->type) {
            struct sockaddr_storage *src_addr = &ctx_p->src_pctx->udp.addr;
            char *sip = "";
            uint16_t sport = 0;
            char src_addr_buf[INET6_ADDRSTRLEN];
            vpn_udp_ntop(src_addr, src_addr_buf, sizeof(src_addr_buf), &sip, &sport);

            if (tport == sport && !strncmp(tip, sip, INET6_ADDRSTRLEN)) {
                if(ctx_p->type == 'n') {
                    APP_WARN("[%c]send udp to self!\n", ctx_p->type);
                    switch_dump_send_route(ctx_p->src_pctx, table, "send udp to self!");
                } else {
                    APP_DEBUG("[%c]send udp to self!\n", ctx_p->type);
                }
                return;
            }
        }
    }

#if DEBUG_INFO
    if(ctx_p->type != 'n') {
        switch_dump_send_route(ctx_p->src_pctx, table, "");
    }
#endif

    int r = switch_write(&table->ctx, ctx_p);
    if (r < 0) {
        return;
    }
    table->tx_bytes += ctx_p->clen;
    table->tx_pks++;
}

static void send_to_heart_target(struct cache_table_t *table, void *p)
{
    if(table == NULL || p == NULL) {
        APP_ERROR("ptr error\n");
        return;
    }
    UDP_CTX *ctx_p = (UDP_CTX *)p;

    if (SWITCH_TAP == table->ctx.type) {
        return;
    }
    if (SWITCH_UDP == table->ctx.type && table->ctx.udp.if_local) {
        return;
    }

#if DEBUG_INFO
    switch_dump_send_route(NULL, table, "[heart]");
#endif

    int r = switch_write(&table->ctx, ctx_p);
    if (r < 0) {
        return;
    }
    table->tx_bytes += ctx_p->clen;
    table->tx_pks++;
}

int switch_add_udp(struct switch_ctx_t *psctx, int if_bind, const char *host, const char *port)
{
    int sock;
    socklen_t sin_size;

    APP_DEBUG("add udp %s:%s\n", host, port);
    if (if_bind) {
        sock = vpn_udp_alloc(if_bind, host, port, &psctx->udp.localaddr, &sin_size);
    } else {
        sock = vpn_udp_alloc(if_bind, host, port, &psctx->udp.addr, &sin_size);
    }
    if (sock < 0) {
        APP_ERROR("Failed to create udp socket\n");
        return -1;
    }

    psctx->type = SWITCH_UDP;
    psctx->udp.sock = sock;
    psctx->udp.if_bind = if_bind;
    psctx->udp.if_local = 1;

    return sock;
}

int switch_add_udp_peer(struct switch_ctx_t *psctx, struct switch_ctx_t *bctx, const char *host, const char *port)
{
    int sock;
    socklen_t sin_size;

    APP_DEBUG("add udp peer %s:%s\n", host, port);
    sock = vpn_get_sockaddr(host, port, &psctx->udp.addr, &sin_size);
    if (sock < 0) {
        APP_ERROR("Failed to create udp sockaddr\n");
        return -1;
    }

    psctx->type = SWITCH_UDP;
    psctx->udp.sock = bctx->udp.sock;
    psctx->udp.if_bind = 0;
    psctx->udp.if_local = 0;

    return bctx->udp.sock;
}

int switch_add_tap(struct switch_ctx_t *psctx, int flags)
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
        APP_ERROR("ioctl(%d, TUNSETIFF, 0x%x) = %s\n", fd, flags, strerror(errno));
        return err;
    }

    APP_INFO("Open tun/tap device: %s for reading...\n", ifr.ifr_name);

    psctx->type = SWITCH_TAP;
    psctx->tap.fd = fd;
    strncpy(psctx->tap.ifname, ifr.ifr_name, sizeof(psctx->tap.ifname));

    return fd;
}

int switch_get_fd(struct switch_ctx_t *psctx)
{
    if (SWITCH_UDP == psctx->type) {
        if (psctx->udp.if_local)
            return psctx->udp.sock;
        else
            return -1;
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

int switch_read(struct switch_ctx_t *psctx, void *buff, int len)
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

int switch_read_decode(uint8_t *out, uint8_t *in, int rlen, uint32_t router_mac)
{
    int dlen = -1;
    struct switch_pack_t *head1;
    out -= sizeof(struct switch_pack_t);
    head1 = (void *)out;

#ifdef USE_CRYPTO
    if (crypto_is_enabled()) {
        dlen = crypto_decrypt(out, in, rlen);
        if(dlen < 0) {
            APP_WARN("decrypt error\n");
            return dlen;
        }
    } else
#endif
    {
        memcpy(out, in, rlen);
        dlen = rlen;
    }

    if (head1->router_mac == router_mac) {
        APP_WARN("router_mac is repeat 0x%08x\n", head1->router_mac);
        return -1;
    }

    return dlen -= sizeof(struct switch_pack_t);
}

int switch_read_encode(uint8_t *out, uint8_t *in, int rlen, uint32_t router_mac)
{
    int dlen = -1;
    struct switch_pack_t *head1;
    in -= sizeof(struct switch_pack_t);
    rlen += sizeof(struct switch_pack_t);
    head1 = (void *)in;

    memset(head1, 0, sizeof(struct switch_pack_t));
    head1->router_mac = router_mac;

#ifdef USE_CRYPTO
    if (crypto_is_enabled()) {
        dlen = crypto_encrypt(out, in, rlen);
        if(dlen < 0) {
            APP_WARN("encrypt error\n");
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

int switch_read_both(UDP_CTX *ctx, void *buff1, void *buff2, int len, uint32_t router_mac)
{
    int dlen = -1;
    int rlen = switch_read(ctx->src_pctx, buff1, len);
    if (rlen < 0) {
        return rlen;
    }

    if (SWITCH_UDP == ctx->src_pctx->type) {
        dlen = switch_read_decode(buff2, buff1, rlen, router_mac);
        if(dlen < 0) {
            return dlen;
        }
        ctx->pbuf = buff2;
        ctx->cbuf = buff1;
        ctx->plen = dlen;
        ctx->clen = rlen;
    } else if (SWITCH_TAP == ctx->src_pctx->type) {
        dlen = switch_read_encode(buff2, buff1, rlen, router_mac);
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

int switch_gen_heart(UDP_CTX *ctx, void *buff1, void *buff2, int len, uint32_t router_mac)
{
    int dlen = -1;
    int rlen = sizeof(struct ethhdr);
    struct ethhdr *eh = (struct ethhdr *)buff1;

    memset(eh->h_dest, 0xff, sizeof(eh->h_dest));
    memset(eh->h_source, 0xff, sizeof(eh->h_source));
    eh->h_proto = 0xffff;

    if (SWITCH_UDP == ctx->src_pctx->type) {
        dlen = switch_read_encode(buff2, buff1, rlen, router_mac);
        if(dlen < 0) {
            APP_WARN("encode error\n");
            return dlen;
        }
        ctx->pbuf = buff1;
        ctx->cbuf = buff2;
        ctx->plen = rlen;
        ctx->clen = dlen;
    } else if (SWITCH_TAP == ctx->src_pctx->type) {
        ctx->clen = ctx->plen = rlen;
        ctx->cbuf = ctx->pbuf = buff1;
    } else {
        return -1;
    }

    ctx->type = 'h';
    return ctx->plen;
}

int switch_run(struct switch_args_t *args)
{
    unsigned char in_buffer[BUF_SIZE * 2];
    unsigned char out_buffer[BUF_SIZE * 2];
    struct cache_table_t *cache_all = NULL;
    uint32_t cache_time = 0;
    uint32_t last_time = 0, last_heart_time = 0;
    struct switch_ctx_t sctx[MAX_CTX_NUM];
    int sctx_count = 0;
    int ret = -1;
    uint32_t router_mac = 0;

#ifdef USE_CRYPTO
    ret = crypto_init();
    if(ret < 0) {
        APP_ERROR("crypto_init error\n");
        return ret;
    }

    if (strcmp(args->password, DEFAULT_PASSWORD) != 0) {
        ret = crypto_set_password(args->password, strlen(args->password));
        if(ret < 0) {
            APP_ERROR("crypto_set_password error\n");
            return ret;
        }
    }

    crypto_gen_rand((void *)&router_mac, sizeof(router_mac));
#else
    router_mac = rand();
#endif
    APP_DEBUG("router_mac = 0x%08x\n", router_mac);

    memset(sctx, 0, sizeof(sctx));
    if (args->if_bind) {
        ret = switch_add_udp(&sctx[sctx_count++], 1, args->local_addr.host, args->local_addr.port);
    } else if (args->server_count) {
        ret = switch_add_udp(&sctx[sctx_count++], 0, args->server_addr[0].host, args->server_addr[0].port);
    } else {
        ret = -1;
    }
    if (ret < 0) {
        APP_ERROR("Failed to create udp socket\n");
        return ret;
    }

    for (int i = 0; i < args->server_count; i++) {
        ret = switch_add_udp_peer(&sctx[sctx_count], &sctx[0], args->server_addr[i].host, args->server_addr[i].port);
        if (ret < 0) {
            APP_ERROR("Failed to create udp server\n");
            return ret;
        }

        cache_table_add_forever(&cache_all, sctx_count, &sctx[sctx_count]);
        sctx_count++;
    }

    if (args->has_tap) {
        /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
         *        IFF_TAP   - TAP device
         *        IFF_NO_PI - Do not provide packet information
         */
        ret = switch_add_tap(&sctx[sctx_count], IFF_TAP | IFF_NO_PI);
        if (ret < 0) {
            APP_ERROR("Failed to allocating tun/tap interface\n");
            return ret;
        }

        cache_table_add_forever(&cache_all, sctx_count, &sctx[sctx_count]);
        sctx_count++;
    }

    while (1) {
        int maxsock = 0;
        fd_set readset;
        struct timeval timeout;

        timeout.tv_sec = 2;
        timeout.tv_usec = 0;

        FD_ZERO(&readset);
        for (int i = 0; i < sctx_count; i++) {
            int cur_fd = switch_get_fd(&sctx[i]);
            if (cur_fd < 0) {
                continue;
            }

            FD_SET(cur_fd, &readset);
            if(cur_fd > maxsock) {
                maxsock = cur_fd;
            }
        }

        if (-1 == select(maxsock + 1, &readset, NULL, NULL, &timeout)) {
            if (errno == EINTR)
                continue;
            APP_ERROR("select() = %s\n", strerror(errno));
            break;
        }

        cache_time = get_time_ms();

        for (int i = 0; i < sctx_count; i++) {
            struct switch_ctx_t *pctx = &sctx[i];
            int cur_fd = switch_get_fd(pctx);
            if (cur_fd < 0) {
                continue;
            }

            if (FD_ISSET(cur_fd, &readset)) {
                UDP_CTX ctx;
                ctx.src_pctx = pctx;

                int rlen = switch_read_both(&ctx, &in_buffer[BUF_SIZE], &out_buffer[BUF_SIZE], BUF_SIZE, router_mac);
                if (rlen < 0) {
                    continue;
                }

                if(rlen < 14) {
                    APP_WARN("ethernet pack error\n");
                    continue;
                }

                /* switch or client todo... */
                struct ethhdr *eh = (struct ethhdr *)ctx.pbuf;
                uint8_t *ether_dst = eh->h_dest;
                uint8_t *ether_src = eh->h_source;
                uint16_t ether_proto = eh->h_proto;

                if (memcmp(ether_src, "\xff\xff\xff\xff\xff\xff", HWADDR_LEN) == 0 &&
                    memcmp(ether_dst, "\xff\xff\xff\xff\xff\xff", HWADDR_LEN) == 0 &&
                    0xffff == ether_proto) {
                    cache_table_add_heart(&cache_all, cache_time, pctx);
                    APP_INFO("[heart] update heart\n");
                    continue;
                }

                cache_table_add(&cache_all, ether_src, cache_time, pctx);


                if (memcmp(ether_dst, "\xff\xff\xff\xff\xff\xff", HWADDR_LEN) == 0 ||
                   memcmp(ether_dst, "\x33\x33", 2) == 0 ) {
                    //广播包
#if DEBUG_INFO
                    APP_DEBUG("!Broadcast : %d %02x:%02x:%02x:%02x:%02x:%02x -> all %04X %5d %5d\n", pctx->type,
                     ether_src[0], ether_src[1], ether_src[2], ether_src[3], ether_src[4], ether_src[5], 
                     ether_proto, ctx.plen, ctx.clen);
#endif
                    ctx.type = 'b';
                    cache_table_iter_once(&cache_all, send_to_target, &ctx);
                } else {
                    struct cache_table_t *target = cache_table_find(&cache_all, ether_dst);
                    if(target == NULL) {
                        //目标硬件地址未找到，泛洪包
#if DEBUG_INFO
                        APP_DEBUG("!Flood : %d %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x %04X %5d %5d\n",
                         pctx->type,
                         ether_src[0], ether_src[1], ether_src[2], ether_src[3], ether_src[4], ether_src[5],
                         ether_dst[0], ether_dst[1], ether_dst[2], ether_dst[3], ether_dst[4], ether_dst[5],
                         ether_proto, ctx.plen, ctx.clen);
#endif
                        ctx.type = 'f';
                        cache_table_iter_once(&cache_all, send_to_target, &ctx);
                        //printf("fl\n");
                    } else {
                        //转发包
#if DEBUG_INFO
                        APP_TRACE("!Normal : %d %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x %04X %5d %5d\n",
                          pctx->type,
                         ether_src[0], ether_src[1], ether_src[2], ether_src[3], ether_src[4], ether_src[5],
                         ether_dst[0], ether_dst[1], ether_dst[2], ether_dst[3], ether_dst[4], ether_dst[5],
                         ether_proto, ctx.plen, ctx.clen);
#endif
                        ctx.type = 'n';
                        send_to_target(target, &ctx);
                    }
                }
            }
        }

        if (cache_time - last_time > TIME_DEBUG) {
            last_time = cache_time;
            printf("Active Count: %d\n", cache_table_count(&cache_all));
            cache_table_print(&cache_all);
        }

        if (cache_time - last_heart_time > MAX_HEART_TIME) {
            last_heart_time = cache_time;
            UDP_CTX ctx;
            ctx.src_pctx = &sctx[0];
            int rlen = switch_gen_heart(&ctx, &in_buffer[BUF_SIZE], &out_buffer[BUF_SIZE], BUF_SIZE, router_mac);
            if (rlen < 0) {
                continue;
            }
            cache_table_iter_once(&cache_all, send_to_heart_target, &ctx);
        }
    }
    for (int i = 0; i < sctx_count; i++) {
        int cur_fd = switch_get_fd(&sctx[i]);
        if (cur_fd < 0) {
            continue;
        }

        close(cur_fd);
    }
    cache_table_delete_all(&cache_all);
    return -1;
}
