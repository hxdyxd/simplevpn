/*
 * rip.c - Provide simplevpn client service
 *
 * Copyright (C) 2024, hxdyxd <hxdyxd@gmail.com>
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

#include <net/if.h>
#include <linux/ip.h>
#include "app_debug.h"
#include "netclock.h"
#include "rip.h"
#include "cache_table.h"

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

void switch_rip_add_item(const struct cache_router_t *src_rt, struct cache_router_t *rt, void *p)
{
    uint8_t rip_sum = 0;
    struct switch_rip_t *rip = (struct switch_rip_t *)p;
    if (!rip) {
        return;
    }

    rt->rtt_send_time = get_time_ms();
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
        if (!dest_rt || !dest_rt->ctx) {
            rt->dest_router = dest_router;
            rt->prefix_length = prefix_length;
            rt->next_hop_router = next_hop_router;
            rt->metric = metric;
            cache_router_add(rt);
            APP_INFO("[heart] A rip_id=%u dest=%08x/%u next=%08x metric=%u <- %08x\n",
                 rip_id, dest_router, prefix_length, next_hop_router, metric, src_router);
        } else if (src_router == dest_rt->next_hop_router && !switch_address_cmp(rt->ctx, dest_rt->ctx)) {
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
            APP_INFO("[heart] C rip_id=%u dest=%08x/%u next=%08x metric=%u <- %08x\n",
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
        dlen = switch_read_encode(buff2, buff1, new_len);
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

    ctx->src_pctx->msg_time = get_time_ms();
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
        switch_rip_add_resp_item(&rt, rip);

        return 0;
    } else {
        APP_WARN("[heart] new err info 0x%08x\n", ntohl(rip->router_mac));
        return -1;
    }

    if (SWITCH_UDP == ctx->src_pctx->type || SWITCH_TCP == ctx->src_pctx->type) {
        dlen = switch_read_encode(in_buff, new_buff, new_len);
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
