/*
 * cache_table.c - Provide simplevpn switch service
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

#include "cache_table.h"
#include "netclock.h"
#include "udp_alloc.h"
#include "app_debug.h"
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>

#define TEST         (0)

#if TEST
struct sockaddr_storage {
    char name[5];
};
#endif

static int switch_dump_ctx__(struct switch_ctx_t *psctx, char *msg, void *buff, int len)
{
    const char *ip = "";
    uint16_t port = 0;
    char addr_buf[INET6_ADDRSTRLEN];
    if (SWITCH_TAP == psctx->type) {
        return snprintf(buff, len, "%s!TUN fd=%d ifname=%s",
         msg,
         psctx->tap.fd, psctx->tap.ifname);
    }

    if (SWITCH_UDP == psctx->type) {
        vpn_udp_ntop(&psctx->udp.addr, addr_buf, sizeof(addr_buf), &ip, &port);

        return snprintf(buff, len, "%s|UDP.%s fd=%d peer=%s:%u",
         msg,
         psctx->tcp.if_bind ? "S" : "C", 
         psctx->udp.sock, ip, port);
    }

    if (SWITCH_TCP == psctx->type) {
        vpn_udp_ntop(&psctx->tcp.addr, addr_buf, sizeof(addr_buf), &ip, &port);

        return snprintf(buff, len, "%s|TCP.%s%s fd=%d peer=%s:%u ws=%d rs=%d",
         msg, 
         psctx->tcp.if_bind ? "S" : "C", psctx->tcp.if_local ? "L" : "", 
         psctx->tcp.sock, ip, port, psctx->tcp.write_buffer_size, psctx->tcp.read_buffer_size);
    }
    return -1;
}

static int switch_dump_table__(struct cache_router_t *s, char *msg, void *buff, int len)
{
    struct in_addr ipaddr;
    char *dest_ip, *next_ip;
    int ret = 0;
    uint32_t cache_time = get_time_ms();
    uint32_t time_dif = cache_time - (s->gc_enable ? s->gc_time : s->time);
    if (!s->metric)
        time_dif = 0;
    ipaddr.s_addr = htonl(s->dest_router);
    dest_ip = strdup(inet_ntoa(ipaddr));
    ipaddr.s_addr = htonl(s->next_hop_router);
    next_ip = strdup(inet_ntoa(ipaddr));
    if (!dest_ip || !next_ip) {
        goto exit;
    }

    ret = snprintf(buff, len, "%sdest=%s/%u next=%s metric=%u rtt=%u %stime=%u",
             msg, dest_ip, s->prefix_length, next_ip, s->metric, s->rtt_time, s->gc_enable?"gc":"", time_dif);
exit:
    free(next_ip);
    free(dest_ip);
    return ret;
}

int switch_dump_send_router(struct switch_ctx_t *psctx, struct cache_router_t *s, char *msg)
{
    int ret = -1;
    char sbuff[128];
    char tbuff[128];

    memset(sbuff, 0, sizeof(sbuff));
    memset(tbuff, 0, sizeof(sbuff));

    if (psctx) {
        ret = switch_dump_ctx__(psctx, "", sbuff, sizeof(sbuff));
        if (ret < 0)
            return ret;
    }

    if (s) {
        ret = switch_dump_table__(s, "", tbuff, sizeof(tbuff));
        if (ret < 0)
            return ret;
    }

    APP_INFO("%s %s -> %s\n", msg, sbuff, tbuff);
    return 0;
}

int switch_router_dump(struct cache_router_t *s, char *msg)
{
    char sbuff[128];
    char tbuff[128];
    memset(sbuff, 0, sizeof(sbuff));
    memset(tbuff, 0, sizeof(sbuff));

    if (s->ctx)
        switch_dump_ctx__(s->ctx, "", sbuff, sizeof(sbuff));
    else
        strncpy(sbuff, "none", sizeof(sbuff));
    switch_dump_table__(s, "", tbuff, sizeof(tbuff));

    APP_INFO("%s %s %s tx=%u\n",
             msg, tbuff, sbuff, s->tx_bytes);
    return 0;
}

void cache_router_add(struct cache_router_t *rt)
{
    struct cache_router_t *s;
    int new_add = 0;
    if (!rt || !rt->router_mac) {
        APP_WARN("add router fail\n");
        return;
    }

    if (rt->dest_router == rt->router_mac && 0 != rt->metric) {
        APP_WARN("add self dest fail\n");
        return;
    }

    if (rt->next_hop_router == rt->router_mac && 0 != rt->metric) {
        APP_WARN("add self next fail\n");
        return;
    }

    HASH_FIND_INT(*rt->table, &rt->dest_router, s);
    if (!s) {
        if (rt->metric >= CACHE_ROUTE_METRIC_MAX)
            return;
        s = (struct cache_router_t *)calloc(1, sizeof *s);
        s->dest_router = rt->dest_router;
        s->router_mac = rt->router_mac;
        s->table = rt->table;
        HASH_ADD_INT(*rt->table, dest_router, s);
        new_add = 1;
    }
    s->prefix_length = rt->prefix_length;
    s->next_hop_router = rt->next_hop_router;
    s->metric = rt->metric;
    s->time = rt->time;
    s->rtt_time = s->time - s->rtt_send_time;
    s->add_router = rt->add_router;
    s->router_data = rt->router_data;

    if (rt->ctx && SWITCH_UDP == rt->ctx->type && rt->ctx->udp.if_bind) {
        if (!s->ctx || !s->alloced_ctx) {
            s->ctx = malloc(sizeof(struct switch_ctx_t));
            s->alloced_ctx = 1;
            APP_DEBUG("alloced ctx %x = %p\n", s->dest_router, rt->ctx);
        }
        memcpy(s->ctx, rt->ctx, sizeof(struct switch_ctx_t));
    } else {
        if (s->alloced_ctx) {
            free(s->ctx);
            s->ctx = NULL;
            s->alloced_ctx = 0;
        }
        if (s->ctx != rt->ctx) {
            APP_DEBUG("update ctx %x = %p -> %p\n", s->dest_router, s->ctx, rt->ctx);
        }
        s->ctx = rt->ctx;
    }
    //memcpy(&s->ctx, &rt->ctx, sizeof(s->ctx));

    if (rt->metric >= CACHE_ROUTE_METRIC_MAX) {
        s->metric = CACHE_ROUTE_METRIC_MAX;
        if (!s->gc_enable) {
            s->gc_enable = 1;
            s->gc_time = rt->time;
        }
    } else {
        if (s->gc_enable) {
            s->gc_enable = 0;
            s->gc_time = rt->time;
        }
    }

    if (s->add_router && (new_add || 0 == s->metric)) {
        s->add_router(s, 1);
    }
}

int cache_router_count(struct cache_router_t *rt)
{
    if(rt->table == NULL)
        return 0;
    return HASH_COUNT(*rt->table);
}

struct cache_router_t *cache_router_find(struct cache_router_t *rt, uint32_t dest_router)
{
    struct cache_router_t *s;
    HASH_FIND_INT(*rt->table, &dest_router, s);
    return s;
}

struct cache_router_t *cache_router_search(struct cache_router_t *rt, uint32_t dest_router)
{
    struct cache_router_t *s;
    int i;
    uint32_t dest_prefix = 0;
    for (i = 0; i < 32; i++) {
        dest_prefix = dest_router & (0xffffffff << i);
        HASH_FIND_INT(*rt->table, &dest_prefix, s);
        if (s && 32 - i <= s->prefix_length) {
            break;
        }
    }
    return s;
}

struct cache_router_t *cache_router_find_by_addr(struct cache_router_t *rt, struct sockaddr_storage *addr)
{
    struct cache_router_t *s;
    HASH_FIND( hh, *rt->table, addr, sizeof(struct sockaddr_storage), s);
    return s;
}

void cache_route_printall(struct cache_router_t *rt)
{
    struct cache_router_t *s, *tmp;
    uint32_t cache_time = 0;
    cache_time = get_time_ms();

    HASH_ITER(hh, *rt->table, s, tmp) {
        uint32_t time_dif = cache_time - s->time;
        if (!s->metric)
            time_dif = 0;
        if (time_dif > CACHE_ROUTE_TIME_OUT) {
            APP_INFO("timeout, dest=%08x next_hop=%08x metric=%u time=%u\n",
                        s->dest_router, s->next_hop_router, s->metric, time_dif);
            s->metric = CACHE_ROUTE_METRIC_MAX;
            if (!s->gc_enable) {
                s->gc_enable = 1;
                s->gc_time = cache_time;
            }
        }
        if (s->gc_enable && (cache_time - s->gc_time) > CACHE_ROUTE_GC_OUT) {
            APP_WARN("delete, dest=%08x next_hop=%08x metric=%u time=%u\n",
                        s->dest_router, s->next_hop_router, s->metric, time_dif);
            if (s->add_router) {
                s->add_router(s, 0);
            }
            HASH_DEL(*rt->table, s);  /* user: pointer to delete */
            if (s->alloced_ctx && s->ctx)
                free(s->ctx);
            free(s);             /* optional; it's up to you! */
            continue;
        }

        switch_router_dump(s, "");
    }
}

void cache_route_iter(struct cache_router_t *rt,
                           void (*call_user_fun)(const struct cache_router_t *, struct cache_router_t *, void *p),
                           void *p)
{
    struct cache_router_t *s, *tmp;

    HASH_ITER(hh, *rt->table, s, tmp) {
        if (s->router_mac == s->dest_router)
            continue;
        call_user_fun(rt, s, p);
    }
}

void cache_router_delete_all(struct cache_router_t *rt)
{
    struct cache_router_t *s, *tmp;

    HASH_ITER(hh, *rt->table, s, tmp) {
        HASH_DEL(*rt->table, s);  /* user: pointer to deletee */
        if (s->alloced_ctx && s->ctx)
            free(s->ctx);
        free(s);             /* optional; it's up to you! */
    }
}
